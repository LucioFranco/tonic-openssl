//! A openssl adaptor for `tonic`.
//!
//! Examples can be found in the `example` crate
//! within the repository.

#![doc(html_root_url = "https://docs.rs/tonic-openssl/0.2.0")]
#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

mod client;
pub use client::{connector, new_endpoint};

use async_stream::try_stream;
use futures::{Stream, TryStreamExt};
use openssl::{
    ssl::{Ssl, SslAcceptor},
    x509::X509,
};
use std::{
    fmt::Debug,
    io,
    ops::ControlFlow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;

/// Wrapper error type.
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A const that contains the on the wire `h2` alpn
/// value that can be passed directly to OpenSSL.
pub const ALPN_H2_WIRE: &[u8] = b"\x02h2";

/// Wrap some incoming stream of io types with OpenSSL's
/// `SslStream` type. This will take some acceptor and a
/// stream of io types and accept connections.
pub fn incoming<IO, IE>(
    incoming: impl Stream<Item = Result<IO, IE>>,
    acceptor: SslAcceptor,
) -> impl Stream<Item = Result<SslStream<IO>, Error>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    IE: Into<crate::Error>,
{
    try_stream! {
        let mut incoming = std::pin::pin!(incoming);
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            // Process the next tcp accept or the next handshake complete.
            match select(&mut incoming, &mut tasks).await {
                SelectOutput::Incoming(stream) => {
                    // Next tcp stream accepted, push to the task set to do handshake in the background.
                    // tls and ssl construct calls do not expect to fail.
                    let ssl = Ssl::new(acceptor.context())?;
                    let mut tls = tokio_openssl::SslStream::new(ssl, stream)?;
                    tasks.spawn(async move {
                        Pin::new(&mut tls).accept().await?;
                        let ssl = SslStream {
                            inner: tls
                        };
                        Ok(ssl)
                    });
                }

                SelectOutput::Io(io) => {
                    // Next ssl stream ready from task set.
                    yield io;
                }

                // tcp accept or client handshake has error.
                // Terminate the server if cannot handle the error.
                SelectOutput::Err(e) => match handle_accept_error(e) {
                    ControlFlow::Continue(_) => continue,
                    ControlFlow::Break(e) => Err(e)?,
                }

                // No more tcp accept stream
                SelectOutput::Done => {
                    break;
                }
            }
        }
    }
}

/// Select when incoming tcp stream is accepted or the next ssl stream is ready.
async fn select<IO: 'static, IE>(
    incoming: &mut (impl Stream<Item = Result<IO, IE>> + Unpin),
    tasks: &mut tokio::task::JoinSet<Result<SslStream<IO>, crate::Error>>,
) -> SelectOutput<IO>
where
    IE: Into<crate::Error>,
{
    if tasks.is_empty() {
        return match incoming.try_next().await {
            Ok(Some(stream)) => SelectOutput::Incoming(stream),
            Ok(None) => SelectOutput::Done,
            Err(e) => SelectOutput::Err(e.into()),
        };
    }

    tokio::select! {
        stream = incoming.try_next() => {
            match stream {
                Ok(Some(stream)) => SelectOutput::Incoming(stream),
                Ok(None) => SelectOutput::Done,
                Err(e) => SelectOutput::Err(e.into()),
            }
        }

        accept = tasks.join_next() => {
            match accept.expect("JoinSet should never end") {
                Ok(Ok(io)) => SelectOutput::Io(io),
                Ok(Err(e)) => SelectOutput::Err(e),
                Err(e) => SelectOutput::Err(e.into()),
            }
        }
    }
}

enum SelectOutput<A> {
    Incoming(A),      // new tcp stream
    Io(SslStream<A>), // new ssl stream
    Err(crate::Error),
    Done,
}

/// When server handles accept error or client connection ssl error,
/// this function determines if server should continue to run.
/// The logic is similar to rustls tonic:
/// https://github.com/hyperium/tonic/blob/e9a8c3c366a9080cca99e9b9aa09ed85c0a90a5e/tonic/src/transport/server/incoming.rs#L90
fn handle_accept_error(e: impl Into<crate::Error>) -> ControlFlow<crate::Error> {
    let e = e.into();

    if let Some(e) = e.downcast_ref::<openssl::ssl::Error>() {
        let e_io = e.io_error();
        if e_io.is_none() {
            // this is ssl error. ssl error on a single client should not abort server.
            return ControlFlow::Continue(());
        }
        // list of io error that should not affect server handling next request.
        // openssl might read from socket and get these errors.
        // TODO: the list is copied from tonic rustls, openssl might have a smaller list.
        let e_io = e_io.unwrap();
        if matches!(
            e_io.kind(),
            io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::Interrupted
                | io::ErrorKind::InvalidData // Raised if TLS handshake failed
                | io::ErrorKind::UnexpectedEof // Raised if TLS handshake failed
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
        ) {
            return ControlFlow::Continue(());
        }
    }
    ControlFlow::Break(e)
}

/// A `SslStream` wrapper type that implements tokio's io traits
/// and tonic's `Connected` trait.
#[derive(Debug)]
pub struct SslStream<S> {
    inner: tokio_openssl::SslStream<S>,
}

impl<S: Connected> Connected for SslStream<S> {
    type ConnectInfo = SslConnectInfo<S::ConnectInfo>;

    fn connect_info(&self) -> Self::ConnectInfo {
        let inner = self.inner.get_ref().connect_info();

        // Currently openssl rust does not support clone of objects
        // So we need to reparse the X509 certs.
        // See: https://github.com/sfackler/rust-openssl/issues/1112
        let ssl = self.inner.ssl();
        let certs = ssl
            .verified_chain()
            .map(|certs| {
                certs
                    .iter()
                    .filter_map(|c| c.to_pem().ok())
                    .filter_map(|p| X509::from_pem(&p).ok())
                    .collect()
            })
            .map(Arc::new);

        SslConnectInfo { inner, certs }
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Connection info for SSL streams.
///
/// This type will be accessible through [request extensions](tonic::Request::extensions).
///
/// See [`Connected`](tonic::transport::server::Connected) for more details.
#[derive(Debug, Clone)]
pub struct SslConnectInfo<T> {
    inner: T,
    certs: Option<Arc<Vec<X509>>>,
}

impl<T> SslConnectInfo<T> {
    /// Get a reference to the underlying connection info.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the underlying connection info.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Return the set of connected peer SSL certificates.
    pub fn peer_certs(&self) -> Option<Arc<Vec<X509>>> {
        self.certs.clone()
    }
}
