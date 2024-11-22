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

use async_stream::try_stream;
use futures::{Stream, TryStream, TryStreamExt};
use openssl::{
    ssl::{Ssl, SslAcceptor},
    x509::X509,
};
use std::{
    fmt::Debug,
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
pub fn incoming<S>(
    incoming: S,
    acceptor: SslAcceptor,
) -> impl Stream<Item = Result<SslStream<S::Ok>, Error>>
where
    S: TryStream + Unpin,
    S::Ok: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static,
    S::Error: Into<crate::Error>,
{
    let mut incoming = incoming;

    try_stream! {
        while let Some(stream) = incoming.try_next().await? {
            let ssl = Ssl::new(acceptor.context())?;
            let mut tls = tokio_openssl::SslStream::new(ssl, stream)?;
            Pin::new(&mut tls).accept().await?;

            let ssl = SslStream {
                inner: tls
            };

            yield ssl;
        }
    }
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
