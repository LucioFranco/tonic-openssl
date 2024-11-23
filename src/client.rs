//! Client connection helpers

use std::net::SocketAddr;

use openssl::ssl::SslConnector;
use tokio::net::TcpStream;
use tonic::transport::{Endpoint, Uri};
use tower::Service;

/// Creates an endpoint with and local uri that is never used.
/// Use `connector` to make connections.
pub fn new_endpoint() -> Endpoint {
    tonic::transport::Endpoint::from_static("http://[::]:50051")
}

/// tonic client connector to connect to https endpoint at addr using
/// openssl settings in ssl.
/// domain is the server name to validate, and if none, the host part in the uri
/// is used instead. Disabling validation is not supported.
/// # Examples
/// ```
/// use openssl::ssl::SslMethod;
/// use openssl::ssl::SslConnector;
/// async fn example(){
///     let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
///     let ch: tonic::transport::Channel= tonic_openssl::new_endpoint()
///         .connect_with_connector(tonic_openssl::connector(
///             "https:://localhost:12345".parse().unwrap(),
///             connector,
///            Some("localhost".to_string()),
///         ))
///         .await.unwrap();
/// }
/// ```
pub fn connector(
    uri: Uri,
    ssl_conn: SslConnector,
    domain: Option<String>,
) -> impl Service<
    Uri,
    Response = impl hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    Future = impl Send + 'static,
    Error = crate::Error,
> {
    tower::service_fn(move |_: Uri| {
        let domain = domain.clone();
        let uri = uri.clone();
        let ssl_conn = ssl_conn.clone();
        async move {
            let addrs = dns_resolve(&uri).await?;
            let ssl_config = ssl_conn.configure()?;

            let ssl = match domain {
                Some(d) => {
                    // configure server name check.
                    ssl_config.into_ssl(&d)?
                }
                // use the host part in the uri to do server name check.
                // unwrap should not panic since the above uri to addr passed.
                None => ssl_config.into_ssl(uri.host().unwrap())?,
            };
            // Connect and get ssl stream
            let io = connect_tcp(addrs).await?;
            let mut stream = tokio_openssl::SslStream::new(ssl, io)?;
            std::pin::Pin::new(&mut stream).connect().await?;
            Ok::<_, crate::Error>(hyper_util::rt::TokioIo::new(stream))
        }
    })
}

/// Use the host:port portion of the uri and resolve to an sockaddr.
/// If uri host portion is an ip string, then directly use the ip addr without
/// dns lookup.
async fn dns_resolve(uri: &Uri) -> std::io::Result<Vec<SocketAddr>> {
    let host_port = uri
        .authority()
        .ok_or(std::io::Error::from(std::io::ErrorKind::InvalidInput))?
        .as_str();
    match host_port.parse::<SocketAddr>() {
        Ok(addr) => Ok(vec![addr]),
        Err(_) => {
            // uri is using a dns name. try resolve it and return the first.
            tokio::net::lookup_host(host_port)
                .await
                .map(|a| a.collect::<Vec<_>>())
        }
    }
}

/// Connect to the target addr (from the same dns). The first success SockAddr connection
/// stream is returned. This is needed because sometimes ipv4 or ipv6 addrs are returned
/// by dns resolution, and only 1 of them works, especially in docker. This is the
/// same logic in hyper client.
async fn connect_tcp(addrs: Vec<SocketAddr>) -> std::io::Result<TcpStream> {
    let mut conn_err = std::io::Error::from(std::io::ErrorKind::AddrNotAvailable);
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => conn_err = e,
        }
    }
    Err(conn_err)
}
