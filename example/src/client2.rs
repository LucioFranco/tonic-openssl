//! This example shows how to replace `tonic::transport::Channel` with a custom
//! implementation. To do this, we need to implement the `tower::Service` trait.
//!
//! This is an adaptation of client.rs which doesn't use closures.
//! This makes it easier to store the resulting GreeterClient inside a struct.
use hello_world::greeter_client::GreeterClient;
use hello_world::HelloRequest;
use hyper::{Request, Response, Uri};
use hyper_openssl::client::legacy::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client, ResponseFuture},
    rt::TokioExecutor,
};
use openssl::{
    ssl::{SslConnector, SslMethod},
    x509::X509,
};
use std::{error::Error, task::Poll};
use tonic::body::BoxBody;
use tonic_openssl::ALPN_H2_WIRE;
use tower::Service;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();
    let pem = tokio::fs::read("example/tls/ca.pem").await.ok();
    let uri = Uri::from_static("https://[::1]:50051");
    let channel = MyChannel::new(pem, uri).await?;
    let mut client: GreeterClient<MyChannel> = GreeterClient::new(channel);
    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });
    let response = client.say_hello(request).await?;
    println!("RESPONSE={:?}", response);
    Ok(())
}

#[derive(Clone)]
pub struct MyChannel {
    uri: Uri,
    client: MyClient,
}

#[derive(Clone)]
enum MyClient {
    ClearText(Client<HttpConnector, BoxBody>),
    Tls(Client<HttpsConnector<HttpConnector>, BoxBody>),
}

impl MyChannel {
    pub async fn new(certificate: Option<Vec<u8>>, uri: Uri) -> Result<Self, Box<dyn Error>> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let client = match certificate {
            None => MyClient::ClearText(
                Client::builder(TokioExecutor::new())
                    .http2_only(true)
                    .build(http),
            ),
            Some(pem) => {
                let ca = X509::from_pem(&pem[..])?;
                let mut connector = SslConnector::builder(SslMethod::tls())?;
                connector.cert_store_mut().add_cert(ca)?;
                connector.set_alpn_protos(ALPN_H2_WIRE)?;
                let mut https = HttpsConnector::with_connector(http, connector)?;
                https.set_callback(|c, _| {
                    c.set_verify_hostname(false);
                    Ok(())
                });
                MyClient::Tls(
                    Client::builder(TokioExecutor::new())
                        .http2_only(true)
                        .build(https),
                )
            }
        };

        Ok(Self { client, uri })
    }
}

// Check out this blog post for an introduction to Tower:
// https://tokio.rs/blog/2021-05-14-inventing-the-service-trait
impl Service<Request<BoxBody>> for MyChannel {
    type Response = Response<hyper::body::Incoming>;
    type Error = hyper_util::client::legacy::Error;
    type Future = ResponseFuture;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, mut req: Request<BoxBody>) -> Self::Future {
        let uri = Uri::builder()
            .scheme(self.uri.scheme().unwrap().clone())
            .authority(self.uri.authority().unwrap().clone())
            .path_and_query(req.uri().path_and_query().unwrap().clone())
            .build()
            .unwrap();
        *req.uri_mut() = uri;
        match &self.client {
            MyClient::ClearText(client) => client.request(req),
            MyClient::Tls(client) => client.request(req),
        }
    }
}
