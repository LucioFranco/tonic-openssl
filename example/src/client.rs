use hello_world::greeter_client::GreeterClient;
use hello_world::HelloRequest;
use hyper::Uri;
use hyper_openssl::client::legacy::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use openssl::{
    ssl::{SslConnector, SslMethod},
    x509::X509,
};
use tonic_openssl::ALPN_H2_WIRE;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let pem = tokio::fs::read("example/tls/ca.pem").await?;
    let ca = X509::from_pem(&pem[..])?;
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.cert_store_mut().add_cert(ca)?;
    connector.set_alpn_protos(ALPN_H2_WIRE)?;

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let mut https = HttpsConnector::with_connector(http, connector)?;

    // This is set because we are currently sending
    // `[::1]:50051` as the hostname but the cert was
    // originally signed with `example.com`. This will
    // disable hostname checking and it is BAD! DON'T DO IT!
    https.set_callback(|c, _| {
        c.set_verify_hostname(false);
        Ok(())
    });

    // Configure hyper's client to be h2 only and build with the
    // correct https connector.
    let hyper = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(https);

    let uri = Uri::from_static("https://[::1]:50051");

    // Hyper's client requires that requests contain full Uris include a scheme and
    // an authority. Tonic's transport will handle this for you but when using the client
    // manually you need ensure the uri's are set correctly.
    let add_origin = tower::service_fn(|mut req: hyper::Request<tonic::body::BoxBody>| {
        let uri = Uri::builder()
            .scheme(uri.scheme().unwrap().clone())
            .authority(uri.authority().unwrap().clone())
            .path_and_query(req.uri().path_and_query().unwrap().clone())
            .build()
            .unwrap();

        *req.uri_mut() = uri;

        hyper.request(req)
    });

    let mut client = GreeterClient::new(add_origin);

    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
