use tonic::{transport::Server, Request, Response, Status};

use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};
use openssl::ssl::{select_next_proto, AlpnError, SslAcceptor, SslFiletype, SslMethod};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::server::TcpConnectInfo;
use tonic_openssl::{SslConnectInfo, ALPN_H2_WIRE};

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file("example/tls/server.key", SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file("example/tls/server.pem")
        .unwrap();
    acceptor.check_private_key().unwrap();
    acceptor.set_alpn_protos(ALPN_H2_WIRE)?;
    acceptor.set_alpn_select_callback(|_ssl, alpn| {
        select_next_proto(ALPN_H2_WIRE, alpn).ok_or(AlpnError::NOACK)
    });
    let acceptor = acceptor.build();

    let addr = "[::1]:50051".parse::<SocketAddr>()?;

    let listener = TcpListener::bind(addr).await?;
    let incoming = tonic_openssl::incoming(TcpListenerStream::new(listener), acceptor);

    let greeter = MyGreeter::default();

    println!("GreeterServer listening on {}", addr);

    Server::builder()
        .add_service(GreeterServer::new(greeter))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

#[derive(Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let remote_addr = request
            .extensions()
            .get::<SslConnectInfo<TcpConnectInfo>>()
            .and_then(|info| info.get_ref().remote_addr());
        println!("Got a request from {:?}", remote_addr);

        let reply = hello_world::HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}
