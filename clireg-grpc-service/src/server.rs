use std::pin::Pin;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codegen::futures_core::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use registry::registry_server::{Registry, RegistryServer};
use registry::{RegistryRequest, RegistryResponse};

pub mod registry {
    include!(concat!(env!("OUT_DIR"), concat!("/", "registry", ".rs")));

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("registry_descriptor");
}

type RegistryResult<T> = Result<Response<T>, Status>;

mod data;

#[derive(Debug, Default)]
pub struct RegistryHandler {
    responses: Arc<Vec<RegistryResponse>>,
}

#[tonic::async_trait]
impl Registry for RegistryHandler {
    type SyncStream = Pin<Box<dyn Stream<Item = Result<RegistryResponse, Status>> + Send>>;

    async fn sync(
        &self,
        request: Request<Streaming<RegistryRequest>>,
    ) -> RegistryResult<Self::SyncStream> {
        println!("Got a request: {:?}", request);

        let (tx, rx) = mpsc::channel(1);

        let mut into = request.into_inner();
        if let Some(request) = into.message().await? {
            if request.full_sync {
                self.stream_creds(tx)
            }
        }

        Ok(Response::new(
            Box::pin(ReceiverStream::new(rx)) as Self::SyncStream
        ))
    }
}

impl RegistryHandler {
    fn stream_creds(&self, tx: Sender<Result<RegistryResponse, Status>>) {
        let responses = self.responses.clone();

        tokio::spawn(async move {
            let max_index = responses.len() - 1;
            let mut i = 0;
            loop {
                let response = responses.get(i).unwrap();
                println!("sending response: {:?}", response);
                match tx.send(Ok(response.clone())).await {
                    Ok(_) => {
                        println!("> sent")
                    }
                    Err(err) => {
                        println!("Error sending stream to client: {}", err);
                        break;
                    }
                }
                match tx
                    .send(Ok(RegistryResponse {
                        credentials: Vec::new(),
                        removals: Vec::new(),
                    }))
                    .await
                {
                    Ok(_) => {
                        println!("> commit")
                    }
                    Err(err) => {
                        println!("Error sending stream to client: {}", err);
                        break;
                    }
                }

                thread::sleep(Duration::from_secs(10));

                // next or start over
                i += 1;
                if i > max_index {
                    i = 0
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(registry::FILE_DESCRIPTOR_SET)
        .build()
        .unwrap();

    let addr = "0.0.0.0:50051".parse().unwrap();

    let handler = RegistryHandler {
        responses: Arc::new(data::load()),
    };
    let svc = RegistryServer::new(handler);

    println!("starting server on port {}", 50051);
    Server::builder()
        .add_service(svc)
        .add_service(reflection)
        .serve(addr)
        .await?;

    Ok(())
}
