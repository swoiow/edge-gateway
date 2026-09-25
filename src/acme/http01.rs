use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

type ChallengeMap = Arc<RwLock<HashMap<String, String>>>;
type ResponseBody = Full<Bytes>;

pub(super) struct Http01Server {
    challenges: ChallengeMap,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Http01Server {
    pub(super) async fn start(listen: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("failed to bind ACME HTTP-01 listener on {listen}"))?;
        let local_addr =
            listener.local_addr().context("failed to read ACME HTTP-01 listener address")?;
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let cancellation = CancellationToken::new();
        let task_challenges = Arc::clone(&challenges);
        let task_cancellation = cancellation.child_token();

        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            info!(listen = %local_addr, "ACME HTTP-01 listener started");
            loop {
                tokio::select! {
                    biased;
                    () = task_cancellation.cancelled() => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer)) => {
                                let challenges = Arc::clone(&task_challenges);
                                connections.spawn(async move {
                                    let service = service_fn(move |request| {
                                        handle_request(request, Arc::clone(&challenges))
                                    });
                                    let mut builder = http1::Builder::new();
                                    builder.keep_alive(false);
                                    match timeout(
                                        CONNECTION_TIMEOUT,
                                        builder.serve_connection(TokioIo::new(stream), service),
                                    )
                                    .await
                                    {
                                        Ok(Ok(())) => {}
                                        Ok(Err(error)) => {
                                            debug!(%peer, error = %error, "ACME HTTP-01 connection failed");
                                        }
                                        Err(_) => {
                                            debug!(%peer, "ACME HTTP-01 connection timed out");
                                        }
                                    }
                                });
                            }
                            Err(error) => {
                                warn!(error = %error, "ACME HTTP-01 accept failed");
                            }
                        }
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(error)) = completed {
                            warn!(error = %error, "ACME HTTP-01 connection task terminated unexpectedly");
                        }
                    }
                }
            }

            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    warn!(error = %error, "ACME HTTP-01 connection task terminated during shutdown");
                }
            }
            info!(listen = %local_addr, "ACME HTTP-01 listener stopped");
        });

        Ok(Self {
            challenges,
            cancellation,
            task: Some(task),
        })
    }

    pub(super) async fn publish(&self, token: String, key_authorization: String) {
        self.challenges.write().await.insert(token, key_authorization);
    }

    pub(super) async fn remove(&self, token: &str) {
        self.challenges.write().await.remove(token);
    }

    pub(super) async fn shutdown(mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            if let Err(error) = task.await {
                warn!(error = %error, "ACME HTTP-01 listener task terminated unexpectedly");
            }
        }
    }
}

impl Drop for Http01Server {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn handle_request(
    request: Request<Incoming>,
    challenges: ChallengeMap,
) -> Result<Response<ResponseBody>, Infallible> {
    if request.method() != Method::GET {
        return Ok(text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed\n",
        ));
    }

    let Some(token) = request.uri().path().strip_prefix(CHALLENGE_PREFIX) else {
        return Ok(text_response(StatusCode::NOT_FOUND, "not found\n"));
    };
    if token.is_empty() || token.contains('/') {
        return Ok(text_response(StatusCode::NOT_FOUND, "not found\n"));
    }

    let response = challenges.read().await.get(token).cloned();
    match response {
        Some(key_authorization) => Ok(text_response(StatusCode::OK, key_authorization)),
        None => Ok(text_response(StatusCode::NOT_FOUND, "not found\n")),
    }
}

fn text_response(status: StatusCode, body: impl Into<Bytes>) -> Response<ResponseBody> {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
}
