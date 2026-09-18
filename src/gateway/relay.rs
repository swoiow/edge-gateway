use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fastwebsockets::{
    FragmentCollectorRead, Frame, OpCode, WebSocket, WebSocketError, WebSocketWrite,
};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::routes::Route;

type GatewayWebSocket = WebSocket<TokioIo<Upgraded>>;
type GatewayRead = FragmentCollectorRead<ReadHalf<TokioIo<Upgraded>>>;
type GatewayWrite = WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>;
type SharedWriter = Arc<Mutex<GatewayWrite>>;

const CLOSE_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) struct ConnectionContext {
    pub(super) connection_id: u64,
    pub(super) peer: SocketAddr,
    pub(super) route: Arc<Route>,
    pub(super) cf_ray: Option<String>,
}

pub(super) async fn run(
    context: ConnectionContext,
    mut downstream: GatewayWebSocket,
    mut backend: GatewayWebSocket,
    shutdown: CancellationToken,
    max_message_size: usize,
) {
    let started = Instant::now();
    let sdk_message_limit = max_message_size.saturating_add(1);
    downstream.set_max_message_size(sdk_message_limit);
    backend.set_max_message_size(sdk_message_limit);

    let (downstream_read, downstream_write) = downstream.split(tokio::io::split);
    let (backend_read, backend_write) = backend.split(tokio::io::split);
    let downstream_read = FragmentCollectorRead::new(downstream_read);
    let backend_read = FragmentCollectorRead::new(backend_read);
    let downstream_write = Arc::new(Mutex::new(downstream_write));
    let backend_write = Arc::new(Mutex::new(backend_write));

    info!(
        connection_id = context.connection_id,
        route_id = context.route.id(),
        route_class = context.route.namespace().as_str(),
        route_path = context.route.path(),
        backend = context.route.backend().display(),
        peer = %context.peer,
        cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
        "websocket relay started"
    );

    let relay_cancellation = CancellationToken::new();
    let mut pumps = JoinSet::new();
    pumps.spawn(pump(
        Direction::ClientToBackend,
        downstream_read,
        Arc::clone(&downstream_write),
        Arc::clone(&backend_write),
        relay_cancellation.child_token(),
    ));
    pumps.spawn(pump(
        Direction::BackendToClient,
        backend_read,
        Arc::clone(&backend_write),
        Arc::clone(&downstream_write),
        relay_cancellation.child_token(),
    ));

    let mut reports = Vec::with_capacity(2);
    let close_reason = tokio::select! {
        () = shutdown.cancelled() => CloseReason::GatewayShutdown,
        result = pumps.join_next() => {
            match result {
                Some(Ok(report)) => {
                    let reason = report.close_reason();
                    reports.push(report);
                    reason
                }
                Some(Err(error)) => {
                    warn!(
                        connection_id = context.connection_id,
                        route_id = context.route.id(),
                        route_class = context.route.namespace().as_str(),
                        error = %error,
                        "websocket relay task terminated unexpectedly"
                    );
                    CloseReason::InternalError
                }
                None => CloseReason::InternalError,
            }
        }
    };

    relay_cancellation.cancel();

    while let Some(result) = pumps.join_next().await {
        match result {
            Ok(report) => reports.push(report),
            Err(error) => {
                warn!(
                    connection_id = context.connection_id,
                    route_id = context.route.id(),
                    route_class = context.route.namespace().as_str(),
                    error = %error,
                    "websocket relay task terminated unexpectedly"
                );
            }
        }
    }

    if matches!(
        close_reason,
        CloseReason::GatewayShutdown | CloseReason::RelayError | CloseReason::InternalError
    ) {
        let (code, reason) = match close_reason {
            CloseReason::GatewayShutdown => (1001, b"gateway shutdown".as_slice()),
            CloseReason::RelayError | CloseReason::InternalError => {
                (1011, b"gateway relay error".as_slice())
            }
            CloseReason::ClientClosed | CloseReason::BackendClosed => (1000, b"".as_slice()),
        };
        close_pair(&downstream_write, &backend_write, code, reason).await;
    }

    let mut client_to_backend_bytes = 0_u64;
    let mut backend_to_client_bytes = 0_u64;
    for report in reports {
        match report.direction {
            Direction::ClientToBackend => client_to_backend_bytes = report.bytes,
            Direction::BackendToClient => backend_to_client_bytes = report.bytes,
        }
        if let PumpEnd::Error(error) = report.end {
            debug!(
                connection_id = context.connection_id,
                route_id = context.route.id(),
                route_class = context.route.namespace().as_str(),
                direction = report.direction.as_str(),
                %error,
                "websocket relay direction ended with an error"
            );
        }
    }

    info!(
        connection_id = context.connection_id,
        route_id = context.route.id(),
        route_class = context.route.namespace().as_str(),
        backend = context.route.backend().display(),
        peer = %context.peer,
        close_reason = close_reason.as_str(),
        client_to_backend_bytes,
        backend_to_client_bytes,
        duration_ms = started.elapsed().as_millis(),
        "websocket relay closed"
    );
}

async fn pump(
    direction: Direction,
    mut reader: GatewayRead,
    own_writer: SharedWriter,
    target_writer: SharedWriter,
    cancellation: CancellationToken,
) -> PumpReport {
    let mut bytes = 0_u64;

    loop {
        let control_writer = Arc::clone(&own_writer);
        let control_cancellation = cancellation.child_token();
        let mut send_control = move |frame| {
            let writer = Arc::clone(&control_writer);
            let cancellation = control_cancellation.child_token();
            async move {
                tokio::select! {
                    () = cancellation.cancelled() => Err(WebSocketError::ConnectionClosed),
                    result = async {
                        let mut writer = writer.lock().await;
                        writer.write_frame(frame).await
                    } => result,
                }
            }
        };

        let frame = tokio::select! {
            () = cancellation.cancelled() => {
                return PumpReport::cancelled(direction, bytes);
            }
            result = reader.read_frame(&mut send_control) => {
                match result {
                    Ok(frame) => frame,
                    Err(error) => return PumpReport::error(direction, bytes, error),
                }
            }
        };

        match frame.opcode {
            OpCode::Text | OpCode::Binary => {
                bytes = bytes.saturating_add(frame.payload.len() as u64);
                if let Err(error) = write_frame(&target_writer, frame, &cancellation).await {
                    return PumpReport::error(direction, bytes, error);
                }
            }
            OpCode::Close => {
                if let Err(error) = write_frame(&target_writer, frame, &cancellation).await {
                    return PumpReport::error(direction, bytes, error);
                }
                return PumpReport::peer_closed(direction, bytes);
            }
            OpCode::Continuation | OpCode::Ping | OpCode::Pong => {}
        }
    }
}

async fn write_frame(
    writer: &SharedWriter,
    frame: Frame<'_>,
    cancellation: &CancellationToken,
) -> Result<(), WebSocketError> {
    tokio::select! {
        () = cancellation.cancelled() => Err(WebSocketError::ConnectionClosed),
        result = async {
            let mut writer = writer.lock().await;
            writer.write_frame(frame).await
        } => result,
    }
}

async fn close_pair(downstream: &SharedWriter, backend: &SharedWriter, code: u16, reason: &[u8]) {
    let close_downstream = best_effort_close(downstream, code, reason);
    let close_backend = best_effort_close(backend, code, reason);
    let (_, _) = tokio::join!(close_downstream, close_backend);
}

async fn best_effort_close(writer: &SharedWriter, code: u16, reason: &[u8]) {
    let close = async {
        let mut writer = writer.lock().await;
        writer.write_frame(Frame::close(code, reason)).await
    };
    let _result = timeout(CLOSE_WRITE_TIMEOUT, close).await;
}

#[derive(Copy, Clone)]
enum Direction {
    ClientToBackend,
    BackendToClient,
}

impl Direction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClientToBackend => "client_to_backend",
            Self::BackendToClient => "backend_to_client",
        }
    }
}

struct PumpReport {
    direction: Direction,
    bytes: u64,
    end: PumpEnd,
}

impl PumpReport {
    const fn cancelled(direction: Direction, bytes: u64) -> Self {
        Self {
            direction,
            bytes,
            end: PumpEnd::Cancelled,
        }
    }

    const fn peer_closed(direction: Direction, bytes: u64) -> Self {
        Self {
            direction,
            bytes,
            end: PumpEnd::PeerClosed,
        }
    }

    fn error(direction: Direction, bytes: u64, error: WebSocketError) -> Self {
        Self {
            direction,
            bytes,
            end: PumpEnd::Error(error.to_string()),
        }
    }

    fn close_reason(&self) -> CloseReason {
        match (&self.end, self.direction) {
            (PumpEnd::PeerClosed, Direction::ClientToBackend) => CloseReason::ClientClosed,
            (PumpEnd::PeerClosed, Direction::BackendToClient) => CloseReason::BackendClosed,
            (PumpEnd::Error(_), _) => CloseReason::RelayError,
            (PumpEnd::Cancelled, _) => CloseReason::InternalError,
        }
    }
}

enum PumpEnd {
    PeerClosed,
    Cancelled,
    Error(String),
}

#[derive(Copy, Clone)]
enum CloseReason {
    ClientClosed,
    BackendClosed,
    GatewayShutdown,
    RelayError,
    InternalError,
}

impl CloseReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::BackendClosed => "backend_closed",
            Self::GatewayShutdown => "gateway_shutdown",
            Self::RelayError => "relay_error",
            Self::InternalError => "internal_error",
        }
    }
}
