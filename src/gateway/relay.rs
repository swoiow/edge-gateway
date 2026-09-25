use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use fastwebsockets::{
    FragmentCollectorRead, Frame, OpCode, Role, WebSocket, WebSocketError, WebSocketRead,
    WebSocketWrite, after_handshake_split,
};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{interval_at, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::ObservabilityMode;
use crate::observability::{
    ActiveConnection, RelayDirection, RuntimeObservability, WebSocketCloseClass,
};
use crate::routes::Route;

type BoxedRead = Box<dyn AsyncRead + Send + Unpin + 'static>;
type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin + 'static>;
type GatewayRead = FragmentCollectorRead<BoxedRead>;
type GatewaySocketRead = WebSocketRead<BoxedRead>;
type GatewayWrite = WebSocketWrite<BoxedWrite>;
type SharedWriter = Arc<Mutex<GatewayWrite>>;

pub(super) struct RelaySocket {
    read: GatewaySocketRead,
    write: GatewayWrite,
}

impl RelaySocket {
    pub(super) fn from_upgraded_websocket(
        websocket: WebSocket<TokioIo<Upgraded>>,
        role: Role,
    ) -> Self {
        let stream = websocket.into_inner();
        let (read, write) = tokio::io::split(stream);
        Self::from_io_halves(read, write, role)
    }

    pub(super) fn from_io_halves<R, W>(read: R, write: W, role: Role) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let read: BoxedRead = Box::new(read);
        let write: BoxedWrite = Box::new(write);
        let (read, write) = after_handshake_split(read, write, role);
        Self { read, write }
    }
}

const CLOSE_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const TCP_BRIDGE_READ_BUFFER_BYTES: usize = 64 * 1024;
const SHORT_LIVED_CONNECTION_THRESHOLD: Duration = Duration::from_secs(30);
const LONG_LIVED_CONNECTION_THRESHOLD: Duration = Duration::from_secs(5 * 60);

pub(super) struct ConnectionContext {
    pub(super) transport_connection_id: u64,
    pub(super) connection_id: u64,
    pub(super) peer: SocketAddr,
    pub(super) route: Arc<Route>,
    pub(super) cf_ray: Option<String>,
    pub(super) downstream_http_version: &'static str,
    pub(super) active_connection: ActiveConnection,
    pub(super) observability: RuntimeObservability,
}

pub(super) async fn run(
    context: ConnectionContext,
    mut downstream: RelaySocket,
    mut backend: RelaySocket,
    shutdown: CancellationToken,
    max_message_size: usize,
) {
    let started = Instant::now();
    let sdk_message_limit = max_message_size.saturating_add(1);
    downstream.read.set_max_message_size(sdk_message_limit);
    backend.read.set_max_message_size(sdk_message_limit);

    let downstream_read = FragmentCollectorRead::new(downstream.read);
    let backend_read = FragmentCollectorRead::new(backend.read);
    let downstream_write = Arc::new(Mutex::new(downstream.write));
    let backend_write = Arc::new(Mutex::new(backend.write));

    if !context.observability.connection_event_logs_enabled() {
        debug!(
            transport_connection_id = context.transport_connection_id,
            connection_id = context.connection_id,
            route_id = context.route.id(),
            route_class = context.route.namespace().as_str(),
            route_path = context.route.path(),
            backend = context.route.backend().display(),
            peer = %context.peer,
            cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
            downstream_http_version = context.downstream_http_version,
            active_websocket_connections =
                context.active_connection.active_connections(),
            "websocket relay started"
        );
    }

    let runtime_observation_enabled = context.observability.mode() != ObservabilityMode::Off;
    let detailed_observation = context.observability.mode() == ObservabilityMode::Diagnostic
        || context.observability.connection_event_logs_enabled();
    let client_to_backend = Arc::new(DirectionDiagnostics::new(
        Instant::now(),
        runtime_observation_enabled || detailed_observation,
        detailed_observation,
    ));
    let backend_to_client = Arc::new(DirectionDiagnostics::new(
        Instant::now(),
        runtime_observation_enabled || detailed_observation,
        detailed_observation,
    ));
    let relay_cancellation = CancellationToken::new();
    let mut pumps = JoinSet::new();
    pumps.spawn(pump(
        Direction::ClientToBackend,
        downstream_read,
        Arc::clone(&downstream_write),
        Arc::clone(&backend_write),
        relay_cancellation.child_token(),
        Arc::clone(&client_to_backend),
        context.observability.clone(),
    ));
    pumps.spawn(pump(
        Direction::BackendToClient,
        backend_read,
        Arc::clone(&backend_write),
        Arc::clone(&downstream_write),
        relay_cancellation.child_token(),
        Arc::clone(&backend_to_client),
        context.observability.clone(),
    ));

    let observation_interval =
        Duration::from_secs(context.observability.observation_interval_seconds().max(1));
    let mut observation_tick = interval_at(
        tokio::time::Instant::now() + observation_interval,
        observation_interval,
    );
    let mut progress = ProgressTracker::default();
    let mut reports = Vec::with_capacity(2);

    let close_reason = loop {
        tokio::select! {
            () = shutdown.cancelled() => break CloseReason::GatewayShutdown,
            result = pumps.join_next() => {
                break match result {
                    Some(Ok(report)) => {
                        let reason = report.close_reason();
                        reports.push(report);
                        reason
                    }
                    Some(Err(error)) => {
                        warn!(
                            transport_connection_id = context.transport_connection_id,
                            connection_id = context.connection_id,
                            route_id = context.route.id(),
                            route_class = context.route.namespace().as_str(),
                            error = %error,
                            "websocket relay task terminated unexpectedly"
                        );
                        CloseReason::InternalError
                    }
                    None => CloseReason::InternalError,
                };
            }
            _ = observation_tick.tick(), if runtime_observation_enabled => {
                observe_progress(
                    &context,
                    &client_to_backend,
                    &backend_to_client,
                    started,
                    observation_interval,
                    &mut progress,
                );
            }
        }
    };

    relay_cancellation.cancel();

    while let Some(result) = pumps.join_next().await {
        match result {
            Ok(report) => reports.push(report),
            Err(error) => {
                warn!(
                    transport_connection_id = context.transport_connection_id,
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

    for report in &reports {
        if let PumpEnd::Error(error) = &report.end {
            warn!(
                transport_connection_id = context.transport_connection_id,
                connection_id = context.connection_id,
                route_id = context.route.id(),
                route_class = context.route.namespace().as_str(),
                direction = report.direction.as_str(),
                failed_stage = report.final_snapshot.stage.as_str(),
                %error,
                "websocket relay direction ended with an error"
            );
        }
    }
    let first_error = reports.iter().find(|report| matches!(&report.end, PumpEnd::Error(_)));
    let first_error_direction = first_error.map(|report| report.direction.as_str()).unwrap_or("-");
    let first_error_stage =
        first_error.map(|report| report.final_snapshot.stage.as_str()).unwrap_or("-");

    let client_snapshot = client_to_backend.snapshot();
    let backend_snapshot = backend_to_client.snapshot();
    let duration = started.elapsed();
    let duration_ms = duration.as_millis();
    let close_class = close_reason.observability_class();
    context.observability.record_websocket_closed(
        close_class,
        duration >= LONG_LIVED_CONNECTION_THRESHOLD,
        duration <= SHORT_LIVED_CONNECTION_THRESHOLD,
    );
    let remaining_active = context.active_connection.active_connections().saturating_sub(1);

    log_closed(
        &context,
        close_reason,
        duration_ms,
        remaining_active,
        first_error_direction,
        first_error_stage,
        &client_snapshot,
        &backend_snapshot,
    );
}

pub(super) async fn run_tcp_backend(
    context: ConnectionContext,
    mut downstream: RelaySocket,
    backend: TcpStream,
    shutdown: CancellationToken,
    max_message_size: usize,
) {
    let started = Instant::now();
    let sdk_message_limit = max_message_size.saturating_add(1);
    downstream.read.set_max_message_size(sdk_message_limit);

    let downstream_write = Arc::new(Mutex::new(downstream.write));
    let (backend_read, backend_write) = backend.into_split();

    if !context.observability.connection_event_logs_enabled() {
        debug!(
            transport_connection_id = context.transport_connection_id,
            connection_id = context.connection_id,
            route_id = context.route.id(),
            route_class = context.route.namespace().as_str(),
            route_path = context.route.path(),
            backend = context.route.backend().display(),
            backend_transport = "tcp",
            peer = %context.peer,
            cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
            downstream_http_version = context.downstream_http_version,
            active_websocket_connections = context.active_connection.active_connections(),
            "websocket-to-tcp relay started"
        );
    }

    let runtime_observation_enabled = context.observability.mode() != ObservabilityMode::Off;
    let detailed_observation = context.observability.mode() == ObservabilityMode::Diagnostic
        || context.observability.connection_event_logs_enabled();
    let client_to_backend = Arc::new(DirectionDiagnostics::new(
        Instant::now(),
        runtime_observation_enabled || detailed_observation,
        detailed_observation,
    ));
    let backend_to_client = Arc::new(DirectionDiagnostics::new(
        Instant::now(),
        runtime_observation_enabled || detailed_observation,
        detailed_observation,
    ));

    let relay_cancellation = CancellationToken::new();
    let mut pumps = JoinSet::new();
    pumps.spawn(pump_websocket_to_tcp(
        downstream.read,
        Arc::clone(&downstream_write),
        backend_write,
        relay_cancellation.child_token(),
        Arc::clone(&client_to_backend),
        context.observability.clone(),
    ));
    pumps.spawn(pump_tcp_to_websocket(
        backend_read,
        Arc::clone(&downstream_write),
        relay_cancellation.child_token(),
        Arc::clone(&backend_to_client),
        context.observability.clone(),
    ));

    let observation_interval =
        Duration::from_secs(context.observability.observation_interval_seconds().max(1));
    let mut observation_tick = interval_at(
        tokio::time::Instant::now() + observation_interval,
        observation_interval,
    );
    let mut progress = ProgressTracker::default();
    let mut reports = Vec::with_capacity(2);

    let close_reason = loop {
        tokio::select! {
            () = shutdown.cancelled() => break CloseReason::GatewayShutdown,
            result = pumps.join_next() => {
                break match result {
                    Some(Ok(report)) => {
                        let reason = report.close_reason();
                        reports.push(report);
                        reason
                    }
                    Some(Err(error)) => {
                        warn!(
                            transport_connection_id = context.transport_connection_id,
                            connection_id = context.connection_id,
                            route_id = context.route.id(),
                            route_class = context.route.namespace().as_str(),
                            error = %error,
                            "websocket-to-tcp relay task terminated unexpectedly"
                        );
                        CloseReason::InternalError
                    }
                    None => CloseReason::InternalError,
                };
            }
            _ = observation_tick.tick(), if runtime_observation_enabled => {
                observe_progress(
                    &context,
                    &client_to_backend,
                    &backend_to_client,
                    started,
                    observation_interval,
                    &mut progress,
                );
            }
        }
    };

    relay_cancellation.cancel();
    while let Some(result) = pumps.join_next().await {
        match result {
            Ok(report) => reports.push(report),
            Err(error) => {
                warn!(
                    transport_connection_id = context.transport_connection_id,
                    connection_id = context.connection_id,
                    route_id = context.route.id(),
                    route_class = context.route.namespace().as_str(),
                    error = %error,
                    "websocket-to-tcp relay task terminated unexpectedly"
                );
            }
        }
    }

    let (code, reason) = match close_reason {
        CloseReason::ClientClosed | CloseReason::BackendClosed => (1000, b"".as_slice()),
        CloseReason::GatewayShutdown => (1001, b"gateway shutdown".as_slice()),
        CloseReason::RelayError | CloseReason::InternalError => {
            (1011, b"gateway relay error".as_slice())
        }
    };
    best_effort_close(&downstream_write, code, reason).await;

    for report in &reports {
        if let PumpEnd::Error(error) = &report.end {
            warn!(
                transport_connection_id = context.transport_connection_id,
                connection_id = context.connection_id,
                route_id = context.route.id(),
                route_class = context.route.namespace().as_str(),
                direction = report.direction.as_str(),
                failed_stage = report.final_snapshot.stage.as_str(),
                %error,
                "websocket-to-tcp relay direction ended with an error"
            );
        }
    }

    let first_error = reports.iter().find(|report| matches!(&report.end, PumpEnd::Error(_)));
    let first_error_direction = first_error.map(|report| report.direction.as_str()).unwrap_or("-");
    let first_error_stage =
        first_error.map(|report| report.final_snapshot.stage.as_str()).unwrap_or("-");
    let client_snapshot = client_to_backend.snapshot();
    let backend_snapshot = backend_to_client.snapshot();
    let duration = started.elapsed();
    let duration_ms = duration.as_millis();
    context.observability.record_websocket_closed(
        close_reason.observability_class(),
        duration >= LONG_LIVED_CONNECTION_THRESHOLD,
        duration <= SHORT_LIVED_CONNECTION_THRESHOLD,
    );
    let remaining_active = context.active_connection.active_connections().saturating_sub(1);

    log_closed(
        &context,
        close_reason,
        duration_ms,
        remaining_active,
        first_error_direction,
        first_error_stage,
        &client_snapshot,
        &backend_snapshot,
    );
}

async fn pump_websocket_to_tcp(
    mut reader: GatewaySocketRead,
    own_writer: SharedWriter,
    mut backend_write: tokio::net::tcp::OwnedWriteHalf,
    cancellation: CancellationToken,
    diagnostics: Arc<DirectionDiagnostics>,
    observability: RuntimeObservability,
) -> PumpReport {
    let direction = Direction::ClientToBackend;
    loop {
        diagnostics.set_stage(RelayStage::AwaitingRead);
        let control_writer = Arc::clone(&own_writer);
        let control_cancellation = cancellation.child_token();
        let control_diagnostics = Arc::clone(&diagnostics);
        let control_observability = observability.clone();
        let mut send_control = move |frame: Frame<'_>| {
            let opcode = frame.opcode;
            let fin = frame.fin;
            // Control payloads are RFC 6455 bounded to 125 bytes. Owning them here
            // keeps the async callback independent from the parser's input buffer.
            let payload: Vec<u8> = frame.payload.into();
            let frame: Frame<'static> = Frame::new(fin, opcode, None, payload.into());
            let writer = Arc::clone(&control_writer);
            let cancellation = control_cancellation.child_token();
            let diagnostics = Arc::clone(&control_diagnostics);
            let observability = control_observability.clone();
            async move {
                diagnostics.record_control_frame(opcode, fin, frame.payload.len());
                observability.record_control_frame(direction.observability_direction());
                tokio::select! {
                    () = cancellation.cancelled() => Err(WebSocketError::ConnectionClosed),
                    result = write_frame_and_flush(
                        &writer,
                        frame,
                        &diagnostics,
                        RelayStage::WritingControlFrame,
                    ) => result,
                }
            }
        };

        let frame = tokio::select! {
            () = cancellation.cancelled() => {
                return PumpReport::cancelled(direction, &diagnostics);
            }
            result = reader.read_frame(&mut send_control) => {
                match result {
                    Ok(frame) => frame,
                    Err(error) => return PumpReport::error(direction, &diagnostics, error),
                }
            }
        };

        match frame.opcode {
            // A TCP backend has byte-stream semantics, so WebSocket message and
            // fragment boundaries intentionally disappear at this boundary.
            OpCode::Text | OpCode::Binary | OpCode::Continuation => {
                let payload_bytes = frame.payload.len();
                diagnostics.record_read(frame.opcode, frame.fin, payload_bytes);
                diagnostics.set_stage(RelayStage::WritingStreamBytes);
                let write_result = tokio::select! {
                    () = cancellation.cancelled() => {
                        return PumpReport::cancelled(direction, &diagnostics);
                    }
                    result = backend_write.write_all(&frame.payload[..]) => result,
                };
                if let Err(error) = write_result {
                    return PumpReport::error(direction, &diagnostics, error);
                }
                diagnostics.record_forwarded(payload_bytes);
                observability
                    .record_forwarded_frame(direction.observability_direction(), payload_bytes);
            }
            OpCode::Close => {
                diagnostics.record_control_frame(frame.opcode, frame.fin, frame.payload.len());
                observability.record_control_frame(direction.observability_direction());
                let _result = timeout(CLOSE_WRITE_TIMEOUT, backend_write.shutdown()).await;
                return PumpReport::peer_closed(direction, &diagnostics);
            }
            OpCode::Ping | OpCode::Pong => {
                diagnostics.record_control_frame(frame.opcode, frame.fin, frame.payload.len());
                observability.record_control_frame(direction.observability_direction());
            }
        }
    }
}

async fn pump_tcp_to_websocket(
    mut backend_read: tokio::net::tcp::OwnedReadHalf,
    downstream_writer: SharedWriter,
    cancellation: CancellationToken,
    diagnostics: Arc<DirectionDiagnostics>,
    observability: RuntimeObservability,
) -> PumpReport {
    let direction = Direction::BackendToClient;
    // One bounded allocation per connection, then reuse it for the lifetime of
    // the tunnel. This avoids hot-loop allocation while keeping backpressure in
    // the socket/write futures instead of an unbounded application queue.
    let mut buffer = vec![0_u8; TCP_BRIDGE_READ_BUFFER_BYTES];

    loop {
        diagnostics.set_stage(RelayStage::AwaitingRead);
        let read = tokio::select! {
            () = cancellation.cancelled() => {
                return PumpReport::cancelled(direction, &diagnostics);
            }
            result = backend_read.read(&mut buffer) => result,
        };
        let payload_bytes = match read {
            Ok(0) => return PumpReport::peer_closed(direction, &diagnostics),
            Ok(read) => read,
            Err(error) => return PumpReport::error(direction, &diagnostics, error),
        };

        diagnostics.record_read(OpCode::Binary, true, payload_bytes);
        let frame = Frame::new(
            true,
            OpCode::Binary,
            None,
            (&buffer[..payload_bytes]).into(),
        );
        if let Err(error) = forward_frame(
            &downstream_writer,
            frame,
            &diagnostics,
            RelayStage::WritingDataFrame,
            &cancellation,
        )
        .await
        {
            return PumpReport::error(direction, &diagnostics, error);
        }
        diagnostics.record_forwarded(payload_bytes);
        observability.record_forwarded_frame(direction.observability_direction(), payload_bytes);
    }
}

async fn pump(
    direction: Direction,
    mut reader: GatewayRead,
    own_writer: SharedWriter,
    target_writer: SharedWriter,
    cancellation: CancellationToken,
    diagnostics: Arc<DirectionDiagnostics>,
    observability: RuntimeObservability,
) -> PumpReport {
    loop {
        diagnostics.set_stage(RelayStage::AwaitingRead);
        let control_writer = Arc::clone(&own_writer);
        let control_cancellation = cancellation.child_token();
        let control_diagnostics = Arc::clone(&diagnostics);
        let control_observability = observability.clone();
        let mut send_control = move |frame: Frame<'_>| {
            let opcode = frame.opcode;
            let fin = frame.fin;
            let payload: Vec<u8> = frame.payload.into();
            let frame: Frame<'static> = Frame::new(fin, opcode, None, payload.into());
            let writer = Arc::clone(&control_writer);
            let cancellation = control_cancellation.child_token();
            let diagnostics = Arc::clone(&control_diagnostics);
            let observability = control_observability.clone();
            async move {
                diagnostics.record_control_frame(opcode, fin, frame.payload.len());
                observability.record_control_frame(direction.observability_direction());
                tokio::select! {
                    () = cancellation.cancelled() => Err(WebSocketError::ConnectionClosed),
                    result = write_frame_and_flush(
                        &writer,
                        frame,
                        &diagnostics,
                        RelayStage::WritingControlFrame,
                    ) => result,
                }
            }
        };

        let frame = tokio::select! {
            () = cancellation.cancelled() => {
                return PumpReport::cancelled(direction, &diagnostics);
            }
            result = reader.read_frame(&mut send_control) => {
                match result {
                    Ok(frame) => frame,
                    Err(error) => {
                        return PumpReport::error(direction, &diagnostics, error);
                    }
                }
            }
        };

        match frame.opcode {
            OpCode::Text | OpCode::Binary => {
                let payload_bytes = frame.payload.len();
                diagnostics.record_read(frame.opcode, frame.fin, payload_bytes);
                if let Err(error) = forward_frame(
                    &target_writer,
                    frame,
                    &diagnostics,
                    RelayStage::WritingDataFrame,
                    &cancellation,
                )
                .await
                {
                    return PumpReport::error(direction, &diagnostics, error);
                }
                diagnostics.record_forwarded(payload_bytes);
                observability
                    .record_forwarded_frame(direction.observability_direction(), payload_bytes);
            }
            OpCode::Close => {
                diagnostics.record_control_frame(frame.opcode, frame.fin, frame.payload.len());
                observability.record_control_frame(direction.observability_direction());
                if let Err(error) = forward_frame(
                    &target_writer,
                    frame,
                    &diagnostics,
                    RelayStage::WritingControlFrame,
                    &cancellation,
                )
                .await
                {
                    return PumpReport::error(direction, &diagnostics, error);
                }
                return PumpReport::peer_closed(direction, &diagnostics);
            }
            OpCode::Continuation | OpCode::Ping | OpCode::Pong => {
                diagnostics.record_control_frame(frame.opcode, frame.fin, frame.payload.len());
                observability.record_control_frame(direction.observability_direction());
            }
        }
    }
}

async fn forward_frame(
    writer: &SharedWriter,
    frame: Frame<'_>,
    diagnostics: &DirectionDiagnostics,
    write_stage: RelayStage,
    cancellation: &CancellationToken,
) -> Result<(), WebSocketError> {
    tokio::select! {
        () = cancellation.cancelled() => Err(WebSocketError::ConnectionClosed),
        result = write_frame_and_flush(writer, frame, diagnostics, write_stage) => result,
    }
}

async fn write_frame_and_flush(
    writer: &SharedWriter,
    frame: Frame<'_>,
    diagnostics: &DirectionDiagnostics,
    write_stage: RelayStage,
) -> Result<(), WebSocketError> {
    diagnostics.set_stage(RelayStage::WaitingWriterLock);
    let mut writer = writer.lock().await;
    diagnostics.set_stage(write_stage);
    writer.write_frame(frame).await?;
    diagnostics.set_stage(RelayStage::FlushingFrame);
    writer.flush().await
}

async fn close_pair(downstream: &SharedWriter, backend: &SharedWriter, code: u16, reason: &[u8]) {
    let close_downstream = best_effort_close(downstream, code, reason);
    let close_backend = best_effort_close(backend, code, reason);
    let (_, _) = tokio::join!(close_downstream, close_backend);
}

async fn best_effort_close(writer: &SharedWriter, code: u16, reason: &[u8]) {
    let close = async {
        let mut writer = writer.lock().await;
        writer.write_frame(Frame::close(code, reason)).await?;
        writer.flush().await
    };
    let _result = timeout(CLOSE_WRITE_TIMEOUT, close).await;
}

fn observe_progress(
    context: &ConnectionContext,
    client_to_backend: &DirectionDiagnostics,
    backend_to_client: &DirectionDiagnostics,
    connection_started: Instant,
    interval: Duration,
    tracker: &mut ProgressTracker,
) {
    let upstream = client_to_backend.snapshot();
    let downstream = backend_to_client.snapshot();
    let forwarded_frames = upstream.forwarded_frames + downstream.forwarded_frames;
    let forwarded_bytes = upstream.forwarded_bytes + downstream.forwarded_bytes;
    let progressed = forwarded_frames != tracker.forwarded_frames;

    if progressed {
        tracker.idle_episode_reported = false;
        tracker.no_progress_episode_reported = false;
    } else if upstream.stage.is_waiting_for_input() && downstream.stage.is_waiting_for_input() {
        if !tracker.idle_episode_reported {
            context.observability.record_websocket_idle_event();
            tracker.idle_episode_reported = true;
        }
    } else if upstream.stage.is_write_path() || downstream.stage.is_write_path() {
        if !tracker.no_progress_episode_reported {
            context.observability.record_websocket_no_progress_event();
            tracker.no_progress_episode_reported = true;
        }
    }

    if context.observability.connection_event_logs_enabled() {
        let interval_seconds = interval.as_secs_f64().max(0.001);
        let interval_bytes = forwarded_bytes.saturating_sub(tracker.forwarded_bytes);
        info!(
            transport_connection_id = context.transport_connection_id,
            connection_id = context.connection_id,
            route_id = context.route.id(),
            route_class = context.route.namespace().as_str(),
            cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
            active_websocket_connections = context.active_connection.active_connections(),
            connection_duration_ms = connection_started.elapsed().as_millis(),
            client_to_backend_stage = upstream.stage.as_str(),
            backend_to_client_stage = downstream.stage.as_str(),
            client_to_backend_forwarded_frames = upstream.forwarded_frames,
            backend_to_client_forwarded_frames = downstream.forwarded_frames,
            client_to_backend_forwarded_bytes = upstream.forwarded_bytes,
            backend_to_client_forwarded_bytes = downstream.forwarded_bytes,
            client_to_backend_small_frames = upstream.small_frames,
            backend_to_client_small_frames = downstream.small_frames,
            client_to_backend_control_frames = upstream.control_frames,
            backend_to_client_control_frames = downstream.control_frames,
            client_to_backend_last_activity_idle_ms = upstream.last_activity_idle_ms,
            backend_to_client_last_activity_idle_ms = downstream.last_activity_idle_ms,
            client_to_backend_last_read_idle_ms = upstream.last_read_idle_ms,
            client_to_backend_last_write_idle_ms = upstream.last_write_idle_ms,
            backend_to_client_last_read_idle_ms = downstream.last_read_idle_ms,
            backend_to_client_last_write_idle_ms = downstream.last_write_idle_ms,
            client_to_backend_last_frame_opcode = upstream.last_frame_opcode,
            client_to_backend_last_frame_fin = upstream.last_frame_fin,
            client_to_backend_last_frame_payload_bytes = upstream.last_frame_payload_bytes,
            backend_to_client_last_frame_opcode = downstream.last_frame_opcode,
            backend_to_client_last_frame_fin = downstream.last_frame_fin,
            backend_to_client_last_frame_payload_bytes = downstream.last_frame_payload_bytes,
            interval_forwarded_bytes = interval_bytes,
            interval_forwarded_bytes_per_second = interval_bytes as f64 / interval_seconds,
            idle = !progressed
                && upstream.stage.is_waiting_for_input()
                && downstream.stage.is_waiting_for_input(),
            no_progress =
                !progressed && (upstream.stage.is_write_path() || downstream.stage.is_write_path()),
            "websocket relay diagnostic progress"
        );
    }

    tracker.forwarded_frames = forwarded_frames;
    tracker.forwarded_bytes = forwarded_bytes;
}

fn log_closed(
    context: &ConnectionContext,
    close_reason: CloseReason,
    duration_ms: u128,
    remaining_active: u64,
    first_error_direction: &'static str,
    first_error_stage: &'static str,
    upstream: &DirectionSnapshot,
    downstream: &DirectionSnapshot,
) {
    let client_to_backend_average_frame_bytes =
        average(upstream.forwarded_bytes, upstream.forwarded_frames);
    let backend_to_client_average_frame_bytes =
        average(downstream.forwarded_bytes, downstream.forwarded_frames);
    let duration_seconds = (duration_ms as f64 / 1000.0).max(0.001);
    let client_to_backend_bytes_per_second = upstream.forwarded_bytes as f64 / duration_seconds;
    let backend_to_client_bytes_per_second = downstream.forwarded_bytes as f64 / duration_seconds;

    if context.observability.connection_event_logs_enabled() {
        info!(
            transport_connection_id = context.transport_connection_id,
            connection_id = context.connection_id,
            route_id = context.route.id(),
            route_class = context.route.namespace().as_str(),
            backend = context.route.backend().display(),
            peer = %context.peer,
            cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
            downstream_http_version = context.downstream_http_version,
            close_reason = close_reason.as_str(),
            duration_ms,
            short_lived = duration_ms <= SHORT_LIVED_CONNECTION_THRESHOLD.as_millis(),
            long_lived = duration_ms >= LONG_LIVED_CONNECTION_THRESHOLD.as_millis(),
            active_websocket_connections = remaining_active,
            first_error_direction,
            first_error_stage,
            client_to_backend_read_frames = upstream.read_frames,
            client_to_backend_forwarded_frames = upstream.forwarded_frames,
            client_to_backend_read_bytes = upstream.read_bytes,
            client_to_backend_bytes = upstream.forwarded_bytes,
            client_to_backend_bytes_per_second,
            client_to_backend_small_frames = upstream.small_frames,
            client_to_backend_control_frames = upstream.control_frames,
            client_to_backend_min_frame_bytes = upstream.minimum_frame_bytes.unwrap_or(0),
            client_to_backend_max_frame_bytes = upstream.maximum_frame_bytes,
            client_to_backend_average_frame_bytes,
            client_to_backend_max_inter_frame_gap_ms = upstream.max_inter_frame_gap_ms,
            client_to_backend_last_activity_idle_ms = upstream.last_activity_idle_ms,
            client_to_backend_last_read_idle_ms = upstream.last_read_idle_ms,
            client_to_backend_last_write_idle_ms = upstream.last_write_idle_ms,
            client_to_backend_last_frame_opcode = upstream.last_frame_opcode,
            client_to_backend_last_frame_fin = upstream.last_frame_fin,
            client_to_backend_last_frame_payload_bytes = upstream.last_frame_payload_bytes,
            backend_to_client_read_frames = downstream.read_frames,
            backend_to_client_forwarded_frames = downstream.forwarded_frames,
            backend_to_client_read_bytes = downstream.read_bytes,
            backend_to_client_bytes = downstream.forwarded_bytes,
            backend_to_client_bytes_per_second,
            backend_to_client_small_frames = downstream.small_frames,
            backend_to_client_control_frames = downstream.control_frames,
            backend_to_client_min_frame_bytes = downstream.minimum_frame_bytes.unwrap_or(0),
            backend_to_client_max_frame_bytes = downstream.maximum_frame_bytes,
            backend_to_client_average_frame_bytes,
            backend_to_client_max_inter_frame_gap_ms = downstream.max_inter_frame_gap_ms,
            backend_to_client_last_activity_idle_ms = downstream.last_activity_idle_ms,
            backend_to_client_last_read_idle_ms = downstream.last_read_idle_ms,
            backend_to_client_last_write_idle_ms = downstream.last_write_idle_ms,
            backend_to_client_last_frame_opcode = downstream.last_frame_opcode,
            backend_to_client_last_frame_fin = downstream.last_frame_fin,
            backend_to_client_last_frame_payload_bytes = downstream.last_frame_payload_bytes,
            "websocket relay closed"
        );
    } else {
        debug!(
            transport_connection_id = context.transport_connection_id,
            connection_id = context.connection_id,
            route_id = context.route.id(),
            route_class = context.route.namespace().as_str(),
            backend = context.route.backend().display(),
            peer = %context.peer,
            cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
            close_reason = close_reason.as_str(),
            duration_ms,
            active_websocket_connections = remaining_active,
            first_error_direction,
            first_error_stage,
            "websocket relay closed"
        );
    }
}

fn average(total: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

const fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x0 => "continuation",
        0x1 => "text",
        0x2 => "binary",
        0x8 => "close",
        0x9 => "ping",
        0xA => "pong",
        _ => "none",
    }
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

    const fn observability_direction(self) -> RelayDirection {
        match self {
            Self::ClientToBackend => RelayDirection::ClientToBackend,
            Self::BackendToClient => RelayDirection::BackendToClient,
        }
    }
}

struct PumpReport {
    direction: Direction,
    final_snapshot: DirectionSnapshot,
    end: PumpEnd,
}

impl PumpReport {
    fn cancelled(direction: Direction, diagnostics: &DirectionDiagnostics) -> Self {
        Self {
            direction,
            final_snapshot: diagnostics.finish(RelayStage::Cancelled),
            end: PumpEnd::Cancelled,
        }
    }

    fn peer_closed(direction: Direction, diagnostics: &DirectionDiagnostics) -> Self {
        Self {
            direction,
            final_snapshot: diagnostics.finish(RelayStage::PeerClosed),
            end: PumpEnd::PeerClosed,
        }
    }

    fn error(
        direction: Direction,
        diagnostics: &DirectionDiagnostics,
        error: impl ToString,
    ) -> Self {
        Self {
            direction,
            final_snapshot: diagnostics.finish_current_stage(),
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

    const fn observability_class(self) -> WebSocketCloseClass {
        match self {
            Self::ClientClosed => WebSocketCloseClass::ClientClosed,
            Self::BackendClosed => WebSocketCloseClass::BackendClosed,
            Self::GatewayShutdown => WebSocketCloseClass::GatewayShutdown,
            Self::RelayError => WebSocketCloseClass::RelayError,
            Self::InternalError => WebSocketCloseClass::InternalError,
        }
    }
}

#[derive(Copy, Clone)]
#[repr(u8)]
enum RelayStage {
    AwaitingRead = 0,
    WaitingWriterLock = 1,
    WritingDataFrame = 2,
    WritingControlFrame = 3,
    WritingStreamBytes = 4,
    FlushingFrame = 5,
    PeerClosed = 6,
    Cancelled = 7,
    Ended = 8,
}

impl RelayStage {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::AwaitingRead,
            1 => Self::WaitingWriterLock,
            2 => Self::WritingDataFrame,
            3 => Self::WritingControlFrame,
            4 => Self::WritingStreamBytes,
            5 => Self::FlushingFrame,
            6 => Self::PeerClosed,
            7 => Self::Cancelled,
            _ => Self::Ended,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingRead => "awaiting_read",
            Self::WaitingWriterLock => "waiting_writer_lock",
            Self::WritingDataFrame => "writing_data_frame",
            Self::WritingControlFrame => "writing_control_frame",
            Self::WritingStreamBytes => "writing_stream_bytes",
            Self::FlushingFrame => "flushing_frame",
            Self::PeerClosed => "peer_closed",
            Self::Cancelled => "cancelled",
            Self::Ended => "ended",
        }
    }

    const fn is_waiting_for_input(self) -> bool {
        matches!(self, Self::AwaitingRead)
    }

    const fn is_write_path(self) -> bool {
        matches!(
            self,
            Self::WaitingWriterLock
                | Self::WritingDataFrame
                | Self::WritingControlFrame
                | Self::WritingStreamBytes
                | Self::FlushingFrame
        )
    }
}

// For WS→WS, FragmentCollectorRead exposes complete data messages after fragment
// collection. For WS→TCP, the raw reader records individual data frames/chunks
// because message boundaries intentionally disappear at the byte-stream boundary.
struct DirectionDiagnostics {
    started: Instant,
    enabled: bool,
    detailed: bool,
    stage: AtomicU8,
    read_frames: AtomicU64,
    forwarded_frames: AtomicU64,
    read_bytes: AtomicU64,
    forwarded_bytes: AtomicU64,
    small_frames: AtomicU64,
    control_frames: AtomicU64,
    minimum_frame_bytes: AtomicU64,
    maximum_frame_bytes: AtomicU64,
    last_frame_elapsed_ms: AtomicU64,
    last_read_elapsed_ms: AtomicU64,
    last_write_elapsed_ms: AtomicU64,
    last_activity_elapsed_ms: AtomicU64,
    max_inter_frame_gap_ms: AtomicU64,
    last_frame_opcode: AtomicU8,
    last_frame_fin: AtomicU8,
    last_frame_payload_bytes: AtomicU64,
}

impl DirectionDiagnostics {
    fn new(started: Instant, enabled: bool, detailed: bool) -> Self {
        Self {
            started,
            enabled,
            detailed,
            stage: AtomicU8::new(RelayStage::AwaitingRead as u8),
            read_frames: AtomicU64::new(0),
            forwarded_frames: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            forwarded_bytes: AtomicU64::new(0),
            small_frames: AtomicU64::new(0),
            control_frames: AtomicU64::new(0),
            minimum_frame_bytes: AtomicU64::new(u64::MAX),
            maximum_frame_bytes: AtomicU64::new(0),
            last_frame_elapsed_ms: AtomicU64::new(0),
            last_read_elapsed_ms: AtomicU64::new(0),
            last_write_elapsed_ms: AtomicU64::new(0),
            last_activity_elapsed_ms: AtomicU64::new(0),
            max_inter_frame_gap_ms: AtomicU64::new(0),
            last_frame_opcode: AtomicU8::new(u8::MAX),
            last_frame_fin: AtomicU8::new(0),
            last_frame_payload_bytes: AtomicU64::new(0),
        }
    }

    fn set_stage(&self, stage: RelayStage) {
        if !self.enabled {
            return;
        }
        self.stage.store(stage as u8, Ordering::Relaxed);
    }

    fn record_read(&self, opcode: OpCode, fin: bool, payload_bytes: usize) {
        if !self.enabled {
            return;
        }
        if !self.detailed {
            return;
        }
        let payload_bytes = payload_bytes as u64;
        let now = self.elapsed_millis();
        let previous = self.last_frame_elapsed_ms.swap(now, Ordering::Relaxed);
        if previous > 0 {
            self.max_inter_frame_gap_ms
                .fetch_max(now.saturating_sub(previous), Ordering::Relaxed);
        }
        self.last_activity_elapsed_ms.store(now, Ordering::Relaxed);
        self.last_read_elapsed_ms.store(now, Ordering::Relaxed);
        self.record_last_frame(opcode, fin, payload_bytes);
        self.read_frames.fetch_add(1, Ordering::Relaxed);
        self.read_bytes.fetch_add(payload_bytes, Ordering::Relaxed);
        if payload_bytes <= 1024 {
            self.small_frames.fetch_add(1, Ordering::Relaxed);
        }
        self.minimum_frame_bytes.fetch_min(payload_bytes, Ordering::Relaxed);
        self.maximum_frame_bytes.fetch_max(payload_bytes, Ordering::Relaxed);
    }

    fn record_forwarded(&self, payload_bytes: usize) {
        if !self.enabled {
            return;
        }
        self.forwarded_frames.fetch_add(1, Ordering::Relaxed);
        if !self.detailed {
            self.set_stage(RelayStage::AwaitingRead);
            return;
        }
        self.forwarded_bytes.fetch_add(payload_bytes as u64, Ordering::Relaxed);
        self.last_activity_elapsed_ms.store(self.elapsed_millis(), Ordering::Relaxed);
        self.last_write_elapsed_ms.store(self.elapsed_millis(), Ordering::Relaxed);
        self.set_stage(RelayStage::AwaitingRead);
    }

    fn record_control_frame(&self, opcode: OpCode, fin: bool, payload_bytes: usize) {
        if !self.detailed {
            return;
        }
        let now = self.elapsed_millis();
        self.control_frames.fetch_add(1, Ordering::Relaxed);
        self.last_activity_elapsed_ms.store(now, Ordering::Relaxed);
        self.last_read_elapsed_ms.store(now, Ordering::Relaxed);
        self.record_last_frame(opcode, fin, payload_bytes as u64);
    }

    fn record_last_frame(&self, opcode: OpCode, fin: bool, payload_bytes: u64) {
        self.last_frame_opcode.store(opcode as u8, Ordering::Relaxed);
        self.last_frame_fin.store(u8::from(fin), Ordering::Relaxed);
        self.last_frame_payload_bytes.store(payload_bytes, Ordering::Relaxed);
    }

    fn finish(&self, stage: RelayStage) -> DirectionSnapshot {
        self.set_stage(stage);
        self.snapshot()
    }

    fn finish_current_stage(&self) -> DirectionSnapshot {
        let snapshot = self.snapshot();
        self.set_stage(RelayStage::Ended);
        snapshot
    }

    fn snapshot(&self) -> DirectionSnapshot {
        let elapsed_ms = self.elapsed_millis();
        let last_activity = self.last_activity_elapsed_ms.load(Ordering::Relaxed);
        let last_read = self.last_read_elapsed_ms.load(Ordering::Relaxed);
        let last_write = self.last_write_elapsed_ms.load(Ordering::Relaxed);
        let minimum = self.minimum_frame_bytes.load(Ordering::Relaxed);
        DirectionSnapshot {
            stage: RelayStage::from_u8(self.stage.load(Ordering::Relaxed)),
            read_frames: self.read_frames.load(Ordering::Relaxed),
            forwarded_frames: self.forwarded_frames.load(Ordering::Relaxed),
            read_bytes: self.read_bytes.load(Ordering::Relaxed),
            forwarded_bytes: self.forwarded_bytes.load(Ordering::Relaxed),
            small_frames: self.small_frames.load(Ordering::Relaxed),
            control_frames: self.control_frames.load(Ordering::Relaxed),
            minimum_frame_bytes: (minimum != u64::MAX).then_some(minimum),
            maximum_frame_bytes: self.maximum_frame_bytes.load(Ordering::Relaxed),
            max_inter_frame_gap_ms: self.max_inter_frame_gap_ms.load(Ordering::Relaxed),
            last_activity_idle_ms: elapsed_ms.saturating_sub(last_activity),
            last_read_idle_ms: elapsed_ms.saturating_sub(last_read),
            last_write_idle_ms: elapsed_ms.saturating_sub(last_write),
            last_frame_opcode: opcode_name(self.last_frame_opcode.load(Ordering::Relaxed)),
            last_frame_fin: self.last_frame_fin.load(Ordering::Relaxed) != 0,
            last_frame_payload_bytes: self.last_frame_payload_bytes.load(Ordering::Relaxed),
        }
    }

    fn elapsed_millis(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

struct DirectionSnapshot {
    stage: RelayStage,
    read_frames: u64,
    forwarded_frames: u64,
    read_bytes: u64,
    forwarded_bytes: u64,
    small_frames: u64,
    control_frames: u64,
    minimum_frame_bytes: Option<u64>,
    maximum_frame_bytes: u64,
    max_inter_frame_gap_ms: u64,
    last_activity_idle_ms: u64,
    last_read_idle_ms: u64,
    last_write_idle_ms: u64,
    last_frame_opcode: &'static str,
    last_frame_fin: bool,
    last_frame_payload_bytes: u64,
}

#[derive(Default)]
struct ProgressTracker {
    forwarded_frames: u64,
    forwarded_bytes: u64,
    idle_episode_reported: bool,
    no_progress_episode_reported: bool,
}
