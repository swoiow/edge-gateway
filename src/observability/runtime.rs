use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::{Instant, interval_at};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::config::{ObservabilityConfig, ObservabilityMode};

#[derive(Clone)]
pub(crate) struct RuntimeObservability {
    inner: Arc<Inner>,
}

pub(crate) struct ObservabilityTask {
    handle: Option<JoinHandle<()>>,
}

pub(crate) struct ActiveConnection {
    inner: Arc<Inner>,
    kind: ConnectionKind,
}

#[derive(Copy, Clone)]
enum ConnectionKind {
    Transport,
    WebSocket,
}

#[derive(Copy, Clone)]
pub(crate) enum RelayDirection {
    ClientToBackend,
    BackendToClient,
}

#[derive(Copy, Clone)]
pub(crate) enum WebSocketCloseClass {
    ClientClosed,
    BackendClosed,
    GatewayShutdown,
    RelayError,
    InternalError,
}

struct Inner {
    mode: ObservabilityMode,
    connection_event_logs_enabled: bool,
    summary_interval_seconds: u64,
    diagnostic_interval_seconds: u64,
    next_transport_connection_id: AtomicU64,
    next_websocket_connection_id: AtomicU64,
    counters: Counters,
}

#[derive(Default)]
struct Counters {
    active_transport_connections: AtomicU64,
    peak_transport_connections: AtomicU64,
    transport_connections_total: AtomicU64,
    tls_handshake_success_total: AtomicU64,
    tls_handshake_failures_total: AtomicU64,
    tls_handshake_timeouts_total: AtomicU64,
    http_connection_errors_total: AtomicU64,
    active_websocket_connections: AtomicU64,
    peak_websocket_connections: AtomicU64,
    websocket_connections_total: AtomicU64,
    websocket_backend_connect_failures_total: AtomicU64,
    websocket_backend_connect_timeouts_total: AtomicU64,
    websocket_upgrade_failures_total: AtomicU64,
    websocket_upgrade_timeouts_total: AtomicU64,
    websocket_relay_failures_total: AtomicU64,
    websocket_idle_events_total: AtomicU64,
    websocket_no_progress_events_total: AtomicU64,
    websocket_long_lived_connections_total: AtomicU64,
    websocket_short_lived_connections_total: AtomicU64,
    websocket_client_closed_total: AtomicU64,
    websocket_backend_closed_total: AtomicU64,
    websocket_gateway_shutdown_total: AtomicU64,
    client_to_backend: DirectionCounters,
    backend_to_client: DirectionCounters,
}

#[derive(Default)]
struct DirectionCounters {
    bytes_total: AtomicU64,
    forwarded_frames_total: AtomicU64,
    small_frames_total: AtomicU64,
    control_frames_total: AtomicU64,
    frames_le_64_bytes_total: AtomicU64,
    frames_le_1024_bytes_total: AtomicU64,
    frames_le_16384_bytes_total: AtomicU64,
    frames_le_65536_bytes_total: AtomicU64,
    frames_le_262144_bytes_total: AtomicU64,
    frames_gt_262144_bytes_total: AtomicU64,
}

impl RuntimeObservability {
    pub(crate) async fn start(
        config: ObservabilityConfig,
        shutdown: CancellationToken,
    ) -> Result<(Self, ObservabilityTask)> {
        let inner = Arc::new(Inner {
            mode: config.mode(),
            connection_event_logs_enabled: config.connection_event_logs_enabled(),
            summary_interval_seconds: config.summary_interval().as_secs(),
            diagnostic_interval_seconds: config.diagnostic_interval().as_secs(),
            next_transport_connection_id: AtomicU64::new(1),
            next_websocket_connection_id: AtomicU64::new(1),
            counters: Counters::default(),
        });
        let runtime = Self {
            inner: Arc::clone(&inner),
        };

        let (path, interval) = match config.mode() {
            ObservabilityMode::Production => (config.summary_file(), config.summary_interval()),
            ObservabilityMode::Diagnostic => {
                (config.diagnostic_file(), config.diagnostic_interval())
            }
            ObservabilityMode::Off => {
                return Ok((runtime, ObservabilityTask { handle: None }));
            }
        };
        let file = open_output(path).await?;
        let handle = tokio::spawn(run_writer(
            file,
            path.to_path_buf(),
            interval,
            inner,
            shutdown,
        ));
        Ok((
            runtime,
            ObservabilityTask {
                handle: Some(handle),
            },
        ))
    }

    pub(crate) fn mode(&self) -> ObservabilityMode {
        self.inner.mode
    }

    pub(crate) fn connection_event_logs_enabled(&self) -> bool {
        self.inner.connection_event_logs_enabled
    }

    pub(crate) fn observation_interval_seconds(&self) -> u64 {
        match self.inner.mode {
            ObservabilityMode::Production => self.inner.summary_interval_seconds,
            ObservabilityMode::Diagnostic => self.inner.diagnostic_interval_seconds,
            ObservabilityMode::Off => self.inner.diagnostic_interval_seconds,
        }
    }

    pub(crate) fn begin_transport_connection(&self) -> (u64, ActiveConnection) {
        let id = self.inner.next_transport_connection_id.fetch_add(1, Ordering::Relaxed);
        self.inner.counters.transport_connections_total.fetch_add(1, Ordering::Relaxed);
        increment_active(
            &self.inner.counters.active_transport_connections,
            &self.inner.counters.peak_transport_connections,
        );
        (
            id,
            ActiveConnection {
                inner: Arc::clone(&self.inner),
                kind: ConnectionKind::Transport,
            },
        )
    }

    pub(crate) fn next_websocket_connection_id(&self) -> u64 {
        self.inner.next_websocket_connection_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn begin_websocket_connection(&self) -> ActiveConnection {
        self.inner.counters.websocket_connections_total.fetch_add(1, Ordering::Relaxed);
        increment_active(
            &self.inner.counters.active_websocket_connections,
            &self.inner.counters.peak_websocket_connections,
        );
        ActiveConnection {
            inner: Arc::clone(&self.inner),
            kind: ConnectionKind::WebSocket,
        }
    }

    pub(crate) fn peak_websocket_connections(&self) -> u64 {
        self.inner.counters.peak_websocket_connections.load(Ordering::Relaxed)
    }

    pub(crate) fn record_tls_handshake_success(&self) {
        if self.inner.mode == ObservabilityMode::Diagnostic {
            increment(&self.inner.counters.tls_handshake_success_total);
        }
    }

    pub(crate) fn record_tls_handshake_failure(&self) {
        increment(&self.inner.counters.tls_handshake_failures_total);
    }

    pub(crate) fn record_tls_handshake_timeout(&self) {
        increment(&self.inner.counters.tls_handshake_timeouts_total);
    }

    pub(crate) fn record_http_connection_error(&self) {
        if self.inner.mode == ObservabilityMode::Diagnostic {
            increment(&self.inner.counters.http_connection_errors_total);
        }
    }

    pub(crate) fn record_websocket_backend_connect_failure(&self) {
        increment(&self.inner.counters.websocket_backend_connect_failures_total);
    }

    pub(crate) fn record_websocket_backend_connect_timeout(&self) {
        increment(&self.inner.counters.websocket_backend_connect_timeouts_total);
    }

    pub(crate) fn record_websocket_upgrade_failure(&self) {
        if self.inner.mode == ObservabilityMode::Diagnostic {
            increment(&self.inner.counters.websocket_upgrade_failures_total);
        }
    }

    pub(crate) fn record_websocket_upgrade_timeout(&self) {
        if self.inner.mode == ObservabilityMode::Diagnostic {
            increment(&self.inner.counters.websocket_upgrade_timeouts_total);
        }
    }

    pub(crate) fn record_websocket_idle_event(&self) {
        if self.inner.mode == ObservabilityMode::Diagnostic {
            increment(&self.inner.counters.websocket_idle_events_total);
        }
    }

    pub(crate) fn record_websocket_no_progress_event(&self) {
        increment(&self.inner.counters.websocket_no_progress_events_total);
    }

    pub(crate) fn record_forwarded_frame(&self, direction: RelayDirection, payload_bytes: usize) {
        if self.inner.mode == ObservabilityMode::Off {
            return;
        }
        let counters = self.direction(direction);
        counters.bytes_total.fetch_add(payload_bytes as u64, Ordering::Relaxed);
        if self.inner.mode != ObservabilityMode::Diagnostic {
            return;
        }
        increment(&counters.forwarded_frames_total);
        if payload_bytes <= 1024 {
            increment(&counters.small_frames_total);
        }
        match payload_bytes {
            0..=64 => increment(&counters.frames_le_64_bytes_total),
            65..=1024 => increment(&counters.frames_le_1024_bytes_total),
            1025..=16384 => increment(&counters.frames_le_16384_bytes_total),
            16385..=65536 => increment(&counters.frames_le_65536_bytes_total),
            65537..=262144 => increment(&counters.frames_le_262144_bytes_total),
            _ => increment(&counters.frames_gt_262144_bytes_total),
        }
    }

    pub(crate) fn record_control_frame(&self, direction: RelayDirection) {
        if self.inner.mode == ObservabilityMode::Diagnostic {
            increment(&self.direction(direction).control_frames_total);
        }
    }

    pub(crate) fn record_websocket_closed(
        &self,
        close_class: WebSocketCloseClass,
        long_lived: bool,
        short_lived: bool,
    ) {
        if self.inner.mode == ObservabilityMode::Off {
            return;
        }
        if matches!(
            close_class,
            WebSocketCloseClass::RelayError | WebSocketCloseClass::InternalError
        ) {
            increment(&self.inner.counters.websocket_relay_failures_total);
        }
        if self.inner.mode != ObservabilityMode::Diagnostic {
            return;
        }
        if long_lived {
            increment(&self.inner.counters.websocket_long_lived_connections_total);
        }
        if short_lived {
            increment(&self.inner.counters.websocket_short_lived_connections_total);
        }
        match close_class {
            WebSocketCloseClass::ClientClosed => {
                increment(&self.inner.counters.websocket_client_closed_total);
            }
            WebSocketCloseClass::BackendClosed => {
                increment(&self.inner.counters.websocket_backend_closed_total);
            }
            WebSocketCloseClass::GatewayShutdown => {
                increment(&self.inner.counters.websocket_gateway_shutdown_total);
            }
            WebSocketCloseClass::RelayError | WebSocketCloseClass::InternalError => {}
        }
    }

    fn direction(&self, direction: RelayDirection) -> &DirectionCounters {
        match direction {
            RelayDirection::ClientToBackend => &self.inner.counters.client_to_backend,
            RelayDirection::BackendToClient => &self.inner.counters.backend_to_client,
        }
    }
}

impl ObservabilityTask {
    pub(crate) async fn wait(mut self) {
        if let Some(handle) = self.handle.take()
            && let Err(error) = handle.await
        {
            warn!(error = %error, "observability writer task terminated unexpectedly");
        }
    }
}

impl ActiveConnection {
    pub(crate) fn active_connections(&self) -> u64 {
        match self.kind {
            ConnectionKind::Transport => {
                self.inner.counters.active_transport_connections.load(Ordering::Relaxed)
            }
            ConnectionKind::WebSocket => {
                self.inner.counters.active_websocket_connections.load(Ordering::Relaxed)
            }
        }
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        let active = match self.kind {
            ConnectionKind::Transport => &self.inner.counters.active_transport_connections,
            ConnectionKind::WebSocket => &self.inner.counters.active_websocket_connections,
        };
        active.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn open_output(path: &std::path::Path) -> Result<File> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.with_context(|| {
            format!(
                "failed to create observability directory {}",
                parent.display()
            )
        })?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("failed to open observability output {}", path.display()))
}

async fn run_writer(
    mut file: File,
    path: PathBuf,
    summary_interval: std::time::Duration,
    inner: Arc<Inner>,
    shutdown: CancellationToken,
) {
    if let Err(error) = write_snapshot(&mut file, &inner).await {
        warn!(
            output = %path.display(),
            error = %error,
            "failed to write initial observability summary"
        );
    }
    let mut ticks = interval_at(Instant::now() + summary_interval, summary_interval);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                if let Err(error) = write_snapshot(&mut file, &inner).await {
                    warn!(
                        output = %path.display(),
                        error = %error,
                        "failed to write final observability summary"
                    );
                }
                if let Err(error) = file.flush().await {
                    warn!(
                        output = %path.display(),
                        error = %error,
                        "failed to flush observability output"
                    );
                }
                return;
            }
            _ = ticks.tick() => {
                if let Err(error) = write_snapshot(&mut file, &inner).await {
                    warn!(
                        output = %path.display(),
                        error = %error,
                        "failed to write observability summary"
                    );
                }
            }
        }
    }
}

async fn write_snapshot(file: &mut File, inner: &Inner) -> Result<()> {
    let line = snapshot_json(inner);
    file.write_all(line.as_bytes())
        .await
        .context("failed to append observability JSONL")?;
    file.write_all(b"\n")
        .await
        .context("failed to terminate observability JSONL record")?;
    file.flush().await.context("failed to flush observability JSONL record")
}

fn snapshot_json(inner: &Inner) -> String {
    let counters = &inner.counters;
    let profile = match inner.mode {
        ObservabilityMode::Off => "off",
        ObservabilityMode::Production => "production",
        ObservabilityMode::Diagnostic => "diagnostic",
    };
    let active_transport_connections = load(&counters.active_transport_connections);
    let active_websocket_connections = load(&counters.active_websocket_connections);
    let mut json = String::with_capacity(2048);
    let _ = write!(
        json,
        concat!(
            "{{\"ts_unix_ms\":{},\"role\":\"gateway\",\"profile\":\"{}\",",
            "\"active_connections\":{},",
            "\"total_connections\":{},",
            "\"active_transport_connections\":{},",
            "\"active_websocket_connections\":{},",
            "\"peak_transport_connections\":{},",
            "\"peak_websocket_connections\":{},",
            "\"transport_connections_total\":{},",
            "\"websocket_connections_total\":{},",
            "\"client_to_backend_bytes_total\":{},",
            "\"backend_to_client_bytes_total\":{},",
            "\"tls_handshake_failures_total\":{},",
            "\"tls_handshake_timeouts_total\":{},",
            "\"websocket_backend_connect_failures_total\":{},",
            "\"websocket_backend_connect_timeouts_total\":{},",
            "\"websocket_relay_failures_total\":{},",
            "\"data_plane_no_progress_events_total\":{}"
        ),
        unix_time_millis(),
        profile,
        active_transport_connections.saturating_add(active_websocket_connections),
        load(&counters.transport_connections_total),
        active_transport_connections,
        active_websocket_connections,
        load(&counters.peak_transport_connections),
        load(&counters.peak_websocket_connections),
        load(&counters.transport_connections_total),
        load(&counters.websocket_connections_total),
        load(&counters.client_to_backend.bytes_total),
        load(&counters.backend_to_client.bytes_total),
        load(&counters.tls_handshake_failures_total),
        load(&counters.tls_handshake_timeouts_total),
        load(&counters.websocket_backend_connect_failures_total),
        load(&counters.websocket_backend_connect_timeouts_total),
        load(&counters.websocket_relay_failures_total),
        load(&counters.websocket_no_progress_events_total),
    );

    if inner.mode == ObservabilityMode::Diagnostic {
        append_diagnostic_fields(&mut json, counters);
    }
    json.push('}');
    json
}

fn append_diagnostic_fields(json: &mut String, counters: &Counters) {
    let _ = write!(
        json,
        concat!(
            ",\"tls_handshake_success_total\":{}",
            ",\"http_connection_errors_total\":{}",
            ",\"websocket_upgrade_failures_total\":{}",
            ",\"websocket_upgrade_timeouts_total\":{}",
            ",\"websocket_idle_events_total\":{}",
            ",\"websocket_long_lived_connections_total\":{}",
            ",\"websocket_short_lived_connections_total\":{}",
            ",\"websocket_client_closed_total\":{}",
            ",\"websocket_backend_closed_total\":{}",
            ",\"websocket_gateway_shutdown_total\":{}"
        ),
        load(&counters.tls_handshake_success_total),
        load(&counters.http_connection_errors_total),
        load(&counters.websocket_upgrade_failures_total),
        load(&counters.websocket_upgrade_timeouts_total),
        load(&counters.websocket_idle_events_total),
        load(&counters.websocket_long_lived_connections_total),
        load(&counters.websocket_short_lived_connections_total),
        load(&counters.websocket_client_closed_total),
        load(&counters.websocket_backend_closed_total),
        load(&counters.websocket_gateway_shutdown_total),
    );
    append_direction_fields(json, "client_to_backend", &counters.client_to_backend);
    append_direction_fields(json, "backend_to_client", &counters.backend_to_client);
}

fn append_direction_fields(json: &mut String, prefix: &str, counters: &DirectionCounters) {
    let _ = write!(
        json,
        concat!(
            ",\"{}_forwarded_frames_total\":{}",
            ",\"{}_small_frames_total\":{}",
            ",\"{}_control_frames_total\":{}",
            ",\"{}_frames_le_64_bytes_total\":{}",
            ",\"{}_frames_le_1024_bytes_total\":{}",
            ",\"{}_frames_le_16384_bytes_total\":{}",
            ",\"{}_frames_le_65536_bytes_total\":{}",
            ",\"{}_frames_le_262144_bytes_total\":{}",
            ",\"{}_frames_gt_262144_bytes_total\":{}"
        ),
        prefix,
        load(&counters.forwarded_frames_total),
        prefix,
        load(&counters.small_frames_total),
        prefix,
        load(&counters.control_frames_total),
        prefix,
        load(&counters.frames_le_64_bytes_total),
        prefix,
        load(&counters.frames_le_1024_bytes_total),
        prefix,
        load(&counters.frames_le_16384_bytes_total),
        prefix,
        load(&counters.frames_le_65536_bytes_total),
        prefix,
        load(&counters.frames_le_262144_bytes_total),
        prefix,
        load(&counters.frames_gt_262144_bytes_total),
    );
}

fn unix_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn increment(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

fn increment_active(active: &AtomicU64, peak: &AtomicU64) {
    let current = active.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    peak.fetch_max(current, Ordering::Relaxed);
}
