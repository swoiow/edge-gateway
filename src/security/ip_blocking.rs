use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::ResolvedClientAddress;
use super::ip_blocking_config::IpBlockingConfig;
use super::ip_blocking_persistence::{
    self as disk, ActiveBlock, BLOCK_SECONDS, BlockRecord, BlockSnapshot, StateWriter,
};

#[derive(Debug, thiserror::Error)]
#[error("durable IP block capacity exhausted")]
struct BlockCapacityReached;

const SHARDS: usize = 64;
const TEMPORARY_SECONDS: u64 = 300;
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ViolationRule {
    InvalidWebsocket,
    InvalidGrpc,
    SizeViolation,
    NamespaceScan,
}
impl ViolationRule {
    fn index(self) -> usize {
        match self {
            Self::InvalidWebsocket => 0,
            Self::InvalidGrpc => 1,
            Self::SizeViolation => 2,
            Self::NamespaceScan => 3,
        }
    }
    fn window(self) -> Duration {
        Duration::from_secs(if matches!(self, Self::SizeViolation) {
            300
        } else {
            60
        })
    }
}
#[derive(Clone, Copy)]
struct RuleWindow {
    since: Instant,
    count: u32,
}
struct ClientWindow {
    rules: [RuleWindow; 4],
    last_seen: Instant,
}
#[derive(Clone)]
struct PendingBlock {
    address: ResolvedClientAddress,
    rule: ViolationRule,
    count: u32,
    deadline: Instant,
}
#[derive(Default)]
struct PersistedBatch {
    snapshot: Option<Arc<BlockSnapshot>>,
    consumed: Vec<IpAddr>,
    activated: Vec<PendingBlock>,
    wall: u64,
    capacity_overflow: bool,
}
#[derive(Default)]
struct BlockCounters {
    violations: [AtomicU64; 4],
    rejects: AtomicU64,
    activated: AtomicU64,
    overflow: AtomicU64,
    persistence_failures: AtomicU64,
    manager_unavailable: AtomicU64,
}
pub(crate) struct IpBlockingRuntime {
    config: IpBlockingConfig,
    durable: ArcSwap<BlockSnapshot>,
    temporary: ArcSwap<HashMap<IpAddr, Instant>>,
    windows: Vec<Mutex<HashMap<IpAddr, ClientWindow>>>,
    pending: Mutex<HashMap<IpAddr, PendingBlock>>,
    hash: RandomState,
    notify: Notify,
    accepting: AtomicBool,
    writer: Option<Arc<StateWriter>>,
    counters: BlockCounters,
}
impl IpBlockingRuntime {
    pub(crate) async fn load(config: IpBlockingConfig) -> Result<Arc<Self>> {
        let (writer, blocks) = if config.file.enabled {
            let path = config.file.state_file.clone();
            let maximum = config.file.max_blocked_client_ips;
            let (writer, blocks) =
                tokio::task::spawn_blocking(move || disk::load_client_ip_blocklist(path, maximum))
                    .await
                    .context("IP block state loader task")??;
            (Some(Arc::new(writer)), blocks)
        } else {
            (None, HashMap::new())
        };
        Ok(Arc::new(Self {
            config,
            durable: ArcSwap::from_pointee(blocks),
            temporary: ArcSwap::from_pointee(HashMap::new()),
            windows: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            pending: Mutex::new(HashMap::new()),
            hash: RandomState::new(),
            notify: Notify::new(),
            accepting: AtomicBool::new(true),
            writer,
            counters: BlockCounters::default(),
        }))
    }
    fn allowed(&self, ip: IpAddr) -> bool {
        self.config.allow.iter().any(|network| network.contains(ip))
    }
    /// Normal reads: immutable snapshots only. No shard lock, I/O or await.
    pub(crate) fn is_client_ip_blocked(&self, address: ResolvedClientAddress) -> bool {
        if !self.config.file.enabled || self.allowed(address.client_ip) {
            return false;
        }
        let now = Instant::now();
        let blocked = self.durable.load().get(&address.client_ip).is_some_and(|b| b.deadline > now)
            || self.temporary.load().get(&address.client_ip).is_some_and(|until| *until > now);
        if blocked {
            self.counters.rejects.fetch_add(1, Ordering::Relaxed);
        }
        blocked
    }
    pub(crate) fn is_scan_namespace(&self, path: &str) -> bool {
        self.config.file.enabled
            && self.config.file.scan_namespaces.iter().any(|prefix| {
                path == prefix
                    || path.strip_prefix(prefix).is_some_and(|suffix| suffix.starts_with('/'))
            })
    }
    /// Invalid requests already receive their protocol rejection. Only threshold crossings queue persistence.
    pub(crate) fn record_client_protocol_violation(
        &self,
        address: ResolvedClientAddress,
        rule: ViolationRule,
    ) {
        if !self.config.file.enabled {
            return;
        }
        self.counters.violations[rule.index()].fetch_add(1, Ordering::Relaxed);
        if self.allowed(address.client_ip) {
            return;
        }
        if !self.accepting.load(Ordering::Acquire) {
            self.counters.manager_unavailable.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let now = Instant::now();
        if self.durable.load().get(&address.client_ip).is_some_and(|b| b.deadline > now)
            || self.temporary.load().get(&address.client_ip).is_some_and(|until| *until > now)
        {
            return;
        }
        let threshold = match rule {
            ViolationRule::InvalidWebsocket => self.config.file.thresholds.invalid_websocket,
            ViolationRule::InvalidGrpc => self.config.file.thresholds.invalid_grpc,
            ViolationRule::SizeViolation => self.config.file.thresholds.size_violation,
            ViolationRule::NamespaceScan => self.config.file.thresholds.namespace_scan,
        };
        let shard_index = self.hash.hash_one(address.client_ip) as usize % SHARDS;
        let capacity = self.config.file.max_tracked_client_ips / SHARDS
            + usize::from(shard_index < self.config.file.max_tracked_client_ips % SHARDS);
        let count = {
            let Ok(mut shard) = self.windows[shard_index].lock() else {
                self.counters.manager_unavailable.fetch_add(1, Ordering::Relaxed);
                return;
            };
            if !shard.contains_key(&address.client_ip) && shard.len() >= capacity {
                self.counters.overflow.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let window = shard.entry(address.client_ip).or_insert_with(|| ClientWindow {
                rules: [RuleWindow {
                    since: now,
                    count: 0,
                }; 4],
                last_seen: now,
            });
            window.last_seen = now;
            let counter = &mut window.rules[rule.index()];
            if now.duration_since(counter.since) >= rule.window() {
                *counter = RuleWindow {
                    since: now,
                    count: 0,
                };
            }
            counter.count = counter.count.saturating_add(1);
            if counter.count < threshold {
                return;
            }
            counter.count
        };
        // This bounded work set is the command authority; Notify is only a coalesced wakeup.
        // No channel message can be silently dropped on a full queue.
        let Ok(mut pending) = self.pending.lock() else {
            self.counters.manager_unavailable.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if pending.contains_key(&address.client_ip) {
            return;
        }
        if pending.len() >= self.config.file.max_pending_activations {
            self.counters.overflow.fetch_add(1, Ordering::Relaxed);
            return;
        }
        pending.insert(
            address.client_ip,
            PendingBlock {
                address,
                rule,
                count,
                deadline: now + Duration::from_secs(TEMPORARY_SECONDS),
            },
        );
        self.publish_temporary(&pending);
        drop(pending);
        self.notify.notify_one();
    }
    fn publish_temporary(&self, pending: &HashMap<IpAddr, PendingBlock>) {
        self.temporary.store(Arc::new(
            pending.iter().map(|(ip, entry)| (*ip, entry.deadline)).collect(),
        ));
    }
    pub(crate) fn start(self: &Arc<Self>, shutdown: CancellationToken) -> JoinHandle<()> {
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            if runtime.config.file.enabled {
                runtime.run_manager(shutdown).await;
            } else {
                shutdown.cancelled().await;
            }
            runtime.accepting.store(false, Ordering::Release);
        })
    }
    async fn run_manager(&self, shutdown: CancellationToken) {
        let mut backoff = Duration::from_secs(1);
        let mut retry_after = Instant::now();
        let mut first_sweep = true;
        let mut last_sweep = Instant::now();
        let mut last_summary = Instant::now();
        loop {
            // Even during backoff, capacity/expiration cleanup and shutdown remain responsive.
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = self.notify.notified() => {},
                () = tokio::time::sleep(Duration::from_millis(250)) => {},
            }
            let now = Instant::now();
            let sweep_due = now.duration_since(last_sweep) >= Duration::from_secs(30);
            if sweep_due {
                for shard in &self.windows {
                    if let Ok(mut table) = shard.lock() {
                        table.retain(|_, window| {
                            now.duration_since(window.last_seen) < Duration::from_secs(1800)
                        });
                    }
                }
                last_sweep = now;
            }
            if let Ok(mut pending) = self.pending.lock() {
                let before = pending.len();
                pending.retain(|_, entry| entry.deadline > now);
                if pending.len() != before {
                    self.publish_temporary(&pending);
                }
            }
            let has_pending = self.pending.lock().map(|p| !p.is_empty()).unwrap_or(false);
            if now >= retry_after && (has_pending || first_sweep || sweep_due) {
                match self.persist_pending(first_sweep).await {
                    Ok(()) => {
                        first_sweep = false;
                        backoff = Duration::from_secs(1);
                        retry_after = Instant::now();
                    }
                    Err(error) => {
                        if !error.is::<BlockCapacityReached>() {
                            self.counters.persistence_failures.fetch_add(1, Ordering::Relaxed);
                        }
                        let event = if error.is::<BlockCapacityReached>() {
                            "ip_block_capacity_exhausted"
                        } else {
                            "ip_block_persistence_failed"
                        };
                        warn!(event, %error, retry_seconds = backoff.as_secs(), "old snapshot retained; pending temporary restriction is bounded to five minutes");
                        retry_after = Instant::now() + backoff;
                        backoff = (backoff * 2).min(Duration::from_secs(60));
                    }
                }
            }
            if last_summary.elapsed() >= Duration::from_secs(60) {
                self.log_summary();
                last_summary = Instant::now();
            }
        }
        self.accepting.store(false, Ordering::Release);
        // Finish bounded pending work. A failed final commit remains a reported failure, not a false durable success.
        loop {
            let pending = self
                .pending
                .lock()
                .map(|mut p| {
                    p.retain(|_, entry| entry.deadline > Instant::now());
                    self.publish_temporary(&p);
                    !p.is_empty()
                })
                .unwrap_or(false);
            if !pending {
                break;
            }
            if let Err(error) = self.persist_pending(false).await {
                warn!(%error, "IP block shutdown commit failed; durable snapshot retained");
                break;
            }
            let full = self.durable.load().len() >= self.config.file.max_blocked_client_ips;
            if full {
                break;
            }
        }
        self.log_summary();
    }
    async fn persist_pending(&self, force_compaction: bool) -> Result<()> {
        let now = Instant::now();
        let old = self.durable.load_full();
        let pending: Vec<_> = {
            let table = self
                .pending
                .lock()
                .map_err(|_| anyhow!("pending activation state unavailable"))?;
            table
                .iter()
                .filter(|(_, p)| p.deadline > now)
                .take(self.config.file.persistence_batch_size)
                .map(|(ip, p)| (*ip, p.clone()))
                .collect()
        };
        let writer = Arc::clone(self.writer.as_ref().context("block state writer missing")?);
        let maximum = self.config.file.max_blocked_client_ips;
        let allow = self.config.allow.clone();
        // Candidate construction, full-table scans, serialization and filesystem
        // work share one supervised blocking transaction, away from Tokio workers.
        // Do not cancel/detach it: the writer lock outlives its last filesystem call.
        let result = tokio::task::spawn_blocking(move || -> Result<PersistedBatch> {
            let now = Instant::now();
            let expired = old.values().any(|b| b.deadline <= now);
            let mut outcome = PersistedBatch::default();
            if pending.is_empty() && !expired && !force_compaction {
                return Ok(outcome);
            }
            if !pending.is_empty() && old.len() >= maximum && !expired && !force_compaction {
                return Err(anyhow!(BlockCapacityReached));
            }
            let mut candidate = (*old).clone();
            candidate.retain(|_, block| block.deadline > now);
            outcome.wall = disk::unix_seconds()?;
            for (ip, proposal) in pending {
                if proposal.deadline <= now {
                    continue;
                }
                if candidate.contains_key(&ip) || allow.iter().any(|network| network.contains(ip)) {
                    outcome.consumed.push(ip);
                    continue;
                }
                if candidate.len() >= maximum {
                    outcome.capacity_overflow = true;
                    break;
                }
                let record = BlockRecord {
                    client_ip: ip,
                    created_at_unix_seconds: outcome.wall,
                    expires_at_unix_seconds: outcome
                        .wall
                        .checked_add(BLOCK_SECONDS)
                        .context("block timestamp overflow")?,
                    rule: proposal.rule,
                    observed_count: proposal.count,
                };
                candidate.insert(
                    ip,
                    ActiveBlock {
                        record,
                        deadline: now + Duration::from_secs(BLOCK_SECONDS),
                    },
                );
                outcome.consumed.push(ip);
                outcome.activated.push(proposal);
            }
            if !outcome.activated.is_empty() || expired || force_compaction {
                let candidate = Arc::new(candidate);
                disk::persist_client_ip_blocklist_atomically(&writer, &candidate)?;
                outcome.snapshot = Some(candidate);
            } else if outcome.capacity_overflow && outcome.consumed.is_empty() {
                return Err(anyhow!(BlockCapacityReached));
            }
            Ok(outcome)
        })
        .await
        .context("block persistence task failed")?;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                if error.is::<BlockCapacityReached>() {
                    self.counters.overflow.fetch_add(1, Ordering::Relaxed);
                }
                return Err(error);
            }
        };
        if let Some(candidate) = outcome.snapshot {
            self.durable.store(candidate);
        }
        if !outcome.consumed.is_empty() {
            self.consume_pending(&outcome.consumed)?;
        }
        if outcome.capacity_overflow {
            self.counters.overflow.fetch_add(1, Ordering::Relaxed);
        }
        self.counters
            .activated
            .fetch_add(outcome.activated.len() as u64, Ordering::Relaxed);
        for proposal in outcome.activated {
            if self.config.file.log_client_ip {
                info!(event = "client_ip_block_activated", client_ip = %proposal.address.client_ip, peer = %proposal.address.peer,
                    client_ip_source = proposal.address.client_ip_source, trusted_proxy = proposal.address.trusted_proxy,
                    rule = proposal.rule.index(), count = proposal.count, expires_at_unix_seconds = outcome.wall + BLOCK_SECONDS,
                    "client IP block committed");
            } else {
                info!(
                    event = "client_ip_block_activated",
                    rule = proposal.rule.index(),
                    count = proposal.count,
                    expires_at_unix_seconds = outcome.wall + BLOCK_SECONDS,
                    "client IP block committed"
                );
            }
        }
        Ok(())
    }
    fn consume_pending(&self, ips: &[IpAddr]) -> Result<()> {
        let mut table = self
            .pending
            .lock()
            .map_err(|_| anyhow!("pending activation state unavailable"))?;
        for ip in ips {
            table.remove(ip);
        }
        self.publish_temporary(&table);
        Ok(())
    }
    fn log_summary(&self) {
        let now = Instant::now();
        let active = self.durable.load().values().filter(|b| b.deadline > now).count();
        let pending = self.pending.lock().map(|p| p.len()).unwrap_or(0);
        info!(
            event = "ip_block_summary",
            active_blocks = active,
            pending_activations = pending,
            activations = self.counters.activated.load(Ordering::Relaxed),
            rejections = self.counters.rejects.load(Ordering::Relaxed),
            websocket_violations = self.counters.violations[0].load(Ordering::Relaxed),
            grpc_violations = self.counters.violations[1].load(Ordering::Relaxed),
            size_violations = self.counters.violations[2].load(Ordering::Relaxed),
            namespace_scans = self.counters.violations[3].load(Ordering::Relaxed),
            capacity_overflow = self.counters.overflow.load(Ordering::Relaxed),
            persistence_failures = self.counters.persistence_failures.load(Ordering::Relaxed),
            manager_unavailable = self.counters.manager_unavailable.load(Ordering::Relaxed),
            "IP blocking bounded counters"
        );
    }
}
