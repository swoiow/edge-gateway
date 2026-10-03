use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use super::ip_blocking::ViolationRule;
use super::network::normalize_ip;

pub(crate) const BLOCK_SECONDS: u64 = 86400;
const MAX_STATE_BYTES: u64 = 32 * 1024 * 1024;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BlockRecord {
    pub(crate) client_ip: IpAddr,
    pub(crate) created_at_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) rule: ViolationRule,
    pub(crate) observed_count: u32,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockFile {
    version: u32,
    blocks: Vec<BlockRecord>,
}
#[derive(Clone)]
pub(crate) struct ActiveBlock {
    pub(crate) record: BlockRecord,
    pub(crate) deadline: Instant,
}
pub(crate) struct StateWriter {
    pub(crate) path: PathBuf,
    _lock: File,
    // At most one known orphan per live writer. A failed cleanup prevents
    // creation of another temporary file rather than accumulating disk state.
    cleanup_temp: Mutex<Option<PathBuf>>,
}
pub(crate) type BlockSnapshot = HashMap<IpAddr, ActiveBlock>;

pub(crate) fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time precedes Unix epoch")?
        .as_secs())
}
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
pub(crate) fn load_client_ip_blocklist(
    path: PathBuf,
    maximum: usize,
) -> Result<(StateWriter, BlockSnapshot)> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).context("create block state directory")?;
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let lock = private_options()
        .create(true)
        .truncate(false)
        .open(PathBuf::from(lock_name))
        .context("open block state writer lock")?;
    lock.try_lock().context("block state is already owned or locking unsupported")?;
    let writer = StateWriter {
        path,
        _lock: lock,
        cleanup_temp: Mutex::new(None),
    };
    let mut file = match File::open(&writer.path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            persist_client_ip_blocklist_atomically(&writer, &HashMap::new())?;
            return Ok((writer, HashMap::new()));
        }
        Err(error) => return Err(error).context("read block state"),
    };
    if file.metadata()?.len() > MAX_STATE_BYTES {
        bail!("block state exceeds 32 MiB");
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        bail!("block state exceeds 32 MiB");
    }
    let disk: BlockFile = serde_json::from_slice(&bytes)
        .context("invalid block state; preserve file and repair offline")?;
    if disk.version != 1 || disk.blocks.len() > maximum {
        bail!("unsupported block state version or entry capacity exceeded");
    }
    let wall = unix_seconds()?;
    let monotonic = Instant::now();
    let mut blocks = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    for mut record in disk.blocks {
        record.client_ip = normalize_ip(record.client_ip);
        if record.expires_at_unix_seconds.checked_sub(record.created_at_unix_seconds)
            != Some(BLOCK_SECONDS)
            || record.observed_count == 0
            || !seen.insert(record.client_ip)
        {
            bail!("invalid block duration/count or duplicate normalized IP");
        }
        let remaining = record.expires_at_unix_seconds.saturating_sub(wall).min(BLOCK_SECONDS);
        if record.expires_at_unix_seconds.saturating_sub(wall) > BLOCK_SECONDS {
            record.created_at_unix_seconds = wall;
            record.expires_at_unix_seconds =
                wall.checked_add(BLOCK_SECONDS).context("clock timestamp overflow")?;
        }
        if remaining != 0 {
            blocks.insert(
                record.client_ip,
                ActiveBlock {
                    record,
                    deadline: monotonic + Duration::from_secs(remaining),
                },
            );
        }
    }
    // Expired on-disk rows are compacted by the manager's first sweep, not hot-path reads.
    Ok((writer, blocks))
}
pub(crate) fn persist_client_ip_blocklist_atomically(
    writer: &StateWriter,
    blocks: &BlockSnapshot,
) -> Result<()> {
    let orphan = writer
        .cleanup_temp
        .lock()
        .map_err(|_| anyhow!("temporary cleanup state unavailable"))?
        .take();
    if let Some(path) = orphan
        && let Err(error) = std::fs::remove_file(&path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        *writer
            .cleanup_temp
            .lock()
            .map_err(|_| anyhow!("temporary cleanup state unavailable"))? = Some(path);
        return Err(error)
            .context("prior block-state temporary cleanup failed; no new temporary created");
    }
    let parent = writer
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let now = Instant::now();
    let mut records: Vec<_> =
        blocks.values().filter(|b| b.deadline > now).map(|b| b.record.clone()).collect();
    records.sort_by_key(|b| b.client_ip);
    let bytes = serde_json::to_vec(&BlockFile {
        version: 1,
        blocks: records,
    })?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        bail!("serialized block state exceeds 32 MiB");
    }
    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temp = parent.join(format!(".ip-blocklist-{}-{suffix}.tmp", std::process::id()));
    let mut created = false;
    let result = (|| -> Result<()> {
        let mut file = private_options().create_new(true).open(&temp)?;
        created = true;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, &writer.path).context("atomically replace block state")?;
        #[cfg(unix)]
        {
            File::open(parent)?
                .sync_all()
                .context("sync block state directory after rename; commit may be on disk")?;
        }
        Ok(())
    })();
    if result.is_err()
        && created
        && let Err(error) = std::fs::remove_file(&temp)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        *writer
            .cleanup_temp
            .lock()
            .map_err(|_| anyhow!("temporary cleanup state unavailable"))? = Some(temp);
    }
    result
}
