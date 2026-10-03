use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::Deserialize;

use super::network::IpNetwork;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FileIpBlockingConfig {
    pub(crate) enabled: bool,
    pub(crate) state_file: PathBuf,
    pub(crate) allow_cidrs: Vec<String>,
    pub(crate) scan_namespaces: Vec<String>,
    pub(crate) max_tracked_client_ips: usize,
    pub(crate) max_blocked_client_ips: usize,
    pub(crate) max_pending_activations: usize,
    pub(crate) persistence_batch_size: usize,
    pub(crate) log_client_ip: bool,
    pub(crate) thresholds: ViolationThresholds,
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ViolationThresholds {
    pub(crate) invalid_websocket: u32,
    pub(crate) invalid_grpc: u32,
    pub(crate) size_violation: u32,
    pub(crate) namespace_scan: u32,
}
impl Default for ViolationThresholds {
    fn default() -> Self {
        Self {
            invalid_websocket: 20,
            invalid_grpc: 20,
            size_violation: 5,
            namespace_scan: 60,
        }
    }
}
impl Default for FileIpBlockingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            state_file: PathBuf::from("state/ip-blocklist-v1.json"),
            allow_cidrs: Vec::new(),
            scan_namespaces: Vec::new(),
            max_tracked_client_ips: 65536,
            max_blocked_client_ips: 50000,
            max_pending_activations: 1024,
            persistence_batch_size: 128,
            log_client_ip: false,
            thresholds: ViolationThresholds::default(),
        }
    }
}
pub(crate) struct IpBlockingConfig {
    pub(crate) file: FileIpBlockingConfig,
    pub(crate) allow: Vec<IpNetwork>,
}
impl FileIpBlockingConfig {
    pub(crate) fn validate(mut self, directory: &Path) -> Result<IpBlockingConfig> {
        if self.state_file.as_os_str().is_empty() || self.state_file.file_name().is_none() {
            bail!("state_file requires a file path");
        }
        if !self.state_file.is_absolute() {
            self.state_file = directory.join(&self.state_file);
        }
        if !(64..=1000000).contains(&self.max_tracked_client_ips) {
            bail!("max_tracked_client_ips must be 64..1000000");
        }
        if !(1..=100000).contains(&self.max_blocked_client_ips) {
            bail!("max_blocked_client_ips must be 1..100000");
        }
        if !(1..=10000).contains(&self.max_pending_activations)
            || self.max_pending_activations > self.max_tracked_client_ips
        {
            bail!("max_pending_activations must be 1..10000 and <= tracked capacity");
        }
        if self.persistence_batch_size == 0
            || self.persistence_batch_size > self.max_pending_activations
        {
            bail!("persistence_batch_size must be 1..max_pending_activations");
        }
        if self.allow_cidrs.len() > 128 || self.scan_namespaces.len() > 128 {
            bail!("allow_cidrs and scan_namespaces each limited to 128");
        }
        let allow = self
            .allow_cidrs
            .iter()
            .map(|value| IpNetwork::parse(value).map_err(anyhow::Error::msg))
            .collect::<Result<Vec<_>>>()?;
        let mut seen = std::collections::HashSet::new();
        for path in &self.scan_namespaces {
            crate::http_proxy::routes::validate_http_path(path).map_err(anyhow::Error::msg)?;
            if path == "/"
                || path.ends_with('/')
                || path.len() > 256
                || path.contains('?')
                || path.contains('#')
                || path.starts_with("/health")
                || !seen.insert(path)
            {
                bail!("scan_namespaces require unique non-root segment prefixes excluding /health");
            }
        }
        for threshold in [
            self.thresholds.invalid_websocket,
            self.thresholds.invalid_grpc,
            self.thresholds.size_violation,
            self.thresholds.namespace_scan,
        ] {
            if !(1..=1000000).contains(&threshold) {
                bail!("thresholds must be 1..1000000");
            }
        }
        Ok(IpBlockingConfig { file: self, allow })
    }
}
