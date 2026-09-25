use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use instant_acme::{
    Account, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::http01::Http01Server;
use super::storage;
use crate::config::{AcmeCertificateConfig, AcmeConfig, AcmeEnvironment, TlsConfig};
use crate::tls::{CertificateMetadata, CertificateStore};

pub(crate) struct AcmeManager {
    config: AcmeConfig,
    tls: TlsConfig,
    store: CertificateStore,
    account: Option<Account>,
}

impl AcmeManager {
    pub(crate) fn new(config: AcmeConfig, tls: TlsConfig, store: CertificateStore) -> Self {
        Self {
            config,
            tls,
            store,
            account: None,
        }
    }

    pub(crate) async fn bootstrap_if_store_empty(&mut self) -> Result<()> {
        if !self.config.enabled() || !self.store.is_empty() {
            return Ok(());
        }

        info!(
            "no TLS certificates are available; running ACME bootstrap before starting data plane"
        );
        let result = self.run_cycle().await;
        if self.store.is_empty() {
            result?;
            bail!("ACME bootstrap completed without producing a usable TLS certificate");
        }
        if let Err(error) = result {
            warn!(
                error = %error,
                tls_certificates = self.store.certificate_count(),
                "ACME bootstrap was only partially successful; starting with available TLS certificates"
            );
        }
        Ok(())
    }

    pub(crate) async fn run_cycle(&mut self) -> Result<()> {
        if !self.config.enabled() {
            return Ok(());
        }

        let account = self.ensure_account().await?;
        let mut due = Vec::new();
        for certificate in self.config.certificates() {
            if self.should_issue(&account, certificate).await {
                due.push(certificate.clone());
            }
        }
        if due.is_empty() {
            return Ok(());
        }

        info!(certificates = due.len(), "ACME renewal batch started");
        let mut http01 = None;
        let mut failures = Vec::new();
        for certificate in due {
            let id = certificate.id().to_owned();
            if let Err(error) = self.issue_certificate(&account, &mut http01, &certificate).await {
                warn!(certificate_id = %id, error = %error, "ACME certificate issuance failed");
                failures.push(format!("{id}: {error}"));
            }
        }
        if let Some(http01) = http01 {
            http01.shutdown().await;
        }

        if failures.is_empty() {
            info!("ACME renewal batch completed");
            Ok(())
        } else {
            bail!(
                "one or more ACME certificate operations failed: {}",
                failures.join("; ")
            )
        }
    }

    async fn ensure_account(&mut self) -> Result<Account> {
        if let Some(account) = &self.account {
            return Ok(account.clone());
        }

        let account_path = self.account_path();
        let builder = Account::builder().context("failed to create ACME HTTP client")?;
        let account = match storage::load_account(&account_path).await? {
            Some(credentials) => builder
                .from_credentials(credentials)
                .await
                .context("failed to restore ACME account")?,
            None => {
                let contact =
                    self.config.email().map(|email| format!("mailto:{email}")).unwrap_or_default();
                let contacts = if contact.is_empty() {
                    Vec::new()
                } else {
                    vec![contact.as_str()]
                };
                let new_account = NewAccount {
                    contact: contacts.as_slice(),
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                };
                let (account, credentials) = builder
                    .create(&new_account, self.directory_url().to_owned(), None)
                    .await
                    .context("failed to create Let's Encrypt ACME account")?;
                storage::save_account(&account_path, &credentials).await?;
                account
            }
        };
        self.account = Some(account.clone());
        Ok(account)
    }

    async fn should_issue(&self, account: &Account, desired: &AcmeCertificateConfig) -> bool {
        let Some(metadata) = self.store.metadata(desired.id()) else {
            info!(
                certificate_id = desired.id(),
                "ACME certificate is missing and will be issued"
            );
            return true;
        };

        if !domains_match(&metadata, desired) {
            info!(
                certificate_id = desired.id(),
                "ACME certificate SAN set differs from desired state"
            );
            return true;
        }

        if let Ok(certificate_id) = CertificateIdentifier::try_from(metadata.leaf_certificate()) {
            match account.renewal_info(&certificate_id).await {
                Ok((renewal_info, _retry_after)) => {
                    let now = unix_now();
                    let start = renewal_info.suggested_window.start.unix_timestamp();
                    let end = renewal_info.suggested_window.end.unix_timestamp();
                    if end > start {
                        let target = renewal_target(start, end, desired.id());
                        if now >= target {
                            info!(
                                certificate_id = desired.id(),
                                target_unix = target,
                                "ACME ARI renewal target reached"
                            );
                            return true;
                        }
                        return false;
                    }
                }
                Err(instant_acme::Error::Unsupported(_)) => {}
                Err(error) => {
                    warn!(certificate_id = desired.id(), error = %error, "failed to query ACME ARI; using expiry fallback");
                }
            }
        }

        let fallback_seconds =
            i64::try_from(self.config.fallback_renew_before().as_secs()).unwrap_or(i64::MAX);
        metadata.not_after_unix().saturating_sub(unix_now()) <= fallback_seconds
    }

    async fn issue_certificate(
        &self,
        account: &Account,
        http01: &mut Option<Http01Server>,
        desired: &AcmeCertificateConfig,
    ) -> Result<()> {
        let identifiers =
            desired.domains().iter().cloned().map(Identifier::Dns).collect::<Vec<_>>();
        let existing_metadata = self.store.metadata(desired.id());
        let replacement_identifier = existing_metadata
            .as_ref()
            .and_then(|metadata| CertificateIdentifier::try_from(metadata.leaf_certificate()).ok());
        let order_request = match replacement_identifier {
            Some(identifier) => NewOrder::new(&identifiers).replaces(identifier),
            None => NewOrder::new(&identifiers),
        };
        let mut order = account
            .new_order(&order_request)
            .await
            .with_context(|| format!("failed to create ACME order for {:?}", desired.id()))?;

        let mut published_tokens = Vec::new();
        let operation = async {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authorization = result.context("failed to load ACME authorization")?;
                match authorization.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    ref status => {
                        return Err(anyhow!("unexpected ACME authorization status {status:?}"));
                    }
                }

                let mut challenge = authorization
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| anyhow!("ACME authorization has no HTTP-01 challenge"))?;
                let token = challenge.token.clone();
                if token.is_empty() || token.contains('/') {
                    bail!("ACME server returned an invalid HTTP-01 token");
                }
                let key_authorization = challenge.key_authorization().as_str().to_owned();

                if http01.is_none() {
                    *http01 = Some(Http01Server::start(self.config.http01_listen()).await?);
                }
                let challenge_server = http01
                    .as_ref()
                    .ok_or_else(|| anyhow!("ACME HTTP-01 listener failed to initialize"))?;

                // Hard ordering contract: response is published before the CA is told the challenge is ready.
                challenge_server
                    .publish(token.clone(), key_authorization)
                    .await;
                published_tokens.push(token);
                challenge
                    .set_ready()
                    .await
                    .context("failed to mark ACME HTTP-01 challenge ready")?;
            }
            drop(authorizations);

            let status = order
                .poll_ready(&acme_retry_policy())
                .await
                .context("failed while waiting for ACME authorizations")?;
            if status != OrderStatus::Ready {
                bail!("unexpected ACME order status after validation: {status:?}");
            }

            let private_key_pem = order
                .finalize()
                .await
                .context("failed to finalize ACME order")?;
            let certificate_pem = order
                .poll_certificate(&acme_retry_policy())
                .await
                .context("failed while waiting for ACME certificate")?;

            let candidate = self
                .store
                .validate_replacement(
                    desired.id(),
                    certificate_pem.as_bytes(),
                    private_key_pem.as_bytes(),
                )
                .with_context(|| {
                    format!(
                        "issued certificate {:?} failed pre-activation TLS validation",
                        desired.id()
                    )
                })?;
            if !domains_match(&candidate, desired) {
                bail!(
                    "issued certificate SANs do not match configured domains for {:?}",
                    desired.id()
                );
            }

            storage::save_certificate_pair(
                &self.tls,
                desired.id(),
                &certificate_pem,
                &private_key_pem,
            )
            .await?;
            self.store
                .reload()
                .await
                .with_context(|| {
                    format!(
                        "new certificate {:?} could not be published to the TLS store",
                        desired.id()
                    )
                })?;
            info!(certificate_id = desired.id(), domains = ?desired.domains(), "ACME certificate activated");
            Ok(())
        }
        .await;

        if let Some(challenge_server) = http01.as_ref() {
            for token in published_tokens {
                challenge_server.remove(&token).await;
            }
        }
        operation
    }

    fn directory_url(&self) -> &'static str {
        match self.config.environment() {
            AcmeEnvironment::Production => LetsEncrypt::Production.url(),
            AcmeEnvironment::Staging => LetsEncrypt::Staging.url(),
        }
    }

    fn account_path(&self) -> PathBuf {
        let environment = match self.config.environment() {
            AcmeEnvironment::Production => "production",
            AcmeEnvironment::Staging => "staging",
        };
        self.config.state_dir().join(format!("letsencrypt-{environment}-account.json"))
    }
}

pub(crate) struct AcmeRuntime {
    task: JoinHandle<()>,
}

impl AcmeRuntime {
    pub(crate) fn start(mut manager: AcmeManager, cancellation: CancellationToken) -> Self {
        let task = tokio::spawn(async move {
            let mut failure_streak = 0_u32;
            loop {
                let cycle_succeeded = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => break,
                    result = manager.run_cycle() => {
                        match result {
                            Ok(()) => true,
                            Err(error) => {
                                warn!(error = %error, "ACME maintenance cycle failed; existing TLS certificates remain active");
                                false
                            }
                        }
                    }
                };

                let delay = if cycle_succeeded {
                    failure_streak = 0;
                    manager.config.check_interval()
                } else {
                    failure_streak = failure_streak.saturating_add(1);
                    acme_failure_retry_delay(failure_streak, manager.config.check_interval())
                };

                tokio::select! {
                    () = cancellation.cancelled() => break,
                    () = sleep(delay) => {}
                }
            }
            info!("ACME maintenance scheduler stopped");
        });
        Self { task }
    }

    pub(crate) async fn wait(self) {
        if let Err(error) = self.task.await {
            warn!(error = %error, "ACME maintenance scheduler terminated unexpectedly");
        }
    }
}

fn domains_match(metadata: &CertificateMetadata, desired: &AcmeCertificateConfig) -> bool {
    let actual = metadata
        .dns_names()
        .iter()
        .filter(|name| !name.starts_with("*."))
        .cloned()
        .collect::<BTreeSet<_>>();
    let desired = desired.domains().iter().cloned().collect::<BTreeSet<_>>();
    actual == desired
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

fn acme_retry_policy() -> RetryPolicy {
    RetryPolicy::new()
        .initial_delay(Duration::from_secs(1))
        .backoff(1.5)
        .timeout(Duration::from_secs(120))
}

fn acme_failure_retry_delay(failure_streak: u32, normal_interval: Duration) -> Duration {
    let retry = match failure_streak {
        0 | 1 => Duration::from_secs(5 * 60),
        2 => Duration::from_secs(15 * 60),
        3 => Duration::from_secs(60 * 60),
        _ => Duration::from_secs(3 * 60 * 60),
    };
    retry.min(normal_interval)
}

fn renewal_target(start: i64, end: i64, certificate_id: &str) -> i64 {
    let span = end.saturating_sub(start);
    if span <= 1 {
        return start;
    }

    // Stable FNV-1a jitter distributes managed certificates through the CA-provided ARI window
    // without adding RNG state to the certificate controller.
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in certificate_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let span = u64::try_from(span).unwrap_or(u64::MAX);
    start.saturating_add(i64::try_from(hash % span).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{acme_failure_retry_delay, renewal_target};

    #[test]
    fn renewal_target_is_stable_and_inside_window() {
        let first = renewal_target(1_000, 2_000, "gateway");
        let second = renewal_target(1_000, 2_000, "gateway");
        assert_eq!(first, second);
        assert!((1_000..2_000).contains(&first));
    }

    #[test]
    fn renewal_targets_spread_by_certificate_id() {
        let gateway = renewal_target(1_000, 100_000, "gateway");
        let api = renewal_target(1_000, 100_000, "api");
        assert_ne!(gateway, api);
    }

    #[test]
    fn failure_retry_is_capped_by_normal_interval() {
        let normal = Duration::from_secs(10 * 60);
        assert_eq!(
            acme_failure_retry_delay(1, normal),
            Duration::from_secs(5 * 60)
        );
        assert_eq!(acme_failure_retry_delay(4, normal), normal);
    }
}
