use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use instant_acme::AccountCredentials;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::config::TlsConfig;

pub(super) async fn load_account(path: &Path) -> Result<Option<AccountCredentials>> {
    match fs::read(path).await {
        Ok(bytes) => {
            let credentials = serde_json::from_slice(&bytes).with_context(|| {
                format!("failed to parse ACME account state {}", path.display())
            })?;
            Ok(Some(credentials))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to read ACME account state {}", path.display())),
    }
}

pub(super) async fn save_account(path: &Path, credentials: &AccountCredentials) -> Result<()> {
    let bytes =
        serde_json::to_vec_pretty(credentials).context("failed to serialize ACME account state")?;
    write_atomic(path, &bytes, true).await
}

pub(super) async fn save_certificate_pair(
    tls: &TlsConfig,
    id: &str,
    certificate_pem: &str,
    private_key_pem: &str,
) -> Result<()> {
    fs::create_dir_all(tls.cert_dir()).await.with_context(|| {
        format!(
            "failed to create TLS certificate directory {}",
            tls.cert_dir().display()
        )
    })?;

    let cert_path = tls.cert_path(id);
    let key_path = tls.key_path(id);
    let cert_temp = temporary_path(&cert_path);
    let key_temp = temporary_path(&key_path);

    write_file(&cert_temp, certificate_pem.as_bytes(), false).await?;
    if let Err(error) = write_file(&key_temp, private_key_pem.as_bytes(), true).await {
        let _ = fs::remove_file(&cert_temp).await;
        return Err(error);
    }

    if let Err(error) = replace_file(&key_temp, &key_path).await {
        let _ = fs::remove_file(&cert_temp).await;
        let _ = fs::remove_file(&key_temp).await;
        return Err(error);
    }
    if let Err(error) = replace_file(&cert_temp, &cert_path).await {
        let _ = fs::remove_file(&cert_temp).await;
        return Err(error);
    }
    Ok(())
}

async fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let temporary = temporary_path(path);
    write_file(&temporary, bytes, private).await?;
    if let Err(error) = replace_file(&temporary, path).await {
        let _ = fs::remove_file(&temporary).await;
        return Err(error);
    }
    Ok(())
}

async fn write_file(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut file = fs::File::create(path)
        .await
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("failed to sync {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private { 0o600 } else { 0o644 };
        fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .await
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = private;

    Ok(())
}

async fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(windows)]
    if fs::try_exists(destination).await.unwrap_or(false) {
        fs::remove_file(destination)
            .await
            .with_context(|| format!("failed to replace {}", destination.display()))?;
    }

    fs::rename(source, destination).await.with_context(|| {
        format!(
            "failed to replace {} with {}",
            destination.display(),
            source.display()
        )
    })
}

fn temporary_path(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let name = path.file_name().and_then(|value| value.to_str()).unwrap_or("acme-state");
    path.with_file_name(format!(".{name}.tmp-{}-{nonce}", std::process::id()))
}
