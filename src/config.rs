use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileRecord {
    pub schema_version: u32,
    pub profile: String,
    pub device_pk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_pk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_pk: Option<String>,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_gateway_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_enrollment: Option<PendingEnrollment>,
    pub key_store: KeyStoreRef,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PendingEnrollment {
    pub code: String,
    pub device_label: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyStoreRef {
    pub kind: String,
    pub id: String,
}

pub fn default_config_dir() -> Result<PathBuf> {
    let base =
        dirs::config_dir().ok_or_else(|| anyhow!("platform config directory unavailable"))?;
    Ok(if cfg!(windows) {
        base.join("Constitute").join("cli")
    } else {
        base.join("constitute").join("cli")
    })
}

pub fn profile_path(config_dir: &Path, profile: &str) -> PathBuf {
    config_dir.join("profiles").join(format!("{profile}.json"))
}

pub fn secret_path(config_dir: &Path, profile: &str) -> PathBuf {
    config_dir
        .join("secrets")
        .join(format!("{profile}.key.json"))
}

pub fn save_profile(config_dir: &Path, profile: &ProfileRecord) -> Result<()> {
    let path = profile_path(config_dir, &profile.profile);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(profile)?;
    fs::write(path, bytes).context("write profile")?;
    Ok(())
}

pub fn load_profile(config_dir: &Path, profile: &str) -> Result<ProfileRecord> {
    let path = profile_path(config_dir, profile);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("profile not found: {}", path.display()))?;
    serde_json::from_str(&raw).context("parse profile")
}

pub fn delete_profile(config_dir: &Path, profile: &str) -> Result<()> {
    let path = profile_path(config_dir, profile);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn list_profiles(config_dir: &Path) -> Result<Vec<String>> {
    let dir = config_dir.join("profiles");
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str())
        {
            out.push(stem.to_string());
        }
    }
    out.sort();
    Ok(out)
}
