use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use constitute_protocol::bytes_to_hex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cli::KeyStoreChoice;
use crate::config::{KeyStoreRef, secret_path};

const OS_SERVICE: &str = "constitute-cli";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedSecretFile {
    schema_version: u32,
    public_key: String,
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub fn store_secret(
    config_dir: &Path,
    profile: &str,
    public_key: &str,
    secret_key: &str,
    choice: KeyStoreChoice,
    passphrase: Option<&str>,
) -> Result<KeyStoreRef> {
    if matches!(choice, KeyStoreChoice::OsPreferred) {
        #[cfg(feature = "os-keyring")]
        {
            let id = os_key_id(profile, public_key);
            if let Ok(entry) = keyring::Entry::new(OS_SERVICE, &id)
                && entry.set_password(secret_key).is_ok()
            {
                return Ok(KeyStoreRef {
                    kind: "osCredentialStore".to_string(),
                    id,
                });
            }
        }
    }
    store_encrypted_file(config_dir, profile, public_key, secret_key, passphrase)
}

pub fn load_secret(
    config_dir: &Path,
    profile: &str,
    key_ref: &KeyStoreRef,
    passphrase: Option<&str>,
) -> Result<Zeroizing<String>> {
    match key_ref.kind.as_str() {
        "osCredentialStore" => {
            #[cfg(feature = "os-keyring")]
            {
                let entry = keyring::Entry::new(OS_SERVICE, &key_ref.id)
                    .context("open OS key store entry")?;
                let secret = entry.get_password().context("read OS key store secret")?;
                Ok(Zeroizing::new(secret))
            }
            #[cfg(not(feature = "os-keyring"))]
            {
                Err(anyhow!("OS key store support is not enabled"))
            }
        }
        "encryptedFileFallback" => load_encrypted_file(config_dir, profile, passphrase),
        other => Err(anyhow!("unsupported key store kind: {other}")),
    }
}

pub fn delete_secret(
    config_dir: &Path,
    profile: &str,
    key_ref: Option<&KeyStoreRef>,
) -> Result<()> {
    if let Some(key_ref) = key_ref
        && key_ref.kind == "osCredentialStore"
    {
        #[cfg(feature = "os-keyring")]
        {
            if let Ok(entry) = keyring::Entry::new(OS_SERVICE, &key_ref.id) {
                let _ = entry.delete_credential();
            }
        }
    }
    let path = secret_path(config_dir, profile);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn store_encrypted_file(
    config_dir: &Path,
    profile: &str,
    public_key: &str,
    secret_key: &str,
    passphrase: Option<&str>,
) -> Result<KeyStoreRef> {
    let passphrase = passphrase
        .map(str::to_string)
        .or_else(|| std::env::var("CONSTITUTE_CLI_PASSPHRASE").ok())
        .ok_or_else(|| anyhow!("passphrase required for encrypted key fallback"))?;
    let passphrase = Zeroizing::new(passphrase);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), secret_key.as_bytes())
        .map_err(|_| anyhow!("encrypt key file failed"))?;
    let record = EncryptedSecretFile {
        schema_version: 1,
        public_key: public_key.to_string(),
        kdf: "argon2id-v1".to_string(),
        salt: bytes_to_hex(&salt),
        nonce: bytes_to_hex(&nonce),
        ciphertext: bytes_to_hex(&ciphertext),
    };
    let path = secret_path(config_dir, profile);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(&record)?)?;
    Ok(KeyStoreRef {
        kind: "encryptedFileFallback".to_string(),
        id: path.display().to_string(),
    })
}

fn load_encrypted_file(
    config_dir: &Path,
    profile: &str,
    passphrase: Option<&str>,
) -> Result<Zeroizing<String>> {
    let passphrase = passphrase
        .map(str::to_string)
        .or_else(|| std::env::var("CONSTITUTE_CLI_PASSPHRASE").ok())
        .ok_or_else(|| anyhow!("passphrase required to unlock encrypted key file"))?;
    let passphrase = Zeroizing::new(passphrase);
    let path = secret_path(config_dir, profile);
    let raw =
        fs::read_to_string(&path).with_context(|| format!("read key file: {}", path.display()))?;
    let record: EncryptedSecretFile = serde_json::from_str(&raw).context("parse key file")?;
    let salt = hex::decode(record.salt)?;
    let nonce = hex::decode(record.nonce)?;
    let ciphertext = hex::decode(record.ciphertext)?;
    let key = derive_key(passphrase.as_bytes(), &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("unlock key file failed"))?;
    let secret = String::from_utf8(plaintext).map_err(|_| anyhow!("secret key is not utf8"))?;
    Ok(Zeroizing::new(secret))
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| anyhow!("derive encrypted key failed"))?;
    Ok(key)
}

fn os_key_id(profile: &str, public_key: &str) -> String {
    format!("{profile}:{public_key}")
}

#[cfg(test)]
mod tests {
    use constitute_protocol::generate_keypair;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn encrypted_file_roundtrip() {
        let dir = tempdir().unwrap();
        let (pk, sk) = generate_keypair();
        let key_ref = store_secret(
            dir.path(),
            "test",
            &pk,
            &sk,
            KeyStoreChoice::EncryptedFile,
            Some("testpass1234"),
        )
        .unwrap();
        let loaded = load_secret(dir.path(), "test", &key_ref, Some("testpass1234")).unwrap();
        assert_eq!(&*loaded, &sk);
        assert_ne!(
            fs::read_to_string(secret_path(dir.path(), "test")).unwrap(),
            sk
        );
    }
}
