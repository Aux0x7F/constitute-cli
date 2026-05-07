use std::collections::HashSet;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use aes::Aes256;
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use constitute_protocol::{
    NostrEvent, NostrFilter, build_unsigned_event, frame_event, frame_req,
    parse_xonly_as_public_key, sign_event, verify_event,
};
use rand::Rng;
use secp256k1::{SecretKey, ecdh};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tungstenite::{Message, connect};

use crate::config::ProfileRecord;
use crate::protocol_ops::now_unix;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairStartOutput {
    pub profile: String,
    pub device_pk: String,
    pub code: String,
    pub relays: Vec<String>,
    pub expires_at: u64,
    pub next_command: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairWaitOutput {
    pub profile: String,
    pub device_pk: String,
    pub identity_label: String,
    pub identity_id: String,
    pub approved_by: String,
}

#[derive(Debug)]
enum RelayObservation {
    Claim {
        relay: String,
        identity: String,
        code_hash: String,
        claim_id: String,
    },
    Approve {
        from_pk: String,
        identity: String,
        encrypted_room_key: String,
    },
}

pub fn make_pair_code() -> String {
    let value = rand::thread_rng().gen_range(100000..=999999);
    value.to_string()
}

pub fn pair_code_hash(identity_label: &str, code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}|{}", identity_label.trim(), code.trim()).as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub fn start_output(profile: &ProfileRecord) -> Result<PairStartOutput> {
    let pending = profile
        .pending_enrollment
        .as_ref()
        .ok_or_else(|| anyhow!("profile does not have pending enrollment"))?;
    Ok(PairStartOutput {
        profile: profile.profile.clone(),
        device_pk: profile.device_pk.clone(),
        code: pending.code.clone(),
        relays: profile.relays.clone(),
        expires_at: pending.expires_at,
        next_command: format!("constitute --profile {} auth wait", profile.profile),
    })
}

pub fn wait_for_pairing(
    profile: &ProfileRecord,
    device_sk: &str,
    timeout_secs: u64,
) -> Result<PairWaitOutput> {
    let pending = profile
        .pending_enrollment
        .as_ref()
        .ok_or_else(|| anyhow!("profile does not have pending enrollment; run auth login first"))?;
    if profile.relays.is_empty() {
        return Err(anyhow!("at least one relay is required for auth wait"));
    }
    let now = now_unix();
    if pending.expires_at <= now {
        return Err(anyhow!("pairing code expired; run auth login --force"));
    }

    let (tx, rx) = mpsc::channel();
    for relay in profile.relays.clone() {
        let tx = tx.clone();
        let code = pending.code.clone();
        let device_pk = profile.device_pk.clone();
        thread::spawn(move || {
            if let Err(err) = observe_relay(&relay, &code, &device_pk, tx) {
                eprintln!("[constitute auth] relay observe degraded {relay}: {err}");
            }
        });
    }
    drop(tx);

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let deadline = Instant::now() + timeout;
    let mut published_claims = HashSet::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("timed out waiting for pairing approval"));
        }
        let observation = match rx.recv_timeout(remaining.min(Duration::from_secs(5))) {
            Ok(observation) => observation,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow!("pairing relay observers stopped before approval"));
            }
        };
        match observation {
            RelayObservation::Claim {
                relay,
                identity,
                code_hash,
                claim_id,
            } => {
                let claim_key = format!("{identity}|{code_hash}|{claim_id}");
                if published_claims.insert(claim_key) {
                    publish_pair_request(
                        &profile.relays,
                        &profile.device_pk,
                        device_sk,
                        &identity,
                        &pending.code,
                        &code_hash,
                        &claim_id,
                        &pending.device_label,
                    )
                    .with_context(|| format!("publish pair request after claim from {relay}"))?;
                }
            }
            RelayObservation::Approve {
                from_pk,
                identity,
                encrypted_room_key,
            } => {
                let payload = decrypt_nip04(device_sk, &from_pk, &encrypted_room_key)?;
                let value: Value = serde_json::from_str(&payload).context("parse pair approval")?;
                let identity_id = value
                    .get("identityId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if identity_id.is_empty() {
                    return Err(anyhow!("pair approval did not contain identityId"));
                }
                return Ok(PairWaitOutput {
                    profile: profile.profile.clone(),
                    device_pk: profile.device_pk.clone(),
                    identity_label: identity,
                    identity_id,
                    approved_by: from_pk,
                });
            }
        }
    }
}

fn observe_relay(
    relay: &str,
    code: &str,
    device_pk: &str,
    tx: mpsc::Sender<RelayObservation>,
) -> Result<()> {
    let (mut socket, _) = connect(relay).with_context(|| format!("connect relay {relay}"))?;
    let req = frame_req(
        "constitute-cli-auth",
        vec![NostrFilter {
            kinds: Some(vec![1]),
            t: Some(vec!["constitute".to_string()]),
            z: None,
        }],
    );
    socket.send(Message::Text(req))?;
    loop {
        let msg = socket.read()?;
        let Message::Text(text) = msg else {
            continue;
        };
        let Some(event) = parse_relay_event(&text)? else {
            continue;
        };
        if !verify_event(&event)? {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<Value>(&event.content) else {
            continue;
        };
        let event_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if event_type == "pair_claim" {
            let identity = payload
                .get("identity")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            let code_hash = payload
                .get("codeHash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if identity.is_empty() || code_hash.is_empty() {
                continue;
            }
            if pair_code_hash(&identity, code) != code_hash {
                continue;
            }
            let claim_id = payload
                .get("claimId")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            let _ = tx.send(RelayObservation::Claim {
                relay: relay.to_string(),
                identity,
                code_hash,
                claim_id,
            });
        } else if event_type == "pair_approve" {
            let to_pk = payload
                .get("toPk")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if to_pk != device_pk {
                continue;
            }
            let identity = payload
                .get("identity")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            let from_pk = payload
                .get("fromPk")
                .and_then(Value::as_str)
                .unwrap_or(event.pubkey.as_str())
                .trim()
                .to_string();
            let encrypted_room_key = payload
                .get("encryptedRoomKey")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_string();
            if from_pk.is_empty() || encrypted_room_key.is_empty() {
                continue;
            }
            let _ = tx.send(RelayObservation::Approve {
                from_pk,
                identity,
                encrypted_room_key,
            });
        }
    }
}

fn parse_relay_event(text: &str) -> Result<Option<NostrEvent>> {
    let value: Value = serde_json::from_str(text).context("parse relay frame")?;
    let Some(items) = value.as_array() else {
        return Ok(None);
    };
    if items.first().and_then(Value::as_str) != Some("EVENT") {
        return Ok(None);
    }
    let event_value = if items.len() >= 3 {
        &items[2]
    } else {
        &items[1]
    };
    Ok(Some(serde_json::from_value(event_value.clone())?))
}

#[allow(clippy::too_many_arguments)]
fn publish_pair_request(
    relays: &[String],
    device_pk: &str,
    device_sk: &str,
    identity: &str,
    code: &str,
    code_hash: &str,
    claim_id: &str,
    device_label: &str,
) -> Result<()> {
    let request_id = format!(
        "cli-enroll-{}-{}",
        device_pk.chars().take(12).collect::<String>(),
        now_unix()
    );
    let payload = json!({
        "type": "pair_request",
        "identity": identity,
        "requestId": request_id,
        "claimId": claim_id,
        "code": code,
        "codeHash": code_hash,
        "devicePk": device_pk,
        "deviceDid": format!("did:device:nostr:{device_pk}"),
        "deviceLabel": device_label,
        "ts": now_unix() * 1000,
        "ttl": 120,
    });
    let unsigned = build_unsigned_event(
        device_pk,
        1,
        vec![
            vec!["t".to_string(), "constitute".to_string()],
            vec!["i".to_string(), identity.to_string()],
        ],
        payload.to_string(),
        now_unix(),
    );
    let event = sign_event(&unsigned, device_sk)?;
    let frame = frame_event(&event);
    let mut delivered = 0usize;
    for relay in relays {
        match connect(relay.as_str()) {
            Ok((mut socket, _)) => {
                if socket.send(Message::Text(frame.clone())).is_ok() {
                    delivered += 1;
                }
            }
            Err(err) => eprintln!("[constitute auth] relay publish degraded {relay}: {err}"),
        }
    }
    if delivered == 0 {
        return Err(anyhow!("pair request was not delivered to any relay"));
    }
    Ok(())
}

fn decrypt_nip04(device_sk: &str, sender_pk: &str, ciphertext: &str) -> Result<String> {
    let (ciphertext_b64, iv_b64) = ciphertext
        .split_once("?iv=")
        .ok_or_else(|| anyhow!("invalid nip04 payload"))?;
    let ciphertext_bytes = STANDARD
        .decode(ciphertext_b64)
        .context("decode nip04 ciphertext")?;
    let iv = STANDARD.decode(iv_b64).context("decode nip04 iv")?;
    let sender_pk = parse_xonly_as_public_key(sender_pk)?;
    let sk_bytes = hex::decode(device_sk).context("decode device secret")?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid device secret"))?;
    let shared = ecdh::shared_secret_point(&sender_pk, &sk);
    let key = &shared[..32];
    let plaintext = Aes256CbcDec::new_from_slices(key, &iv)
        .map_err(|_| anyhow!("invalid nip04 key or iv"))?
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext_bytes)
        .map_err(|_| anyhow!("nip04 decrypt failed"))?;
    String::from_utf8(plaintext).map_err(|_| anyhow!("nip04 plaintext is not utf8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_code_hash_matches_account_contract() {
        assert_eq!(
            pair_code_hash("@Aux", "123456"),
            URL_SAFE_NO_PAD.encode(Sha256::digest("@Aux|123456".as_bytes()))
        );
    }
}
