use anyhow::{Context, Result, anyhow};
use constitute_protocol::{
    ServiceExchangeFrame, bytes_to_hex, canonical_json, hex_to_bytes, pubkey_from_sk_hex,
    validate_service_exchange_frame,
};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn build_signed_frame(
    kind: &str,
    issuer_sk: &str,
    recipient_service_pk: &str,
    host_gateway_pk: &str,
    payload: Value,
) -> Result<ServiceExchangeFrame> {
    let now = now_unix();
    let issuer_pk = pubkey_from_sk_hex(issuer_sk)?;
    let mut frame = ServiceExchangeFrame {
        frame_id: format!("frame-{}", Uuid::new_v4()),
        schema_version: 1,
        kind: kind.to_string(),
        issuer_pk,
        recipient_service_pk: recipient_service_pk.to_string(),
        host_gateway_pk: host_gateway_pk.to_string(),
        issued_at: now,
        expires_at: now + 90,
        trace_id: Some(format!("trace-{}", Uuid::new_v4())),
        request_id: Some(format!("request-{}", Uuid::new_v4())),
        correlation_id: None,
        route_hint: json!({}),
        sealed_payload: payload,
        signature: String::new(),
    };
    frame.signature = sign_frame(&frame, issuer_sk)?;
    validate_service_exchange_frame(&frame)?;
    Ok(frame)
}

pub fn sign_frame(frame: &ServiceExchangeFrame, issuer_sk: &str) -> Result<String> {
    let digest = frame_digest(frame)?;
    let msg = Message::from_digest_slice(&digest).map_err(|_| anyhow!("invalid frame digest"))?;
    let sk_bytes = hex_to_bytes(issuer_sk)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid signing secret key"))?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &sk);
    Ok(bytes_to_hex(
        secp.sign_schnorr_no_aux_rand(&msg, &keypair).as_ref(),
    ))
}

pub fn verify_frame_signature(frame: &ServiceExchangeFrame) -> Result<bool> {
    validate_service_exchange_frame(frame)?;
    let digest = frame_digest(frame)?;
    let msg = Message::from_digest_slice(&digest).map_err(|_| anyhow!("invalid frame digest"))?;
    let sig_bytes = hex_to_bytes(&frame.signature)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| anyhow!("invalid frame signature"))?;
    let pk_bytes = hex_to_bytes(&frame.issuer_pk)?;
    let pk =
        XOnlyPublicKey::from_slice(&pk_bytes).map_err(|_| anyhow!("invalid issuer public key"))?;
    let secp = Secp256k1::new();
    Ok(secp.verify_schnorr(&sig, &msg, &pk).is_ok())
}

pub fn frame_digest(frame: &ServiceExchangeFrame) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(frame).context("serialize frame")?;
    if let Value::Object(map) = &mut value {
        map.insert("signature".to_string(), Value::String(String::new()));
    }
    Ok(Sha256::digest(canonical_json(&value)?.as_bytes()).to_vec())
}

pub fn parse_payload(payload_json: Option<&str>) -> Result<Value> {
    match payload_json {
        Some(raw) => serde_json::from_str(raw).context("parse payload json"),
        None => Ok(json!({})),
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
