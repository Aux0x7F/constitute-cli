use anyhow::{Context, Result, anyhow};
use constitute_protocol::{
    CaacEnvelope, SwarmFrame, SwarmFrameBody, SwarmFrameKind, ZoneScope, canonical_json,
    pubkey_from_sk_hex, seal_envelope, swarm_frame_id, validate_swarm_frame,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub fn build_signed_frame(
    kind: &str,
    issuer_sk: &str,
    recipient_member_ref: &str,
    host_gateway_ref: &str,
    payload: Value,
) -> Result<SwarmFrame> {
    let now = now_unix();
    let now_ms = now * 1000;
    let expires_at_ms = now_ms + 90_000;
    let issuer_pk = pubkey_from_sk_hex(issuer_sk)?;
    let frame_kind: SwarmFrameKind = serde_json::from_value(Value::String(kind.to_string()))
        .with_context(|| {
            format!("parse swarm frame kind {kind}; expected a protocol frame kind")
        })?;
    let envelope = seal_envelope(
        kind,
        &payload,
        issuer_sk,
        &[recipient_member_ref.to_string()],
        now,
        now + 90,
    )?;
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: frame_kind,
        issuer: issuer_pk,
        audience: json!({
            "memberRef": recipient_member_ref,
            "gatewayRef": host_gateway_ref
        }),
        zone_scope: Some(ZoneScope {
            zone_id: "zone_lab".to_string(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(30),
            max_hops: Some(2),
        }),
        issued_at: now_ms,
        expires_at: Some(expires_at_ms),
        nonce: format!("nonce-{}", Uuid::new_v4().simple()),
        correlation_id: Some(format!("corr-{}", Uuid::new_v4().simple())),
        channel_id: None,
        record_ref: None,
        capability: None,
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(serde_json::to_value(envelope).context("serialize CAAC envelope")?),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, now_ms)?;
    Ok(frame)
}

pub fn verify_frame_signature(frame: &SwarmFrame) -> Result<bool> {
    validate_swarm_frame(frame, now_unix() * 1000)?;
    let envelope_value = frame
        .body
        .envelope
        .as_ref()
        .ok_or_else(|| anyhow!("swarm frame missing CAAC envelope"))?;
    let envelope: CaacEnvelope =
        serde_json::from_value(envelope_value.clone()).context("parse CAAC envelope")?;
    constitute_protocol::verify_envelope_signature(&envelope)
}

pub fn parse_payload(payload_json: Option<&str>) -> Result<Value> {
    match payload_json {
        Some(raw) => serde_json::from_str(raw).context("parse payload json"),
        None => Ok(json!({})),
    }
}

#[allow(dead_code)]
pub fn frame_digest(frame: &SwarmFrame) -> Result<String> {
    canonical_json(&serde_json::to_value(frame).context("serialize swarm frame")?)
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
