// domain-owned-vocabulary: projection.repair.request service.intent
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use constitute_protocol::{
    CaacValidationMode, CapabilityAdvertisement, CapabilityDefinition, CapabilityDirectoryEntry,
    ChannelDescriptor, ChannelPolicy, HostedServiceDescriptor, ProjectionDeltaOpKind,
    ProjectionPathSegment, SwarmFrame, SwarmFrameBody, SwarmFrameKind, SwarmProjectionDelta,
    SwarmRecordRef, ZoneScope, active_capability_advertisements, capability_entries_matching,
    parse_xonly_as_public_key, pubkey_from_sk_hex, seal_envelope, swarm_frame_id,
    validate_caac_envelope_for_mode, validate_capability_advertisement,
    validate_capability_definition, validate_capability_directory_entry, validate_capability_name,
    validate_channel_descriptor, validate_channel_policy, validate_projection_delta,
    validate_swarm_frame,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwarmDirectory {
    #[serde(default)]
    pub definitions: Vec<CapabilityDefinition>,
    #[serde(default)]
    pub advertisements: Vec<CapabilityAdvertisement>,
    #[serde(default)]
    pub entries: Vec<CapabilityDirectoryEntry>,
    #[serde(default)]
    pub channels: Vec<ChannelDescriptor>,
    #[serde(default)]
    pub policies: Vec<ChannelPolicy>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityLookupOutput {
    pub capability: String,
    pub definition: CapabilityDefinition,
    pub active_advertisements: Vec<CapabilityAdvertisement>,
    pub entries: Vec<CapabilityDirectoryEntry>,
    pub channels: Vec<ChannelDescriptor>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelListOutput {
    pub capability: String,
    pub channels: Vec<ChannelDescriptor>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeltaApplyResult {
    pub projection_id: String,
    pub base_revision: u64,
    pub revision: u64,
    pub changed: bool,
    pub state: Value,
}

#[derive(Clone, Debug)]
pub enum CaacBodyMode<'a> {
    Product {
        issuer_secret: &'a str,
        recipient_pks: Vec<String>,
    },
    Fixture,
}

pub fn load_swarm_directory(dir: &Path) -> Result<SwarmDirectory> {
    let path = dir.join("swarm-directory.json");
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read swarm directory fixture {}", path.display()))?;
    let directory: SwarmDirectory =
        serde_json::from_str(&raw).context("parse swarm directory fixture")?;
    validate_swarm_directory(&directory)?;
    Ok(directory)
}

pub fn capability_lookup(
    directory: &SwarmDirectory,
    capability: &str,
    now_ms: u64,
) -> Result<CapabilityLookupOutput> {
    validate_capability_name(capability)?;
    let definition = directory
        .definitions
        .iter()
        .find(|definition| definition.capability == capability)
        .cloned()
        .ok_or_else(|| anyhow!("capability not found: {capability}"))?;
    let active_advertisements = active_capability_advertisements(&directory.advertisements, now_ms)
        .into_iter()
        .filter(|advertisement| advertisement.capability == capability)
        .cloned()
        .collect::<Vec<_>>();
    let entries = active_entries_for_capability(directory, capability, &active_advertisements);
    let channels = channels_for_entries(directory, &entries);
    Ok(CapabilityLookupOutput {
        capability: capability.to_string(),
        definition,
        active_advertisements,
        entries,
        channels,
    })
}

pub fn channel_list(
    directory: &SwarmDirectory,
    capability: &str,
    now_ms: u64,
) -> Result<ChannelListOutput> {
    let lookup = capability_lookup(directory, capability, now_ms)?;
    Ok(ChannelListOutput {
        capability: lookup.capability,
        channels: lookup.channels,
    })
}

pub fn build_channel_create_frame(
    directory: &SwarmDirectory,
    capability: &str,
    issuer: &str,
    now_ms: u64,
    body_mode: &CaacBodyMode<'_>,
) -> Result<SwarmFrame> {
    let lookup = capability_lookup(directory, capability, now_ms)?;
    let entry = lookup
        .entries
        .first()
        .ok_or_else(|| anyhow!("capability has no active directory entries: {capability}"))?;
    let channel_id = format!(
        "{}.channel.{}",
        capability.replace('.', "-"),
        Uuid::new_v4().simple()
    );
    let nonce = format!("nonce-{}", Uuid::new_v4().simple());
    let audience = json!({
        "serviceRef": entry.service_ref.as_deref(),
        "memberRef": entry.member_ref.as_deref()
    });
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::RecordPublish,
        issuer: issuer.to_string(),
        audience: audience.clone(),
        zone_scope: Some(ZoneScope {
            zone_id: "zone_lab".to_string(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(30),
            max_hops: Some(2),
        }),
        issued_at: now_ms,
        expires_at: Some(now_ms + 90_000),
        nonce,
        correlation_id: Some(format!("corr-{}", Uuid::new_v4().simple())),
        channel_id: Some(channel_id.clone()),
        record_ref: Some(SwarmRecordRef {
            kind: "channel.descriptor".to_string(),
            id: channel_id.clone(),
            revision: Some(1),
        }),
        capability: Some(capability.to_string()),
        body: caac_body(
            "channel.descriptor.create",
            json!({
                "capability": capability,
                "channelId": channel_id,
                "entryId": entry.entry_id.clone(),
                "audience": audience,
            }),
            body_mode,
            &[
                entry.service_ref.as_deref(),
                entry.member_ref.as_deref(),
                Some(issuer),
            ],
            now_ms,
            now_ms + 90_000,
        )?,
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, now_ms)?;
    Ok(frame)
}

pub fn build_projection_observe_frame(
    descriptor: &HostedServiceDescriptor,
    channel_id: &str,
    issuer: &str,
    now_ms: u64,
    body_mode: &CaacBodyMode<'_>,
) -> Result<SwarmFrame> {
    let channel_id = channel_id.trim();
    if channel_id.is_empty() {
        return Err(anyhow!("projection observe requires channel id"));
    }
    let capability = if channel_id == descriptor.surface_channel {
        constitute_protocol::CAPABILITY_SERVICE_SURFACE_OBSERVE
    } else {
        constitute_protocol::CAPABILITY_PROJECTION_OBSERVE
    };
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::ChannelObserve,
        issuer: issuer.to_string(),
        audience: json!({
            "serviceRef": descriptor.service_pk.clone(),
            "gatewayRef": descriptor.host_gateway_pk.clone(),
        }),
        zone_scope: Some(default_zone_scope()),
        issued_at: now_ms,
        expires_at: Some(now_ms + 90_000),
        nonce: format!("nonce-{}", Uuid::new_v4().simple()),
        correlation_id: Some(format!("observe-{}", Uuid::new_v4().simple())),
        channel_id: Some(channel_id.to_string()),
        record_ref: Some(SwarmRecordRef {
            kind: "projection".to_string(),
            id: channel_id.to_string(),
            revision: None,
        }),
        capability: Some(capability.to_string()),
        body: caac_body(
            constitute_protocol::CAPABILITY_PROJECTION_OBSERVE,
            json!({
                "service": descriptor.service.clone(),
                "channelId": channel_id,
                "capability": capability,
            }),
            body_mode,
            &[
                Some(descriptor.service_pk.as_str()),
                Some(descriptor.host_gateway_pk.as_str()),
            ],
            now_ms,
            now_ms + 90_000,
        )?,
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, now_ms)?;
    Ok(frame)
}

pub fn build_service_intent_frame(
    descriptor: &HostedServiceDescriptor,
    channel_id: &str,
    issuer: &str,
    intent: Value,
    now_ms: u64,
    body_mode: &CaacBodyMode<'_>,
) -> Result<SwarmFrame> {
    let channel_id = channel_id.trim();
    if channel_id.is_empty() {
        return Err(anyhow!("service intent requires channel id"));
    }
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::ServiceIntent,
        issuer: issuer.to_string(),
        audience: json!({
            "serviceRef": descriptor.service_pk.clone(),
            "gatewayRef": descriptor.host_gateway_pk.clone(),
        }),
        zone_scope: Some(default_zone_scope()),
        issued_at: now_ms,
        expires_at: Some(now_ms + 90_000),
        nonce: format!("nonce-{}", Uuid::new_v4().simple()),
        correlation_id: Some(format!("intent-{}", Uuid::new_v4().simple())),
        channel_id: Some(channel_id.to_string()),
        record_ref: Some(SwarmRecordRef {
            kind: "service.intent".to_string(),
            id: format!("intent-{}", Uuid::new_v4().simple()),
            revision: Some(1),
        }),
        capability: Some(constitute_protocol::CAPABILITY_SERVICE_INTENT_INVOKE.to_string()),
        body: caac_body(
            "service.intent",
            json!({
                "service": descriptor.service.clone(),
                "channelId": channel_id,
                "intent": intent,
            }),
            body_mode,
            &[
                Some(descriptor.service_pk.as_str()),
                Some(descriptor.host_gateway_pk.as_str()),
            ],
            now_ms,
            now_ms + 90_000,
        )?,
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, now_ms)?;
    Ok(frame)
}

pub fn build_projection_repair_frame(
    issuer: &str,
    delta: &SwarmProjectionDelta,
    body_mode: &CaacBodyMode<'_>,
) -> Result<SwarmFrame> {
    let issued_at = delta.issued_at.saturating_mul(1000);
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::ProjectionRepairRequest,
        issuer: issuer.to_string(),
        audience: json!({ "projectionId": delta.projection_id }),
        zone_scope: Some(ZoneScope {
            zone_id: "zone_lab".to_string(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(10),
            max_hops: Some(1),
        }),
        issued_at,
        expires_at: Some(issued_at + 90_000),
        nonce: format!("nonce-{}", Uuid::new_v4().simple()),
        correlation_id: Some(format!("repair-{}", delta.projection_id)),
        channel_id: None,
        record_ref: None,
        capability: Some(constitute_protocol::CAPABILITY_PROJECTION_OBSERVE.to_string()),
        body: caac_body(
            "projection.repair.request",
            json!({
                "projectionId": delta.projection_id,
                "baseRevision": delta.base_revision,
                "revision": delta.revision,
            }),
            body_mode,
            &[Some(issuer)],
            issued_at,
            issued_at + 90_000,
        )?,
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, issued_at)?;
    Ok(frame)
}

fn default_zone_scope() -> ZoneScope {
    ZoneScope {
        zone_id: "zone_lab".to_string(),
        privacy: Some("rawIds".to_string()),
        ttl: Some(30),
        max_hops: Some(2),
    }
}

fn caac_body(
    kind: &str,
    claims: Value,
    mode: &CaacBodyMode<'_>,
    fallback_recipients: &[Option<&str>],
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<SwarmFrameBody> {
    match mode {
        CaacBodyMode::Fixture => Ok(test_data_caac_body(kind, claims)),
        CaacBodyMode::Product {
            issuer_secret,
            recipient_pks,
        } => {
            let issuer_pk = pubkey_from_sk_hex(issuer_secret)?;
            let recipients = product_recipient_pks(recipient_pks, fallback_recipients)?;
            if !recipients.iter().any(|recipient| recipient == &issuer_pk) {
                // Include the issuer so diagnostics can prove the body opens locally.
                // Service and gateway recipients still own route delivery.
                let mut with_issuer = recipients;
                with_issuer.push(issuer_pk);
                return product_caac_body(
                    kind,
                    claims,
                    issuer_secret,
                    &with_issuer,
                    issued_at_ms,
                    expires_at_ms,
                );
            }
            product_caac_body(
                kind,
                claims,
                issuer_secret,
                &recipients,
                issued_at_ms,
                expires_at_ms,
            )
        }
    }
}

fn product_caac_body(
    kind: &str,
    claims: Value,
    issuer_secret: &str,
    recipient_pks: &[String],
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<SwarmFrameBody> {
    if recipient_pks.is_empty() {
        return Err(anyhow!(
            "product CAAC body requires at least one public key recipient"
        ));
    }
    let envelope = seal_envelope(
        kind,
        &claims,
        issuer_secret,
        recipient_pks,
        issued_at_ms / 1000,
        expires_at_ms / 1000,
    )?;
    let envelope_value = serde_json::to_value(envelope)?;
    validate_caac_envelope_for_mode(
        &envelope_value,
        CaacValidationMode::Product,
        issued_at_ms / 1000,
    )?;
    Ok(SwarmFrameBody {
        encoding: "caac".to_string(),
        envelope: Some(envelope_value),
        public_bootstrap: false,
        payload: None,
        signature: None,
    })
}

fn test_data_caac_body(kind: &str, metadata: Value) -> SwarmFrameBody {
    SwarmFrameBody {
        encoding: "caac".to_string(),
        envelope: Some(json!({
            "envelopeId": format!("test-data-caac-{}", Uuid::new_v4().simple()),
            "testOnly": true,
            "fixtureKind": kind,
            "metadata": metadata
        })),
        public_bootstrap: false,
        payload: None,
        signature: Some("test-only-fixture-signature".to_string()),
    }
}

fn product_recipient_pks(explicit: &[String], fallback: &[Option<&str>]) -> Result<Vec<String>> {
    let mut recipients = Vec::new();
    for candidate in explicit
        .iter()
        .map(String::as_str)
        .map(Some)
        .chain(fallback.iter().copied())
        .flatten()
    {
        let candidate = candidate.trim();
        if candidate.is_empty() || parse_xonly_as_public_key(candidate).is_err() {
            continue;
        }
        if !recipients.iter().any(|value| value == candidate) {
            recipients.push(candidate.to_string());
        }
    }
    if recipients.is_empty() {
        Err(anyhow!(
            "product CAAC body has no usable public key recipients"
        ))
    } else {
        Ok(recipients)
    }
}

pub fn apply_projection_delta(
    state: Value,
    delta: &SwarmProjectionDelta,
    current_revision: u64,
) -> Result<DeltaApplyResult> {
    validate_projection_delta(delta, current_revision)?;
    let mut next = state;
    let before = next.clone();
    for op in &delta.ops {
        match op.op {
            ProjectionDeltaOpKind::AppendUnique => {
                let target = value_at_path_mut(&mut next, &op.path)?;
                let Some(array) = target.as_array_mut() else {
                    return Err(anyhow!("appendUnique target is not an array"));
                };
                let value = op.value.clone().expect("validated value");
                if !array.iter().any(|item| item == &value) {
                    array.push(value);
                }
            }
            ProjectionDeltaOpKind::Remove => remove_path(&mut next, &op.path)?,
            ProjectionDeltaOpKind::Set | ProjectionDeltaOpKind::Replace => write_path(
                &mut next,
                &op.path,
                op.value.clone().expect("validated value"),
            )?,
        }
    }
    Ok(DeltaApplyResult {
        projection_id: delta.projection_id.clone(),
        base_revision: delta.base_revision,
        revision: delta.revision,
        changed: before != next,
        state: next,
    })
}

pub fn shared_infra_uses_boundary_refs(directory: &SwarmDirectory) -> bool {
    let member_refs = directory
        .entries
        .iter()
        .map(|entry| entry.member_ref.as_deref())
        .chain(
            directory
                .advertisements
                .iter()
                .flat_map(|advertisement| [advertisement.member_ref.as_deref()]),
        )
        .flatten()
        .filter(|value| !value.trim().is_empty());
    let service_refs = directory
        .entries
        .iter()
        .map(|entry| entry.service_ref.as_deref())
        .chain(
            directory
                .advertisements
                .iter()
                .flat_map(|advertisement| [advertisement.service_ref.as_deref()]),
        )
        .flatten()
        .filter(|value| !value.trim().is_empty());
    member_refs.into_iter().all(is_resolved_member_ref)
        && service_refs
            .into_iter()
            .all(|value| value.starts_with("service-raw-"))
}

fn is_resolved_member_ref(value: &str) -> bool {
    let text = value.trim();
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn validate_swarm_directory(directory: &SwarmDirectory) -> Result<()> {
    for definition in &directory.definitions {
        validate_capability_definition(definition)?;
    }
    for advertisement in &directory.advertisements {
        validate_capability_advertisement(advertisement, 0)?;
    }
    for entry in &directory.entries {
        validate_capability_directory_entry(entry)?;
    }
    for channel in &directory.channels {
        validate_channel_descriptor(channel)?;
    }
    for policy in &directory.policies {
        validate_channel_policy(policy)?;
    }
    Ok(())
}

fn active_entries_for_capability(
    directory: &SwarmDirectory,
    capability: &str,
    active_advertisements: &[CapabilityAdvertisement],
) -> Vec<CapabilityDirectoryEntry> {
    let mut entries = capability_entries_matching(&directory.entries, capability);
    if active_advertisements.is_empty() {
        return entries;
    }
    entries.retain(|entry| {
        active_advertisements
            .iter()
            .any(|advertisement| advertisement_matches_entry(advertisement, entry))
    });
    entries
}

fn advertisement_matches_entry(
    advertisement: &CapabilityAdvertisement,
    entry: &CapabilityDirectoryEntry,
) -> bool {
    if !advertisement
        .channel_refs
        .iter()
        .any(|id| id == &entry.channel_id)
    {
        return false;
    }
    let service_matches = entry.service_ref.is_none()
        || advertisement.service_ref.is_none()
        || entry.service_ref == advertisement.service_ref;
    let member_matches = entry.member_ref.is_none()
        || advertisement.member_ref.is_none()
        || entry.member_ref == advertisement.member_ref;
    service_matches && member_matches
}

fn channels_for_entries(
    directory: &SwarmDirectory,
    entries: &[CapabilityDirectoryEntry],
) -> Vec<ChannelDescriptor> {
    let ids = entries
        .iter()
        .map(|entry| entry.channel_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut channels = directory
        .channels
        .iter()
        .filter(|channel| ids.contains(channel.channel_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    channels.sort_by(|a, b| a.channel_id.cmp(&b.channel_id));
    channels
}

fn value_at_path_mut<'a>(
    value: &'a mut Value,
    path: &[ProjectionPathSegment],
) -> Result<&'a mut Value> {
    let mut cursor = value;
    for segment in path {
        cursor = match segment {
            ProjectionPathSegment::Key(key) => cursor
                .get_mut(key)
                .ok_or_else(|| anyhow!("projection delta path missing key: {key}"))?,
            ProjectionPathSegment::Index(index) => cursor
                .get_mut(*index)
                .ok_or_else(|| anyhow!("projection delta path missing index: {index}"))?,
        };
    }
    Ok(cursor)
}

fn write_path(value: &mut Value, path: &[ProjectionPathSegment], next: Value) -> Result<()> {
    let (parent_path, leaf) = path
        .split_last()
        .map(|(leaf, parent)| (parent, leaf))
        .ok_or_else(|| anyhow!("projection delta op missing path"))?;
    let parent = value_at_path_mut(value, parent_path)?;
    match (parent, leaf) {
        (Value::Object(map), ProjectionPathSegment::Key(key)) => {
            map.insert(key.clone(), next);
            Ok(())
        }
        (Value::Array(items), ProjectionPathSegment::Index(index)) => {
            let slot = items
                .get_mut(*index)
                .ok_or_else(|| anyhow!("projection delta path missing index: {index}"))?;
            *slot = next;
            Ok(())
        }
        _ => Err(anyhow!(
            "projection delta path parent has incompatible type"
        )),
    }
}

fn remove_path(value: &mut Value, path: &[ProjectionPathSegment]) -> Result<()> {
    let (parent_path, leaf) = path
        .split_last()
        .map(|(leaf, parent)| (parent, leaf))
        .ok_or_else(|| anyhow!("projection delta op missing path"))?;
    let parent = value_at_path_mut(value, parent_path)?;
    match (parent, leaf) {
        (Value::Object(map), ProjectionPathSegment::Key(key)) => {
            map.remove(key);
            Ok(())
        }
        (Value::Array(items), ProjectionPathSegment::Index(index)) => {
            if *index < items.len() {
                items.remove(*index);
                Ok(())
            } else {
                Err(anyhow!("projection delta path missing index: {index}"))
            }
        }
        _ => Err(anyhow!(
            "projection delta path parent has incompatible type"
        )),
    }
}
