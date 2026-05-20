// domain-owned-vocabulary: logging.default.72h.low projection.observer.update
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use constitute_protocol::{
    ProjectionCoverage, ProjectionFreshness, ProjectionFreshnessState, ProjectionObserverUpdate,
    ProjectionRecord, ProjectionSyncState, validate_projection_observer_update,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::protocol_ops::now_unix;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeObserverEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub service: String,
    pub channel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<ProjectionObserverUpdate>,
    pub freshness: ProjectionFreshness,
    pub coverage: ProjectionCoverage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionStoreResult {
    pub projection_key: String,
    pub projection: ProjectionRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observer_event: Option<RuntimeObserverEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeServiceIdentity {
    pub service: String,
    pub service_pk: String,
    pub host_gateway_pk: String,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RuntimeState {
    #[serde(default)]
    descriptors: BTreeMap<String, Value>,
    #[serde(default)]
    retained_projections: BTreeMap<String, ProjectionRecord>,
    #[serde(default)]
    projection_policies: BTreeMap<String, Value>,
    #[serde(default)]
    relay_hints: Vec<String>,
    #[serde(default)]
    gateway_hints: BTreeMap<String, Value>,
    #[serde(default)]
    service_identities: BTreeMap<String, RuntimeServiceIdentity>,
    #[serde(default)]
    updated_at: u64,
}

#[derive(Clone, Debug)]
pub struct RuntimeStore {
    path: PathBuf,
    state: RuntimeState,
}

impl RuntimeStore {
    pub fn open(config_dir: &Path, profile: &str) -> Result<Self> {
        let path = runtime_state_path(config_dir, profile);
        if !path.exists() {
            return Ok(Self {
                path,
                state: RuntimeState::default(),
            });
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read runtime state {}", path.display()))?;
        let state = serde_json::from_str(&raw).context("parse runtime state")?;
        Ok(Self { path, state })
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_vec_pretty(&self.state)?)
            .with_context(|| format!("write runtime state {}", self.path.display()))
    }

    pub fn remember_descriptor(&mut self, descriptor: &impl Serialize) -> Result<()> {
        let value = serde_json::to_value(descriptor)?;
        let service = value
            .get("service")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        if service.is_empty() {
            return Ok(());
        }
        let service_pk = value
            .get("servicePk")
            .or_else(|| value.get("service_pk"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        let host_gateway_pk = value
            .get("hostGatewayPk")
            .or_else(|| value.get("host_gateway_pk"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        self.state.descriptors.insert(service.clone(), value);
        if !service_pk.is_empty() || !host_gateway_pk.is_empty() {
            self.state.service_identities.insert(
                service.clone(),
                RuntimeServiceIdentity {
                    service,
                    service_pk,
                    host_gateway_pk,
                    updated_at: now_unix() * 1000,
                },
            );
        }
        self.touch();
        Ok(())
    }

    pub fn remember_relay_hints(&mut self, relays: &[String]) {
        for relay in relays {
            let trimmed = relay.trim();
            if !trimmed.is_empty() && !self.state.relay_hints.iter().any(|item| item == trimmed) {
                self.state.relay_hints.push(trimmed.to_string());
            }
        }
        self.touch();
    }

    pub fn store_projection(
        &mut self,
        projection: ProjectionRecord,
    ) -> Result<ProjectionStoreResult> {
        let key = projection_store_key(&projection);
        let existing = self.state.retained_projections.get(&key).cloned();
        let existing_count = existing.as_ref().map(projection_payload_count).unwrap_or(0);
        let merged = merge_projection_record(existing.as_ref(), &projection)?;
        let stored = merged;
        let semantically_equal = existing
            .as_ref()
            .map(|old| projection_semantically_equal(old, &stored))
            .unwrap_or(false);
        if semantically_equal {
            let mut refreshed = existing.expect("existing checked");
            refreshed.cursor = stored.cursor.clone().or(refreshed.cursor);
            refreshed.freshness = stored.freshness.clone();
            self.state
                .retained_projections
                .insert(key.clone(), refreshed.clone());
            self.touch();
            return Ok(ProjectionStoreResult {
                projection_key: key,
                projection: refreshed,
                observer_event: None,
            });
        }

        let changed_count = projection_payload_count(&stored).saturating_sub(existing_count);
        self.state
            .retained_projections
            .insert(key.clone(), stored.clone());
        self.touch();
        let update = projection_observer_update(&key, &stored, changed_count);
        validate_projection_observer_update(&update)?;
        let coverage = update.coverage.clone();
        let freshness = update.freshness.clone();
        Ok(ProjectionStoreResult {
            projection_key: key,
            projection: stored.clone(),
            observer_event: Some(RuntimeObserverEvent {
                event_type: "projection.observer.update".to_string(),
                service: stored.service.clone(),
                channel_id: stored.channel_id.clone(),
                projection: Some(serde_json::to_value(&stored)?),
                update: Some(update),
                freshness,
                coverage,
            }),
        })
    }

    fn touch(&mut self) {
        self.state.updated_at = now_unix() * 1000;
    }
}

pub fn runtime_state_path(config_dir: &Path, profile: &str) -> PathBuf {
    config_dir.join("runtime").join(profile).join("state.json")
}

pub fn projection_store_key(projection: &ProjectionRecord) -> String {
    projection_key_parts(
        if projection.service_pk.trim().is_empty() {
            projection.service.trim()
        } else {
            projection.service_pk.trim()
        },
        projection.channel_id.trim(),
        &projection_policy_id(projection),
    )
}

pub fn projection_key_parts(service_key: &str, channel_id: &str, policy_id: &str) -> String {
    [service_key.trim(), channel_id.trim(), policy_id.trim()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("|")
}

pub fn projection_policy_id(projection: &ProjectionRecord) -> String {
    projection
        .scope
        .get("policyId")
        .or_else(|| projection.scope.get("policy_id"))
        .and_then(Value::as_str)
        .or_else(|| {
            projection
                .payload
                .get("policy")
                .and_then(|policy| policy.get("policyId").or_else(|| policy.get("policy_id")))
                .and_then(Value::as_str)
        })
        .unwrap_or("default")
        .trim()
        .to_string()
}

pub fn projection_payload_count(projection: &ProjectionRecord) -> u64 {
    payload_event_items(&projection.payload)
        .map(|items| items.len() as u64)
        .or_else(|| {
            projection
                .payload
                .get("items")
                .and_then(Value::as_array)
                .map(|items| items.len() as u64)
        })
        .unwrap_or_else(|| if projection.payload.is_object() { 1 } else { 0 })
}

pub fn projection_coverage(projection: &ProjectionRecord) -> ProjectionCoverage {
    if let Some(coverage) = projection
        .payload
        .get("coverage")
        .or_else(|| projection.safe_facts.get("coverage"))
        .and_then(|value| serde_json::from_value::<ProjectionCoverage>(value.clone()).ok())
    {
        return coverage;
    }

    let materialized_count = projection_payload_count(projection);
    let target_count = projection
        .scope
        .get("targetCount")
        .or_else(|| projection.scope.get("target_count"))
        .and_then(Value::as_u64);
    let completion_ratio = match target_count {
        Some(target) if target > 0 => (materialized_count as f64 / target as f64).min(1.0),
        Some(_) => 1.0,
        None => {
            if materialized_count > 0 {
                1.0
            } else {
                0.0
            }
        }
    };
    let (oldest_observed_at, newest_observed_at) = event_time_bounds(projection);
    ProjectionCoverage {
        materialized_count,
        target_count,
        completion_ratio,
        complete_severity_bands: vec![],
        oldest_observed_at,
        newest_observed_at,
        sync_state: if matches!(projection.freshness.state, ProjectionFreshnessState::Error) {
            ProjectionSyncState::Degraded
        } else {
            ProjectionSyncState::CompleteEnough
        },
    }
}

pub fn projection_observer_update(
    projection_key: &str,
    projection: &ProjectionRecord,
    changed_count: u64,
) -> ProjectionObserverUpdate {
    ProjectionObserverUpdate {
        projection_key: projection_key.to_string(),
        changed_count,
        coverage: projection_coverage(projection),
        freshness: projection.freshness.clone(),
        diagnostics: projection.diagnostics.clone(),
    }
}

pub fn merge_projection_record(
    existing: Option<&ProjectionRecord>,
    next: &ProjectionRecord,
) -> Result<ProjectionRecord> {
    let Some(existing) = existing else {
        return Ok(next.clone());
    };
    if projection_replaces_event_set(next) {
        return Ok(next.clone());
    }
    let Some(next_events) = payload_event_items(&next.payload) else {
        return Ok(next.clone());
    };

    let mut merged_events: Vec<Value> = payload_event_items(&existing.payload)
        .cloned()
        .unwrap_or_default();
    let mut index = HashMap::new();
    for (idx, event) in merged_events.iter().enumerate() {
        index.insert(event_stable_key(event), idx);
    }
    for event in next_events {
        let key = event_stable_key(event);
        if let Some(idx) = index.get(&key).copied() {
            merged_events[idx] = merge_json_objects(&merged_events[idx], event);
        } else {
            index.insert(key, merged_events.len());
            merged_events.push(event.clone());
        }
    }
    merged_events.sort_by(|a, b| {
        event_time(b)
            .cmp(&event_time(a))
            .then_with(|| event_stable_key(a).cmp(&event_stable_key(b)))
    });

    let mut merged = next.clone();
    let mut payload = next.payload.clone();
    if let Value::Object(map) = &mut payload {
        map.insert("events".to_string(), Value::Array(merged_events));
    }
    merged.payload = payload;
    Ok(merged)
}

pub fn projection_semantically_equal(left: &ProjectionRecord, right: &ProjectionRecord) -> bool {
    projection_semantic_shape(left) == projection_semantic_shape(right)
}

fn projection_semantic_shape(projection: &ProjectionRecord) -> Value {
    let mut value = serde_json::to_value(projection).unwrap_or_else(|_| json!({}));
    if let Value::Object(map) = &mut value {
        map.remove("retainedAt");
        if let Some(Value::Object(cursor)) = map.get_mut("cursor") {
            cursor.remove("updatedAt");
        }
        if let Some(Value::Object(freshness)) = map.get_mut("freshness") {
            freshness.remove("updatedAt");
            freshness.remove("staleAfter");
        }
        if let Some(Value::Object(payload)) = map.get_mut("payload") {
            payload.remove("requestId");
            payload.remove("retainedAt");
        }
    }
    value
}

fn projection_replaces_event_set(projection: &ProjectionRecord) -> bool {
    payload_event_items(&projection.payload).is_some()
        && (projection.payload.get("policy").is_some()
            || projection.payload.get("coverage").is_some()
            || projection.scope.get("policyId").is_some()
            || projection.scope.get("coverage").is_some())
}

fn payload_event_items(payload: &Value) -> Option<&Vec<Value>> {
    payload.get("events").and_then(Value::as_array)
}

fn event_stable_key(event: &Value) -> String {
    for key in ["eventId", "event_id", "logEventId", "id", "cursor"] {
        if let Some(value) = event.get(key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return format!("{key}:{trimmed}");
            }
        }
    }
    serde_json::to_string(&stable_json(event)).unwrap_or_else(|_| "event".to_string())
}

fn event_time(event: &Value) -> u64 {
    for key in ["occurredAt", "occurred_at", "ts", "timestamp"] {
        if let Some(value) = event.get(key).and_then(Value::as_u64) {
            return value;
        }
        if let Some(text) = event.get(key).and_then(Value::as_str)
            && let Ok(value) = text.parse::<u64>()
        {
            return value;
        }
    }
    0
}

fn event_time_bounds(projection: &ProjectionRecord) -> (Option<u64>, Option<u64>) {
    let Some(events) = payload_event_items(&projection.payload) else {
        return (None, None);
    };
    let mut observed = events.iter().map(event_time).filter(|value| *value > 0);
    let Some(first) = observed.next() else {
        return (None, None);
    };
    let mut min = first;
    let mut max = first;
    for value in observed {
        min = min.min(value);
        max = max.max(value);
    }
    (Some(min), Some(max))
}

fn merge_json_objects(left: &Value, right: &Value) -> Value {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let mut merged = left.clone();
            for (key, value) in right {
                merged.insert(key.clone(), value.clone());
            }
            Value::Object(merged)
        }
        (_, right) => right.clone(),
    }
}

fn stable_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), stable_json(&map[&key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(stable_json).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use constitute_protocol::{ProjectionCursor, ProjectionFreshness};
    use serde_json::json;

    use super::*;

    fn projection(events: Vec<Value>, scope: Value) -> ProjectionRecord {
        ProjectionRecord {
            channel_id: constitute_protocol::PROJECTION_CHANNEL_LOGGING_EVENTS.to_string(),
            service: "logging".to_string(),
            service_pk: "svc".to_string(),
            producer: json!({}),
            cursor: Some(ProjectionCursor {
                value: "cursor".to_string(),
                updated_at: 1,
            }),
            freshness: ProjectionFreshness {
                state: ProjectionFreshnessState::Fresh,
                updated_at: 1,
                stale_after: Some(2),
                reason: None,
            },
            scope,
            materialization_budget_ref: Some("logging.default.72h.low".to_string()),
            consumer_floor_ref: Some("cli.retained-projection.floor".to_string()),
            payload_schema: None,
            payload: json!({ "events": events }),
            safe_facts: json!({}),
            encrypted_detail_refs: vec![],
            diagnostics: vec![],
        }
    }

    #[test]
    fn projection_key_uses_service_pk_channel_and_default_policy() {
        let record = projection(vec![], json!({}));
        assert_eq!(projection_store_key(&record), "svc|logging.events|default");
    }

    #[test]
    fn authoritative_policy_projection_replaces_events() {
        let existing = projection(
            vec![json!({ "eventId": "old", "occurredAt": 1 })],
            json!({ "policyId": "default" }),
        );
        let next = projection(
            vec![json!({ "eventId": "new", "occurredAt": 2 })],
            json!({ "policyId": "default" }),
        );
        let merged = merge_projection_record(Some(&existing), &next).unwrap();
        assert_eq!(projection_payload_count(&merged), 1);
        assert_eq!(merged.payload["events"][0]["eventId"], "new");
    }

    #[test]
    fn semantic_refresh_ignores_freshness_time() {
        let left = projection(vec![json!({ "eventId": "a" })], json!({}));
        let mut right = left.clone();
        right.freshness.updated_at = 99;
        assert!(projection_semantically_equal(&left, &right));
    }

    #[test]
    fn non_authoritative_events_merge_by_key() {
        let existing = projection(vec![json!({ "eventId": "a", "occurredAt": 1 })], json!({}));
        let next = projection(vec![json!({ "eventId": "b", "occurredAt": 2 })], json!({}));
        let merged = merge_projection_record(Some(&existing), &next).unwrap();
        assert_eq!(projection_payload_count(&merged), 2);
        assert_eq!(merged.payload["events"][0]["eventId"], "b");
    }
}
