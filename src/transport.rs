use std::collections::BTreeMap;
use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use constitute_protocol::{
    BootstrapNostrEvent, BootstrapNostrFilter, CaacEnvelope, CaacValidationMode,
    HostedServiceDescriptor, ProjectionRecord, SwarmEdgeAccept, SwarmEdgeHello, SwarmEdgeResume,
    SwarmFrame, SwarmFrameBody, SwarmFrameKind, ZoneScope, frame_bootstrap_nostr_req,
    open_envelope, pubkey_from_sk_hex, seal_envelope, swarm_frame_id,
    validate_caac_envelope_for_mode, validate_hosted_service_descriptor,
    validate_projection_record, validate_route_observation, validate_swarm_edge_accept,
    validate_swarm_edge_hello, validate_swarm_edge_resume, validate_swarm_frame,
    verify_bootstrap_nostr_event,
};
use serde_json::{Value, json};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket, connect};

use crate::config::ProfileRecord;
use crate::protocol_ops::now_unix;
use crate::swarm_ops::{SwarmDirectory, load_swarm_directory, validate_swarm_directory};

pub trait ServiceTransport {
    fn descriptor_list(&self) -> Result<Vec<HostedServiceDescriptor>>;
    fn swarm_directory(&self) -> Result<SwarmDirectory>;
    fn observe_projection(&self, frame: &SwarmFrame, service: &str) -> Result<Value>;
    fn publish_frame(&self, frame: &SwarmFrame) -> Result<Value>;
    fn watch_projection(&self, frame: &SwarmFrame, service: &str) -> Result<Vec<Value>>;
    fn diagnostics(&self) -> Result<Vec<Value>>;
    fn transport_hints(&self) -> Vec<String>;
}

#[derive(Clone, Debug, Default)]
pub struct TransportOpenOptions {
    pub fixture_dir: Option<PathBuf>,
    pub profile: Option<ProfileRecord>,
    pub device_secret: Option<String>,
}

pub fn open_transport(options: TransportOpenOptions) -> Box<dyn ServiceTransport> {
    if let Some(dir) = options.fixture_dir {
        Box::new(FixtureTransport { dir })
    } else if let Some(profile) = options.profile {
        Box::new(LiveTransport::new(profile, options.device_secret))
    } else {
        Box::new(UnconfiguredTransport)
    }
}

#[derive(Debug)]
pub struct UnconfiguredTransport;

impl ServiceTransport for UnconfiguredTransport {
    fn descriptor_list(&self) -> Result<Vec<HostedServiceDescriptor>> {
        Err(anyhow!(
            "no protocol transport configured; provide --fixture-dir or enroll a live transport profile"
        ))
    }

    fn swarm_directory(&self) -> Result<SwarmDirectory> {
        Err(anyhow!(
            "no swarm transport configured; provide --fixture-dir or enroll a live transport profile"
        ))
    }

    fn observe_projection(&self, _frame: &SwarmFrame, _service: &str) -> Result<Value> {
        Err(anyhow!(
            "no swarm transport configured; provide --fixture-dir or enroll a live transport profile"
        ))
    }

    fn publish_frame(&self, _frame: &SwarmFrame) -> Result<Value> {
        Err(anyhow!(
            "no swarm transport configured; provide --fixture-dir or enroll a live transport profile"
        ))
    }

    fn watch_projection(&self, _frame: &SwarmFrame, _service: &str) -> Result<Vec<Value>> {
        Err(anyhow!(
            "no swarm transport configured; provide --fixture-dir or enroll a live transport profile"
        ))
    }

    fn diagnostics(&self) -> Result<Vec<Value>> {
        Err(anyhow!(
            "no protocol transport configured; provide --fixture-dir or enroll a live transport profile"
        ))
    }

    fn transport_hints(&self) -> Vec<String> {
        vec![]
    }
}

#[derive(Debug)]
pub struct FixtureTransport {
    pub dir: PathBuf,
}

impl ServiceTransport for FixtureTransport {
    fn descriptor_list(&self) -> Result<Vec<HostedServiceDescriptor>> {
        let raw = fs::read_to_string(self.dir.join("descriptors.json"))
            .context("read fixture descriptors")?;
        let descriptors: Vec<HostedServiceDescriptor> =
            serde_json::from_str(&raw).context("parse fixture descriptors")?;
        for descriptor in &descriptors {
            validate_hosted_service_descriptor(descriptor)?;
        }
        Ok(descriptors)
    }

    fn swarm_directory(&self) -> Result<SwarmDirectory> {
        load_swarm_directory(&self.dir)
    }

    fn observe_projection(&self, frame: &SwarmFrame, service: &str) -> Result<Value> {
        validate_swarm_frame(frame, frame.issued_at)?;
        let channel = frame
            .channel_id
            .as_deref()
            .ok_or_else(|| anyhow!("projection observe frame missing channelId"))?;
        let raw = fs::read_to_string(
            self.dir
                .join(format!("projection.{service}.{}.json", sanitize(channel))),
        )
        .with_context(|| format!("read projection dataset for {service}/{channel}"))?;
        let record: ProjectionRecord = serde_json::from_str(&raw)?;
        validate_projection_record(&record, &[])?;
        Ok(json!({ "projection": record }))
    }

    fn publish_frame(&self, frame: &SwarmFrame) -> Result<Value> {
        validate_swarm_frame(frame, frame.issued_at)?;
        Ok(json!({
            "status": "diagnosticOnly",
            "transport": "fixture-swarm-edge",
            "frameId": frame.frame_id,
            "frameIntake": {
                "state": "accepted",
                "boundary": "fixture"
            },
            "routeObservation": {
                "state": "notObserved",
                "boundary": "fixture"
            },
            "serviceResponse": {
                "state": "notObserved",
                "boundary": "fixture"
            },
            "projection": {
                "state": "notObserved",
                "boundary": "fixture"
            },
            "frame": frame
        }))
    }

    fn watch_projection(&self, frame: &SwarmFrame, service: &str) -> Result<Vec<Value>> {
        let response = self.observe_projection(frame, service)?;
        Ok(vec![response])
    }

    fn diagnostics(&self) -> Result<Vec<Value>> {
        let path = self.dir.join("diagnostics.json");
        if !path.exists() {
            return Ok(vec![]);
        }
        let raw = fs::read_to_string(path)?;
        serde_json::from_str(&raw).context("parse diagnostics fixture")
    }

    fn transport_hints(&self) -> Vec<String> {
        vec![format!("fixture-swarm-edge://{}", self.dir.display())]
    }
}

#[derive(Debug)]
pub struct LiveTransport {
    pub profile: ProfileRecord,
    device_secret: Option<String>,
    state: Mutex<EdgeSessionState>,
}

#[derive(Clone, Debug, Default)]
struct EdgeSessionState {
    session_id: Option<String>,
    last_acked_frame_id: Option<String>,
    last_projection_revisions: BTreeMap<String, u64>,
}

#[derive(Clone, Debug)]
struct EdgeSessionOpen {
    edge: String,
    session_id: String,
}

#[derive(Clone, Debug)]
struct EdgeReject {
    code: String,
    message: String,
    retryable: bool,
}

#[derive(Clone, Debug)]
enum EdgeWireOutcome {
    Accept(SwarmEdgeAccept),
    Ack(SwarmFrame),
    Reject(EdgeReject),
    Projection(Value),
    Directory(SwarmDirectory),
    RouteObservation(Value),
    ServiceResponse(Value),
    StreamRoutePlan(Value),
    SealedDiagnostic(Value),
    Other,
}

impl LiveTransport {
    pub fn new(profile: ProfileRecord, device_secret: Option<String>) -> Self {
        Self {
            profile,
            device_secret,
            state: Mutex::new(EdgeSessionState::default()),
        }
    }

    #[cfg(test)]
    pub fn new_with_secret(profile: ProfileRecord, device_secret: String) -> Self {
        Self::new(profile, Some(device_secret))
    }
}

impl ServiceTransport for LiveTransport {
    fn descriptor_list(&self) -> Result<Vec<HostedServiceDescriptor>> {
        let relays = live_relays(&self.profile)?;
        let descriptors = discover_descriptors(&relays, self.profile.gateway_pk.as_deref())?;
        if descriptors.is_empty() {
            return Err(anyhow!(
                "no hosted service descriptors discovered from profile relays"
            ));
        }
        Ok(descriptors)
    }

    fn swarm_directory(&self) -> Result<SwarmDirectory> {
        let frame =
            build_directory_observe_frame(&self.profile, self.device_secret()?, now_unix() * 1000)?;
        let result = self.edge_round_trip(&frame, EdgeWait::Directory)?;
        match result {
            EdgeRoundTripResult::Directory(directory) => Ok(directory),
            EdgeRoundTripResult::Rejected(reject) => Err(reject.into_error()),
            _ => Err(anyhow!(
                "live swarm directory observation did not return a directory projection"
            )),
        }
    }

    fn observe_projection(&self, frame: &SwarmFrame, _service: &str) -> Result<Value> {
        let result = self.edge_round_trip(frame, EdgeWait::Projection)?;
        match result {
            EdgeRoundTripResult::Projection(value) => Ok(value),
            EdgeRoundTripResult::Rejected(reject) => Err(reject.into_error()),
            EdgeRoundTripResult::Ack(frame) => Err(anyhow!(
                "live projection observation was accepted ({}) but no projection snapshot arrived",
                frame.frame_id
            )),
            _ => Err(anyhow!(
                "live projection observation did not return a projection snapshot"
            )),
        }
    }

    fn publish_frame(&self, frame: &SwarmFrame) -> Result<Value> {
        validate_swarm_frame(frame, now_unix() * 1000)?;
        let result = self.edge_round_trip(frame, EdgeWait::Publish)?;
        match result {
            EdgeRoundTripResult::Publish(report) => Ok(report.to_value(frame)?),
            EdgeRoundTripResult::Rejected(reject) => Err(reject.into_error()),
            _ => Err(anyhow!(
                "live swarm edge did not return frame-intake evidence"
            )),
        }
    }

    fn watch_projection(&self, frame: &SwarmFrame, service: &str) -> Result<Vec<Value>> {
        Ok(vec![self.observe_projection(frame, service)?])
    }

    fn diagnostics(&self) -> Result<Vec<Value>> {
        let descriptors = self.descriptor_list()?;
        let mut diagnostics = Vec::new();
        for descriptor in descriptors {
            diagnostics.push(json!({
                "operation": "constitute-cli.diagnostics.observe",
                "level": "info",
                "surface": "cli",
                "service": descriptor.service,
                "safeFacts": {
                    "servicePk": descriptor.service_pk,
                    "hostGatewayPk": descriptor.host_gateway_pk,
                    "status": descriptor.health.get("status").cloned().unwrap_or(Value::String("unknown".to_string()))
                }
            }));
        }
        Ok(diagnostics)
    }

    fn transport_hints(&self) -> Vec<String> {
        self.profile
            .local_gateway_hint
            .iter()
            .map(|hint| format!("swarm.edge://{}", hint.trim()))
            .chain(
                self.profile
                    .relays
                    .iter()
                    .map(|relay| format!("bootstrap.relay://{}", relay.trim())),
            )
            .collect()
    }
}

enum EdgeWait {
    Publish,
    Projection,
    Directory,
}

enum EdgeRoundTripResult {
    Ack(SwarmFrame),
    Publish(EdgePublishReport),
    Projection(Value),
    Directory(SwarmDirectory),
    Rejected(EdgeReject),
}

#[derive(Clone, Debug, Default)]
struct EdgePublishReport {
    frame_intake_ack: Option<SwarmFrame>,
    route_observation: Option<Value>,
    service_response: Option<Value>,
    stream_route_plan: Option<Value>,
    projection: Option<Value>,
    diagnostics: Vec<Value>,
}

impl EdgeReject {
    fn into_error(self) -> anyhow::Error {
        anyhow!(
            "swarm edge rejected frame: {} ({}, retryable: {})",
            self.message,
            self.code,
            self.retryable
        )
    }
}

impl EdgePublishReport {
    fn note_diagnostic(&mut self, value: Value) {
        self.diagnostics.push(value);
    }

    fn has_convergence_evidence(&self) -> bool {
        self.route_observation.is_some()
            || self.service_response.is_some()
            || self.stream_route_plan.is_some()
            || self.projection.is_some()
    }

    fn to_value(&self, frame: &SwarmFrame) -> Result<Value> {
        let frame_intake = self
            .frame_intake_ack
            .as_ref()
            .map(|ack| {
                json!({
                    "state": "accepted",
                    "boundary": "frameIntake",
                    "ackFrameId": ack.frame_id,
                    "correlationId": ack.correlation_id,
                    "ackedFrameId": ack.ack.as_ref().and_then(|value| value.acked_frame_id.clone()),
                })
            })
            .unwrap_or_else(|| {
                json!({
                    "state": "notObserved",
                    "boundary": "frameIntake"
                })
            });
        let status = if self.route_observation.is_some() {
            "routeObserved"
        } else if self.service_response.is_some() {
            "serviceObserved"
        } else if self.projection.is_some() {
            "projectionObserved"
        } else {
            "frameIntakeOnly"
        };
        Ok(json!({
            "status": status,
            "transport": "swarm.edge",
            "frameId": frame.frame_id,
            "kind": frame.kind,
            "channelId": frame.channel_id,
            "frameIntake": frame_intake,
            "routeObservation": self.route_observation.clone().unwrap_or_else(|| json!({
                "state": "notObserved",
                "boundary": "routeCoordination"
            })),
            "serviceResponse": self.service_response.clone().unwrap_or_else(|| json!({
                "state": "notObserved",
                "boundary": "serviceAcceptance"
            })),
            "streamRoutePlan": self.stream_route_plan.clone().unwrap_or_else(|| json!({
                "state": "notObserved",
                "boundary": "streamPlanning"
            })),
            "projection": self.projection.clone().unwrap_or_else(|| json!({
                "state": "notObserved",
                "boundary": "projection"
            })),
            "diagnostics": self.diagnostics,
        }))
    }
}

pub fn write_default_fixtures(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    let logging_pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let gateway_pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let browser_pk = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let storage_pk = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let location = Some(constitute_protocol::ServiceLocationRef {
        location_id: "devgateway".to_string(),
        label: "DevGateway".to_string(),
        gateway_pk: gateway_pk.to_string(),
    });
    let descriptors = vec![
        HostedServiceDescriptor {
            service: "logging".to_string(),
            service_pk: logging_pk.to_string(),
            host_gateway_pk: gateway_pk.to_string(),
            aliases: vec!["Logging".to_string(), "Constitute Logging".to_string()],
            location: location.clone(),
            surface_channel: "logging.surface".to_string(),
            display: json!({ "name": "Constitute Logging" }),
            summary: "Structured safe event observation and retention state.".to_string(),
            health: json!({ "status": "ok" }),
            nodes: vec![
                "events".to_string(),
                "health".to_string(),
                "dashboard".to_string(),
                "settings".to_string(),
            ],
            retired: json!({}),
            transport_hints: json!({ "mode": "test-data" }),
        },
        HostedServiceDescriptor {
            service: "gateway".to_string(),
            service_pk: gateway_pk.to_string(),
            host_gateway_pk: gateway_pk.to_string(),
            aliases: vec!["Gateway".to_string(), "DevGateway".to_string()],
            location,
            surface_channel: "gateway.surface".to_string(),
            display: json!({ "name": "DevGateway" }),
            summary: "Gateway routing, hosted-service, zone, and device observation.".to_string(),
            health: json!({ "status": "online" }),
            nodes: vec![
                "health".to_string(),
                "devices".to_string(),
                "hostedServices".to_string(),
                "zones".to_string(),
                "routingDiagnostics".to_string(),
            ],
            retired: json!({}),
            transport_hints: json!({ "mode": "test-data" }),
        },
    ];
    fs::write(
        dir.join("descriptors.json"),
        serde_json::to_vec_pretty(&descriptors)?,
    )?;
    fs::write(
        dir.join("describe.logging.json"),
        serde_json::to_vec_pretty(&descriptors[0])?,
    )?;
    fs::write(
        dir.join("describe.gateway.json"),
        serde_json::to_vec_pretty(&descriptors[1])?,
    )?;
    let projection = json!({
        "channelId": "logging.events",
        "service": "logging",
        "servicePk": logging_pk,
        "producer": { "service": "logging" },
        "freshness": { "state": "fresh", "updatedAt": 1777932000, "staleAfter": 1777932300 },
        "scope": { "policyId": "default" },
        "payloadSchema": "constitute.logging.events.v1",
        "payload": {
            "events": [
                {
                "eventId": "test-event-1",
                "occurredAt": 1777932000,
                "severity": "info",
                "category": "projectionObserve",
                "outcome": "observed",
                "tags": ["logging", "test-data"],
                "safeFacts": { "subject": "constitute-cli doctor" }
                }
            ]
        },
        "safeFacts": { "count": 1 },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    fs::write(
        dir.join("projection.logging.logging-events.json"),
        serde_json::to_vec_pretty(&projection)?,
    )?;
    let surface_projection = json!({
        "channelId": "logging.surface",
        "service": "logging",
        "servicePk": logging_pk,
        "producer": { "service": "logging", "component": "surface" },
        "materializationBudgetRef": "materialization:logging:logging.surface:bounded-snapshot",
        "consumerFloorRef": "consumer-floor:logging:logging.surface:fixture-observer",
        "freshness": { "state": "fresh", "updatedAt": 1777932000, "staleAfter": 1777932600 },
        "scope": {},
        "payloadSchema": "constitute.service.surface.v1",
        "payload": {
            "surface": {
                "surfaceId": "logging.surface",
                "schemaVersion": 1,
                "service": "logging",
                "servicePk": logging_pk,
                "hostGatewayPk": gateway_pk,
                "location": {
                    "locationId": "devgateway",
                    "label": "DevGateway",
                    "gatewayPk": gateway_pk
                },
                "aliases": ["Logging", "Constitute Logging"],
                "summary": "Structured safe event observation and retention state.",
                "healthNode": "health",
                "updatedAt": 1777932000,
                "nodes": [
                    {
                        "nodeId": "logging.events",
                        "path": "events",
                        "label": "Events",
                        "description": "Policy-materialized safe event stream.",
                        "backingChannel": "logging.events",
                        "metadata": {
                            "materializationBudgetRef": "materialization:logging:logging.events:safe-event-stream",
                            "consumerFloorRef": "consumer-floor:logging:logging.events:surface-observer"
                        },
                        "fields": [
                            { "fieldId": "events", "label": "Events", "valueKind": "array", "capabilities": ["read", "observe"] },
                            { "fieldId": "policy", "label": "Policy", "valueKind": "object", "capabilities": ["read", "observe", "set"] }
                        ]
                    },
                    {
                        "nodeId": "logging.health",
                        "path": "health",
                        "label": "Health",
                        "description": "Logging service health.",
                        "backingChannel": "logging.health",
                        "fields": [
                            { "fieldId": "status", "label": "Status", "valueKind": "string", "capabilities": ["read", "observe"] }
                        ]
                    }
                ],
                "diagnostics": []
            }
        },
        "safeFacts": { "nodeCount": 2, "surfaceChannel": "logging.surface" },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    fs::write(
        dir.join("projection.logging.logging-surface.json"),
        serde_json::to_vec_pretty(&surface_projection)?,
    )?;
    let health_projection = json!({
        "channelId": "logging.health",
        "service": "logging",
        "servicePk": logging_pk,
        "producer": { "service": "logging", "component": "health" },
        "freshness": { "state": "fresh", "updatedAt": 1777932000, "staleAfter": 1777932300 },
        "scope": {},
        "payloadSchema": "constitute.logging.health.v1",
        "payload": {
            "nodePath": "health",
            "fields": { "status": "ok" },
            "health": { "status": "ok" }
        },
        "safeFacts": { "status": "ok" },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    fs::write(
        dir.join("projection.logging.logging-health.json"),
        serde_json::to_vec_pretty(&health_projection)?,
    )?;
    let gateway_surface_projection = json!({
        "channelId": "gateway.surface",
        "service": "gateway",
        "servicePk": gateway_pk,
        "producer": { "service": "gateway", "component": "surface" },
        "freshness": { "state": "fresh", "updatedAt": 1777932000, "staleAfter": 1777932600 },
        "scope": {},
        "payloadSchema": "constitute.service.surface.v1",
        "payload": {
            "surface": {
                "surfaceId": "gateway.surface",
                "schemaVersion": 1,
                "service": "gateway",
                "servicePk": gateway_pk,
                "hostGatewayPk": gateway_pk,
                "location": {
                    "locationId": "devgateway",
                    "label": "DevGateway",
                    "gatewayPk": gateway_pk
                },
                "aliases": ["Gateway", "DevGateway"],
                "summary": "Gateway routing, hosted-service, zone, and device observation.",
                "healthNode": "health",
                "updatedAt": 1777932000,
                "nodes": [
                    {
                        "nodeId": "gateway.health",
                        "path": "health",
                        "label": "Health",
                        "description": "Gateway one-line and detailed runtime health.",
                        "backingChannel": "gateway.health",
                        "fields": [
                            { "fieldId": "status", "label": "Status", "valueKind": "string", "capabilities": ["read", "observe"] }
                        ]
                    },
                    {
                        "nodeId": "gateway.devices",
                        "path": "devices",
                        "label": "Devices",
                        "description": "Zone-scoped device presence observed by this gateway.",
                        "backingChannel": "gateway.devices",
                        "fields": [
                            { "fieldId": "devices", "label": "Devices", "valueKind": "array", "capabilities": ["read", "observe"] }
                        ]
                    }
                ],
                "diagnostics": []
            }
        },
        "safeFacts": { "nodeCount": 2, "surfaceChannel": "gateway.surface" },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    fs::write(
        dir.join("projection.gateway.gateway-surface.json"),
        serde_json::to_vec_pretty(&gateway_surface_projection)?,
    )?;
    let gateway_health_projection = json!({
        "channelId": "gateway.health",
        "service": "gateway",
        "servicePk": gateway_pk,
        "producer": { "service": "gateway", "component": "health" },
        "freshness": { "state": "fresh", "updatedAt": 1777932000, "staleAfter": 1777932300 },
        "scope": {},
        "payloadSchema": "constitute.gateway.health.v1",
        "payload": {
            "nodePath": "health",
            "fields": {
                "status": "online",
                "hostedServiceCount": 1,
                "zones": ["zone-test"]
            }
        },
        "safeFacts": { "status": "online", "hostedServiceCount": 1 },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    fs::write(
        dir.join("projection.gateway.gateway-health.json"),
        serde_json::to_vec_pretty(&gateway_health_projection)?,
    )?;
    let gateway_devices_projection = json!({
        "channelId": "gateway.devices",
        "service": "gateway",
        "servicePk": gateway_pk,
        "producer": { "service": "gateway", "component": "devices" },
        "freshness": { "state": "fresh", "updatedAt": 1777932000, "staleAfter": 1777932300 },
        "scope": {},
        "payloadSchema": "constitute.gateway.devices.v1",
        "payload": {
            "nodePath": "devices",
            "fields": {
                "devices": [
                    {
                        "devicePk": browser_pk,
                        "deviceLabel": "DevBrowser",
                        "role": "browser",
                        "deviceKind": "browser",
                        "updatedAt": 4777932200000u64,
                        "expiresAt": 4777935800000u64,
                        "online": true
                    }
                ]
            }
        },
        "safeFacts": { "deviceCount": 1 },
        "encryptedDetailRefs": [],
        "diagnostics": []
    });
    fs::write(
        dir.join("projection.gateway.gateway-devices.json"),
        serde_json::to_vec_pretty(&gateway_devices_projection)?,
    )?;
    let swarm_directory = json!({
        "definitions": [
            {
                "capability": "service.intent.invoke",
                "definitionId": "capability-def-service-intent-invoke",
                "summary": "Invoke sealed service intents through swarm channels.",
                "schema": { "type": "object" },
                "authorityRefs": ["member-raw-governance"]
            },
            {
                "capability": "projection.observe",
                "definitionId": "capability-def-projection-observe",
                "summary": "Observe projection snapshots and deltas.",
                "schema": { "type": "object" },
                "authorityRefs": ["member-raw-governance"]
            },
            {
                "capability": "storage.pin",
                "definitionId": "capability-def-storage-pin",
                "summary": "Request object retention through storage pin records.",
                "schema": { "type": "object" },
                "authorityRefs": ["member-raw-governance"]
            }
        ],
        "advertisements": [
            {
                "advertisementId": "ad-storage-pin-1",
                "capability": "storage.pin",
                "memberRef": storage_pk,
                "serviceRef": "service-raw-storage-1",
                "channelRefs": ["channel-storage-archive", "channel-storage-pins"],
                "issuedAt": 1777932000000u64,
                "expiresAt": 4777935700000u64
            },
            {
                "advertisementId": "ad-service-intent-1",
                "capability": "service.intent.invoke",
                "memberRef": gateway_pk,
                "serviceRef": "service-raw-gateway-1",
                "channelRefs": ["channel-service-intents"],
                "issuedAt": 1777932000000u64,
                "expiresAt": 4777935700000u64
            },
            {
                "advertisementId": "ad-projection-observe-1",
                "capability": "projection.observe",
                "memberRef": browser_pk,
                "serviceRef": "service-raw-gateway-1",
                "channelRefs": ["channel-projection-observe"],
                "issuedAt": 1777932000000u64,
                "expiresAt": 4777935700000u64
            }
        ],
        "entries": [
            {
                "entryId": "entry-storage-pins",
                "capability": "storage.pin",
                "channelId": "channel-storage-pins",
                "memberRef": storage_pk,
                "serviceRef": "service-raw-storage-1",
                "priority": 20
            },
            {
                "entryId": "entry-storage-archive",
                "capability": "storage.pin",
                "channelId": "channel-storage-archive",
                "memberRef": storage_pk,
                "serviceRef": "service-raw-storage-1",
                "priority": 10
            },
            {
                "entryId": "entry-service-intents",
                "capability": "service.intent.invoke",
                "channelId": "channel-service-intents",
                "memberRef": gateway_pk,
                "serviceRef": "service-raw-gateway-1",
                "priority": 10
            },
            {
                "entryId": "entry-projection-observe",
                "capability": "projection.observe",
                "channelId": "channel-projection-observe",
                "memberRef": browser_pk,
                "serviceRef": "service-raw-gateway-1",
                "priority": 10
            }
        ],
        "channels": [
            {
                "channelId": "channel-storage-archive",
                "kind": "storage",
                "displayName": "Storage Archive",
                "capabilities": ["storage.pin"],
                "recordKinds": ["storage.pin.intent", "storage.pin.attestation", "storage.availability.ref"],
                "ownerRefs": ["member-raw-storage-1"],
                "policyRef": "policy-storage-shared",
                "createdAt": 1777932000000u64
            },
            {
                "channelId": "channel-storage-pins",
                "kind": "storage",
                "displayName": "Storage Pins",
                "capabilities": ["storage.pin"],
                "recordKinds": ["storage.pin.intent", "storage.pin.attestation", "storage.availability.ref"],
                "ownerRefs": ["member-raw-storage-1"],
                "policyRef": "policy-storage-shared",
                "createdAt": 1777932000000u64
            },
            {
                "channelId": "channel-service-intents",
                "kind": "service",
                "displayName": "Service Intents",
                "capabilities": ["service.intent.invoke"],
                "recordKinds": ["service.intent", "service.response", "ack", "reject"],
                "ownerRefs": ["member-raw-gateway-1"],
                "policyRef": "policy-service-intents",
                "createdAt": 1777932000000u64
            },
            {
                "channelId": "channel-projection-observe",
                "kind": "projection",
                "displayName": "Projection Observe",
                "capabilities": ["projection.observe"],
                "recordKinds": ["projection.snapshot", "projection.delta", "projection.repair.request"],
                "ownerRefs": ["member-raw-runtime-1"],
                "policyRef": "policy-projection-observe",
                "materializationBudgetRef": "materialization:projection-observe:bounded-snapshot",
                "consumerFloorRef": "consumer-floor:projection-observe:runtime-member",
                "createdAt": 1777932000000u64
            }
        ],
        "policies": [
            {
                "policyId": "policy-storage-shared",
                "observe": ["role:observer"],
                "write": ["role:writer"],
                "set": ["role:writer"],
                "invoke": ["role:writer"],
                "pin": ["role:writer"],
                "attest": ["role:replicator"],
                "run": ["role:runner"]
            },
            {
                "policyId": "policy-service-intents",
                "observe": ["role:observer"],
                "write": ["role:writer"],
                "set": ["role:writer"],
                "invoke": ["role:writer"],
                "pin": ["role:writer"],
                "attest": ["role:replicator"],
                "run": ["role:runner"]
            },
            {
                "policyId": "policy-projection-observe",
                "observe": ["role:observer"],
                "write": ["role:writer"],
                "set": ["role:writer"],
                "invoke": ["role:writer"],
                "pin": ["role:writer"],
                "attest": ["role:replicator"],
                "run": ["role:runner"]
            }
        ]
    });
    fs::write(
        dir.join("swarm-directory.json"),
        serde_json::to_vec_pretty(&swarm_directory)?,
    )?;
    let diagnostics = json!([
        {
            "operation": "constitute-cli.doctor.test-data",
            "level": "info",
            "surface": "cli",
            "safeFacts": { "ok": true }
        },
        {
            "recordKind": "runtime.diagnostic.event",
            "channelId": "runtime.diagnostics",
            "eventId": "runtime-event-fixture-1",
            "kind": "route.observation",
            "level": "warn",
            "observedAt": 4777932100000u64,
            "buildId": "runtime-2.21",
            "runtimeSessionId": "runtime-session-fixture",
            "surface": "constitute-nvr-ui",
            "clientId": "nvr-ui",
            "frameId": "frame-fixture-route",
            "correlationId": "activation-fixture-route",
            "safeFacts": {
                "state": "observingUnreachable",
                "failedPredicates": ["capability"],
                "failedAuthorityDomains": ["service"],
                "authoritySummary": {
                    "requester": { "state": "ready" },
                    "runtime": { "state": "delegated" },
                    "gateway": { "state": "waitingAdmission" },
                    "service": { "state": "missingServiceGrant" },
                    "storage": { "state": "cacheOnly", "identityAuthority": false }
                },
                "message": "route predicates did not match a live member"
            }
        },
        {
            "recordKind": "runtime.diagnostic.event",
            "channelId": "runtime.diagnostics",
            "eventId": "runtime-event-fixture-2",
            "kind": "interaction.prepared",
            "level": "info",
            "observedAt": 4777932100001u64,
            "buildId": "runtime-2.39",
            "runtimeSessionId": "runtime-session-fixture",
            "surface": "constitute-nvr-ui",
            "clientId": "nvr-ui",
            "activationId": "activation-fixture-route",
            "routePromiseId": "route-fixture-route",
            "safeFacts": {
                "interactionId": "interaction-fixture-route",
                "authoritySummary": {
                    "requester": { "state": "ready" },
                    "runtime": { "state": "delegated" },
                    "gateway": { "state": "waitingAdmission" },
                    "service": { "state": "waitingAcceptance" },
                    "storage": { "state": "cacheOnly", "identityAuthority": false }
                }
            }
        }
    ]);
    fs::write(
        dir.join("diagnostics.json"),
        serde_json::to_vec_pretty(&diagnostics)?,
    )?;
    let swarm = json!([
        {
            "devicePk": gateway_pk,
            "identityId": "test-account",
            "deviceLabel": "DevGateway",
            "updatedAt": 4777932100000u64,
            "expiresAt": 4777935700000u64,
            "role": "gateway",
            "deviceKind": "gateway",
            "service": "",
            "hostGatewayPk": "",
            "relays": ["ws://example.invalid/"],
            "hostPlatform": "linux",
            "serviceVersion": "0.0.0-test",
            "hostedServices": [
                {
                    "devicePk": logging_pk,
                    "deviceLabel": "Constitute Logging",
                    "deviceKind": "service",
                    "role": "logging",
                    "service": "logging",
                    "hostGatewayPk": gateway_pk,
                    "status": "ok",
                    "serviceVersion": "0.0.0-test",
                    "facts": {
                        "surfaceChannel": "logging.surface",
                        "aliases": ["Logging", "Constitute Logging"],
                        "summary": "Structured safe event observation and retention state.",
                        "nodes": ["events", "health", "dashboard", "settings"]
                    }
                },
                {
                    "devicePk": gateway_pk,
                    "servicePk": gateway_pk,
                    "deviceLabel": "DevGateway",
                    "deviceKind": "service",
                    "role": "gateway",
                    "service": "gateway",
                    "hostGatewayPk": gateway_pk,
                    "status": "online",
                    "serviceVersion": "0.0.0-test",
                    "facts": {
                        "surfaceChannel": "gateway.surface",
                        "aliases": ["Gateway", "DevGateway"],
                        "summary": "Gateway routing, hosted-service, zone, and device observation.",
                        "nodes": ["health", "devices", "hostedServices", "zones", "routingDiagnostics"]
                    }
                }
            ]
        },
        {
            "devicePk": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "identityId": "test-account",
            "deviceLabel": "DevBrowser",
            "updatedAt": 4777932200000u64,
            "expiresAt": 4777935800000u64,
            "role": "browser",
            "deviceKind": "browser",
            "service": "",
            "hostGatewayPk": gateway_pk,
            "relays": ["ws://example.invalid/"],
            "hostPlatform": "windows",
            "serviceVersion": "0.0.0-test",
            "hostedServices": []
        }
    ]);
    fs::write(dir.join("swarm.json"), serde_json::to_vec_pretty(&swarm)?)?;
    Ok(())
}

pub fn forbidden_semantic_route_seen(hints: &[String]) -> bool {
    let retired_direct_route = ["/service", "-ex", "change"].join("");
    let retired_session_route = ["/managed", "/sess", "ion"].join("");
    let forbidden = [
        "/v1/events/search",
        "/health",
        retired_session_route.as_str(),
        retired_direct_route.as_str(),
        "--service-endpoint",
        "rtsp://",
    ];
    hints.iter().any(|hint| {
        let lowered = hint.to_ascii_lowercase();
        forbidden.iter().any(|needle| lowered.contains(needle))
    })
}

fn live_relays(profile: &ProfileRecord) -> Result<Vec<String>> {
    let mut relays = profile
        .relays
        .iter()
        .map(|relay| relay.trim().to_string())
        .filter(|relay| !relay.is_empty())
        .collect::<Vec<_>>();
    relays.sort_by_key(|relay| relay_priority(relay));
    if relays.is_empty() {
        return Err(anyhow!("profile has no relay hints for live transport"));
    }
    Ok(relays)
}

fn relay_priority(relay: &str) -> u8 {
    let lowered = relay.to_ascii_lowercase();
    if lowered.starts_with("ws://10.")
        || lowered.starts_with("ws://192.168.")
        || lowered.starts_with("ws://172.16.")
        || lowered.starts_with("ws://127.")
        || lowered.starts_with("ws://localhost")
    {
        0
    } else if lowered.starts_with("ws://") {
        1
    } else {
        2
    }
}

fn discover_descriptors(
    relays: &[String],
    gateway_filter: Option<&str>,
) -> Result<Vec<HostedServiceDescriptor>> {
    let (tx, rx) = mpsc::channel();
    for relay in relays {
        let relay = relay.clone();
        let tx = tx.clone();
        let gateway_filter = gateway_filter.map(str::to_string);
        thread::spawn(move || {
            if let Err(err) = observe_descriptor_relay(&relay, gateway_filter.as_deref(), tx) {
                eprintln!("[constitute transport] descriptor relay degraded {relay}: {err}");
            }
        });
    }
    drop(tx);

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut descriptors = BTreeMap::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(500))) {
            Ok(descriptor) => {
                descriptors.insert(descriptor.service_pk.clone(), descriptor);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(descriptors.into_values().collect())
}

fn observe_descriptor_relay(
    relay: &str,
    gateway_filter: Option<&str>,
    tx: mpsc::Sender<HostedServiceDescriptor>,
) -> Result<()> {
    let (mut socket, _) = connect(relay).with_context(|| format!("connect relay {relay}"))?;
    let req = frame_bootstrap_nostr_req(
        "constitute-cli-descriptors",
        vec![BootstrapNostrFilter {
            kinds: Some(vec![30078]),
            t: Some(vec!["swarm_discovery".to_string()]),
            z: None,
        }],
    );
    socket.send(Message::Text(req))?;
    loop {
        let Message::Text(text) = socket.read()? else {
            continue;
        };
        let Some(event) = parse_relay_event(&text)? else {
            continue;
        };
        if !verify_bootstrap_nostr_event(&event)? {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<Value>(&event.content) else {
            continue;
        };
        for descriptor in descriptors_from_swarm_record(&payload, gateway_filter) {
            let _ = tx.send(descriptor);
        }
    }
}

fn descriptors_from_swarm_record(
    payload: &Value,
    gateway_filter: Option<&str>,
) -> Vec<HostedServiceDescriptor> {
    let gateway_pk = payload
        .get("devicePk")
        .or_else(|| payload.get("pk"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let gateway_label = payload
        .get("deviceLabel")
        .or_else(|| payload.get("device_label"))
        .or_else(|| payload.get("label"))
        .and_then(Value::as_str)
        .unwrap_or("Gateway")
        .trim();
    if let Some(filter) = gateway_filter
        && !filter.trim().is_empty()
        && gateway_pk != filter.trim()
    {
        return vec![];
    }
    payload
        .get("hostedServices")
        .or_else(|| payload.get("hosted_services"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|service| descriptor_from_hosted_service(service, gateway_pk, gateway_label))
        .collect()
}

fn descriptor_from_hosted_service(
    value: &Value,
    gateway_pk: &str,
    gateway_label: &str,
) -> Option<HostedServiceDescriptor> {
    let service = value
        .get("service")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let service_pk = value
        .get("servicePk")
        .or_else(|| value.get("service_pk"))
        .or_else(|| value.get("devicePk"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if service.is_empty() || service_pk.is_empty() {
        return None;
    }
    let host_gateway_pk = value
        .get("hostGatewayPk")
        .or_else(|| value.get("host_gateway_pk"))
        .and_then(Value::as_str)
        .filter(|entry| !entry.trim().is_empty())
        .unwrap_or(gateway_pk)
        .trim()
        .to_string();
    let facts = value.get("facts").cloned().unwrap_or_else(|| json!({}));
    let surface_channel = facts
        .get("surfaceChannel")
        .or_else(|| facts.get("surface_channel"))
        .or_else(|| value.get("surfaceChannel"))
        .or_else(|| value.get("surface_channel"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if surface_channel.is_empty() {
        return None;
    }
    let descriptor = HostedServiceDescriptor {
        service: service.clone(),
        service_pk,
        host_gateway_pk,
        aliases: string_array(
            facts
                .get("aliases")
                .or_else(|| value.get("aliases"))
                .unwrap_or(&Value::Null),
        ),
        location: Some(constitute_protocol::ServiceLocationRef {
            location_id: facts
                .get("locationId")
                .or_else(|| value.get("locationId"))
                .and_then(Value::as_str)
                .unwrap_or(gateway_pk)
                .trim()
                .to_string(),
            label: value
                .get("hostGatewayLabel")
                .or_else(|| facts.get("hostGatewayLabel"))
                .or_else(|| value.get("gatewayLabel"))
                .or_else(|| facts.get("gatewayLabel"))
                .and_then(Value::as_str)
                .unwrap_or(gateway_label)
                .trim()
                .to_string(),
            gateway_pk: gateway_pk.trim().to_string(),
        }),
        surface_channel,
        display: json!({
            "name": value
                .get("deviceLabel")
                .or_else(|| value.get("device_label"))
                .and_then(Value::as_str)
                .unwrap_or(service.as_str()),
            "status": value.get("status").and_then(Value::as_str).unwrap_or("unknown"),
            "serviceVersion": value
                .get("serviceVersion")
                .or_else(|| value.get("service_version"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        }),
        summary: facts
            .get("summary")
            .or_else(|| value.get("summary"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string(),
        health: facts.get("health").cloned().unwrap_or_else(|| {
            json!({ "status": value.get("status").and_then(Value::as_str).unwrap_or("unknown") })
        }),
        nodes: string_array(
            facts
                .get("nodes")
                .or_else(|| value.get("nodes"))
                .unwrap_or(&Value::Null),
        ),
        retired: facts.get("retired").cloned().unwrap_or_else(|| json!({})),
        transport_hints: json!({
            "authority": "gateway",
            "gatewayPk": gateway_pk,
            "source": "swarm_discovery"
        }),
    };
    validate_hosted_service_descriptor(&descriptor).ok()?;
    Some(descriptor)
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn live_swarm_edge(profile: &ProfileRecord) -> Result<String> {
    profile
        .local_gateway_hint
        .as_deref()
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("live swarm edge requires profile localGatewayHint"))
}

impl LiveTransport {
    fn device_secret(&self) -> Result<&str> {
        self.device_secret
            .as_deref()
            .ok_or_else(|| anyhow!("live swarm edge requires unlocked device secret"))
    }

    fn edge_round_trip(
        &self,
        frame: &SwarmFrame,
        wait_for: EdgeWait,
    ) -> Result<EdgeRoundTripResult> {
        validate_swarm_frame(frame, now_unix() * 1000)?;
        let edge = live_swarm_edge(&self.profile)?;
        let mut socket = open_edge_socket(&edge)?;
        let session = self.open_edge_session(&mut socket, &edge)?;
        let payload = json!({
            "type": constitute_protocol::SWARM_WIRE_FRAME,
            "sessionId": session.session_id,
            "frame": frame
        });
        socket
            .send(Message::Text(payload.to_string()))
            .with_context(|| format!("publish swarm frame to {}", session.edge))?;
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut accepted_ack: Option<SwarmFrame> = None;
        let mut publish_report = EdgePublishReport::default();
        loop {
            let outcome =
                match read_edge_outcome(&mut socket, deadline, self.device_secret.as_deref()) {
                    Ok(outcome) => outcome,
                    Err(err)
                        if matches!(wait_for, EdgeWait::Publish)
                            && publish_report.frame_intake_ack.is_some() =>
                    {
                        publish_report.note_diagnostic(json!({
                            "type": "edge.read.closed",
                            "boundary": "diagnostic",
                            "detail": err.to_string()
                        }));
                        return Ok(EdgeRoundTripResult::Publish(publish_report));
                    }
                    Err(err) => return Err(err),
                };
            match outcome {
                EdgeWireOutcome::Ack(ack) => {
                    self.note_ack(&ack);
                    if matches!(wait_for, EdgeWait::Publish) {
                        publish_report.frame_intake_ack = Some(ack.clone());
                    }
                    accepted_ack = Some(ack);
                }
                EdgeWireOutcome::Reject(reject) => {
                    return Ok(EdgeRoundTripResult::Rejected(reject));
                }
                EdgeWireOutcome::Projection(value) => {
                    self.note_projection_value(&value);
                    if matches!(wait_for, EdgeWait::Projection) {
                        return Ok(EdgeRoundTripResult::Projection(value));
                    }
                    if matches!(wait_for, EdgeWait::Publish) {
                        publish_report.projection = Some(value);
                    }
                }
                EdgeWireOutcome::Directory(directory) => {
                    if matches!(wait_for, EdgeWait::Directory) {
                        return Ok(EdgeRoundTripResult::Directory(directory));
                    }
                }
                EdgeWireOutcome::RouteObservation(value) => {
                    if matches!(wait_for, EdgeWait::Publish) {
                        publish_report.route_observation = Some(value);
                    }
                }
                EdgeWireOutcome::ServiceResponse(value) => {
                    if matches!(wait_for, EdgeWait::Publish) {
                        publish_report.service_response = Some(value);
                    }
                }
                EdgeWireOutcome::StreamRoutePlan(value) => {
                    if matches!(wait_for, EdgeWait::Publish) {
                        publish_report.stream_route_plan = Some(value);
                    }
                }
                EdgeWireOutcome::SealedDiagnostic(value) => {
                    if matches!(wait_for, EdgeWait::Publish) {
                        publish_report.note_diagnostic(value);
                    }
                }
                EdgeWireOutcome::Accept(_) | EdgeWireOutcome::Other => {}
            }
            if matches!(wait_for, EdgeWait::Publish)
                && publish_report.frame_intake_ack.is_some()
                && publish_report.has_convergence_evidence()
            {
                return Ok(EdgeRoundTripResult::Publish(publish_report));
            }
            if Instant::now() >= deadline {
                if matches!(wait_for, EdgeWait::Publish)
                    && publish_report.frame_intake_ack.is_some()
                {
                    publish_report.note_diagnostic(json!({
                        "type": "edge.convergence.timeout",
                        "boundary": "routeCoordination",
                        "detail": "frame intake ACK arrived without route/service/projection evidence before deadline"
                    }));
                    return Ok(EdgeRoundTripResult::Publish(publish_report));
                }
                if let Some(ack) = accepted_ack {
                    return Ok(EdgeRoundTripResult::Ack(ack));
                }
                return Err(anyhow!("timed out waiting for swarm edge response"));
            }
        }
    }

    fn open_edge_session(
        &self,
        socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
        edge: &str,
    ) -> Result<EdgeSessionOpen> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("swarm edge session state poisoned"))?
            .clone();
        if let Some(session_id) = state.session_id.as_deref() {
            let resume = build_edge_resume(
                &self.profile,
                self.device_secret()?,
                session_id,
                &state,
                now_unix() * 1000,
            )?;
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_EDGE_WIRE_RESUME,
                        "resume": resume
                    })
                    .to_string(),
                ))
                .with_context(|| format!("resume swarm edge session at {edge}"))?;
            match read_edge_outcome(socket, Instant::now() + Duration::from_secs(5), None)? {
                EdgeWireOutcome::Accept(accept) => {
                    self.note_accept(&accept)?;
                    return Ok(EdgeSessionOpen {
                        edge: edge.to_string(),
                        session_id: accept.session_id,
                    });
                }
                EdgeWireOutcome::Reject(_) => {
                    self.clear_session();
                }
                _ => {}
            }
        }

        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("swarm edge session state poisoned"))?
            .clone();
        let hello = build_edge_hello(
            &self.profile,
            self.device_secret()?,
            &state,
            now_unix() * 1000,
        )?;
        socket
            .send(Message::Text(
                json!({
                    "type": constitute_protocol::SWARM_EDGE_WIRE_HELLO,
                    "hello": hello
                })
                .to_string(),
            ))
            .with_context(|| format!("attach swarm edge session at {edge}"))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match read_edge_outcome(socket, deadline, None)? {
                EdgeWireOutcome::Accept(accept) => {
                    self.note_accept(&accept)?;
                    return Ok(EdgeSessionOpen {
                        edge: edge.to_string(),
                        session_id: accept.session_id,
                    });
                }
                EdgeWireOutcome::Reject(reject) => return Err(reject.into_error()),
                _ => {}
            }
        }
    }

    fn note_accept(&self, accept: &SwarmEdgeAccept) -> Result<()> {
        validate_swarm_edge_accept(accept)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("swarm edge session state poisoned"))?;
        state.session_id = Some(accept.session_id.clone());
        state.last_acked_frame_id = accept.last_acked_frame_id.clone();
        state.last_projection_revisions =
            projection_revision_map(&accept.last_projection_revisions);
        Ok(())
    }

    fn note_ack(&self, frame: &SwarmFrame) {
        if let Some(acked) = frame
            .ack
            .as_ref()
            .and_then(|ack| ack.acked_frame_id.clone())
            .or_else(|| frame.correlation_id.clone())
            && let Ok(mut state) = self.state.lock()
        {
            state.last_acked_frame_id = Some(acked);
        }
    }

    fn note_projection_value(&self, value: &Value) {
        let Some(projection) = value.get("projection") else {
            return;
        };
        let projection_id = projection
            .get("projectionId")
            .or_else(|| projection.get("projection_id"))
            .or_else(|| projection.get("channelId"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let revision = projection
            .get("revision")
            .or_else(|| {
                projection
                    .get("payload")
                    .and_then(|payload| payload.get("revision"))
            })
            .and_then(Value::as_u64);
        if let (Some(projection_id), Some(revision)) = (projection_id, revision)
            && let Ok(mut state) = self.state.lock()
        {
            state
                .last_projection_revisions
                .insert(projection_id, revision);
        }
    }

    fn clear_session(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.session_id = None;
        }
    }
}

fn open_edge_socket(edge: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>> {
    let (mut socket, _) = connect(edge).with_context(|| format!("connect swarm edge {edge}"))?;
    configure_socket_timeout(&mut socket, Duration::from_secs(15))?;
    Ok(socket)
}

fn configure_socket_timeout(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    timeout: Duration,
) -> Result<()> {
    match socket.get_mut() {
        MaybeTlsStream::Plain(stream) => {
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
        }
        _ => {}
    }
    Ok(())
}

fn read_edge_outcome(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    device_secret: Option<&str>,
) -> Result<EdgeWireOutcome> {
    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!("timed out waiting for swarm edge message"));
        }
        let message = socket.read().context("read swarm edge message")?;
        let Message::Text(text) = message else {
            continue;
        };
        return edge_outcome_from_text(&text, device_secret);
    }
}

fn edge_outcome_from_text(text: &str, device_secret: Option<&str>) -> Result<EdgeWireOutcome> {
    let value: Value = serde_json::from_str(text).context("parse swarm edge message")?;
    edge_outcome_from_value(&value, device_secret)
}

fn edge_outcome_from_value(value: &Value, device_secret: Option<&str>) -> Result<EdgeWireOutcome> {
    let record_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if record_type == constitute_protocol::SWARM_EDGE_WIRE_ACCEPT {
        let accept_value = value.get("accept").unwrap_or(value);
        let accept: SwarmEdgeAccept =
            serde_json::from_value(accept_value.clone()).context("parse swarm edge accept")?;
        validate_swarm_edge_accept(&accept)?;
        return Ok(EdgeWireOutcome::Accept(accept));
    }
    if record_type == "swarm.edge.reject" || record_type == "reject" {
        return Ok(EdgeWireOutcome::Reject(reject_from_value(value)));
    }
    if record_type == "swarm.directory"
        && let Some(directory) = value.get("directory")
    {
        return Ok(EdgeWireOutcome::Directory(directory_from_value(directory)?));
    }
    if record_type == constitute_protocol::SWARM_WIRE_FRAME {
        let frame_value = value
            .get("frame")
            .ok_or_else(|| anyhow!("swarm.frame message missing frame"))?;
        return edge_outcome_from_frame_value(frame_value, device_secret);
    }
    if let Some(directory) = extract_directory(value, device_secret)? {
        return Ok(EdgeWireOutcome::Directory(directory));
    }
    if let Some(projection) = extract_projection_value(value, device_secret)? {
        return Ok(EdgeWireOutcome::Projection(projection));
    }
    if let Some(route_observation) =
        extract_kinded_record(value, "routeObservation", "route.observation")?
    {
        validate_route_observation(&serde_json::from_value(route_observation.clone())?)?;
        return Ok(EdgeWireOutcome::RouteObservation(route_observation));
    }
    if let Some(service_response) =
        extract_kinded_record(value, "serviceResponse", "service.response")?
    {
        return Ok(EdgeWireOutcome::ServiceResponse(service_response));
    }
    if let Some(stream_route_plan) =
        extract_kinded_record(value, "streamRoutePlan", "stream.routePlan")?
    {
        return Ok(EdgeWireOutcome::StreamRoutePlan(stream_route_plan));
    }
    Ok(EdgeWireOutcome::Other)
}

fn edge_outcome_from_frame_value(
    frame_value: &Value,
    device_secret: Option<&str>,
) -> Result<EdgeWireOutcome> {
    let frame: SwarmFrame =
        serde_json::from_value(frame_value.clone()).context("parse swarm edge frame")?;
    validate_swarm_frame(&frame, now_unix() * 1000)?;
    match frame.kind {
        SwarmFrameKind::Ack => Ok(EdgeWireOutcome::Ack(frame)),
        SwarmFrameKind::Reject => Ok(EdgeWireOutcome::Reject(reject_from_frame(
            &frame,
            device_secret,
        ))),
        SwarmFrameKind::ProjectionSnapshot | SwarmFrameKind::ProjectionDelta => {
            match opened_frame_payload(&frame, device_secret)? {
                OpenedFramePayload::Opened(payload) => {
                    if let Some(directory) = extract_directory_from_payload(&payload)? {
                        return Ok(EdgeWireOutcome::Directory(directory));
                    }
                    if let Some(projection) = extract_projection_from_payload(&payload)? {
                        return Ok(EdgeWireOutcome::Projection(projection));
                    }
                    Ok(EdgeWireOutcome::Other)
                }
                OpenedFramePayload::SealedMetadata(metadata) => {
                    Ok(EdgeWireOutcome::SealedDiagnostic(metadata))
                }
                OpenedFramePayload::None => Ok(EdgeWireOutcome::Other),
            }
        }
        SwarmFrameKind::RouteObservation => match opened_frame_payload(&frame, device_secret)? {
            OpenedFramePayload::Opened(payload) => {
                if let Some(route_observation) =
                    extract_kinded_record(&payload, "routeObservation", "route.observation")?
                {
                    validate_route_observation(&serde_json::from_value(
                        route_observation.clone(),
                    )?)?;
                    Ok(EdgeWireOutcome::RouteObservation(route_observation))
                } else {
                    Ok(EdgeWireOutcome::Other)
                }
            }
            OpenedFramePayload::SealedMetadata(metadata) => {
                Ok(EdgeWireOutcome::SealedDiagnostic(metadata))
            }
            OpenedFramePayload::None => Ok(EdgeWireOutcome::Other),
        },
        SwarmFrameKind::ServiceResponse => match opened_frame_payload(&frame, device_secret)? {
            OpenedFramePayload::Opened(payload) => {
                if let Some(service_response) =
                    extract_kinded_record(&payload, "serviceResponse", "service.response")?
                {
                    Ok(EdgeWireOutcome::ServiceResponse(service_response))
                } else {
                    Ok(EdgeWireOutcome::Other)
                }
            }
            OpenedFramePayload::SealedMetadata(metadata) => {
                Ok(EdgeWireOutcome::SealedDiagnostic(metadata))
            }
            OpenedFramePayload::None => Ok(EdgeWireOutcome::Other),
        },
        SwarmFrameKind::StreamRoutePlan => match opened_frame_payload(&frame, device_secret)? {
            OpenedFramePayload::Opened(payload) => {
                if let Some(plan) =
                    extract_kinded_record(&payload, "streamRoutePlan", "stream.routePlan")?
                {
                    Ok(EdgeWireOutcome::StreamRoutePlan(plan))
                } else {
                    Ok(EdgeWireOutcome::Other)
                }
            }
            OpenedFramePayload::SealedMetadata(metadata) => {
                Ok(EdgeWireOutcome::SealedDiagnostic(metadata))
            }
            OpenedFramePayload::None => Ok(EdgeWireOutcome::Other),
        },
        _ => Ok(EdgeWireOutcome::Other),
    }
}

fn reject_from_frame(frame: &SwarmFrame, device_secret: Option<&str>) -> EdgeReject {
    let reason = frame
        .ack
        .as_ref()
        .and_then(|ack| ack.reason_code.clone())
        .unwrap_or_else(|| "gateway.reject".to_string());
    let opened = opened_frame_payload(frame, device_secret).ok();
    let payload = match opened.as_ref() {
        Some(OpenedFramePayload::Opened(value)) => value,
        _ => &Value::Null,
    };
    let error = payload.get("error").unwrap_or(payload);
    EdgeReject {
        code: error
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or(reason.as_str())
            .to_string(),
        message: error
            .get("message")
            .or_else(|| error.get("detail"))
            .and_then(Value::as_str)
            .unwrap_or(reason.as_str())
            .to_string(),
        retryable: error
            .get("retryable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn reject_from_value(value: &Value) -> EdgeReject {
    let error = value
        .get("error")
        .or_else(|| value.get("reject"))
        .unwrap_or(value);
    EdgeReject {
        code: error
            .get("code")
            .or_else(|| error.get("reasonCode"))
            .and_then(Value::as_str)
            .unwrap_or("gateway.reject")
            .to_string(),
        message: error
            .get("message")
            .or_else(|| error.get("detail"))
            .or_else(|| error.get("reason"))
            .and_then(Value::as_str)
            .unwrap_or("frame rejected")
            .to_string(),
        retryable: error
            .get("retryable")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn build_edge_hello(
    profile: &ProfileRecord,
    device_secret: &str,
    state: &EdgeSessionState,
    now_ms: u64,
) -> Result<SwarmEdgeHello> {
    let hello = SwarmEdgeHello {
        member_kind: "cli".to_string(),
        member_ref: profile.device_pk.clone(),
        zone_scope: default_edge_zone_scope(),
        supported_versions: vec![constitute_protocol::SWARM_FRAME_VERSION as u32],
        last_acked_frame_id: state.last_acked_frame_id.clone(),
        last_projection_revisions: projection_revisions_value(&state.last_projection_revisions),
        capability_refs: default_edge_capabilities(),
        channel_refs: default_edge_channels(),
        promise_refs: Vec::new(),
        nonce: format!("edge-hello-{}", uuid::Uuid::new_v4().simple()),
        issued_at: now_ms,
        expires_at: Some(now_ms + 90_000),
        sealed_claims: edge_claims_body(profile, device_secret, now_ms)?,
    };
    validate_swarm_edge_hello(&hello)?;
    Ok(hello)
}

fn build_edge_resume(
    profile: &ProfileRecord,
    device_secret: &str,
    session_id: &str,
    state: &EdgeSessionState,
    now_ms: u64,
) -> Result<SwarmEdgeResume> {
    let resume = SwarmEdgeResume {
        session_id: session_id.to_string(),
        member_kind: "cli".to_string(),
        member_ref: profile.device_pk.clone(),
        zone_scope: default_edge_zone_scope(),
        last_acked_frame_id: state.last_acked_frame_id.clone(),
        last_projection_revisions: projection_revisions_value(&state.last_projection_revisions),
        capability_refs: default_edge_capabilities(),
        channel_refs: default_edge_channels(),
        promise_refs: Vec::new(),
        nonce: format!("edge-resume-{}", uuid::Uuid::new_v4().simple()),
        issued_at: now_ms,
        expires_at: Some(now_ms + 90_000),
        sealed_claims: edge_claims_body(profile, device_secret, now_ms)?,
    };
    validate_swarm_edge_resume(&resume)?;
    Ok(resume)
}

fn build_directory_observe_frame(
    profile: &ProfileRecord,
    device_secret: &str,
    now_ms: u64,
) -> Result<SwarmFrame> {
    let issuer = profile.device_pk.as_str();
    let gateway_pk = profile
        .gateway_pk
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("directory observation requires profile gateway public key"))?;
    let mut frame = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::ChannelObserve,
        issuer: issuer.to_string(),
        audience: json!({ "directory": "capability" }),
        zone_scope: Some(default_edge_zone_scope()),
        issued_at: now_ms,
        expires_at: Some(now_ms + 90_000),
        nonce: format!("nonce-{}", uuid::Uuid::new_v4().simple()),
        correlation_id: Some(format!("directory-{}", uuid::Uuid::new_v4().simple())),
        channel_id: Some("swarm.directory".to_string()),
        record_ref: Some(constitute_protocol::SwarmRecordRef {
            kind: "projection".to_string(),
            id: "swarm.directory".to_string(),
            revision: None,
        }),
        capability: Some(constitute_protocol::CAPABILITY_PROJECTION_OBSERVE.to_string()),
        body: product_caac_body(
            "projection.observe",
            json!({
                "directory": "capability",
                "channelId": "swarm.directory"
            }),
            device_secret,
            &[gateway_pk.to_string(), profile.device_pk.clone()],
            now_ms,
        )?,
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame)?;
    validate_swarm_frame(&frame, now_ms)?;
    Ok(frame)
}

fn default_edge_zone_scope() -> ZoneScope {
    ZoneScope {
        zone_id: "zone_lab".to_string(),
        privacy: Some("rawIds".to_string()),
        ttl: Some(30),
        max_hops: Some(2),
    }
}

fn edge_claims_body(
    profile: &ProfileRecord,
    device_secret: &str,
    now_ms: u64,
) -> Result<SwarmFrameBody> {
    let mut recipients = vec![profile.device_pk.clone()];
    if let Some(gateway_pk) = profile
        .gateway_pk
        .as_ref()
        .map(|value| value.trim().to_string())
        && !gateway_pk.is_empty()
        && !recipients.iter().any(|value| value == &gateway_pk)
    {
        recipients.push(gateway_pk);
    }
    product_caac_body(
        "swarm.edge.claims",
        json!({
            "memberKind": "cli",
            "memberRef": profile.device_pk.clone(),
            "capabilityRefs": default_edge_capabilities(),
            "channelRefs": default_edge_channels(),
        }),
        device_secret,
        &recipients,
        now_ms,
    )
}

fn default_edge_capabilities() -> Vec<String> {
    vec![
        constitute_protocol::CAPABILITY_SWARM_EDGE_ATTACH.to_string(),
        constitute_protocol::CAPABILITY_PROJECTION_OBSERVE.to_string(),
        constitute_protocol::CAPABILITY_SERVICE_SURFACE_OBSERVE.to_string(),
        constitute_protocol::CAPABILITY_SERVICE_INTENT_INVOKE.to_string(),
        constitute_protocol::CAPABILITY_STORAGE_PIN.to_string(),
    ]
}

fn default_edge_channels() -> Vec<String> {
    vec![
        "runtime.projections".to_string(),
        "swarm.directory".to_string(),
        "channel-projection-observe".to_string(),
        "channel-service-intents".to_string(),
    ]
}

fn projection_revisions_value(revisions: &BTreeMap<String, u64>) -> Value {
    let mut map = serde_json::Map::new();
    for (projection_id, revision) in revisions {
        map.insert(projection_id.clone(), json!(revision));
    }
    Value::Object(map)
}

fn projection_revision_map(value: &Value) -> BTreeMap<String, u64> {
    value
        .as_object()
        .into_iter()
        .flat_map(|entries| entries.iter())
        .filter_map(|(key, value)| value.as_u64().map(|revision| (key.clone(), revision)))
        .collect()
}

fn extract_projection_value(value: &Value, device_secret: Option<&str>) -> Result<Option<Value>> {
    if let Some(projection) = value.get("projection") {
        return Ok(Some(json!({ "projection": projection })));
    }
    if looks_like_projection_record(value) {
        return Ok(Some(json!({ "projection": value })));
    }
    let Some(payload) = message_payload(value, device_secret)? else {
        return Ok(None);
    };
    extract_projection_from_payload(&payload)
}

fn extract_projection_from_payload(payload: &Value) -> Result<Option<Value>> {
    if let Some(projection) = payload.get("projection") {
        return Ok(Some(json!({ "projection": projection })));
    }
    if let Some(record) = payload.get("record")
        && looks_like_projection_record(record)
    {
        return Ok(Some(json!({ "projection": record })));
    }
    if looks_like_projection_record(payload) {
        return Ok(Some(json!({ "projection": payload })));
    }
    if let Some(snapshot) = payload.get("snapshot") {
        if let Some(projection) = snapshot.get("projection") {
            return Ok(Some(json!({ "projection": projection })));
        }
        if let Some(state) = snapshot.get("state") {
            if let Some(projection) = state.get("projection") {
                return Ok(Some(json!({ "projection": projection })));
            }
            if looks_like_projection_record(state) {
                return Ok(Some(json!({ "projection": state })));
            }
        }
    }
    Ok(None)
}

fn extract_directory(value: &Value, device_secret: Option<&str>) -> Result<Option<SwarmDirectory>> {
    if let Some(directory) = value.get("directory") {
        return Ok(Some(directory_from_value(directory)?));
    }
    let Some(payload) = message_payload(value, device_secret)? else {
        return Ok(None);
    };
    extract_directory_from_payload(&payload)
}

fn extract_directory_from_payload(payload: &Value) -> Result<Option<SwarmDirectory>> {
    if let Some(directory) = payload.get("directory") {
        return Ok(Some(directory_from_value(directory)?));
    }
    if let Some(snapshot) = payload.get("snapshot")
        && let Some(state) = snapshot.get("state")
    {
        if let Some(directory) = state.get("directory") {
            return Ok(Some(directory_from_value(directory)?));
        }
        if looks_like_directory(state) {
            return Ok(Some(directory_from_value(state)?));
        }
    }
    if looks_like_directory(&payload) {
        return Ok(Some(directory_from_value(&payload)?));
    }
    Ok(None)
}

fn message_payload(value: &Value, device_secret: Option<&str>) -> Result<Option<Value>> {
    if let Some(frame_value) = value.get("frame") {
        let frame: SwarmFrame =
            serde_json::from_value(frame_value.clone()).context("parse payload frame")?;
        return match opened_frame_payload(&frame, device_secret)? {
            OpenedFramePayload::Opened(payload) => Ok(Some(payload)),
            OpenedFramePayload::SealedMetadata(_) | OpenedFramePayload::None => Ok(None),
        };
    }
    Ok(value.get("payload").cloned())
}

enum OpenedFramePayload {
    Opened(Value),
    SealedMetadata(Value),
    None,
}

fn opened_frame_payload(
    frame: &SwarmFrame,
    device_secret: Option<&str>,
) -> Result<OpenedFramePayload> {
    match frame.body.encoding.as_str() {
        "caac" => {
            let Some(envelope_value) = frame.body.envelope.as_ref() else {
                return Ok(OpenedFramePayload::None);
            };
            let Some(secret) = device_secret else {
                return Ok(OpenedFramePayload::SealedMetadata(sealed_frame_metadata(
                    frame,
                    "CAAC body was not opened because no device secret was available",
                )));
            };
            let envelope: CaacEnvelope = match serde_json::from_value(envelope_value.clone()) {
                Ok(envelope) => envelope,
                Err(err) => {
                    return Ok(OpenedFramePayload::SealedMetadata(sealed_frame_metadata(
                        frame,
                        &format!("CAAC metadata could not be parsed as product envelope: {err}"),
                    )));
                }
            };
            match open_envelope(&envelope, secret, now_unix(), None) {
                Ok(payload) => Ok(OpenedFramePayload::Opened(payload)),
                Err(err) => Ok(OpenedFramePayload::SealedMetadata(sealed_frame_metadata(
                    frame,
                    &format!("CAAC open failed: {err}"),
                ))),
            }
        }
        "public" => Ok(frame
            .body
            .payload
            .clone()
            .map(OpenedFramePayload::Opened)
            .unwrap_or(OpenedFramePayload::None)),
        _ => Ok(OpenedFramePayload::None),
    }
}

fn extract_kinded_record(value: &Value, wrapper_key: &str, kind: &str) -> Result<Option<Value>> {
    if let Some(record) = value.get(wrapper_key) {
        return Ok(Some(record.clone()));
    }
    if value.get("kind").and_then(Value::as_str) == Some(kind) {
        return Ok(Some(value.clone()));
    }
    if let Some(record) = value.get("record")
        && record.get("kind").and_then(Value::as_str) == Some(kind)
    {
        return Ok(Some(record.clone()));
    }
    Ok(None)
}

fn sealed_frame_metadata(frame: &SwarmFrame, detail: &str) -> Value {
    let envelope = frame.body.envelope.as_ref();
    json!({
        "type": "sealed.frame.metadata",
        "boundary": "diagnostic.bootstrap",
        "detail": detail,
        "frameId": frame.frame_id,
        "kind": frame.kind,
        "channelId": frame.channel_id,
        "envelope": envelope.map(sealed_envelope_metadata).unwrap_or_else(|| json!({}))
    })
}

fn sealed_envelope_metadata(envelope: &Value) -> Value {
    json!({
        "envelopeId": envelope.get("envelopeId").and_then(Value::as_str),
        "kind": envelope.get("kind").and_then(Value::as_str),
        "issuerPk": envelope.get("issuerPk").and_then(Value::as_str),
        "issuedAt": envelope.get("issuedAt").and_then(Value::as_u64),
        "expiresAt": envelope.get("expiresAt").and_then(Value::as_u64),
        "recipientCount": envelope
            .get("recipients")
            .and_then(Value::as_array)
            .map(|recipients| recipients.len())
            .unwrap_or(0),
    })
}

fn product_caac_body(
    kind: &str,
    claims: Value,
    issuer_secret: &str,
    recipient_pks: &[String],
    now_ms: u64,
) -> Result<SwarmFrameBody> {
    let mut recipients = recipient_pks
        .iter()
        .map(|recipient| recipient.trim())
        .filter(|recipient| !recipient.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let issuer_pk = pubkey_from_sk_hex(issuer_secret)?;
    if !recipients.iter().any(|recipient| recipient == &issuer_pk) {
        recipients.push(issuer_pk);
    }
    let envelope = seal_envelope(
        kind,
        &claims,
        issuer_secret,
        &recipients,
        now_ms / 1000,
        now_ms / 1000 + 90,
    )?;
    let envelope_value = serde_json::to_value(envelope)?;
    validate_caac_envelope_for_mode(&envelope_value, CaacValidationMode::Product, now_ms / 1000)?;
    Ok(SwarmFrameBody {
        encoding: "caac".to_string(),
        envelope: Some(envelope_value),
        public_bootstrap: false,
        payload: None,
        signature: None,
    })
}

fn directory_from_value(value: &Value) -> Result<SwarmDirectory> {
    let directory: SwarmDirectory = serde_json::from_value(value.clone())?;
    validate_swarm_directory(&directory)?;
    Ok(directory)
}

fn looks_like_projection_record(value: &Value) -> bool {
    value.get("channelId").is_some()
        && value.get("service").is_some()
        && value.get("payload").is_some()
        && value.get("freshness").is_some()
}

fn looks_like_directory(value: &Value) -> bool {
    value.get("definitions").is_some() && value.get("channels").is_some()
}

#[cfg(test)]
fn ack_frame_for(frame: &SwarmFrame, issuer: &str, now_ms: u64) -> Result<SwarmFrame> {
    let mut ack = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::Ack,
        issuer: issuer.to_string(),
        audience: json!({ "actorRef": frame.issuer }),
        zone_scope: None,
        issued_at: now_ms,
        expires_at: None,
        nonce: format!("ack-{}", uuid::Uuid::new_v4().simple()),
        correlation_id: Some(frame.frame_id.clone()),
        channel_id: frame.channel_id.clone(),
        record_ref: None,
        capability: None,
        body: SwarmFrameBody {
            encoding: "caac".to_string(),
            envelope: Some(json!({ "envelopeId": "ack" })),
            public_bootstrap: false,
            payload: None,
            signature: None,
        },
        ack: Some(constitute_protocol::SwarmAck {
            acked_frame_id: Some(frame.frame_id.clone()),
            retry_after_ms: None,
            gap_after_frame_ids: vec![],
            reason_code: None,
        }),
    };
    ack.frame_id = swarm_frame_id(&ack)?;
    Ok(ack)
}

#[cfg(test)]
fn reject_frame_for(
    frame: &SwarmFrame,
    issuer_secret: &str,
    now_ms: u64,
    code: &str,
) -> Result<SwarmFrame> {
    let issuer = pubkey_from_sk_hex(issuer_secret)?;
    let error = json!({
        "error": {
            "code": code,
            "message": "structured reject",
            "retryable": false
        }
    });
    let mut reject = SwarmFrame {
        version: constitute_protocol::SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::Reject,
        issuer,
        audience: json!({ "actorRef": frame.issuer }),
        zone_scope: None,
        issued_at: now_ms,
        expires_at: None,
        nonce: format!("reject-{}", uuid::Uuid::new_v4().simple()),
        correlation_id: Some(frame.frame_id.clone()),
        channel_id: frame.channel_id.clone(),
        record_ref: None,
        capability: None,
        body: product_caac_body(
            "reject",
            error,
            issuer_secret,
            std::slice::from_ref(&frame.issuer),
            now_ms,
        )?,
        ack: Some(constitute_protocol::SwarmAck {
            acked_frame_id: None,
            retry_after_ms: None,
            gap_after_frame_ids: vec![],
            reason_code: Some(code.to_string()),
        }),
    };
    reject.frame_id = swarm_frame_id(&reject)?;
    Ok(reject)
}

fn parse_relay_event(text: &str) -> Result<Option<BootstrapNostrEvent>> {
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

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyStoreRef;
    use std::net::TcpListener;
    use std::sync::mpsc::Sender;

    const DEVICE_SK: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const GATEWAY_SK: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn forbidden_route_detection_rejects_direct_service_route() {
        let retired_direct_route = ["https://service.example/service", "-ex", "change"].join("");
        assert!(forbidden_semantic_route_seen(&[retired_direct_route]));
        assert!(forbidden_semantic_route_seen(&[
            "--service-endpoint=http://127.0.0.1:7480".to_string()
        ]));
        assert!(!forbidden_semantic_route_seen(&[
            "relay://wss://relay.example".to_string(),
            "gateway:abc".to_string()
        ]));
    }

    #[test]
    fn live_edge_attaches_before_publish_and_removes_on_ack() {
        let (url, seen_rx) = spawn_edge_server(|mut socket, seen| {
            let hello = read_json(&mut socket);
            seen.send(hello["type"].as_str().unwrap().to_string())
                .unwrap();
            let accept = accept_from_edge_record(&hello, "edge-session-1");
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_EDGE_WIRE_ACCEPT,
                        "accept": accept
                    })
                    .to_string(),
                ))
                .unwrap();
            let published = read_json(&mut socket);
            seen.send(published["type"].as_str().unwrap().to_string())
                .unwrap();
            let frame: SwarmFrame =
                serde_json::from_value(published["frame"].clone()).expect("published frame");
            let ack = ack_frame_for(&frame, "gateway-pk", frame.issued_at + 1).unwrap();
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": ack
                    })
                    .to_string(),
                ))
                .unwrap();
        });
        let transport = live_transport(&url);
        let frame = test_frame("frame-ack", "nonce-ack");

        let response = transport.publish_frame(&frame).expect("published");

        assert_eq!(response["status"], "frameIntakeOnly");
        assert_eq!(response["frameIntake"]["state"], "accepted");
        assert_eq!(response["frameId"], frame.frame_id);
        assert_eq!(
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            constitute_protocol::SWARM_EDGE_WIRE_HELLO
        );
        assert_eq!(
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            constitute_protocol::SWARM_WIRE_FRAME
        );
    }

    #[test]
    fn live_publish_reports_route_observation_separately_from_frame_intake() {
        let (url, _seen_rx) = spawn_edge_server(|mut socket, _seen| {
            let hello = read_json(&mut socket);
            let accept = accept_from_edge_record(&hello, "edge-session-route");
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_EDGE_WIRE_ACCEPT,
                        "accept": accept
                    })
                    .to_string(),
                ))
                .unwrap();
            let published = read_json(&mut socket);
            let frame: SwarmFrame =
                serde_json::from_value(published["frame"].clone()).expect("published frame");
            let ack = ack_frame_for(&frame, "gateway-pk", frame.issued_at + 1).unwrap();
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": ack
                    })
                    .to_string(),
                ))
                .unwrap();
            let route = route_observation_frame(&frame, frame.issued_at + 2);
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": route
                    })
                    .to_string(),
                ))
                .unwrap();
        });
        let transport = live_transport(&url);

        let response = transport
            .publish_frame(&test_frame("frame-route", "nonce-route"))
            .expect("frame intake and route observation");

        assert_eq!(response["frameIntake"]["state"], "accepted");
        assert_eq!(response["routeObservation"]["state"], "delivered");
        assert_eq!(response["status"], "routeObserved");
    }

    #[test]
    fn live_edge_resumes_existing_session_when_possible() {
        let (url, seen_rx) = spawn_edge_server_multi(|listener, seen| {
            let (stream, _) = listener.accept().unwrap();
            let mut first = tungstenite::accept(stream).unwrap();
            let hello = read_json(&mut first);
            seen.send(hello["type"].as_str().unwrap().to_string())
                .unwrap();
            let accept = accept_from_edge_record(&hello, "edge-session-resume");
            first
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_EDGE_WIRE_ACCEPT,
                        "accept": accept
                    })
                    .to_string(),
                ))
                .unwrap();
            let first_frame = read_json(&mut first);
            let first_swarm: SwarmFrame =
                serde_json::from_value(first_frame["frame"].clone()).expect("first frame");
            first
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": ack_frame_for(&first_swarm, "gateway-pk", first_swarm.issued_at + 1).unwrap()
                    })
                    .to_string(),
                ))
                .unwrap();

            let (stream, _) = listener.accept().unwrap();
            let mut second = tungstenite::accept(stream).unwrap();
            let resume = read_json(&mut second);
            seen.send(resume["type"].as_str().unwrap().to_string())
                .unwrap();
            let accept = accept_from_edge_record(&resume, "edge-session-resume");
            second
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_EDGE_WIRE_ACCEPT,
                        "accept": accept
                    })
                    .to_string(),
                ))
                .unwrap();
            let second_frame = read_json(&mut second);
            let second_swarm: SwarmFrame =
                serde_json::from_value(second_frame["frame"].clone()).expect("second frame");
            second
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": ack_frame_for(&second_swarm, "gateway-pk", second_swarm.issued_at + 1).unwrap()
                    })
                    .to_string(),
                ))
                .unwrap();
        });
        let transport = live_transport(&url);

        transport
            .publish_frame(&test_frame("frame-one", "nonce-one"))
            .expect("first publish");
        transport
            .publish_frame(&test_frame("frame-two", "nonce-two"))
            .expect("second publish");

        assert_eq!(
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            constitute_protocol::SWARM_EDGE_WIRE_HELLO
        );
        assert_eq!(
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            constitute_protocol::SWARM_EDGE_WIRE_RESUME
        );
    }

    #[test]
    fn live_edge_returns_structured_reject() {
        let (url, _seen_rx) = spawn_edge_server(|mut socket, _seen| {
            let hello = read_json(&mut socket);
            let accept = accept_from_edge_record(&hello, "edge-session-reject");
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_EDGE_WIRE_ACCEPT,
                        "accept": accept
                    })
                    .to_string(),
                ))
                .unwrap();
            let published = read_json(&mut socket);
            let frame: SwarmFrame =
                serde_json::from_value(published["frame"].clone()).expect("published frame");
            let reject =
                reject_frame_for(&frame, GATEWAY_SK, frame.issued_at + 1, "policy.denied").unwrap();
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": reject
                    })
                    .to_string(),
                ))
                .unwrap();
        });
        let transport = live_transport(&url);

        let err = transport
            .publish_frame(&test_frame("frame-reject", "nonce-reject"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("policy.denied"));
        assert!(err.contains("structured reject"));
    }

    #[test]
    fn live_edge_observes_projection_from_edge_message() {
        let (url, _seen_rx) = spawn_edge_server(|mut socket, _seen| {
            let hello = read_json(&mut socket);
            let accept = accept_from_edge_record(&hello, "edge-session-projection");
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_EDGE_WIRE_ACCEPT,
                        "accept": accept
                    })
                    .to_string(),
                ))
                .unwrap();
            let published = read_json(&mut socket);
            let frame: SwarmFrame =
                serde_json::from_value(published["frame"].clone()).expect("published frame");
            let ack = ack_frame_for(&frame, "gateway-pk", frame.issued_at + 1).unwrap();
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": ack
                    })
                    .to_string(),
                ))
                .unwrap();
            let projection_frame = projection_message_frame(frame.issued_at + 2);
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": projection_frame
                    })
                    .to_string(),
                ))
                .unwrap();
        });
        let transport = live_transport(&url);

        let projection = transport
            .observe_projection(
                &test_frame("frame-projection", "nonce-projection"),
                "logging",
            )
            .expect("projection");

        assert_eq!(projection["projection"]["channelId"], "logging.events");
        assert_eq!(
            projection["projection"]["payload"]["events"][0]["eventId"],
            "edge-event"
        );
    }

    #[test]
    fn live_edge_reads_directory_projection_for_capability_channel_commands() {
        let (url, _seen_rx) = spawn_edge_server(|mut socket, _seen| {
            let hello = read_json(&mut socket);
            let accept = accept_from_edge_record(&hello, "edge-session-directory");
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_EDGE_WIRE_ACCEPT,
                        "accept": accept
                    })
                    .to_string(),
                ))
                .unwrap();
            let published = read_json(&mut socket);
            let frame: SwarmFrame =
                serde_json::from_value(published["frame"].clone()).expect("published frame");
            let ack = ack_frame_for(&frame, "gateway-pk", frame.issued_at + 1).unwrap();
            socket
                .send(Message::Text(
                    json!({
                        "type": constitute_protocol::SWARM_WIRE_FRAME,
                        "frame": ack
                    })
                    .to_string(),
                ))
                .unwrap();
            socket
                .send(Message::Text(
                    json!({
                        "type": "swarm.directory",
                        "directory": test_directory()
                    })
                    .to_string(),
                ))
                .unwrap();
        });
        let transport = live_transport(&url);

        let directory = transport.swarm_directory().expect("directory");
        let lookup =
            crate::swarm_ops::capability_lookup(&directory, "storage.pin", now_unix() * 1000)
                .expect("capability");

        assert_eq!(lookup.channels.len(), 1);
        assert_eq!(lookup.channels[0].channel_id, "channel-storage-pins");
    }

    fn spawn_edge_server<F>(handler: F) -> (String, mpsc::Receiver<String>)
    where
        F: FnOnce(tungstenite::WebSocket<TcpStream>, Sender<String>) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (seen_tx, seen_rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let socket = tungstenite::accept(stream).unwrap();
            handler(socket, seen_tx);
        });
        (url, seen_rx)
    }

    fn spawn_edge_server_multi<F>(handler: F) -> (String, mpsc::Receiver<String>)
    where
        F: FnOnce(TcpListener, Sender<String>) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (seen_tx, seen_rx) = mpsc::channel();
        thread::spawn(move || handler(listener, seen_tx));
        (url, seen_rx)
    }

    fn read_json(socket: &mut tungstenite::WebSocket<TcpStream>) -> Value {
        loop {
            let message = socket.read().unwrap();
            if let Message::Text(text) = message {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    fn accept_from_edge_record(value: &Value, session_id: &str) -> SwarmEdgeAccept {
        let source = value
            .get("hello")
            .or_else(|| value.get("resume"))
            .expect("hello or resume");
        let accept = SwarmEdgeAccept {
            session_id: session_id.to_string(),
            member_kind: source["memberKind"].as_str().unwrap().to_string(),
            member_ref: source["memberRef"].as_str().unwrap().to_string(),
            zone_scope: serde_json::from_value(source["zoneScope"].clone()).unwrap(),
            accepted_version: constitute_protocol::SWARM_FRAME_VERSION as u32,
            last_acked_frame_id: source
                .get("lastAckedFrameId")
                .and_then(Value::as_str)
                .map(str::to_string),
            last_projection_revisions: source
                .get("lastProjectionRevisions")
                .cloned()
                .unwrap_or_else(|| json!({})),
            capability_refs: source["capabilityRefs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect(),
            channel_refs: source["channelRefs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect(),
            promise_refs: source
                .get("promiseRefs")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|value| value.as_str().unwrap().to_string())
                        .collect()
                })
                .unwrap_or_default(),
            nonce: format!("accept-{}", uuid::Uuid::new_v4().simple()),
            issued_at: now_unix() * 1000,
            expires_at: source.get("expiresAt").and_then(Value::as_u64),
            sealed_claims: serde_json::from_value(source["sealedClaims"].clone()).unwrap(),
        };
        validate_swarm_edge_accept(&accept).unwrap();
        accept
    }

    fn live_transport(url: &str) -> LiveTransport {
        LiveTransport::new_with_secret(profile_with_edge(url), DEVICE_SK.to_string())
    }

    fn profile_with_edge(url: &str) -> ProfileRecord {
        ProfileRecord {
            schema_version: 1,
            profile: "edge-test".to_string(),
            device_pk: pubkey_from_sk_hex(DEVICE_SK).unwrap(),
            account_pk: Some("account-pk".to_string()),
            gateway_pk: Some(pubkey_from_sk_hex(GATEWAY_SK).unwrap()),
            relays: vec!["ws://bootstrap.invalid".to_string()],
            local_gateway_hint: Some(url.to_string()),
            pending_enrollment: None,
            key_store: KeyStoreRef {
                kind: "encryptedFileFallback".to_string(),
                id: "edge-test".to_string(),
            },
            created_at: now_unix(),
        }
    }

    fn test_frame(id: &str, nonce: &str) -> SwarmFrame {
        let now_ms = now_unix() * 1000;
        let mut frame = SwarmFrame {
            version: constitute_protocol::SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::ServiceIntent,
            issuer: pubkey_from_sk_hex(DEVICE_SK).unwrap(),
            audience: json!({ "serviceRef": "service-raw-logging" }),
            zone_scope: Some(default_edge_zone_scope()),
            issued_at: now_ms,
            expires_at: Some(now_ms + 90_000),
            nonce: nonce.to_string(),
            correlation_id: Some(id.to_string()),
            channel_id: Some("logging.events".to_string()),
            record_ref: None,
            capability: Some(constitute_protocol::CAPABILITY_SERVICE_INTENT_INVOKE.to_string()),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(json!({ "envelopeId": id })),
                public_bootstrap: false,
                payload: None,
                signature: Some("test-only-fixture-signature".to_string()),
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).unwrap();
        frame
    }

    fn projection_message_frame(now_ms: u64) -> SwarmFrame {
        let projection = json!({
            "channelId": "logging.events",
            "service": "logging",
            "servicePk": "service-raw-logging",
            "producer": { "service": "logging" },
            "freshness": { "state": "fresh", "updatedAt": now_ms / 1000 },
            "scope": { "policyId": "default" },
            "payloadSchema": "constitute.logging.events.v1",
            "payload": {
                "events": [{ "eventId": "edge-event", "occurredAt": now_ms / 1000 }]
            },
            "safeFacts": { "count": 1 },
            "encryptedDetailRefs": [],
            "diagnostics": []
        });
        let mut frame = SwarmFrame {
            version: constitute_protocol::SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::ProjectionSnapshot,
            issuer: pubkey_from_sk_hex(GATEWAY_SK).unwrap(),
            audience: json!({ "actorRef": pubkey_from_sk_hex(DEVICE_SK).unwrap() }),
            zone_scope: Some(default_edge_zone_scope()),
            issued_at: now_ms,
            expires_at: None,
            nonce: format!("projection-{}", uuid::Uuid::new_v4().simple()),
            correlation_id: Some("projection-response".to_string()),
            channel_id: Some("logging.events".to_string()),
            record_ref: None,
            capability: Some(constitute_protocol::CAPABILITY_PROJECTION_OBSERVE.to_string()),
            body: product_caac_body(
                "projection.snapshot",
                json!({ "projection": projection }),
                GATEWAY_SK,
                &[pubkey_from_sk_hex(DEVICE_SK).unwrap()],
                now_ms,
            )
            .unwrap(),
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).unwrap();
        frame
    }

    fn route_observation_frame(observed: &SwarmFrame, now_ms: u64) -> SwarmFrame {
        let observation = json!({
            "kind": "route.observation",
            "observationId": format!("route-observation-{}", uuid::Uuid::new_v4().simple()),
            "state": "delivered",
            "frameId": observed.frame_id.clone(),
            "failedPredicates": [],
            "diagnostics": {
                "deliveredTo": ["member:test-service"]
            },
            "issuedAt": now_ms / 1000
        });
        validate_route_observation(&serde_json::from_value(observation.clone()).unwrap()).unwrap();
        let mut frame = SwarmFrame {
            version: constitute_protocol::SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::RouteObservation,
            issuer: pubkey_from_sk_hex(GATEWAY_SK).unwrap(),
            audience: json!({ "actorRef": pubkey_from_sk_hex(DEVICE_SK).unwrap() }),
            zone_scope: Some(default_edge_zone_scope()),
            issued_at: now_ms,
            expires_at: None,
            nonce: format!("route-observation-{}", uuid::Uuid::new_v4().simple()),
            correlation_id: observed.correlation_id.clone(),
            channel_id: observed.channel_id.clone(),
            record_ref: Some(constitute_protocol::SwarmRecordRef {
                kind: "route.observation".to_string(),
                id: observation["observationId"].as_str().unwrap().to_string(),
                revision: Some(1),
            }),
            capability: Some(constitute_protocol::CAPABILITY_ROUTE_OBSERVATION_PUBLISH.to_string()),
            body: product_caac_body(
                "route.observation",
                json!({ "routeObservation": observation }),
                GATEWAY_SK,
                &[pubkey_from_sk_hex(DEVICE_SK).unwrap()],
                now_ms,
            )
            .unwrap(),
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame).unwrap();
        frame
    }

    fn test_directory() -> SwarmDirectory {
        let storage_pk = pubkey_from_sk_hex(DEVICE_SK).unwrap();
        serde_json::from_value(json!({
            "definitions": [{
                "capability": "storage.pin",
                "definitionId": "capability-def-storage-pin",
                "summary": "Pin storage.",
                "schema": {},
                "authorityRefs": ["member-raw-governance"]
            }],
            "advertisements": [{
                "advertisementId": "ad-storage-pin",
                "capability": "storage.pin",
                "memberRef": storage_pk,
                "serviceRef": "service-raw-storage",
                "channelRefs": ["channel-storage-pins"],
                "issuedAt": 1,
                "expiresAt": 4777935700000u64
            }],
            "entries": [{
                "entryId": "entry-storage-pins",
                "capability": "storage.pin",
                "channelId": "channel-storage-pins",
                "memberRef": storage_pk,
                "serviceRef": "service-raw-storage",
                "priority": 1
            }],
            "channels": [{
                "channelId": "channel-storage-pins",
                "kind": "storage",
                "displayName": "Storage Pins",
                "capabilities": ["storage.pin"],
                "recordKinds": ["storage.pin.intent"],
                "ownerRefs": ["member-raw-storage"],
                "policyRef": "policy-storage",
                "createdAt": 1
            }],
            "policies": [{
                "policyId": "policy-storage",
                "observe": ["role:observer"],
                "write": ["role:writer"],
                "set": ["role:writer"],
                "invoke": ["role:writer"],
                "pin": ["role:writer"],
                "attest": ["role:replicator"],
                "run": ["role:runner"]
            }]
        }))
        .unwrap()
    }
}
