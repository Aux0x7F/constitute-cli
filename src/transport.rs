use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use constitute_protocol::{
    HostedServiceDescriptor, ProjectionRecord, SERVICE_FRAME_DESCRIBE_REQUEST,
    SERVICE_FRAME_INVOKE_REQUEST, SERVICE_FRAME_PROJECTION_REQUEST, ServiceExchangeFrame,
    validate_hosted_service_descriptor, validate_projection_record,
};
use serde_json::{Value, json};

pub trait ServiceTransport {
    fn descriptor_list(&self) -> Result<Vec<HostedServiceDescriptor>>;
    fn exchange(&self, frame: &ServiceExchangeFrame) -> Result<Value>;
    fn diagnostics(&self) -> Result<Vec<Value>>;
    fn transport_hints(&self) -> Vec<String>;
}

pub fn open_transport(fixture_dir: Option<PathBuf>) -> Box<dyn ServiceTransport> {
    if let Some(dir) = fixture_dir {
        Box::new(FixtureTransport { dir })
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

    fn exchange(&self, _frame: &ServiceExchangeFrame) -> Result<Value> {
        Err(anyhow!(
            "no protocol transport configured; provide --fixture-dir or enroll a live transport profile"
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

    fn exchange(&self, frame: &ServiceExchangeFrame) -> Result<Value> {
        match frame.kind.as_str() {
            SERVICE_FRAME_DESCRIBE_REQUEST => {
                let service = service_from_payload_or_frame(frame)?;
                let raw = fs::read_to_string(self.dir.join(format!("describe.{service}.json")))
                    .with_context(|| format!("read describe fixture for {service}"))?;
                let descriptor: HostedServiceDescriptor = serde_json::from_str(&raw)?;
                validate_hosted_service_descriptor(&descriptor)?;
                Ok(json!({ "descriptor": descriptor }))
            }
            SERVICE_FRAME_PROJECTION_REQUEST => {
                let service = service_from_payload_or_frame(frame)?;
                let channel = frame
                    .sealed_payload
                    .get("channelId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("projection payload missing channelId"))?;
                let raw = fs::read_to_string(
                    self.dir
                        .join(format!("projection.{service}.{}.json", sanitize(channel))),
                )
                .with_context(|| format!("read projection fixture for {service}/{channel}"))?;
                let record: ProjectionRecord = serde_json::from_str(&raw)?;
                let allowed = self
                    .descriptor_list()?
                    .into_iter()
                    .find(|d| d.service == service)
                    .map(|d| d.projection_channels)
                    .unwrap_or_default();
                validate_projection_record(&record, &allowed)?;
                Ok(json!({ "projection": record }))
            }
            SERVICE_FRAME_INVOKE_REQUEST => {
                Ok(json!({ "ok": true, "kind": frame.kind, "echo": frame.sealed_payload }))
            }
            _ => Ok(json!({ "ok": true, "kind": frame.kind })),
        }
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
        vec![format!("fixture://{}", self.dir.display())]
    }
}

pub fn write_default_fixtures(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    let logging_pk = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let gateway_pk = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let descriptors = vec![HostedServiceDescriptor {
        service: "logging".to_string(),
        service_pk: logging_pk.to_string(),
        host_gateway_pk: gateway_pk.to_string(),
        display: json!({ "name": "Constitute Logging" }),
        capabilities: vec!["observe".to_string(), "diagnostics".to_string()],
        projection_channels: vec![
            "logging.events".to_string(),
            "logging.health".to_string(),
            "logging.dashboard".to_string(),
        ],
        invocation_kinds: vec![],
        transport_hints: json!({ "fixture": true }),
        health_summary: json!({ "status": "ok" }),
    }];
    fs::write(
        dir.join("descriptors.json"),
        serde_json::to_vec_pretty(&descriptors)?,
    )?;
    fs::write(
        dir.join("describe.logging.json"),
        serde_json::to_vec_pretty(&descriptors[0])?,
    )?;
    let projection = json!({
        "channelId": "logging.events",
        "service": "logging",
        "servicePk": logging_pk,
        "producer": { "service": "logging" },
        "freshness": { "state": "fresh", "updatedAt": 1777932000, "staleAfter": 1777932300 },
        "scope": { "policyId": "fixture" },
        "payloadSchema": "constitute.logging.events.v1",
        "payload": {
            "events": [
                {
                "eventId": "fixture-event-1",
                "occurredAt": 1777932000,
                "severity": "info",
                "category": "serviceSignal",
                "outcome": "observed",
                "tags": ["logging", "fixture"],
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
    let diagnostics = json!([
        {
            "operation": "constitute-cli.doctor.fixture",
            "level": "info",
            "surface": "cli",
            "safeFacts": { "ok": true }
        }
    ]);
    fs::write(
        dir.join("diagnostics.json"),
        serde_json::to_vec_pretty(&diagnostics)?,
    )?;
    Ok(())
}

pub fn forbidden_semantic_route_seen(hints: &[String]) -> bool {
    let forbidden = [
        "/v1/events/search",
        "/health",
        "/managed/session",
        "rtsp://",
    ];
    hints.iter().any(|hint| {
        let lowered = hint.to_ascii_lowercase();
        forbidden.iter().any(|needle| lowered.contains(needle))
    })
}

fn service_from_payload_or_frame(frame: &ServiceExchangeFrame) -> Result<String> {
    frame
        .sealed_payload
        .get("service")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            frame
                .route_hint
                .get("service")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| anyhow!("service exchange payload missing service"))
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}
