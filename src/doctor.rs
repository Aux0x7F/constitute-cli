use constitute_protocol::{
    SERVICE_FRAME_DESCRIBE_REQUEST, SERVICE_FRAME_PROJECTION_REQUEST,
    validate_hosted_service_descriptor, validate_projection_record,
};
use serde::Serialize;
use serde_json::json;

use crate::app::AppContext;
use crate::config::load_profile;
use crate::keystore::load_secret;
use crate::protocol_ops::build_signed_frame;
use crate::transport::{forbidden_semantic_route_seen, open_transport};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub status: String,
    pub profile: String,
    pub steps: Vec<DoctorStep>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorStep {
    pub name: String,
    pub status: String,
    pub detail: String,
}

pub fn run_doctor(ctx: &AppContext, full: bool) -> DoctorReport {
    let mut steps = Vec::new();
    let profile = match load_profile(&ctx.config_dir, &ctx.profile) {
        Ok(profile) => {
            steps.push(pass("profile.read", "profile metadata loaded"));
            profile
        }
        Err(err) => {
            steps.push(fail("profile.read", err.to_string()));
            return report(ctx, steps);
        }
    };
    let secret = match load_secret(
        &ctx.config_dir,
        &ctx.profile,
        &profile.key_store,
        ctx.passphrase.as_deref(),
    ) {
        Ok(secret) => {
            steps.push(pass("device-key.unlock", "device key unlocked"));
            secret
        }
        Err(err) => {
            steps.push(fail("device-key.unlock", err.to_string()));
            return report(ctx, steps);
        }
    };
    if profile.account_pk.as_deref().unwrap_or_default().is_empty() {
        steps.push(warn(
            "account.association",
            "profile has no account public key",
        ));
    } else {
        steps.push(pass(
            "account.association",
            "profile is associated with an account public key",
        ));
    }
    let transport = open_transport(ctx.fixture_dir.clone());
    let descriptors = match transport.descriptor_list() {
        Ok(descriptors) => {
            steps.push(pass(
                "gateway.descriptors",
                format!("{} descriptor(s)", descriptors.len()),
            ));
            descriptors
        }
        Err(err) => {
            steps.push(fail("gateway.descriptors", err.to_string()));
            return report(ctx, steps);
        }
    };
    for descriptor in &descriptors {
        match validate_hosted_service_descriptor(descriptor) {
            Ok(()) => steps.push(pass("descriptor.validate", descriptor.service.clone())),
            Err(err) => steps.push(fail(
                "descriptor.validate",
                format!("{}: {err}", descriptor.service),
            )),
        }
    }
    if forbidden_semantic_route_seen(&transport.transport_hints()) {
        steps.push(fail(
            "transport.boundary",
            "forbidden raw service semantic route present",
        ));
    } else {
        steps.push(pass(
            "transport.boundary",
            "no forbidden raw service semantic route hints",
        ));
    }
    if let Some(logging) = descriptors.iter().find(|d| d.service == "logging") {
        let describe_frame = build_signed_frame(
            SERVICE_FRAME_DESCRIBE_REQUEST,
            &secret,
            &logging.service_pk,
            &logging.host_gateway_pk,
            json!({ "service": "logging" }),
        );
        match describe_frame.and_then(|frame| transport.exchange(&frame)) {
            Ok(_) => steps.push(pass("service.describe", "logging describe roundtrip")),
            Err(err) => steps.push(fail("service.describe", err.to_string())),
        }
        let projection_frame = build_signed_frame(
            SERVICE_FRAME_PROJECTION_REQUEST,
            &secret,
            &logging.service_pk,
            &logging.host_gateway_pk,
            json!({
                "requestId": "doctor-logging-events",
                "service": "logging",
                "channelId": "logging.events",
                "filters": {}
            }),
        );
        match projection_frame.and_then(|frame| transport.exchange(&frame)) {
            Ok(value) => {
                if let Some(projection) = value.get("projection") {
                    match serde_json::from_value(projection.clone()) {
                        Ok(record) => {
                            match validate_projection_record(&record, &logging.projection_channels)
                            {
                                Ok(()) => steps.push(pass(
                                    "projection.logging.events",
                                    "projection validated",
                                )),
                                Err(err) => {
                                    steps.push(fail("projection.logging.events", err.to_string()))
                                }
                            }
                        }
                        Err(err) => steps.push(fail("projection.logging.events", err.to_string())),
                    }
                } else {
                    steps.push(fail(
                        "projection.logging.events",
                        "response missing projection",
                    ));
                }
            }
            Err(err) => steps.push(fail("projection.logging.events", err.to_string())),
        }
    } else {
        steps.push(fail("service.logging", "logging descriptor unavailable"));
    }
    if full {
        match transport.diagnostics() {
            Ok(items) => steps.push(pass(
                "diagnostics.observe",
                format!("{} diagnostic item(s)", items.len()),
            )),
            Err(err) => steps.push(warn("diagnostics.observe", err.to_string())),
        }
    }
    report(ctx, steps)
}

fn report(ctx: &AppContext, steps: Vec<DoctorStep>) -> DoctorReport {
    let status = if steps.iter().any(|s| s.status == "fail") {
        "fail"
    } else if steps.iter().any(|s| s.status == "warn") {
        "warn"
    } else {
        "pass"
    };
    DoctorReport {
        status: status.to_string(),
        profile: ctx.profile.clone(),
        steps,
    }
}

fn pass(name: impl Into<String>, detail: impl Into<String>) -> DoctorStep {
    step(name, "pass", detail)
}

fn warn(name: impl Into<String>, detail: impl Into<String>) -> DoctorStep {
    step(name, "warn", detail)
}

fn fail(name: impl Into<String>, detail: impl Into<String>) -> DoctorStep {
    step(name, "fail", detail)
}

fn step(
    name: impl Into<String>,
    status: impl Into<String>,
    detail: impl Into<String>,
) -> DoctorStep {
    DoctorStep {
        name: name.into(),
        status: status.into(),
        detail: detail.into(),
    }
}
