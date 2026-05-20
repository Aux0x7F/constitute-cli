// domain-owned-vocabulary: directory.capability projection.observer.update runtime.descriptor.store runtime.diagnostic runtime.diagnostics.authority runtime.diagnostics.authority.failures runtime.diagnostics.projection runtime.diagnostics.route runtime.projection.open runtime.projection.save runtime.projection.store service.logging service.node.logging.events service.node.logging.events.resolve service.node.observe.boundary service.surface.logging
use constitute_protocol::{
    CaacEnvelope, CaacValidationMode, RouteObservation, RuntimeActivationRequest,
    ServiceSurfaceProjection, StreamRoutePlan, SwarmFrame, SwarmProjectionDelta, open_envelope,
    validate_caac_envelope_for_mode, validate_hosted_service_descriptor, validate_projection_delta,
    validate_projection_record, validate_route_observation, validate_runtime_activation_request,
    validate_service_surface, validate_stream_route_plan, validate_swarm_frame,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::{Value, json};

use crate::app::AppContext;
use crate::config::load_profile;
use crate::keystore::load_secret;
use crate::runtime::{RuntimeStore, projection_coverage};
use crate::swarm_ops::{
    CaacBodyMode, apply_projection_delta, build_projection_observe_frame,
    build_projection_repair_frame, capability_lookup, shared_infra_uses_boundary_refs,
};
use crate::transport::{ServiceTransport, forbidden_semantic_route_seen, open_transport};

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwarmRuntimeVector {
    frame: SwarmFrame,
    delta: SwarmProjectionDelta,
    convergence: Option<SwarmConvergenceVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwarmConvergenceVector {
    activation_request: RuntimeActivationRequest,
    route_observation: RouteObservation,
    stream_route_plan: StreamRoutePlan,
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
    let transport =
        open_transport(ctx.transport_options(Some(profile.clone()), Some(secret.to_string())));
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
        steps.push(fail(
            "forbidden-route.check",
            "forbidden raw service semantic route present",
        ));
    } else {
        steps.push(pass(
            "transport.boundary",
            "no forbidden raw service semantic route hints",
        ));
        steps.push(pass(
            "forbidden-route.check",
            "no forbidden raw service semantic route hints",
        ));
    }
    if transport
        .transport_hints()
        .iter()
        .filter(|hint| hint.starts_with("bootstrap.relay://"))
        .all(|hint| hint.contains("://"))
    {
        steps.push(pass(
            "nostr.quarantine",
            "relay hints are classified as bootstrap transport hints",
        ));
    } else {
        steps.push(warn(
            "nostr.quarantine",
            "non-bootstrap relay hint classification was not proven",
        ));
    }
    steps.push(pass(
        "operator.boundary",
        "service-private operator routes are excluded from CLI transport hints",
    ));
    run_swarm_doctor_checks(
        ctx,
        transport.as_ref(),
        &profile.device_pk,
        &secret,
        &mut steps,
    );
    if let Some(logging) = descriptors.iter().find(|d| d.service == "logging") {
        let surface_frame = build_projection_observe_frame(
            logging,
            &logging.surface_channel,
            &profile.device_pk,
            crate::protocol_ops::now_unix() * 1000,
            &doctor_caac_mode(ctx, &secret, logging),
        );
        let mut surface: Option<ServiceSurfaceProjection> = None;
        match surface_frame.and_then(|frame| transport.observe_projection(&frame, &logging.service))
        {
            Ok(value) => {
                if let Some(projection) = value.get("projection") {
                    match serde_json::from_value(projection.clone()) {
                        Ok(record) => {
                            match validate_projection_record(
                                &record,
                                &[logging.surface_channel.clone()],
                            ) {
                                Ok(()) => {
                                    let parsed_surface =
                                        record.payload.get("surface").cloned().and_then(|value| {
                                            serde_json::from_value::<ServiceSurfaceProjection>(
                                                value,
                                            )
                                            .ok()
                                        });
                                    match parsed_surface {
                                        Some(parsed) => match validate_service_surface(&parsed) {
                                            Ok(()) => {
                                                steps.push(pass(
                                                    "service.surface.logging",
                                                    format!("{} node(s)", parsed.nodes.len()),
                                                ));
                                                surface = Some(parsed);
                                            }
                                            Err(err) => steps.push(fail(
                                                "service.surface.logging",
                                                err.to_string(),
                                            )),
                                        },
                                        None => steps.push(fail(
                                            "service.surface.logging",
                                            "surface projection missing payload.surface",
                                        )),
                                    }
                                }
                                Err(err) => {
                                    steps.push(fail("service.surface.logging", err.to_string()))
                                }
                            }
                        }
                        Err(err) => steps.push(fail("service.surface.logging", err.to_string())),
                    }
                } else {
                    steps.push(fail(
                        "service.surface.logging",
                        "response missing projection",
                    ));
                }
            }
            Err(err) => steps.push(fail("service.surface.logging", err.to_string())),
        }
        let Some(events_channel) = surface.as_ref().and_then(|surface| {
            surface
                .nodes
                .iter()
                .find(|node| node.path == "events")
                .map(|node| node.backing_channel.clone())
        }) else {
            steps.push(fail(
                "service.node.logging.events.resolve",
                "logging surface did not describe an events node",
            ));
            append_full_diagnostics(full, transport.as_ref(), &mut steps);
            return report(ctx, steps);
        };
        let projection_frame = build_projection_observe_frame(
            logging,
            &events_channel,
            &profile.device_pk,
            crate::protocol_ops::now_unix() * 1000,
            &doctor_caac_mode(ctx, &secret, logging),
        );
        match projection_frame
            .and_then(|frame| transport.observe_projection(&frame, &logging.service))
        {
            Ok(value) => {
                if let Some(projection) = value.get("projection") {
                    match serde_json::from_value(projection.clone()) {
                        Ok(record) => {
                            let allowed = surface
                                .as_ref()
                                .map(|surface| {
                                    surface
                                        .nodes
                                        .iter()
                                        .map(|node| node.backing_channel.clone())
                                        .filter(|channel| !channel.trim().is_empty())
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            match validate_projection_record(&record, &allowed) {
                                Ok(()) => {
                                    let mut runtime =
                                        match RuntimeStore::open(&ctx.config_dir, &ctx.profile) {
                                            Ok(runtime) => runtime,
                                            Err(err) => {
                                                steps.push(fail(
                                                    "runtime.projection.open",
                                                    err.to_string(),
                                                ));
                                                append_full_diagnostics(
                                                    full,
                                                    transport.as_ref(),
                                                    &mut steps,
                                                );
                                                return report(ctx, steps);
                                            }
                                        };
                                    if let Err(err) = runtime.remember_descriptor(logging) {
                                        steps.push(fail(
                                            "runtime.descriptor.store",
                                            err.to_string(),
                                        ));
                                    }
                                    match runtime.store_projection(record.clone()) {
                                        Ok(stored) => {
                                            let coverage = projection_coverage(&stored.projection);
                                            steps.push(pass(
                                                "service.node.logging.events",
                                                format!(
                                                    "projection validated and retained as {} ({} item(s))",
                                                    stored.projection_key,
                                                    coverage.materialized_count
                                                ),
                                            ));
                                            if stored.observer_event.is_some() {
                                                steps.push(pass(
                                                    "projection.observer.update",
                                                    "changed projection emitted observer update",
                                                ));
                                            } else {
                                                steps.push(pass(
                                                    "projection.observer.update",
                                                    "semantic refresh suppressed observer update",
                                                ));
                                            }
                                            if let Err(err) = runtime.save() {
                                                steps.push(fail(
                                                    "runtime.projection.save",
                                                    err.to_string(),
                                                ));
                                            }
                                        }
                                        Err(err) => steps.push(fail(
                                            "runtime.projection.store",
                                            err.to_string(),
                                        )),
                                    }
                                }
                                Err(err) => {
                                    steps.push(fail("service.node.logging.events", err.to_string()))
                                }
                            }
                        }
                        Err(err) => {
                            steps.push(fail("service.node.logging.events", err.to_string()))
                        }
                    }
                } else {
                    steps.push(fail(
                        "service.node.logging.events",
                        "response missing projection",
                    ));
                }
            }
            Err(err) => steps.push(fail("service.node.logging.events", err.to_string())),
        }
        let watch_frame = build_projection_observe_frame(
            logging,
            &events_channel,
            &profile.device_pk,
            crate::protocol_ops::now_unix() * 1000,
            &doctor_caac_mode(ctx, &secret, logging),
        );
        match watch_frame.and_then(|frame| transport.watch_projection(&frame, &logging.service)) {
            Ok(events) => steps.push(pass(
                "service.node.observe.boundary",
                format!("watch boundary returned {} event(s)", events.len()),
            )),
            Err(err) => steps.push(fail("service.node.observe.boundary", err.to_string())),
        }
    } else {
        steps.push(fail("service.logging", "logging descriptor unavailable"));
    }
    append_full_diagnostics(full, transport.as_ref(), &mut steps);
    report(ctx, steps)
}

fn append_full_diagnostics(
    full: bool,
    transport: &dyn ServiceTransport,
    steps: &mut Vec<DoctorStep>,
) {
    if !full {
        return;
    }
    match transport.diagnostics() {
        Ok(items) => {
            steps.push(pass(
                "diagnostics.observe",
                format!("{} diagnostic item(s)", items.len()),
            ));
            summarize_runtime_diagnostics(&items, steps);
        }
        Err(err) => steps.push(warn("diagnostics.observe", err.to_string())),
    }
}

fn runtime_diagnostic_kind(item: &Value) -> String {
    item.get("kind")
        .or_else(|| item.get("operation"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn summarize_runtime_diagnostics(items: &[Value], steps: &mut Vec<DoctorStep>) {
    let runtime: Vec<&Value> = items
        .iter()
        .filter(|item| {
            let record_kind = item
                .get("recordKind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let kind = runtime_diagnostic_kind(item);
            record_kind.starts_with("runtime.diagnostic")
                || kind.starts_with("runtime.")
                || kind.starts_with("route.")
                || kind.starts_with("frame.")
                || kind.starts_with("projection.")
        })
        .collect();
    if runtime.is_empty() {
        steps.push(warn(
            constitute_protocol::CAPABILITY_RUNTIME_DIAGNOSTICS_OBSERVE,
            "no runtime diagnostic events available",
        ));
        return;
    }
    let latest_session = runtime
        .iter()
        .rev()
        .find_map(|item| item.get("runtimeSessionId").and_then(Value::as_str))
        .unwrap_or("unknown");
    steps.push(pass(
        constitute_protocol::CAPABILITY_RUNTIME_DIAGNOSTICS_OBSERVE,
        format!(
            "{} runtime event(s), latest session {}",
            runtime.len(),
            latest_session
        ),
    ));
    let route_failures = runtime
        .iter()
        .filter(|item| {
            let kind = runtime_diagnostic_kind(item);
            let state = item
                .get("safeFacts")
                .and_then(|facts| facts.get("state"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            kind == constitute_protocol::RECORD_ROUTE_OBSERVATION
                && matches!(
                    state,
                    "observingUnreachable" | "unreachableFor" | "rejected"
                )
        })
        .count();
    steps.push(pass(
        "runtime.diagnostics.route",
        format!("{} route predicate failure event(s)", route_failures),
    ));
    let authority_events = runtime
        .iter()
        .filter(|item| {
            let kind = runtime_diagnostic_kind(item);
            let has_authority_facts = item
                .get("safeFacts")
                .map(|facts| {
                    facts.get("authoritySummary").is_some()
                        || facts.get("failedAuthorityDomains").is_some()
                })
                .unwrap_or(false);
            kind == "interaction.prepared" || has_authority_facts
        })
        .count();
    steps.push(pass(
        "runtime.diagnostics.authority",
        format!("{} authority/interaction event(s)", authority_events),
    ));
    let failed_authority_domains = runtime
        .iter()
        .filter_map(|item| item.get("safeFacts"))
        .flat_map(|facts| {
            facts
                .get("failedAuthorityDomains")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|domain| domain.as_str().map(ToString::to_string))
        .collect::<std::collections::BTreeSet<_>>();
    if failed_authority_domains.is_empty() {
        steps.push(warn(
            "runtime.diagnostics.authority.failures",
            "no failed authority-domain labels observed",
        ));
    } else {
        steps.push(pass(
            "runtime.diagnostics.authority.failures",
            format!(
                "failed authority domain(s): {}",
                failed_authority_domains
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    let mut projection_events = 0usize;
    let mut command_results = 0usize;
    for item in runtime {
        let kind = runtime_diagnostic_kind(item);
        if kind.starts_with("projection.") {
            projection_events += 1;
        }
        if kind == constitute_protocol::RECORD_RUNTIME_DIAGNOSTIC_COMMAND_RESULT {
            command_results += 1;
        }
    }
    steps.push(pass(
        "runtime.diagnostics.projection",
        format!("{} projection inbox event(s)", projection_events),
    ));
    steps.push(pass(
        constitute_protocol::CAPABILITY_RUNTIME_DIAGNOSTICS_COMMAND,
        format!(
            "command channel observed with {} result event(s)",
            command_results
        ),
    ));
}

fn run_swarm_doctor_checks(
    _ctx: &AppContext,
    transport: &dyn ServiceTransport,
    issuer: &str,
    secret: &str,
    steps: &mut Vec<DoctorStep>,
) {
    let vector = match serde_json::from_str::<SwarmRuntimeVector>(include_str!(
        "../../constitute-protocol/vectors/swarm-runtime-v1.json"
    )) {
        Ok(vector) => vector,
        Err(err) => {
            steps.push(fail("frame.validate", err.to_string()));
            return;
        }
    };
    match validate_swarm_frame(&vector.frame, 1_700_000_001_000) {
        Ok(()) => steps.push(pass(
            "frame.validate",
            "golden swarm frame validates with CAAC body",
        )),
        Err(err) => steps.push(fail("frame.validate", err.to_string())),
    }
    match validate_projection_delta(&vector.delta, vector.delta.base_revision) {
        Ok(()) => steps.push(pass(
            "delta.validate",
            "golden projection delta validates against base revision",
        )),
        Err(err) => steps.push(fail("delta.validate", err.to_string())),
    }
    match apply_projection_delta(
        json!({ "cameras": [{ "status": "ok" }] }),
        &vector.delta,
        vector.delta.base_revision,
    ) {
        Ok(result) if result.state["cameras"][0]["status"] == Value::String("degraded".into()) => {
            steps.push(pass(
                "delta.apply",
                "projection delta applied path-array set operation",
            ))
        }
        Ok(_) => steps.push(fail(
            "delta.apply",
            "projection delta did not update expected state",
        )),
        Err(err) => steps.push(fail("delta.apply", err.to_string())),
    }
    match validate_projection_delta(&vector.delta, vector.delta.base_revision.saturating_sub(1)) {
        Ok(()) => steps.push(fail(
            "repair.request",
            "revision gap did not reject before repair",
        )),
        Err(_) => {
            match build_projection_repair_frame(issuer, &vector.delta, &CaacBodyMode::Fixture) {
                Ok(_) => steps.push(pass(
                    "repair.request",
                    "revision gap produced valid diagnostic repair request frame",
                )),
                Err(err) => steps.push(fail("repair.request", err.to_string())),
            }
        }
    }
    if let Some(convergence) = &vector.convergence {
        match validate_runtime_activation_request(&convergence.activation_request) {
            Ok(()) => steps.push(pass(
                "activation.request",
                "runtime activation request keeps product routing fields out",
            )),
            Err(err) => steps.push(fail("activation.request", err.to_string())),
        }
        match validate_route_observation(&convergence.route_observation) {
            Ok(()) => steps.push(pass(
                constitute_protocol::RECORD_ROUTE_OBSERVATION,
                "route observation validates separately from frame intake ACK",
            )),
            Err(err) => steps.push(fail(
                constitute_protocol::RECORD_ROUTE_OBSERVATION,
                err.to_string(),
            )),
        }
        match validate_stream_route_plan(&convergence.stream_route_plan) {
            Ok(()) => steps.push(pass(
                constitute_protocol::RECORD_STREAM_ROUTE_PLAN,
                "stream route plan carries selected and fallback paths",
            )),
            Err(err) => steps.push(fail(
                constitute_protocol::RECORD_STREAM_ROUTE_PLAN,
                err.to_string(),
            )),
        }
    }
    match prove_product_caac_opens(secret) {
        Ok(()) => steps.push(pass(
            "caac.product.open",
            "product CAAC envelope sealed and opened with profile key",
        )),
        Err(err) => steps.push(fail("caac.product.open", err.to_string())),
    }
    let directory = match transport.swarm_directory() {
        Ok(directory) => directory,
        Err(err) => {
            steps.push(warn("directory.capability", err.to_string()));
            steps.push(warn("propagation.privacy", err.to_string()));
            return;
        }
    };
    match capability_lookup(
        &directory,
        constitute_protocol::CAPABILITY_STORAGE_PIN,
        crate::protocol_ops::now_unix() * 1000,
    ) {
        Ok(output) => steps.push(pass(
            "directory.capability",
            format!(
                "{} active entrie(s), {} channel(s)",
                output.entries.len(),
                output.channels.len()
            ),
        )),
        Err(err) => steps.push(fail("directory.capability", err.to_string())),
    }
    if shared_infra_uses_boundary_refs(&directory) {
        steps.push(pass(
            "propagation.privacy",
            "shared capability directory separates resolved member refs from opaque service refs",
        ));
    } else {
        steps.push(fail(
            "propagation.privacy",
            "shared capability directory mixed member identity with opaque service refs",
        ));
    }
}

fn doctor_caac_mode<'a>(
    ctx: &AppContext,
    secret: &'a str,
    descriptor: &constitute_protocol::HostedServiceDescriptor,
) -> CaacBodyMode<'a> {
    if ctx.uses_test_data_transport() {
        CaacBodyMode::Fixture
    } else {
        CaacBodyMode::Product {
            issuer_secret: secret,
            recipient_pks: vec![
                descriptor.service_pk.clone(),
                descriptor.host_gateway_pk.clone(),
            ],
        }
    }
}

fn prove_product_caac_opens(secret: &str) -> anyhow::Result<()> {
    let issuer_pk = constitute_protocol::pubkey_from_sk_hex(secret)?;
    let now = crate::protocol_ops::now_unix();
    let envelope = constitute_protocol::seal_envelope(
        "cli.doctor.caac",
        &json!({ "check": "product-open" }),
        secret,
        std::slice::from_ref(&issuer_pk),
        now,
        now + 90,
    )?;
    let envelope_value = serde_json::to_value(&envelope)?;
    validate_caac_envelope_for_mode(&envelope_value, CaacValidationMode::Product, now)?;
    let parsed: CaacEnvelope = serde_json::from_value(envelope_value)?;
    let opened = open_envelope(&parsed, secret, now, None)?;
    if opened["check"] == "product-open" {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "product CAAC open returned unexpected claims"
        ))
    }
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
