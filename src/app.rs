// domain-owned-vocabulary: runtime.diagnostic runtime.diagnostics service.node.snapshot
use std::io::Write;

use anyhow::{Context, Result, anyhow};
use constitute_protocol::{
    HostedServiceDescriptor, ProjectionRecord, ServiceNodeSetRequest, ServiceSurfaceProjection,
    generate_keypair, validate_hosted_service_descriptor, validate_projection_record,
    validate_service_node_set_request, validate_service_surface,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::*;
use crate::config::{
    PendingEnrollment, ProfileRecord, delete_profile, list_profiles, load_profile, save_profile,
};
use crate::doctor::run_doctor;
use crate::interactive;
use crate::keystore::{delete_secret, load_secret, store_secret};
use crate::output::{print_json, print_value};
use crate::pairing::{make_pair_code, start_output, wait_for_pairing};
use crate::protocol_ops::{build_signed_frame, now_unix, parse_payload, verify_frame_signature};
use crate::runtime::{RuntimeStore, projection_coverage};
use crate::swarm_ops::{
    CaacBodyMode, build_channel_create_frame, build_projection_observe_frame,
    build_service_intent_frame, capability_lookup, channel_list,
};
use crate::transport::{ServiceTransport, open_transport, write_default_fixtures};

pub use crate::config::AppContext;

pub fn run_command(ctx: AppContext, cli: Cli) -> Result<()> {
    match cli.command {
        None => interactive::run(),
        Some(Command::Auth(command)) => run_auth(ctx, command),
        Some(Command::Service(command)) => run_service(ctx, command),
        Some(Command::Capability(command)) => run_capability(ctx, command),
        Some(Command::Channel(command)) => run_channel(ctx, command),
        Some(Command::Diagnostics(command)) => run_diagnostics(ctx, command),
        Some(Command::Protocol(command)) => run_protocol(ctx, command),
        Some(Command::Config(command)) => run_config(ctx, command),
        Some(Command::Doctor(args)) => {
            let report = run_doctor(&ctx, args.full);
            print_value(ctx.json, &report, || human_doctor(&report))?;
            if report.status == "fail" {
                Err(anyhow!("doctor failed"))
            } else {
                Ok(())
            }
        }
    }
}

fn run_diagnostics(ctx: AppContext, command: DiagnosticsCommand) -> Result<()> {
    match command.command {
        DiagnosticsSubcommand::Runtime(args) => {
            let transport = open_cli_transport(&ctx)?;
            let raw = transport.diagnostics()?;
            let since_ms = parse_duration_ms(args.since.as_deref()).unwrap_or(0);
            let cutoff = if since_ms > 0 {
                Some(now_millis().saturating_sub(since_ms))
            } else {
                None
            };
            let surface_filter = args.surface.unwrap_or_default();
            let surface_filter = surface_filter.trim().to_string();
            let mut events: Vec<Value> = Vec::new();
            for event in raw {
                if !is_runtime_diagnostic_event(&event) {
                    continue;
                }
                if !surface_filter.is_empty() {
                    let surface_matches = event
                        .get("surface")
                        .and_then(Value::as_str)
                        .map(|surface| surface == surface_filter)
                        .unwrap_or(false);
                    if !surface_matches {
                        continue;
                    }
                }
                if let Some(cutoff) = cutoff {
                    let within_window = event_time_ms(&event)
                        .map(|value| value >= cutoff)
                        .unwrap_or(true);
                    if !within_window {
                        continue;
                    }
                }
                events.push(event);
            }
            let output = json!({
                "status": "ok",
                "kind": "runtime.diagnostics",
                "count": events.len(),
                "filters": {
                    "since": args.since,
                    "surface": if surface_filter.is_empty() { Value::Null } else { Value::String(surface_filter) },
                },
                "events": events,
            });
            print_value(ctx.json, &output, || human_runtime_diagnostics(&output))
        }
    }
}

fn run_capability(ctx: AppContext, command: CapabilityCommand) -> Result<()> {
    let transport = open_cli_transport(&ctx)?;
    let directory = transport.swarm_directory()?;
    let output = capability_lookup(&directory, &command.name, now_unix() * 1000)?;
    print_value(ctx.json, &output, || human_capability(&output))
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_duration_ms(value: Option<&str>) -> Option<u64> {
    let text = value?.trim();
    if text.is_empty() {
        return None;
    }
    let (number, unit): (String, String) = text.chars().partition(|ch| ch.is_ascii_digit());
    let amount: u64 = number.parse().ok()?;
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "ms" => 1,
        "s" | "sec" | "secs" | "second" | "seconds" => 1_000,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_000,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        _ => return None,
    };
    Some(amount.saturating_mul(multiplier))
}

fn event_time_ms(event: &Value) -> Option<u64> {
    let value = event
        .get("observedAt")
        .or_else(|| event.get("occurredAt"))
        .or_else(|| event.get("timestamp"))
        .and_then(Value::as_u64)?;
    if value > 9_999_999_999 {
        Some(value)
    } else {
        Some(value.saturating_mul(1_000))
    }
}

fn is_runtime_diagnostic_event(event: &Value) -> bool {
    let record_kind = event
        .get("recordKind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = event
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let operation = event
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or_default();
    record_kind.starts_with("runtime.diagnostic")
        || kind.starts_with("runtime.")
        || kind.starts_with("route.")
        || kind.starts_with("frame.")
        || kind.starts_with("projection.")
        || operation.starts_with("runtime.")
}

fn human_runtime_diagnostics(output: &Value) -> String {
    let count = output.get("count").and_then(Value::as_u64).unwrap_or(0);
    let mut lines = vec![format!("runtime diagnostics {count} event(s)")];
    if let Some(events) = output.get("events").and_then(Value::as_array) {
        for event in events.iter().take(12) {
            let kind = event
                .get("kind")
                .or_else(|| event.get("operation"))
                .and_then(Value::as_str)
                .unwrap_or("runtime.diagnostic");
            let level = event.get("level").and_then(Value::as_str).unwrap_or("info");
            let surface = event.get("surface").and_then(Value::as_str).unwrap_or("");
            lines.push(format!("{level} {kind} {surface}").trim().to_string());
        }
    }
    lines.join("\n")
}

fn run_channel(ctx: AppContext, command: ChannelCommand) -> Result<()> {
    match command.command {
        ChannelSubcommand::List(args) => {
            let transport = open_cli_transport(&ctx)?;
            let directory = transport.swarm_directory()?;
            let output = channel_list(&directory, &args.capability, now_unix() * 1000)?;
            print_value(ctx.json, &output, || human_channel_list(&output))
        }
        ChannelSubcommand::Create(args) => {
            let (profile, secret) = if ctx.uses_test_data_transport() {
                (None, None)
            } else {
                let (profile, secret) = load_profile_and_secret(&ctx)?;
                (Some(profile), Some(secret))
            };
            let transport = open_cli_transport_with_profile(&ctx, profile.clone(), secret.clone());
            let directory = transport.swarm_directory()?;
            let issuer = profile
                .as_ref()
                .map(|profile| profile.device_pk.clone())
                .unwrap_or_else(|| "member-raw-cli".to_string());
            let body_mode = caac_body_mode(&ctx, secret.as_deref(), &[]);
            let frame = build_channel_create_frame(
                &directory,
                &args.capability,
                &issuer,
                now_unix() * 1000,
                &body_mode,
            )?;
            let publication = transport.publish_frame(&frame)?;
            if !ctx.uses_test_data_transport() {
                return print_value(ctx.json, &publication, || {
                    serde_json::to_string_pretty(&publication).unwrap_or_default()
                });
            }
            print_value(ctx.json, &frame, || {
                serde_json::to_string_pretty(&frame).unwrap_or_default()
            })
        }
    }
}

fn run_auth(ctx: AppContext, command: AuthCommand) -> Result<()> {
    match command.command {
        AuthSubcommand::Login(args) => auth_login(ctx, args),
        AuthSubcommand::Wait(args) => auth_wait(ctx, args),
        AuthSubcommand::Status => {
            let profile = load_profile(&ctx.config_dir, &ctx.profile)?;
            print_value(ctx.json, &profile, || {
                let enrollment = if profile.pending_enrollment.is_some() {
                    "\nenrollment pending"
                } else {
                    ""
                };
                format!(
                    "profile {}\ndevice {}\naccount {}\ngateway {}\nkey store {}{}",
                    profile.profile,
                    profile.device_pk,
                    profile.account_pk.as_deref().unwrap_or("not associated"),
                    profile.gateway_pk.as_deref().unwrap_or("not set"),
                    profile.key_store.kind,
                    enrollment
                )
            })
        }
        AuthSubcommand::Logout => {
            let profile = load_profile(&ctx.config_dir, &ctx.profile).ok();
            delete_secret(
                &ctx.config_dir,
                &ctx.profile,
                profile.as_ref().map(|p| &p.key_store),
            )?;
            delete_profile(&ctx.config_dir, &ctx.profile)?;
            println!("profile {} removed", ctx.profile);
            Ok(())
        }
        AuthSubcommand::Profiles => {
            let profiles = list_profiles(&ctx.config_dir)?;
            print_value(ctx.json, &profiles, || profiles.join("\n"))
        }
        AuthSubcommand::Use { profile_name } => {
            let profile = load_profile(&ctx.config_dir, &profile_name)?;
            print_value(ctx.json, &profile, || {
                format!(
                    "profile {} is available; pass --profile {}",
                    profile.profile, profile.profile
                )
            })
        }
    }
}

fn auth_login(ctx: AppContext, args: AuthLoginArgs) -> Result<()> {
    let existing = load_profile(&ctx.config_dir, &ctx.profile).ok();
    if existing.is_some() && !args.force {
        return Err(anyhow!("profile already exists; pass --force to replace"));
    }
    if !args.manual && profile_relays_empty(&args.relays) {
        return Err(anyhow!("at least one --relay is required for pairing auth"));
    }
    let passphrase_arg = args.passphrase;
    let key_store = args.key_store;
    let is_manual = args.manual;
    let account_pk = args.account_pk;
    let gateway_pk = args.gateway_pk;
    let relays = args.relays;
    let local_gateway = args.local_gateway;
    let device_label = args.device_label;
    let (device_pk, device_sk) = generate_keypair();
    let passphrase = passphrase_arg.as_deref().or(ctx.passphrase.as_deref());
    let key_ref = store_secret(
        &ctx.config_dir,
        &ctx.profile,
        &device_pk,
        &device_sk,
        key_store,
        passphrase,
    )?;
    let now = crate::protocol_ops::now_unix();
    let profile = ProfileRecord {
        schema_version: 1,
        profile: ctx.profile.clone(),
        device_pk: device_pk.clone(),
        account_pk: if is_manual { account_pk } else { None },
        gateway_pk: if is_manual { gateway_pk } else { None },
        relays,
        local_gateway_hint: local_gateway,
        pending_enrollment: if is_manual {
            None
        } else {
            Some(PendingEnrollment {
                code: make_pair_code(),
                device_label,
                created_at: now,
                expires_at: now + 10 * 60,
            })
        },
        key_store: key_ref,
        created_at: now,
    };
    save_profile(&ctx.config_dir, &profile)?;
    if is_manual {
        print_value(ctx.json, &profile, || {
            format!(
                "profile {} created for device {}",
                profile.profile, profile.device_pk
            )
        })
    } else {
        let output = start_output(&profile)?;
        print_value(ctx.json, &output, || {
            format!(
                "pairing code {}\nclaim this code from an already-linked account device, then run: {}",
                output.code, output.next_command
            )
        })
    }
}

fn auth_wait(ctx: AppContext, args: AuthWaitArgs) -> Result<()> {
    let (mut profile, secret) = load_profile_and_secret(&ctx)?;
    let output = wait_for_pairing(&profile, &secret, args.timeout_secs)?;
    profile.account_pk = Some(output.identity_id.clone());
    profile.pending_enrollment = None;
    save_profile(&ctx.config_dir, &profile)?;
    print_value(ctx.json, &output, || {
        format!(
            "profile {} associated with {} ({})",
            output.profile, output.identity_label, output.identity_id
        )
    })
}

fn profile_relays_empty(relays: &[String]) -> bool {
    relays.iter().all(|relay| relay.trim().is_empty())
}

fn run_service(ctx: AppContext, command: ServiceCommand) -> Result<()> {
    let mut path = Vec::new();
    let mut desired = serde_json::Map::new();
    for token in command.path {
        if let Some((field, value)) = token.split_once('=') {
            let key = field.trim();
            if key.is_empty() {
                return Err(anyhow!("set fields must use field=value"));
            }
            desired.insert(key.to_string(), parse_field_value(value));
        } else {
            path.push(token);
        }
    }
    if path.is_empty() {
        return run_service_catalog(ctx);
    }

    let (profile, _secret) = load_profile_and_secret(&ctx)?;
    let issuer = profile.device_pk.clone();
    let transport = open_cli_transport_with_profile(&ctx, Some(profile), Some(_secret.clone()));
    let mut runtime = RuntimeStore::open(&ctx.config_dir, &ctx.profile)?;
    let descriptors = transport.descriptor_list()?;
    let resolved = resolve_service_path(&descriptors, &path)?;
    let descriptor = resolved.descriptor;
    validate_hosted_service_descriptor(&descriptor)?;
    runtime.remember_descriptor(&descriptor)?;
    let surface = fetch_service_surface(
        &ctx,
        transport.as_ref(),
        &issuer,
        &_secret,
        &descriptor,
        &mut runtime,
    )?;
    if resolved.node_path.is_empty() {
        runtime.save()?;
        let output = service_detail_value(&descriptor, &surface);
        return print_value(ctx.json, &output, || human_service_detail(&output));
    }
    let node = constitute_protocol::find_service_node(&surface, &resolved.node_path)
        .ok_or_else(|| anyhow!("service node not found: {}", resolved.node_path))?
        .clone();
    if !desired.is_empty() {
        let req = ServiceNodeSetRequest {
            request_id: format!("cli-set-{}", uuid::Uuid::new_v4()),
            service: descriptor.service.clone(),
            node_path: node.path.clone(),
            desired: Value::Object(desired),
        };
        validate_service_node_set_request(&req, &surface)?;
        let frame = build_service_intent_frame(
            &descriptor,
            &node.backing_channel,
            &issuer,
            serde_json::to_value(req)?,
            now_unix() * 1000,
            &caac_body_mode(&ctx, Some(&_secret), &descriptor_recipients(&descriptor)),
        )?;
        let value = transport.publish_frame(&frame)?;
        runtime.save()?;
        return print_value(ctx.json, &value, || {
            serde_json::to_string_pretty(&value).unwrap_or_default()
        });
    }
    let channel = node.backing_channel.trim();
    if channel.is_empty() {
        return Err(anyhow!("service node has no backing projection channel"));
    }
    if command.observe {
        emit_watch_event(
            &ctx,
            &watch_missing_snapshot_event(&descriptor.service, channel),
        )?;
    }
    let output = request_service_projection(
        &ctx,
        transport.as_ref(),
        &issuer,
        &_secret,
        &descriptor,
        Some(&surface),
        channel,
        &mut runtime,
    )?;
    runtime.save()?;
    if command.observe {
        if let Some(observer) = output.get("observer").filter(|value| !value.is_null()) {
            emit_watch_event(&ctx, observer)?;
        }
        emit_watch_event(
            &ctx,
            &json!({
                "type": "service.node.snapshot",
                "service": descriptor.service,
                "nodePath": node.path,
                "materializationBudgetRef": projection_materialization_budget_ref(&descriptor.service, channel),
                "consumerFloorRef": projection_consumer_floor_ref(&descriptor.service, channel),
                "value": output
            }),
        )?;
        Ok(())
    } else {
        print_value(ctx.json, &output, || {
            serde_json::to_string_pretty(&output).unwrap_or_default()
        })
    }
}

fn run_service_catalog(ctx: AppContext) -> Result<()> {
    let transport = open_descriptor_transport(&ctx)?;
    let descriptors = transport.descriptor_list()?;
    let mut runtime = RuntimeStore::open(&ctx.config_dir, &ctx.profile)?;
    for descriptor in &descriptors {
        validate_hosted_service_descriptor(descriptor)?;
        runtime.remember_descriptor(descriptor)?;
    }
    if let Ok(profile) = load_profile(&ctx.config_dir, &ctx.profile) {
        runtime.remember_relay_hints(&profile.relays);
    }
    runtime.save()?;
    let value = json!({
        "root": ["service", "capability", "channel", "diagnostics", "protocol", "auth", "config", "doctor", "help"],
        "locations": service_catalog_locations(&descriptors),
        "services": descriptors.iter().map(service_catalog_entry).collect::<Vec<_>>(),
    });
    print_value(ctx.json, &value, || human_service_catalog(&value))
}

fn fetch_service_surface(
    ctx: &AppContext,
    transport: &dyn ServiceTransport,
    issuer: &str,
    secret: &str,
    descriptor: &HostedServiceDescriptor,
    runtime: &mut RuntimeStore,
) -> Result<ServiceSurfaceProjection> {
    let output = request_service_projection(
        ctx,
        transport,
        issuer,
        secret,
        descriptor,
        None,
        &descriptor.surface_channel,
        runtime,
    )?;
    let projection_value = output
        .get("projection")
        .cloned()
        .ok_or_else(|| anyhow!("surface projection missing projection"))?;
    let record: ProjectionRecord = serde_json::from_value(projection_value)?;
    let surface_value = record
        .payload
        .get("surface")
        .cloned()
        .ok_or_else(|| anyhow!("surface projection missing payload.surface"))?;
    let surface: ServiceSurfaceProjection = serde_json::from_value(surface_value)?;
    validate_service_surface(&surface)?;
    Ok(surface)
}

fn request_service_projection(
    ctx: &AppContext,
    transport: &dyn ServiceTransport,
    issuer: &str,
    secret: &str,
    descriptor: &HostedServiceDescriptor,
    surface: Option<&ServiceSurfaceProjection>,
    channel: &str,
    runtime: &mut RuntimeStore,
) -> Result<Value> {
    let frame = build_projection_observe_frame(
        descriptor,
        channel,
        issuer,
        now_unix() * 1000,
        &caac_body_mode(ctx, Some(secret), &descriptor_recipients(descriptor)),
    )?;
    let value = transport.observe_projection(&frame, &descriptor.service)?;
    runtime.remember_descriptor(&descriptor)?;
    if let Some(projection) = value.get("projection") {
        let record: ProjectionRecord = serde_json::from_value(projection.clone())?;
        let allowed = descriptor_surface_channels(descriptor, surface);
        validate_projection_record(&record, &allowed)?;
        let stored = runtime.store_projection(record)?;
        let projection = stored.projection.clone();
        let observer = stored
            .observer_event
            .as_ref()
            .and_then(|event| serde_json::to_value(event).ok());
        return Ok(json!({
            "projectionKey": stored.projection_key,
            "materializationBudgetRef": projection_materialization_budget_ref(&descriptor.service, channel),
            "consumerFloorRef": projection_consumer_floor_ref(&descriptor.service, channel),
            "projection": projection,
            "freshness": projection.freshness,
            "coverage": projection_coverage(&projection),
            "observer": observer
        }));
    }
    Ok(value)
}

fn descriptor_surface_channels(
    descriptor: &HostedServiceDescriptor,
    surface: Option<&ServiceSurfaceProjection>,
) -> Vec<String> {
    let mut channels = vec![descriptor.surface_channel.clone()];
    if let Some(surface) = surface {
        for node in &surface.nodes {
            let channel = node.backing_channel.trim();
            if !channel.is_empty() && !channels.iter().any(|value| value == channel) {
                channels.push(channel.to_string());
            }
        }
    }
    channels
}

fn projection_materialization_budget_ref(service: &str, channel: &str) -> String {
    format!("materialization:{service}:{channel}:bounded-snapshot")
}

fn projection_consumer_floor_ref(service: &str, channel: &str) -> String {
    format!("consumer-floor:{service}:{channel}:cli-observer")
}

fn watch_missing_snapshot_event(service: &str, channel: &str) -> Value {
    let updated_at = now_unix() * 1000;
    json!({
        "type": constitute_protocol::RECORD_PROJECTION_SNAPSHOT,
        "service": service,
        "channelId": channel,
        "materializationBudgetRef": projection_materialization_budget_ref(service, channel),
        "consumerFloorRef": projection_consumer_floor_ref(service, channel),
        "freshness": {
            "state": "missing",
            "updatedAt": updated_at,
            "reason": "retained projection not available before live watch sync"
        },
        "coverage": {
            "materializedCount": 0,
            "completionRatio": 0.0,
            "completeSeverityBands": [],
            "syncState": "syncing"
        }
    })
}

fn emit_watch_event(ctx: &AppContext, event: &Value) -> Result<()> {
    if ctx.json {
        println!("{}", serde_json::to_string(event)?);
    } else {
        println!("{}", serde_json::to_string_pretty(event)?);
    }
    std::io::stdout().flush()?;
    Ok(())
}

#[derive(Clone, Debug)]
struct ResolvedServicePath {
    descriptor: HostedServiceDescriptor,
    node_path: String,
}

fn resolve_service_path(
    descriptors: &[HostedServiceDescriptor],
    tokens: &[String],
) -> Result<ResolvedServicePath> {
    if tokens.is_empty() {
        return Err(anyhow!("service path is required"));
    }
    let mut candidates = descriptors.to_vec();
    let mut service_index = 0usize;
    if tokens.len() >= 2 {
        let location_token = normalize_lookup(&tokens[0]);
        let service_matches = candidates
            .iter()
            .filter(|descriptor| descriptor_service_matches(descriptor, &location_token))
            .collect::<Vec<_>>();
        let service_path_is_plausible = service_matches.iter().any(|descriptor| {
            tokens
                .get(1)
                .map(|node_token| descriptor_node_matches(descriptor, node_token))
                .unwrap_or(false)
        });
        let matched = candidates
            .iter()
            .filter(|descriptor| descriptor_location_matches(descriptor, &location_token))
            .cloned()
            .collect::<Vec<_>>();
        if !matched.is_empty() && !service_path_is_plausible {
            candidates = matched;
            service_index = 1;
        }
    }
    if service_index == 0 {
        let location_count = unique_location_count(descriptors);
        if location_count > 1 {
            let maybe_matches = candidates
                .iter()
                .filter(|descriptor| {
                    descriptor_service_matches(descriptor, &normalize_lookup(&tokens[0]))
                })
                .cloned()
                .collect::<Vec<_>>();
            if maybe_matches.len() > 1 {
                return Err(anyhow!(
                    "service path is ambiguous; include location. candidates:\n{}",
                    maybe_matches
                        .iter()
                        .map(|descriptor| format!(
                            "service {} {}",
                            descriptor_location_label(descriptor),
                            service_display_label(descriptor)
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                ));
            }
        }
    }
    let service_token = tokens
        .get(service_index)
        .ok_or_else(|| anyhow!("service name is required"))?;
    let service_lookup = normalize_lookup(service_token);
    let matches = candidates
        .into_iter()
        .filter(|descriptor| descriptor_service_matches(descriptor, &service_lookup))
        .collect::<Vec<_>>();
    let descriptor = match matches.len() {
        1 => matches.into_iter().next().expect("one match"),
        0 => return Err(anyhow!("service not found: {service_token}")),
        _ => {
            return Err(anyhow!(
                "service path is ambiguous; include location. candidates:\n{}",
                matches
                    .iter()
                    .map(|descriptor| format!(
                        "service {} {}",
                        descriptor_location_label(descriptor),
                        service_display_label(descriptor)
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
    };
    let node_path = tokens
        .iter()
        .skip(service_index + 1)
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    Ok(ResolvedServicePath {
        descriptor,
        node_path,
    })
}

fn descriptor_node_matches(descriptor: &HostedServiceDescriptor, token: &str) -> bool {
    let lookup = normalize_lookup(token);
    descriptor
        .nodes
        .iter()
        .any(|node| normalize_lookup(node) == lookup)
}

fn descriptor_service_matches(descriptor: &HostedServiceDescriptor, lookup: &str) -> bool {
    let display_label = service_display_label(descriptor);
    [&descriptor.service, &descriptor.service_pk, &display_label]
        .iter()
        .any(|value| normalize_lookup(value) == lookup)
        || descriptor
            .aliases
            .iter()
            .any(|alias| normalize_lookup(alias) == lookup)
}

fn descriptor_location_matches(descriptor: &HostedServiceDescriptor, lookup: &str) -> bool {
    [
        descriptor.host_gateway_pk.as_str(),
        descriptor_location_label(descriptor).as_str(),
        descriptor
            .location
            .as_ref()
            .map(|location| location.location_id.as_str())
            .unwrap_or_default(),
    ]
    .iter()
    .any(|value| normalize_lookup(value) == lookup)
}

fn unique_location_count(descriptors: &[HostedServiceDescriptor]) -> usize {
    let mut values = descriptors
        .iter()
        .map(|descriptor| descriptor.host_gateway_pk.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values.len()
}

fn normalize_lookup(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase()
        .replace([' ', '_'], "-")
}

fn service_display_label(descriptor: &HostedServiceDescriptor) -> String {
    descriptor
        .display
        .get("name")
        .or_else(|| descriptor.display.get("deviceLabel"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| descriptor.service.clone())
}

fn descriptor_location_label(descriptor: &HostedServiceDescriptor) -> String {
    descriptor
        .location
        .as_ref()
        .map(|location| location.label.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            descriptor
                .display
                .get("location")
                .and_then(Value::as_str)
                .map(|value| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| descriptor.host_gateway_pk.clone())
}

fn service_catalog_locations(descriptors: &[HostedServiceDescriptor]) -> Vec<Value> {
    let mut locations = descriptors
        .iter()
        .map(|descriptor| {
            json!({
                "label": descriptor_location_label(descriptor),
                "gatewayPk": descriptor.host_gateway_pk,
            })
        })
        .collect::<Vec<_>>();
    locations.sort_by_key(|value| value["label"].as_str().unwrap_or_default().to_string());
    locations.dedup_by(|left, right| left["gatewayPk"] == right["gatewayPk"]);
    locations
}

fn service_catalog_entry(descriptor: &HostedServiceDescriptor) -> Value {
    json!({
        "location": descriptor_location_label(descriptor),
        "service": descriptor.service,
        "servicePk": descriptor.service_pk,
        "label": service_display_label(descriptor),
        "summary": descriptor.summary,
        "health": descriptor.health,
        "surfaceChannel": descriptor.surface_channel,
        "nodes": descriptor.nodes,
        "aliases": descriptor.aliases,
    })
}

fn service_detail_value(
    descriptor: &HostedServiceDescriptor,
    surface: &ServiceSurfaceProjection,
) -> Value {
    json!({
        "location": descriptor_location_label(descriptor),
        "service": descriptor.service,
        "servicePk": descriptor.service_pk,
        "label": service_display_label(descriptor),
        "summary": surface.summary,
        "healthNode": surface.health_node,
        "nodes": surface.nodes,
        "surfaceChannel": descriptor.surface_channel,
    })
}

fn human_service_catalog(value: &Value) -> String {
    let mut lines = vec!["service".to_string()];
    for service in value["services"].as_array().into_iter().flatten() {
        lines.push(format!(
            "{} / {} - {}",
            service["location"].as_str().unwrap_or("unknown"),
            service["label"].as_str().unwrap_or("service"),
            service["summary"].as_str().unwrap_or("")
        ));
        let nodes = service["nodes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        if !nodes.is_empty() {
            lines.push(format!("  nodes: {}", nodes.join(", ")));
        }
    }
    lines.join("\n")
}

fn human_service_detail(value: &Value) -> String {
    let mut lines = vec![format!(
        "{} / {}",
        value["location"].as_str().unwrap_or("unknown"),
        value["label"].as_str().unwrap_or("service")
    )];
    if let Some(summary) = value["summary"].as_str().filter(|value| !value.is_empty()) {
        lines.push(summary.to_string());
    }
    for node in value["nodes"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  {} - {}",
            node["path"].as_str().unwrap_or("node"),
            node["description"].as_str().unwrap_or("")
        ));
    }
    lines.join("\n")
}

fn human_capability(value: &crate::swarm_ops::CapabilityLookupOutput) -> String {
    let mut lines = vec![format!("capability {}", value.capability)];
    if !value.definition.summary.trim().is_empty() {
        lines.push(value.definition.summary.clone());
    }
    for entry in &value.entries {
        lines.push(format!(
            "  {} {}",
            entry.channel_id,
            entry
                .service_ref
                .as_deref()
                .or(entry.member_ref.as_deref())
                .unwrap_or("unbound")
        ));
    }
    lines.join("\n")
}

fn human_channel_list(value: &crate::swarm_ops::ChannelListOutput) -> String {
    let mut lines = vec![format!("channels {}", value.capability)];
    for channel in &value.channels {
        lines.push(format!(
            "  {} - {}",
            channel.channel_id, channel.display_name
        ));
    }
    lines.join("\n")
}

fn parse_field_value(raw: &str) -> Value {
    let trimmed = raw.trim();
    serde_json::from_str(trimmed).unwrap_or_else(|_| Value::String(trimmed.to_string()))
}

fn descriptor_recipients(descriptor: &HostedServiceDescriptor) -> Vec<String> {
    [
        descriptor.service_pk.as_str(),
        descriptor.host_gateway_pk.as_str(),
    ]
    .into_iter()
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(str::to_string)
    .collect()
}

fn caac_body_mode<'a>(
    ctx: &AppContext,
    secret: Option<&'a str>,
    recipient_pks: &[String],
) -> CaacBodyMode<'a> {
    if ctx.uses_test_data_transport() {
        CaacBodyMode::Fixture
    } else {
        CaacBodyMode::Product {
            issuer_secret: secret.expect("live CAAC mode requires unlocked device secret"),
            recipient_pks: recipient_pks.to_vec(),
        }
    }
}

fn run_protocol(ctx: AppContext, command: ProtocolCommand) -> Result<()> {
    match command.command {
        ProtocolSubcommand::Fixtures(fixture) => match fixture.command {
            FixtureSubcommand::Write { dir } => {
                write_default_fixtures(&dir)?;
                println!("fixtures written to {}", dir.display());
                Ok(())
            }
        },
        ProtocolSubcommand::Frame(frame) => match frame.command {
            FrameSubcommand::Decode { file } => {
                let raw = std::fs::read_to_string(file)?;
                let value: Value = serde_json::from_str(&raw)?;
                print_json(&value)
            }
            FrameSubcommand::Verify { file } => {
                let raw = std::fs::read_to_string(file)?;
                let frame: constitute_protocol::SwarmFrame = serde_json::from_str(&raw)?;
                let valid = verify_frame_signature(&frame)?;
                let result = json!({ "valid": valid });
                print_value(ctx.json, &result, || format!("valid: {valid}"))
            }
            FrameSubcommand::Sign {
                kind,
                recipient_service_pk,
                host_gateway_pk,
                payload_json,
            } => {
                let (_profile, secret) = load_profile_and_secret(&ctx)?;
                let payload = parse_payload(payload_json.as_deref())?;
                let frame = build_signed_frame(
                    &kind,
                    &secret,
                    &recipient_service_pk,
                    &host_gateway_pk,
                    payload,
                )?;
                print_value(ctx.json, &frame, || {
                    serde_json::to_string_pretty(&frame).unwrap_or_default()
                })
            }
        },
    }
}

fn run_config(ctx: AppContext, command: ConfigCommand) -> Result<()> {
    match command.command {
        ConfigSubcommand::Show => {
            let value = json!({
                "profile": ctx.profile,
                "configDir": ctx.config_dir,
                "fixtureDir": ctx.test_data_path(),
            });
            print_value(ctx.json, &value, || {
                format!(
                    "profile {}\nconfig {}",
                    value["profile"].as_str().unwrap_or("default"),
                    value["configDir"].as_str().unwrap_or("")
                )
            })
        }
    }
}

fn open_cli_transport(ctx: &AppContext) -> Result<Box<dyn ServiceTransport>> {
    if ctx.uses_test_data_transport() {
        return Ok(open_transport(ctx.transport_options(None, None)));
    }
    let (profile, secret) = load_profile_and_secret(ctx)?;
    Ok(open_cli_transport_with_profile(
        ctx,
        Some(profile),
        Some(secret),
    ))
}

fn open_descriptor_transport(ctx: &AppContext) -> Result<Box<dyn ServiceTransport>> {
    if ctx.uses_test_data_transport() {
        return Ok(open_transport(ctx.transport_options(None, None)));
    }
    let profile = load_profile(&ctx.config_dir, &ctx.profile)?;
    Ok(open_cli_transport_with_profile(ctx, Some(profile), None))
}

fn open_cli_transport_with_profile(
    ctx: &AppContext,
    profile: Option<ProfileRecord>,
    secret: Option<String>,
) -> Box<dyn ServiceTransport> {
    open_transport(ctx.transport_options(profile, secret))
}

fn load_profile_and_secret(ctx: &AppContext) -> Result<(ProfileRecord, String)> {
    let profile = load_profile(&ctx.config_dir, &ctx.profile)?;
    let secret = load_secret(
        &ctx.config_dir,
        &ctx.profile,
        &profile.key_store,
        ctx.passphrase.as_deref(),
    )
    .context("unlock profile secret")?
    .to_string();
    Ok((profile, secret))
}

fn human_doctor(report: &crate::doctor::DoctorReport) -> String {
    let mut lines = vec![format!("doctor {}", report.status)];
    for step in &report.steps {
        lines.push(format!("{} {} - {}", step.status, step.name, step.detail));
    }
    lines.join("\n")
}

#[derive(Serialize)]
#[allow(dead_code)]
struct CommandStatus<'a> {
    status: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use constitute_protocol::ServiceLocationRef;

    fn descriptor(
        service: &str,
        label: &str,
        aliases: &[&str],
        location_label: &str,
        nodes: &[&str],
    ) -> HostedServiceDescriptor {
        HostedServiceDescriptor {
            service: service.to_string(),
            service_pk: format!("{service}-pk"),
            host_gateway_pk: "gateway-pk".to_string(),
            aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            location: Some(ServiceLocationRef {
                location_id: normalize_lookup(location_label),
                label: location_label.to_string(),
                gateway_pk: "gateway-pk".to_string(),
            }),
            surface_channel: format!("{service}.surface"),
            display: json!({ "name": label }),
            summary: String::new(),
            health: json!({ "status": "ok" }),
            nodes: nodes.iter().map(|node| node.to_string()).collect(),
            retired: json!({}),
            transport_hints: json!({}),
        }
    }

    #[test]
    fn service_path_prefers_service_alias_when_next_segment_is_node() {
        let descriptors = vec![
            descriptor(
                "gateway",
                "DevGateway",
                &["Gateway"],
                "DevGateway",
                &["health", "devices"],
            ),
            descriptor(
                "logging",
                "Constitute Logging",
                &["Logging"],
                "Gateway",
                &["events"],
            ),
        ];
        let resolved = resolve_service_path(
            &descriptors,
            &["Gateway".to_string(), "devices".to_string()],
        )
        .expect("gateway devices resolves as service/node");
        assert_eq!(resolved.descriptor.service, "gateway");
        assert_eq!(resolved.node_path, "devices");
    }

    #[test]
    fn service_path_uses_location_when_next_segment_is_service_alias() {
        let descriptors = vec![
            descriptor(
                "gateway",
                "DevGateway",
                &["Gateway"],
                "DevGateway",
                &["health", "devices"],
            ),
            descriptor(
                "logging",
                "Constitute Logging",
                &["Logging"],
                "Gateway",
                &["events"],
            ),
        ];
        let resolved = resolve_service_path(
            &descriptors,
            &[
                "Gateway".to_string(),
                "Logging".to_string(),
                "events".to_string(),
            ],
        )
        .expect("gateway logging events resolves as location/service/node");
        assert_eq!(resolved.descriptor.service, "logging");
        assert_eq!(resolved.node_path, "events");
    }
}
