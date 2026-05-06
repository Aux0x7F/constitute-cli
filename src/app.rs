use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use constitute_protocol::{
    HostedServiceDescriptor, ProjectionRecord, SERVICE_FRAME_CONTROL_REQUEST,
    SERVICE_FRAME_DESCRIBE_REQUEST, SERVICE_FRAME_INVOKE_REQUEST, SERVICE_FRAME_PROJECTION_REQUEST,
    ServiceProjectionRequest, generate_keypair, validate_hosted_service_descriptor,
    validate_projection_record, validate_service_exchange_frame,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::*;
use crate::config::{
    ProfileRecord, default_config_dir, delete_profile, list_profiles, load_profile, save_profile,
};
use crate::doctor::run_doctor;
use crate::interactive;
use crate::keystore::{delete_secret, load_secret, store_secret};
use crate::output::{print_json, print_value};
use crate::protocol_ops::{build_signed_frame, parse_payload, verify_frame_signature};
use crate::transport::{open_transport, write_default_fixtures};

#[derive(Clone, Debug)]
pub struct AppContext {
    pub profile: String,
    pub config_dir: PathBuf,
    pub fixture_dir: Option<PathBuf>,
    pub json: bool,
    pub passphrase: Option<String>,
}

impl AppContext {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        Ok(Self {
            profile: cli.profile.clone(),
            config_dir: cli
                .config_dir
                .clone()
                .map(Ok)
                .unwrap_or_else(default_config_dir)?,
            fixture_dir: cli.fixture_dir.clone(),
            json: cli.json,
            passphrase: std::env::var("CONSTITUTE_CLI_PASSPHRASE").ok(),
        })
    }
}

pub fn run_command(ctx: AppContext, cli: Cli) -> Result<()> {
    match cli.command {
        None => interactive::run(),
        Some(Command::Auth(command)) => run_auth(ctx, command),
        Some(Command::Gateway(command)) => run_gateway(ctx, command),
        Some(Command::Service(command)) => run_service(ctx, command),
        Some(Command::Projection(command)) => run_projection(ctx, command),
        Some(Command::Diagnostics(command)) => run_diagnostics(ctx, command),
        Some(Command::Protocol(command)) => run_protocol(ctx, command),
        Some(Command::Control(command)) => run_control(ctx, command),
        Some(Command::Invoke(command)) => run_invoke(ctx, command),
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

fn run_auth(ctx: AppContext, command: AuthCommand) -> Result<()> {
    match command.command {
        AuthSubcommand::Login(args) => auth_login(ctx, args),
        AuthSubcommand::Status => {
            let profile = load_profile(&ctx.config_dir, &ctx.profile)?;
            print_value(ctx.json, &profile, || {
                format!(
                    "profile {}\ndevice {}\naccount {}\ngateway {}\nkey store {}",
                    profile.profile,
                    profile.device_pk,
                    profile.account_pk.as_deref().unwrap_or("not associated"),
                    profile.gateway_pk.as_deref().unwrap_or("not set"),
                    profile.key_store.kind
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
    if !args.manual {
        return Err(anyhow!(
            "only --manual enrollment is implemented in this slice"
        ));
    }
    let existing = load_profile(&ctx.config_dir, &ctx.profile).ok();
    if existing.is_some() && !args.force {
        return Err(anyhow!("profile already exists; pass --force to replace"));
    }
    let (device_pk, device_sk) = generate_keypair();
    let passphrase = args.passphrase.as_deref().or(ctx.passphrase.as_deref());
    let key_ref = store_secret(
        &ctx.config_dir,
        &ctx.profile,
        &device_pk,
        &device_sk,
        args.key_store,
        passphrase,
    )?;
    let profile = ProfileRecord {
        schema_version: 1,
        profile: ctx.profile.clone(),
        device_pk,
        account_pk: args.account_pk,
        gateway_pk: args.gateway_pk,
        relays: args.relays,
        local_gateway_hint: args.local_gateway,
        key_store: key_ref,
        created_at: crate::protocol_ops::now_unix(),
    };
    save_profile(&ctx.config_dir, &profile)?;
    print_value(ctx.json, &profile, || {
        format!(
            "profile {} created for device {}",
            profile.profile, profile.device_pk
        )
    })
}

fn run_gateway(ctx: AppContext, command: GatewayCommand) -> Result<()> {
    match command.command {
        GatewaySubcommand::Discover | GatewaySubcommand::Status => {
            let profile = load_profile(&ctx.config_dir, &ctx.profile).ok();
            let transport = open_transport(ctx.fixture_dir.clone());
            let descriptors = transport.descriptor_list().unwrap_or_default();
            let status = json!({
                "profile": ctx.profile,
                "gatewayPk": profile.as_ref().and_then(|p| p.gateway_pk.clone()),
                "relays": profile.as_ref().map(|p| p.relays.clone()).unwrap_or_default(),
                "transportHints": transport.transport_hints(),
                "descriptorCount": descriptors.len()
            });
            print_value(ctx.json, &status, || {
                format!(
                    "profile {}\ndescriptors {}\ntransport {}",
                    status["profile"].as_str().unwrap_or("unknown"),
                    status["descriptorCount"],
                    status["transportHints"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0)
                )
            })
        }
    }
}

fn run_service(ctx: AppContext, command: ServiceCommand) -> Result<()> {
    match command.command {
        ServiceSubcommand::List => {
            let transport = open_transport(ctx.fixture_dir.clone());
            let descriptors = transport.descriptor_list()?;
            for descriptor in &descriptors {
                validate_hosted_service_descriptor(descriptor)?;
            }
            print_value(ctx.json, &descriptors, || {
                descriptors
                    .iter()
                    .map(|d| format!("{} {}", d.service, d.service_pk))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        }
        ServiceSubcommand::Describe { service } => {
            let (profile, secret) = load_profile_and_secret(&ctx)?;
            let descriptor = descriptor_for(&ctx, &service)?;
            let frame = build_signed_frame(
                SERVICE_FRAME_DESCRIBE_REQUEST,
                &secret,
                &descriptor.service_pk,
                &descriptor.host_gateway_pk,
                json!({ "service": service, "issuer": profile.device_pk }),
            )?;
            let value = open_transport(ctx.fixture_dir.clone()).exchange(&frame)?;
            print_value(ctx.json, &value, || {
                serde_json::to_string_pretty(&value).unwrap_or_default()
            })
        }
    }
}

fn run_projection(ctx: AppContext, command: ProjectionCommand) -> Result<()> {
    match command.command {
        ProjectionSubcommand::Get {
            service,
            channel,
            limit,
            policy,
        } => {
            let (_profile, secret) = load_profile_and_secret(&ctx)?;
            let descriptor = descriptor_for(&ctx, &service)?;
            let req = ServiceProjectionRequest {
                request_id: format!("cli-projection-{}", uuid::Uuid::new_v4()),
                channel_id: channel.clone(),
                service: service.clone(),
                cursor: None,
                limit,
                filters: json!({}),
                policy: policy.map(|policy_id| constitute_protocol::ProjectionPolicy {
                    policy_id,
                    channel_id: channel.clone(),
                    service: service.clone(),
                    scope: json!({}),
                    rolling_window_hours: None,
                    max_verbosity_class: None,
                    min_severity: None,
                    excluded_verbosity_classes: vec![],
                    sync_depth_target: json!({}),
                    retention_target: json!({}),
                }),
            };
            constitute_protocol::validate_service_projection_request(&req)?;
            let frame = build_signed_frame(
                SERVICE_FRAME_PROJECTION_REQUEST,
                &secret,
                &descriptor.service_pk,
                &descriptor.host_gateway_pk,
                serde_json::to_value(req)?,
            )?;
            let value = open_transport(ctx.fixture_dir.clone()).exchange(&frame)?;
            if let Some(projection) = value.get("projection") {
                let record: ProjectionRecord = serde_json::from_value(projection.clone())?;
                validate_projection_record(&record, &descriptor.projection_channels)?;
            }
            print_value(ctx.json, &value, || {
                serde_json::to_string_pretty(&value).unwrap_or_default()
            })
        }
        ProjectionSubcommand::Watch { service, channel } => {
            let message = json!({
                "status": "notStarted",
                "service": service,
                "channel": channel,
                "detail": "watch transport attaches at the same service exchange boundary; live adapter is not configured in this slice"
            });
            print_value(ctx.json, &message, || {
                message["detail"].as_str().unwrap_or_default().to_string()
            })
        }
    }
}

fn run_diagnostics(ctx: AppContext, command: DiagnosticsCommand) -> Result<()> {
    match command.command {
        DiagnosticsSubcommand::Tail { service, trace } => {
            let mut diagnostics = open_transport(ctx.fixture_dir.clone()).diagnostics()?;
            if let Some(service) = service {
                diagnostics.retain(|item| {
                    item.get("service").and_then(Value::as_str) == Some(service.as_str())
                });
            }
            if let Some(trace) = trace {
                diagnostics.retain(|item| {
                    item.get("traceId").and_then(Value::as_str) == Some(trace.as_str())
                });
            }
            print_value(ctx.json, &diagnostics, || {
                serde_json::to_string_pretty(&diagnostics).unwrap_or_default()
            })
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
                let frame: constitute_protocol::ServiceExchangeFrame = serde_json::from_str(&raw)?;
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
                validate_service_exchange_frame(&frame)?;
                print_value(ctx.json, &frame, || {
                    serde_json::to_string_pretty(&frame).unwrap_or_default()
                })
            }
        },
    }
}

fn run_control(ctx: AppContext, command: ControlCommand) -> Result<()> {
    let (_profile, secret) = load_profile_and_secret(&ctx)?;
    let descriptor = descriptor_for(&ctx, &command.service)?;
    let payload = json!({
        "service": command.service,
        "action": command.action,
        "payload": parse_payload(command.payload_json.as_deref())?
    });
    let frame = build_signed_frame(
        SERVICE_FRAME_CONTROL_REQUEST,
        &secret,
        &descriptor.service_pk,
        &descriptor.host_gateway_pk,
        payload,
    )?;
    let value = open_transport(ctx.fixture_dir.clone()).exchange(&frame)?;
    print_value(ctx.json, &value, || {
        serde_json::to_string_pretty(&value).unwrap_or_default()
    })
}

fn run_invoke(ctx: AppContext, command: InvokeCommand) -> Result<()> {
    let (_profile, secret) = load_profile_and_secret(&ctx)?;
    let descriptor = descriptor_for(&ctx, &command.service)?;
    let payload = json!({
        "service": command.service,
        "kind": command.kind,
        "payload": parse_payload(command.payload_json.as_deref())?
    });
    let frame = build_signed_frame(
        SERVICE_FRAME_INVOKE_REQUEST,
        &secret,
        &descriptor.service_pk,
        &descriptor.host_gateway_pk,
        payload,
    )?;
    let value = open_transport(ctx.fixture_dir.clone()).exchange(&frame)?;
    print_value(ctx.json, &value, || {
        serde_json::to_string_pretty(&value).unwrap_or_default()
    })
}

fn descriptor_for(ctx: &AppContext, service: &str) -> Result<HostedServiceDescriptor> {
    open_transport(ctx.fixture_dir.clone())
        .descriptor_list()?
        .into_iter()
        .find(|d| d.service == service)
        .ok_or_else(|| anyhow!("service descriptor not found: {service}"))
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
