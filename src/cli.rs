use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "constitute",
    version,
    about = "Protocol-native Constitution console client"
)]
pub struct Cli {
    #[arg(long, global = true, default_value = "default")]
    pub profile: String,
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    pub fixture_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Auth(AuthCommand),
    Gateway(GatewayCommand),
    Service(ServiceCommand),
    Projection(ProjectionCommand),
    Diagnostics(DiagnosticsCommand),
    Protocol(ProtocolCommand),
    Control(ControlCommand),
    Invoke(InvokeCommand),
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
pub struct AuthCommand {
    #[command(subcommand)]
    pub command: AuthSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthSubcommand {
    Login(AuthLoginArgs),
    Wait(AuthWaitArgs),
    Status,
    Logout,
    Profiles,
    Use { profile_name: String },
}

#[derive(Debug, Args)]
pub struct AuthLoginArgs {
    #[arg(long)]
    pub manual: bool,
    #[arg(long)]
    pub account_pk: Option<String>,
    #[arg(long)]
    pub gateway_pk: Option<String>,
    #[arg(long = "relay")]
    pub relays: Vec<String>,
    #[arg(long)]
    pub local_gateway: Option<String>,
    #[arg(long, default_value = "Constitute CLI")]
    pub device_label: String,
    #[arg(long, value_enum, default_value_t = KeyStoreChoice::OsPreferred)]
    pub key_store: KeyStoreChoice,
    #[arg(long)]
    pub passphrase: Option<String>,
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct AuthWaitArgs {
    #[arg(long, default_value_t = 180)]
    pub timeout_secs: u64,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KeyStoreChoice {
    OsPreferred,
    EncryptedFile,
}

#[derive(Debug, Args)]
pub struct GatewayCommand {
    #[command(subcommand)]
    pub command: GatewaySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum GatewaySubcommand {
    Discover,
    Status,
}

#[derive(Debug, Args)]
pub struct ServiceCommand {
    #[command(subcommand)]
    pub command: ServiceSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ServiceSubcommand {
    List,
    Describe { service: String },
}

#[derive(Debug, Args)]
pub struct ProjectionCommand {
    #[command(subcommand)]
    pub command: ProjectionSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProjectionSubcommand {
    Get {
        service: String,
        channel: String,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        policy: Option<String>,
    },
    Watch {
        service: String,
        channel: String,
    },
}

#[derive(Debug, Args)]
pub struct DiagnosticsCommand {
    #[command(subcommand)]
    pub command: DiagnosticsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum DiagnosticsSubcommand {
    Tail {
        #[arg(long)]
        service: Option<String>,
        #[arg(long)]
        trace: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct ProtocolCommand {
    #[command(subcommand)]
    pub command: ProtocolSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProtocolSubcommand {
    Fixtures(FixtureCommand),
    Frame(FrameCommand),
}

#[derive(Debug, Args)]
pub struct FixtureCommand {
    #[command(subcommand)]
    pub command: FixtureSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum FixtureSubcommand {
    Write {
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct FrameCommand {
    #[command(subcommand)]
    pub command: FrameSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum FrameSubcommand {
    Decode {
        #[arg(long)]
        file: PathBuf,
    },
    Verify {
        #[arg(long)]
        file: PathBuf,
    },
    Sign {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        recipient_service_pk: String,
        #[arg(long)]
        host_gateway_pk: String,
        #[arg(long)]
        payload_json: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct ControlCommand {
    pub service: String,
    pub action: String,
    #[arg(long)]
    pub payload_json: Option<String>,
}

#[derive(Debug, Args)]
pub struct InvokeCommand {
    pub service: String,
    pub kind: String,
    #[arg(long)]
    pub payload_json: Option<String>,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub full: bool,
}
