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
    Authority(AuthorityCommand),
    Service(ServiceCommand),
    Capability(CapabilityCommand),
    Channel(ChannelCommand),
    Diagnostics(DiagnosticsCommand),
    Protocol(ProtocolCommand),
    Config(ConfigCommand),
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
pub struct AuthorityCommand {
    #[command(subcommand)]
    pub command: AuthoritySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthoritySubcommand {
    Proof(AuthorityProofArgs),
}

#[derive(Debug, Args)]
pub struct AuthorityProofArgs {
    #[arg(long, default_value = "identity:aux")]
    pub owner_identity_ref: String,
    #[arg(long, default_value = "identity:agent-dev")]
    pub grantee_identity_ref: String,
    #[arg(long, default_value = "member:agent-dev-browser")]
    pub grantee_member_ref: String,
    #[arg(long = "subject-ref")]
    pub subject_refs: Vec<String>,
    #[arg(long = "action-grant-ref")]
    pub action_grant_refs: Vec<String>,
    #[arg(long = "access-group-ref")]
    pub access_group_refs: Vec<String>,
    #[arg(long = "access-epoch-ref")]
    pub access_epoch_refs: Vec<String>,
    #[arg(long = "private-envelope-ref")]
    pub private_envelope_refs: Vec<String>,
    #[arg(long = "revocation-ref")]
    pub revocation_refs: Vec<String>,
    #[arg(long = "evidence-ref")]
    pub evidence_refs: Vec<String>,
    #[arg(long, default_value_t = 600)]
    pub expires_secs: u64,
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
pub struct ServiceCommand {
    #[arg(long)]
    pub observe: bool,
    #[arg(value_name = "PATH", num_args = 0..)]
    pub path: Vec<String>,
}

#[derive(Debug, Args)]
pub struct CapabilityCommand {
    pub name: String,
}

#[derive(Debug, Args)]
pub struct ChannelCommand {
    #[command(subcommand)]
    pub command: ChannelSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ChannelSubcommand {
    List(ChannelListArgs),
    Create(ChannelCreateArgs),
}

#[derive(Debug, Args)]
pub struct ChannelListArgs {
    #[arg(long)]
    pub capability: String,
}

#[derive(Debug, Args)]
pub struct ChannelCreateArgs {
    #[arg(long)]
    pub capability: String,
}

#[derive(Debug, Args)]
pub struct DiagnosticsCommand {
    #[command(subcommand)]
    pub command: DiagnosticsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum DiagnosticsSubcommand {
    Runtime(RuntimeDiagnosticsArgs),
}

#[derive(Debug, Args)]
pub struct RuntimeDiagnosticsArgs {
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub surface: Option<String>,
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
pub struct ConfigCommand {
    #[command(subcommand)]
    pub command: ConfigSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ConfigSubcommand {
    Show,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub full: bool,
}
