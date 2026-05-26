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
    Source(SourceCommand),
    Test(TestCommand),
    Lifecycle(LifecycleCommand),
    Service(ServiceCommand),
    Capability(CapabilityCommand),
    Channel(ChannelCommand),
    Diagnostics(DiagnosticsCommand),
    Protocol(ProtocolCommand),
    Config(ConfigCommand),
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
pub struct LifecycleCommand {
    #[command(subcommand)]
    pub command: LifecycleSubcommand,
}

#[derive(Debug, Args)]
pub struct TestCommand {
    #[command(subcommand)]
    pub command: TestSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum TestSubcommand {
    Run(TestRunArgs),
}

#[derive(Debug, Args)]
pub struct TestRunArgs {
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long, default_value = "test-run:native-dev:selected-flow")]
    pub run_ref: String,
    #[arg(long, default_value = "test-contract:native-dev:selected-flow")]
    pub test_contract_ref: String,
    #[arg(long, default_value = "member:operator-cli")]
    pub requester_ref: String,
    #[arg(long, default_value = "app:nvr")]
    pub app_ref: String,
    #[arg(long, default_value = "app-subversion:nvr:dev")]
    pub app_subversion_ref: String,
    #[arg(long, default_value = "profile:browser")]
    pub profile_ref: String,
    #[arg(long, default_value = "runtime:browser:shared-worker")]
    pub runtime_ref: String,
    #[arg(long, default_value = "gateway:dev")]
    pub gateway_ref: String,
    #[arg(long, default_value = "flow:nvr-preview-media:candidate")]
    pub selected_flow_ref: String,
    #[arg(
        long,
        default_value = "fulfillment:preview:nvr-preview-media-flow:decomposition"
    )]
    pub fulfillment_session_ref: String,
    #[arg(long, default_value = "edge:firefox:managed-launch")]
    pub managed_launch_edge_ref: String,
    #[arg(long, default_value = "retention:test-run:auto")]
    pub retention_policy_ref: String,
    #[arg(long = "materialization-ref")]
    pub materialization_refs: Vec<String>,
    #[arg(long = "observation-ref")]
    pub observation_refs: Vec<String>,
    #[arg(long = "evidence-ref")]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum LifecycleSubcommand {
    Request(LifecycleRequestArgs),
}

#[derive(Debug, Args)]
pub struct SourceCommand {
    #[command(subcommand)]
    pub command: SourceSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SourceSubcommand {
    Candidate(SourceCandidateArgs),
}

#[derive(Debug, Args)]
pub struct SourceCandidateArgs {
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long, default_value = "source:graph:native-dev")]
    pub source_graph_ref: String,
    #[arg(long, default_value = "source:snapshot:native-dev:current")]
    pub parent_snapshot_ref: String,
    #[arg(long, default_value = "source:candidate:native-dev:current")]
    pub candidate_ref: String,
    #[arg(long, default_value = "member:operator-cli")]
    pub author_ref: String,
    #[arg(long, default_value = "source:file:native-dev:fixture")]
    pub file_ref: String,
    #[arg(long, default_value = "source:path:native-dev:fixture")]
    pub path_ref: String,
    #[arg(long, default_value = "authoring/fixture.txt")]
    pub virtual_path: String,
    #[arg(long, default_value = "authoring candidate fixture")]
    pub content: String,
    #[arg(long, default_value = "storage:container:source-candidate")]
    pub storage_container_ref: String,
    #[arg(long = "branch-ref")]
    pub branch_refs: Vec<String>,
    #[arg(long = "writer-grant-ref")]
    pub writer_grant_refs: Vec<String>,
    #[arg(long = "authority-ref")]
    pub authority_refs: Vec<String>,
    #[arg(long = "dirty-projection-ref")]
    pub dirty_projection_refs: Vec<String>,
    #[arg(long = "evidence-ref")]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Args)]
pub struct LifecycleRequestArgs {
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long, default_value = "promote")]
    pub operation: String,
    #[arg(long, default_value = "source:snapshot:native-dev:current")]
    pub subject_ref: String,
    #[arg(long, default_value = "manager:host-fabric:lifecycle")]
    pub manager_ref: String,
    #[arg(long, default_value = "member:operator-cli")]
    pub requester_ref: String,
    #[arg(long = "service-ref")]
    pub service_refs: Vec<String>,
    #[arg(long = "capability-ref")]
    pub capability_refs: Vec<String>,
    #[arg(long = "authority-ref")]
    pub authority_refs: Vec<String>,
    #[arg(long = "grant-ref")]
    pub grant_refs: Vec<String>,
    #[arg(long = "evidence-ref")]
    pub evidence_refs: Vec<String>,
    #[arg(long = "proof-ref")]
    pub proof_refs: Vec<String>,
    #[arg(long)]
    pub release_ref: Option<String>,
    #[arg(long)]
    pub rollback_ref: Option<String>,
    #[arg(long, default_value_t = 600)]
    pub expires_secs: u64,
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
