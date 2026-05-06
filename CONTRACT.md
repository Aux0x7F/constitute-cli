# constitute-cli Contract

This repo follows the Constitution project contract hierarchy without exposing
local workspace details in synced repository content.

## Current

`constitute-cli` is the native Linux/Windows console client for protocol-native
operator workflows.

- Binary name: `constitute`.
- No-arg mode: interactive command shell.
- Subcommand mode: deterministic command execution with stable exit codes.
- Shared protocol source: `constitute-protocol`.
- Verification command: `constitute doctor`.

## Authority Boundaries

- CLI owns local device profile state and local secret unlock.
- CLI does not become a Gateway-specific utility.
- CLI does not call hosted-service semantic HTTP APIs directly.
- Gateway may route and attest service exchange frames.
- Services own semantic validation and projection/control/invoke/watch payloads.
- Diagnostics are explicit side-channel output, not hidden UI behavior.

## Secret Handling

- Public profile metadata may be stored as plaintext.
- Device secret material must never be written plaintext.
- OS credential storage is preferred when available.
- Encrypted-at-rest file storage is the required fallback.
- TPM wrapping is planned hardening, not a v1 dependency.

## Verification

Every significant CLI feature must be coverable by `constitute doctor` or a
dedicated protocol fixture test. `doctor --full --json` is the standard
agent/CI proof path.
