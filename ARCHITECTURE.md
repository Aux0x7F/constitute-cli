# constitute-cli Architecture

## Role

`constitute-cli` is a native protocol client. It gives operators and automation
a terminal surface for the same service descriptor, service exchange,
projection, control, invoke, watch, and diagnostics contracts used by
first-party app/runtime flows.

It is not `constitute-protocol-cli` as a separate product. Low-level protocol
inspection exists under `constitute protocol ...`, but the product binary is
`constitute`.

## Command Modes

- No arguments: open an interactive shell using the same command registry as
  subcommand mode.
- With subcommands: execute once, print human output by default, print
  structured output with `--json`, and exit nonzero on failure.

## Identity And Profiles

Profiles live under the platform config directory unless `--config-dir` is set.

- Windows: `%APPDATA%\Constitute\cli`
- Linux: `~/.config/constitute/cli`

Profile metadata stores public device/account/gateway hints. Secret key
material is stored through a key-store abstraction:

- preferred: OS credential store
- fallback: encrypted-at-rest file using Argon2id and XChaCha20-Poly1305

The CLI generates one persistent device identity per profile. Each operation
creates short-lived service exchange frames and request IDs.

## Enrollment

`constitute auth login` creates a pending CLI device profile and prints a
six-digit pairing code. An already-linked account device claims that code from
the account pairing UI. `constitute auth wait` observes the matching relay
claim, publishes the signed `pair_request`, waits for `pair_approve`, decrypts
the returned identity association, and persists the approved profile.

`constitute auth login --manual` remains available for deterministic fixtures
and isolated tests where an existing account association is injected directly.

## Transport Boundary

Transport adapters carry generic protocol records. They must not expose or rely
on service-specific product routes. The first implementation includes fixture
transport for deterministic verification; live relay/gateway adapters attach at
the same trait boundary.

## Verification

`constitute doctor` verifies the whole configured process:

- config/profile readability
- device key unlock
- gateway/service descriptor reachability
- service describe frame roundtrip
- logging projection frame roundtrip
- projection validation
- diagnostics availability when requested
- absence of forbidden raw service semantic route usage
