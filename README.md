# constitute-cli

Protocol-native Constitution console client.

`constitute-cli` ships the `constitute` binary. It is a native operator/client
surface for account/device identity, hosted service descriptors, CAAC service
exchange frames, projections, diagnostics, and lab verification.

## Contract

- `constitute` with no arguments opens an interactive command shell.
- `constitute <subcommand> ...` runs non-interactively and exits with stable
  status codes.
- The CLI uses `constitute-protocol` records instead of hosted-service semantic
  HTTP APIs.
- Gateway is a route/attestation authority. Services own semantic projection,
  control, invoke, watch, and diagnostic behavior.

## Initial Commands

```powershell
constitute auth login --profile lab --manual --account-pk <pk> --gateway-pk <pk>
constitute auth status --profile lab
constitute service list --profile lab
constitute service describe logging --profile lab
constitute projection get logging logging.events --profile lab --json
constitute diagnostics tail --profile lab
constitute doctor --profile lab --full --json
```

For local verification without a live enrolled account, write deterministic
protocol fixtures and point commands at them:

```powershell
constitute protocol fixtures write --dir .\tmp\fixtures
constitute auth login --profile fixture --manual --account-pk fixture-account --gateway-pk fixture-gateway --key-store encrypted-file --passphrase testpass1234 --config-dir .\tmp\config
constitute doctor --profile fixture --full --json --config-dir .\tmp\config --fixture-dir .\tmp\fixtures
```

## Boundary

The CLI must not call raw service routes such as `/v1/events/search`, `/health`,
`/managed/session`, or service-owned local URLs as product APIs. Temporary
transport adapters may exist below the protocol boundary only when they carry
generic signed/sealed service frames.

