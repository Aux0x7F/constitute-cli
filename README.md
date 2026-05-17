# constitute-cli

`constitute-cli` provides the `constitute` terminal client for developers and
operators.

It is the native command-line surface for exploring the service catalogue,
capabilities, projections, channels, swarm edge attachment, and diagnostic flows
that also need to work outside a browser. Normal commands use swarm directory,
projection observe, and `SwarmFrame` publication operations.

The CLI is a convergence witness. It reports catalogue, frame intake, route,
projection, service, storage, and diagnostics state without becoming the owner
of browser runtime or service execution semantics.

Useful test-data checks:

```bash
constitute protocol fixtures write --dir ./tmp/fixtures
constitute --fixture-dir ./tmp/fixtures capability storage.pin
constitute --fixture-dir ./tmp/fixtures channel list --capability storage.pin
constitute --fixture-dir ./tmp/fixtures --json channel create --capability storage.pin
```

For live frame submission, enroll or inject a profile with `localGatewayHint`
pointing at the gateway swarm edge endpoint. Low-level legacy frame inspection
remains under `protocol frame`.
