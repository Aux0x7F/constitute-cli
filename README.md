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

Authority proof:

```bash
constitute --json authority proof --grantee-member-ref member:agent-dev-cli
```

This emits a protocol-validated `authority.multiIdentity.proof` record for the
Aux-to-agent full-access proof shape. The record keeps sync, read,
write/reduce, and revoke/expire checks on their own agreement planes.

Source candidate:

```bash
constitute --json source candidate --candidate-ref source:candidate:native-dev:current
constitute --json source candidate --input ./tmp/source-candidate-input.json
```

This emits a protocol-validated `source.snapshot` candidate from typed
authoring posture flags or a typed input posture passed through `--input`. It is
a native source lifecycle surface; local files and folder mounts remain
materializations of the refs carried by the record. Input posture must declare a
supported kind such as `source.candidate.input.posture`,
`authoring.edit-intent.posture`, or `authoring.candidate-fixture.posture`; raw
command payloads are rejected at the adapter boundary.

Lifecycle request:

```bash
constitute --json lifecycle request --operation promote --subject-ref source:snapshot:native-dev:current
```

This emits a protocol-validated service-manager operation intent. Its flags
are typed posture projection at the adapter boundary, not imperative truth.
The CLI is the action adapter; lifecycle truth still reduces through
contracts, fabric posture, and selected fulfillers.

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
