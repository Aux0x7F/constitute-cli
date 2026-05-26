use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

fn write_fixture_profile(config_dir: &std::path::Path, fixture_dir: &std::path::Path) {
    Command::cargo_bin("constitute")
        .unwrap()
        .args(["protocol", "fixtures", "write", "--dir"])
        .arg(fixture_dir)
        .assert()
        .success();

    Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--profile",
            "fixture",
            "--config-dir",
            config_dir.to_str().unwrap(),
            "auth",
            "login",
            "--manual",
            "--account-pk",
            "fixture-account",
            "--gateway-pk",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--key-store",
            "encrypted-file",
            "--passphrase",
            "testpass1234",
        ])
        .assert()
        .success();
}

#[test]
fn help_exposes_protocol_native_commands() {
    let mut cmd = Command::cargo_bin("constitute").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Protocol-native Constitution console client",
        ))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("authority"))
        .stdout(predicate::str::contains("source"))
        .stdout(predicate::str::contains("test"))
        .stdout(predicate::str::contains("lifecycle"))
        .stdout(predicate::str::contains("service"))
        .stdout(predicate::str::contains("capability"))
        .stdout(predicate::str::contains("channel"))
        .stdout(predicate::str::contains("diagnostics"))
        .stdout(predicate::str::contains("protocol"))
        .stdout(predicate::str::contains("config"));
}

#[test]
fn source_candidate_outputs_protocol_source_snapshot() {
    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--json",
            "source",
            "candidate",
            "--source-graph-ref",
            "source:graph:native-dev",
            "--parent-snapshot-ref",
            "source:snapshot:native-dev:constitute-cli:parent",
            "--candidate-ref",
            "source:candidate:native-dev:constitute-cli:test",
            "--author-ref",
            "member:operator-cli",
            "--dirty-projection-ref",
            "materialized:source-index:native-dev:constitute-cli:dirty",
            "--evidence-ref",
            "proof-event:operator:authoring-candidate-fixture",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(record["kind"], constitute_protocol::RECORD_SOURCE_SNAPSHOT);
    assert_eq!(
        record["parentSnapshotRefs"][0],
        "source:snapshot:native-dev:constitute-cli:parent"
    );
    assert_eq!(
        record["candidateRefs"][0],
        "source:candidate:native-dev:constitute-cli:test"
    );
    assert_eq!(record["signaturePosture"], "devUnsigned");
    assert!(
        record["treeHashRef"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(
        record["storageObjectRefs"][0]
            .as_str()
            .unwrap()
            .starts_with("storage:object:")
    );
}

#[test]
fn source_candidate_accepts_typed_input_posture() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("source-candidate-input.json");
    std::fs::write(
        &input_path,
        serde_json::json!({
            "kind": "authoring.edit-intent.posture",
            "sourceGraphRef": "source:graph:native-dev",
            "parentSnapshotRef": "source:snapshot:native-dev:constitute-cli:parent",
            "candidateRef": "source:candidate:native-dev:constitute-cli:typed-input",
            "authorRef": "member:operator-cli",
            "fileRef": "source:file:constitute-cli:README.md",
            "pathRef": "source:path:constitute-cli:README.md",
            "virtualPath": "README.md",
            "content": "typed posture input candidate",
            "storageContainerRef": "storage:container:source-candidate:constitute-cli",
            "dirtyProjectionRefs": ["materialized:source-index:native-dev:constitute-cli:dirty"],
            "evidenceRefs": ["proof-event:operator:authoring-edit-intent"]
        })
        .to_string(),
    )
    .unwrap();

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args(["--json", "source", "candidate", "--input"])
        .arg(&input_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(record["kind"], constitute_protocol::RECORD_SOURCE_SNAPSHOT);
    assert_eq!(
        record["candidateRefs"][0],
        "source:candidate:native-dev:constitute-cli:typed-input"
    );
    assert_eq!(record["fileEntries"][0]["virtualPath"], "README.md");
    assert_eq!(
        record["evidenceRefs"][0],
        "proof-event:operator:authoring-edit-intent"
    );
}

#[test]
fn source_candidate_rejects_untyped_input_posture() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("source-candidate-input.json");
    std::fs::write(
        &input_path,
        serde_json::json!({
            "kind": "raw.command.payload",
            "candidateRef": "source:candidate:native-dev:constitute-cli:bad-input",
            "content": "not a supported source candidate posture"
        })
        .to_string(),
    )
    .unwrap();

    Command::cargo_bin("constitute")
        .unwrap()
        .args(["--json", "source", "candidate", "--input"])
        .arg(&input_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unsupported source candidate input posture kind",
        ));
}

#[test]
fn test_run_outputs_native_contract_run_materialization() {
    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--json",
            "test",
            "run",
            "--run-ref",
            "test-run:native-dev:selected-flow:fixture",
            "--test-contract-ref",
            "test-contract:native-dev:selected-flow",
            "--app-subversion-ref",
            "app-subversion:nvr:dev",
            "--profile-ref",
            "profile:browser",
            "--selected-flow-ref",
            "flow:nvr-preview-media:candidate",
            "--fulfillment-session-ref",
            "fulfillment:preview:nvr-preview-media-flow:decomposition",
            "--observation-ref",
            "observation:runtime:nvr-preview:materialized",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(record["kind"], "test.contract-run.materialization");
    assert_eq!(record["state"], "ready");
    assert_eq!(
        record["selectedFlow"]["fulfillmentSessionRef"],
        "fulfillment:preview:nvr-preview-media-flow:decomposition"
    );
    assert_eq!(record["managedLaunchIntent"]["browserFamily"], "firefox");
    assert_eq!(
        record["evidence"]["nativeContractOrchestrationProof"]["state"],
        "ready"
    );
    assert_eq!(
        record["evidence"]["liveFirefoxProof"]["state"],
        "evidenceMaterialized"
    );
    assert_eq!(record["safeFacts"]["workspaceOpsIsAdapterOnly"], true);
    assert_eq!(
        record["safeFacts"]["nativeProofCanCoverContractAndOrchestrationWithoutFirefox"],
        true
    );
}

#[test]
fn test_run_accepts_typed_contract_run_input_posture() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("contract-run-input.json");
    std::fs::write(
        &input_path,
        serde_json::json!({
            "kind": "test.contract-run.input.posture",
            "runRef": "test-run:native-dev:selected-flow:typed",
            "testContractRef": "test-contract:native-dev:selected-flow",
            "appRef": "app:nvr",
            "appSubversionRef": "app-subversion:nvr:typed",
            "profileRef": "profile:browser",
            "runtimeRef": "runtime:browser:shared-worker",
            "gatewayRef": "gateway:dev",
            "selectedFlowRef": "flow:nvr-preview-media:candidate",
            "fulfillmentSessionRef": "fulfillment:preview:nvr-preview-media-flow:decomposition",
            "managedLaunchEdgeRef": "edge:firefox:managed-launch",
            "retentionPolicyRef": "retention:test-run:auto",
            "materializationRefs": ["materialization:test-contract-run:typed"],
            "evidenceRefs": ["evidence:contract-run:orchestration"],
            "observationRefs": []
        })
        .to_string(),
    )
    .unwrap();

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args(["--json", "test", "run", "--input"])
        .arg(&input_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(record["kind"], "test.contract-run.materialization");
    assert_eq!(record["runRef"], "test-run:native-dev:selected-flow:typed");
    assert_eq!(record["appSubversionRef"], "app-subversion:nvr:typed");
    assert_eq!(record["evidence"]["liveFirefoxProof"]["state"], "pending");
    assert_eq!(
        record["materialization"]["materializationRefs"][0],
        "materialization:test-contract-run:typed"
    );
}

#[test]
fn test_run_rejects_untyped_contract_run_input_posture() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("contract-run-input.json");
    std::fs::write(
        &input_path,
        serde_json::json!({
            "kind": "raw.browser-proof.payload",
            "runRef": "test-run:native-dev:selected-flow:bad"
        })
        .to_string(),
    )
    .unwrap();

    Command::cargo_bin("constitute")
        .unwrap()
        .args(["--json", "test", "run", "--input"])
        .arg(&input_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unsupported test run input posture kind",
        ));
}

#[test]
fn lifecycle_request_outputs_service_manager_operation_intent() {
    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--json",
            "lifecycle",
            "request",
            "--operation",
            "promote",
            "--subject-ref",
            "source:snapshot:native-dev:constitute-build:head",
            "--service-ref",
            "service:build",
            "--evidence-ref",
            "proof-event:operator:cli-lifecycle-bridge",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        record["kind"],
        constitute_protocol::RECORD_SERVICE_MANAGER_OPERATION_POSTURE
    );
    assert_eq!(record["operation"], "promote");
    assert_eq!(record["state"], "requested");
    assert_eq!(
        record["subjectRef"],
        "source:snapshot:native-dev:constitute-build:head"
    );
    assert_eq!(record["safeFacts"]["cliIsActionAdapter"], true);
    assert_eq!(record["safeFacts"]["operatorOwnsLifecycleTruth"], false);
    assert_eq!(record["safeFacts"]["typedFlagsArePostureProjection"], true);
    assert_eq!(record["safeFacts"]["commandLineIsAdapterTransport"], true);
}

#[test]
fn authority_proof_outputs_multi_identity_contract() {
    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--json",
            "authority",
            "proof",
            "--owner-identity-ref",
            "identity:aux",
            "--grantee-identity-ref",
            "identity:agent-dev",
            "--grantee-member-ref",
            "member:agent-dev-cli",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let proof: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        proof["kind"],
        constitute_protocol::RECORD_AUTHORITY_MULTI_IDENTITY_PROOF
    );
    assert_eq!(proof["ownerIdentityRef"], "identity:aux");
    assert_eq!(proof["granteeIdentityRef"], "identity:agent-dev");
    assert_eq!(proof["granteeMemberRef"], "member:agent-dev-cli");
    assert_eq!(
        proof["state"],
        constitute_protocol::AUTHORITY_PROOF_STATE_PROVED
    );

    let checks = proof["checks"].as_array().unwrap();
    assert!(checks.iter().any(|check| {
        check["check"] == constitute_protocol::AUTHORITY_PROOF_CHECK_SYNC
            && check["plane"] == constitute_protocol::AGREEMENT_PLANE_DELIVERY_WITNESS
    }));
    assert!(checks.iter().any(|check| {
        check["check"] == constitute_protocol::AUTHORITY_PROOF_CHECK_READ
            && check["plane"] == constitute_protocol::AGREEMENT_PLANE_ACCESS_AUTHORITY
    }));
    assert!(checks.iter().any(|check| {
        check["check"] == constitute_protocol::AUTHORITY_PROOF_CHECK_WRITE_REDUCE
            && check["plane"] == constitute_protocol::AGREEMENT_PLANE_ACTION_AUTHORITY
    }));
    assert!(checks.iter().any(|check| {
        check["check"] == constitute_protocol::AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE
            && check["plane"] == constitute_protocol::AGREEMENT_PLANE_ACTION_AUTHORITY
    }));
}

#[test]
fn fixture_doctor_verifies_full_protocol_flow() {
    let root = tempdir().unwrap();
    let config_dir = root.path().join("config");
    let fixture_dir = root.path().join("fixtures");

    write_fixture_profile(&config_dir, &fixture_dir);

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--profile",
            "fixture",
            "--config-dir",
            config_dir.to_str().unwrap(),
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "doctor",
            "--full",
        ])
        .env("CONSTITUTE_CLI_PASSPHRASE", "testpass1234")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["status"], "pass");
    let steps = report["steps"].as_array().unwrap();
    assert!(steps.iter().any(|s| s["name"] == "service.surface.logging"));
    assert!(
        steps
            .iter()
            .any(|s| s["name"] == "service.node.logging.events")
    );
    assert!(
        steps
            .iter()
            .any(|s| s["name"] == "projection.observer.update")
    );
    assert!(
        steps
            .iter()
            .any(|s| s["name"] == "service.node.observe.boundary")
    );
    assert!(steps.iter().any(|s| s["name"] == "diagnostics.observe"));
    assert!(
        steps
            .iter()
            .any(|s| s["name"] == constitute_protocol::CAPABILITY_RUNTIME_DIAGNOSTICS_OBSERVE)
    );
    assert!(
        steps
            .iter()
            .any(|s| s["name"] == "runtime.diagnostics.route")
    );
    assert!(
        steps
            .iter()
            .any(|s| s["name"] == "runtime.diagnostics.authority")
    );
    assert!(
        steps
            .iter()
            .any(|s| s["name"] == "runtime.diagnostics.authority.failures")
    );
    assert!(steps.iter().any(|s| s["name"] == "transport.boundary"));
    assert!(steps.iter().any(|s| s["name"] == "frame.validate"));
    assert!(steps.iter().any(|s| s["name"] == "directory.capability"));
    assert!(steps.iter().any(|s| s["name"] == "delta.apply"));
    assert!(steps.iter().any(|s| s["name"] == "repair.request"));
    assert!(steps.iter().any(|s| s["name"] == "propagation.privacy"));
    assert!(steps.iter().any(|s| s["name"] == "forbidden-route.check"));
}

#[test]
fn fixture_runtime_diagnostics_query_returns_runtime_events() {
    let root = tempdir().unwrap();
    let config_dir = root.path().join("config");
    let fixture_dir = root.path().join("fixtures");

    write_fixture_profile(&config_dir, &fixture_dir);

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--profile",
            "fixture",
            "--config-dir",
            config_dir.to_str().unwrap(),
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "diagnostics",
            "runtime",
            "--surface",
            "constitute-nvr-ui",
        ])
        .env("CONSTITUTE_CLI_PASSPHRASE", "testpass1234")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["kind"], "runtime.diagnostics");
    assert_eq!(report["count"], 2);
    assert_eq!(
        report["events"][0]["recordKind"],
        constitute_protocol::RECORD_RUNTIME_DIAGNOSTIC_EVENT
    );
    assert!(
        report["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == constitute_protocol::RECORD_ROUTE_OBSERVATION)
    );
    assert!(
        report["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "interaction.prepared")
    );
}

#[test]
fn fixture_capability_returns_definition_and_active_entries() {
    let root = tempdir().unwrap();
    let fixture_dir = root.path().join("fixtures");
    Command::cargo_bin("constitute")
        .unwrap()
        .args(["protocol", "fixtures", "write", "--dir"])
        .arg(&fixture_dir)
        .assert()
        .success();

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "capability",
            constitute_protocol::CAPABILITY_STORAGE_PIN,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        value["definition"]["capability"],
        constitute_protocol::CAPABILITY_STORAGE_PIN
    );
    assert_eq!(value["entries"].as_array().unwrap().len(), 2);
    assert!(
        value["activeAdvertisements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|ad| ad["serviceRef"] == "service-raw-storage-1")
    );
}

#[test]
fn fixture_channel_list_returns_sorted_channels_for_capability() {
    let root = tempdir().unwrap();
    let fixture_dir = root.path().join("fixtures");
    Command::cargo_bin("constitute")
        .unwrap()
        .args(["protocol", "fixtures", "write", "--dir"])
        .arg(&fixture_dir)
        .assert()
        .success();

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "channel",
            "list",
            "--capability",
            constitute_protocol::CAPABILITY_STORAGE_PIN,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).unwrap();
    let channel_ids = value["channels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|channel| channel["channelId"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        channel_ids,
        vec![
            "channel-storage-archive".to_string(),
            "channel-storage-pins".to_string()
        ]
    );
}

#[test]
fn fixture_channel_create_emits_valid_sealed_swarm_frame() {
    let root = tempdir().unwrap();
    let fixture_dir = root.path().join("fixtures");
    Command::cargo_bin("constitute")
        .unwrap()
        .args(["protocol", "fixtures", "write", "--dir"])
        .arg(&fixture_dir)
        .assert()
        .success();

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "channel",
            "create",
            "--capability",
            constitute_protocol::CAPABILITY_STORAGE_PIN,
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let frame: constitute_protocol::SwarmFrame = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        frame.capability.as_deref(),
        Some(constitute_protocol::CAPABILITY_STORAGE_PIN)
    );
    assert_eq!(frame.body.encoding, "caac");
    assert!(frame.body.envelope.as_ref().unwrap().is_object());
    assert!(frame.body.payload.is_none());
    constitute_protocol::validate_swarm_frame(&frame, frame.issued_at).unwrap();
}

#[test]
fn service_list_uses_descriptors_from_protocol_transport() {
    let root = tempdir().unwrap();
    let fixture_dir = root.path().join("fixtures");
    Command::cargo_bin("constitute")
        .unwrap()
        .args(["protocol", "fixtures", "write", "--dir"])
        .arg(&fixture_dir)
        .assert()
        .success();

    Command::cargo_bin("constitute")
        .unwrap()
        .args(["--fixture-dir", fixture_dir.to_str().unwrap(), "service"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Constitute Logging"))
        .stdout(predicate::str::contains("Gateway"))
        .stdout(predicate::str::contains("DevGateway"))
        .stdout(predicate::str::contains("events"));
}

#[test]
fn service_catalog_reports_generic_locations_and_services() {
    let root = tempdir().unwrap();
    let fixture_dir = root.path().join("fixtures");
    Command::cargo_bin("constitute")
        .unwrap()
        .args(["protocol", "fixtures", "write", "--dir"])
        .arg(&fixture_dir)
        .assert()
        .success();

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "service",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let status: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(status["root"][0], "service");
    assert!(
        status["locations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|location| location["label"] == "DevGateway")
    );
    assert!(
        status["services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "logging"
                && service["surfaceChannel"] == "logging.surface")
    );
    assert!(
        status["services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|service| service["service"] == "gateway"
                && service["surfaceChannel"] == "gateway.surface")
    );
}

#[test]
fn service_node_access_materializes_fixture_projection_runtime_state() {
    let root = tempdir().unwrap();
    let config_dir = root.path().join("config");
    let fixture_dir = root.path().join("fixtures");
    write_fixture_profile(&config_dir, &fixture_dir);

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--profile",
            "fixture",
            "--config-dir",
            config_dir.to_str().unwrap(),
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "service",
            "logging",
            "events",
            "--json",
        ])
        .env("CONSTITUTE_CLI_PASSPHRASE", "testpass1234")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        value["projection"]["channelId"],
        constitute_protocol::PROJECTION_CHANNEL_LOGGING_EVENTS
    );
    assert_eq!(
        value["projectionKey"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|logging.events|default"
    );
    assert!(config_dir.join("runtime/fixture/state.json").exists());
}

#[test]
fn service_node_access_can_observe_gateway_devices_without_top_level_gateway_namespace() {
    let root = tempdir().unwrap();
    let config_dir = root.path().join("config");
    let fixture_dir = root.path().join("fixtures");
    write_fixture_profile(&config_dir, &fixture_dir);

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--profile",
            "fixture",
            "--config-dir",
            config_dir.to_str().unwrap(),
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "service",
            "Gateway",
            "devices",
        ])
        .env("CONSTITUTE_CLI_PASSPHRASE", "testpass1234")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["projection"]["channelId"], "gateway.devices");
    assert_eq!(
        value["projection"]["payload"]["fields"]["devices"][0]["deviceLabel"],
        "DevBrowser"
    );
    assert_eq!(
        value["projection"]["payload"]["fields"]["devices"][0]["online"],
        true
    );
}

#[test]
fn service_observe_prints_snapshot_and_observer_update_json_lines() {
    let root = tempdir().unwrap();
    let config_dir = root.path().join("config");
    let fixture_dir = root.path().join("fixtures");
    write_fixture_profile(&config_dir, &fixture_dir);

    let output = Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--profile",
            "fixture",
            "--config-dir",
            config_dir.to_str().unwrap(),
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "service",
            "--observe",
            "logging",
            "events",
        ])
        .env("CONSTITUTE_CLI_PASSPHRASE", "testpass1234")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let lines = String::from_utf8(output).unwrap();
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "service.node.snapshot")
    );
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "projection.observer.update")
    );
}

#[test]
fn service_node_set_uses_generic_control_boundary() {
    let root = tempdir().unwrap();
    let config_dir = root.path().join("config");
    let fixture_dir = root.path().join("fixtures");
    write_fixture_profile(&config_dir, &fixture_dir);

    Command::cargo_bin("constitute")
        .unwrap()
        .args([
            "--profile",
            "fixture",
            "--config-dir",
            config_dir.to_str().unwrap(),
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "--json",
            "service",
            "logging",
            "events",
            "policy={\"mode\":\"test\"}",
        ])
        .env("CONSTITUTE_CLI_PASSPHRASE", "testpass1234")
        .assert()
        .success()
        .stdout(predicate::str::contains("service.intent"));
}
