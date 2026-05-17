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
        .stdout(predicate::str::contains("service"))
        .stdout(predicate::str::contains("capability"))
        .stdout(predicate::str::contains("channel"))
        .stdout(predicate::str::contains("diagnostics"))
        .stdout(predicate::str::contains("protocol"))
        .stdout(predicate::str::contains("config"));
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
            .any(|s| s["name"] == "runtime.diagnostics.observe")
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
        "runtime.diagnostic.event"
    );
    assert!(report["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["kind"] == "route.observation"));
    assert!(report["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["kind"] == "interaction.prepared"));
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
            "storage.pin",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["definition"]["capability"], "storage.pin");
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
            "storage.pin",
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
            "storage.pin",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let frame: constitute_protocol::SwarmFrame = serde_json::from_slice(&output).unwrap();
    assert_eq!(frame.capability.as_deref(), Some("storage.pin"));
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
    assert_eq!(value["projection"]["channelId"], "logging.events");
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
