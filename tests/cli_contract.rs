use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

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
        .stdout(predicate::str::contains("projection"));
}

#[test]
fn fixture_doctor_verifies_full_protocol_flow() {
    let root = tempdir().unwrap();
    let config_dir = root.path().join("config");
    let fixture_dir = root.path().join("fixtures");

    Command::cargo_bin("constitute")
        .unwrap()
        .args(["protocol", "fixtures", "write", "--dir"])
        .arg(&fixture_dir)
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
    assert!(steps.iter().any(|s| s["name"] == "service.describe"));
    assert!(
        steps
            .iter()
            .any(|s| s["name"] == "projection.logging.events")
    );
    assert!(steps.iter().any(|s| s["name"] == "transport.boundary"));
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
        .args([
            "--fixture-dir",
            fixture_dir.to_str().unwrap(),
            "service",
            "list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("logging"))
        .stdout(predicate::str::contains(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ));
}
