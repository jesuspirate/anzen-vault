use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn binary_and_help_use_the_anzen_name() {
    Command::cargo_bin("anzen")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: anzen"))
        .stdout(predicate::str::contains("--chain-backend <CHAIN_BACKEND>"))
        .stdout(predicate::str::contains("--rpc-url <RPC_URL>"))
        .stdout(predicate::str::contains("--electrum-url <ELECTRUM_URL>"));
}

#[test]
fn device_setup_and_vault_init_are_separate_and_monthly_spending_starts_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "phone", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Simulated phone initialized"))
        .stdout(predicate::str::contains("Phone mnemonic:"))
        .stdout(predicate::str::contains("Phone vault key:"))
        .stdout(predicate::str::contains("descriptor:").not());

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "hww", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Simulated HWW initialized"))
        .stdout(predicate::str::contains("HWW mnemonic:"))
        .stdout(predicate::str::contains("HWW vault key:"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Cold storage descriptor: tr("))
        .stdout(predicate::str::contains(
            "Phone recovery: 61,200 blocks (~14 months)",
        ))
        .stdout(predicate::str::contains(
            "HWW recovery:   65,535 blocks (~15 months)",
        ))
        .stdout(predicate::str::contains("Monthly spending: disabled"))
        .stdout(predicate::str::contains("Emergency access: disabled"))
        .stdout(predicate::str::contains("hot external descriptor").not())
        .stdout(predicate::str::contains("Hard limit").not());

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "policy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("older(61200)"))
        .stdout(predicate::str::contains("older(65535)"))
        .stdout(predicate::str::contains("Vault address: bcrt1p"))
        .stdout(predicate::str::contains("Monthly spending: disabled"))
        .stdout(predicate::str::contains("Emergency access: disabled"));
}

#[test]
fn phone_cli_exposes_the_complete_emergency_access_lifecycle() {
    Command::cargo_bin("anzen")
        .unwrap()
        .args(["phone", "set-policy", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--emergency-access-limit"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["phone", "emergency", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("initiate"))
        .stdout(predicate::str::contains("withdraw"))
        .stdout(predicate::str::contains("cancel"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["phone", "rotate-key", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--vanity"))
        .stdout(predicate::str::contains("--output"));
}

#[test]
fn phone_cli_addresses_allowances_by_sequential_step() {
    for command in ["authorize", "revoke", "apply-soft-limit"] {
        Command::cargo_bin("anzen")
            .unwrap()
            .args(["phone", command, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("<STEP>"))
            .stdout(predicate::str::contains("<MONTH>").not());
    }
}

#[test]
fn hww_cli_exposes_blanket_controller_revocation() {
    Command::cargo_bin("anzen")
        .unwrap()
        .args(["hww", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("revoke-policy"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["hww", "revoke-policy", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--yes"))
        .stdout(predicate::str::contains("destination"));
}

#[test]
fn hww_can_be_initialized_first_for_a_future_vanity_phone() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "hww", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Simulated HWW initialized"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "phone", "init"])
        .assert()
        .success();

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "init"])
        .assert()
        .success();
}

#[test]
fn vanity_phone_init_requires_an_initialized_hww() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "phone", "init", "--vanity"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "initialize the HWW before using phone init --vanity",
        ));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["phone", "init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--vanity"));
}

#[test]
fn legacy_config_filename_remains_readable() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    for args in [["phone", "init"], ["hww", "init"], ["init", ""]] {
        let args = args.into_iter().filter(|arg| !arg.is_empty());
        Command::cargo_bin("anzen")
            .unwrap()
            .arg("--data-dir")
            .arg(data_dir)
            .args(args)
            .assert()
            .success();
    }

    std::fs::rename(dir.path().join("anzen.json"), dir.path().join("vault.json")).unwrap();

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "policy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Cold storage descriptor:"));
}

#[test]
fn legacy_bundled_device_commands_are_not_exposed() {
    for command in [
        "ceremony",
        "monthly",
        "soft-limit",
        "hot-address",
        "restore-phone",
        "sweep",
        "rotate-phone",
    ] {
        Command::cargo_bin("anzen")
            .unwrap()
            .arg(command)
            .assert()
            .failure()
            .stderr(predicate::str::contains("unrecognized subcommand"));
    }
}

#[test]
fn mainnet_mode_is_persisted_and_requires_the_dangerous_flag_every_time() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();
    let danger = "--dangerously-enable-mainnet";

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, danger, "phone", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MAINNET — REAL FUNDS"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "hww", "init"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "pass --dangerously-enable-mainnet on every command",
        ));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, danger, "hww", "init"])
        .assert()
        .success();

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "init"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "pass --dangerously-enable-mainnet on every command",
        ));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, danger, "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault address: bc1p"))
        .stdout(predicate::str::contains("fixed 1 sat/vB MVP fees"));

    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("anzen.json")).unwrap()).unwrap();
    assert_eq!(config["network"], "mainnet");

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "policy"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mainnet vault is locked"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args([
            "--data-dir",
            data_dir,
            "phone",
            "rotate-key",
            "--vanity",
            "--output",
            "rotation.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mainnet vault is locked"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, danger, "policy"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault address: bc1p"));
}

#[test]
fn dangerous_mainnet_flag_cannot_convert_an_existing_regtest_vault() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "phone", "init"])
        .assert()
        .success();

    Command::cargo_bin("anzen")
        .unwrap()
        .args([
            "--data-dir",
            data_dir,
            "--dangerously-enable-mainnet",
            "hww",
            "init",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot change an existing vault"));
}

#[test]
fn openpgp_friend_decrypts_the_descriptor_bound_cloud_backup() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();
    for args in [vec!["phone", "init"], vec!["hww", "init"], vec!["init"]] {
        Command::cargo_bin("anzen")
            .unwrap()
            .args(["--data-dir", data_dir])
            .args(args)
            .assert()
            .success();
    }

    let public = dir.path().join("alice.pub.asc");
    let private = dir.path().join("alice.sec.asc");
    let recovery = dir.path().join("friend-recovery.json");
    let backup = dir.path().join("cloud/phone-seed-backup.json");
    Command::cargo_bin("anzen")
        .unwrap()
        .args([
            "--data-dir",
            data_dir,
            "social",
            "generate-friend-key",
            "--name",
            "Alice",
        ])
        .arg("--public-key")
        .arg(&public)
        .arg("--private-key")
        .arg(&private)
        .assert()
        .success()
        .stdout(predicate::str::contains("OpenPGP key generated"));
    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "hww", "add-recovery-friend"])
        .arg(&public)
        .arg("--yes")
        .assert()
        .success()
        .stdout(predicate::str::contains("Recovery friend added"));

    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("anzen.json")).unwrap()).unwrap();
    let backup_text = std::fs::read_to_string(&backup).unwrap();
    let backup_json: serde_json::Value = serde_json::from_str(&backup_text).unwrap();
    assert_eq!(backup_json["friends"].as_array().unwrap().len(), 1);
    assert!(!backup_text.contains(config["vault_descriptor"].as_str().unwrap()));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "social", "decrypt-backup"])
        .arg(&backup)
        .arg("--private-key")
        .arg(&private)
        .arg("--output")
        .arg(&recovery)
        .assert()
        .success()
        .stdout(predicate::str::contains("Social recovery decrypted"))
        .stdout(predicate::str::contains("Cold storage descriptor: tr("));
    let recovered: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&recovery).unwrap()).unwrap();
    assert_eq!(recovered["vault_descriptor"], config["vault_descriptor"]);

    std::fs::remove_file(dir.path().join("phone/device.json")).unwrap();
    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "phone", "restore"])
        .arg(&recovery)
        .assert()
        .success()
        .stdout(predicate::str::contains("Phone key restored"));
}

#[test]
fn health_checks_and_recovery_kit_work_without_a_chain_backend() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();
    for args in [["phone", "init"], ["hww", "init"]] {
        Command::cargo_bin("anzen")
            .unwrap()
            .arg("--data-dir")
            .arg(data_dir)
            .args(args)
            .assert()
            .success();
    }
    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "init"])
        .assert()
        .success();

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "health", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Phone: never checked"))
        .stdout(predicate::str::contains("Hardware wallet: never checked"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "health", "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Phone: healthy"))
        .stdout(predicate::str::contains("Hardware wallet: healthy"));

    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "health", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Next check due"))
        .stdout(predicate::str::contains("never checked").not());

    Command::cargo_bin("anzen")
        .unwrap()
        .args([
            "--data-dir",
            data_dir,
            "savings",
            "create",
            "--unlock",
            "2030-01-01",
        ])
        .assert()
        .success();

    let kit = dir.path().join("kit.html");
    Command::cargo_bin("anzen")
        .unwrap()
        .args([
            "--data-dir",
            data_dir,
            "recovery-kit",
            "--owner",
            "Jet",
            "--output",
        ])
        .arg(&kit)
        .assert()
        .success()
        .stdout(predicate::str::contains("Recovery kit written"));
    let html = std::fs::read_to_string(&kit).unwrap();
    assert!(html.contains("How to get to Jet&#39;s vault"));
    assert!(html.contains("Savings lock opening January 1, 2030"));
    assert!(html.contains("Working</span> last checked"));
    assert!(
        !html.contains("mnemonic"),
        "the kit must never contain secrets"
    );

    // A different hardware wallet is caught.
    let other = tempfile::tempdir().unwrap();
    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", other.path().to_str().unwrap(), "hww", "init"])
        .assert()
        .success();
    std::fs::copy(
        other.path().join("hww/device.json"),
        dir.path().join("hww/device.json"),
    )
    .unwrap();
    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", data_dir, "health", "check", "--device", "hww"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Hardware wallet: FAILED"));
}

fn anzen_ok(data_dir: &str, args: &[&str]) -> String {
    let output = Command::cargo_bin("anzen")
        .unwrap()
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "anzen {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn an_heir_is_named_before_the_vault_and_can_rebuild_it_from_the_kit() {
    let heir_home = tempfile::tempdir().unwrap();
    let owner_home = tempfile::tempdir().unwrap();
    let heir_dir = heir_home.path().to_str().unwrap();
    let owner_dir = owner_home.path().to_str().unwrap();

    // The heir makes a key on their own device and hands the owner its public half.
    let created = anzen_ok(heir_dir, &["heir", "init", "--name", "Maya"]);
    let heir_key = created
        .lines()
        .find_map(|line| line.strip_prefix("Heir key: "))
        .unwrap()
        .to_owned();
    assert!(created.contains("Heir's secret words"));

    anzen_ok(
        owner_dir,
        &["heir", "import", "--name", "Maya", "--key", &heir_key],
    );
    anzen_ok(owner_dir, &["phone", "init"]);
    anzen_ok(owner_dir, &["hww", "init"]);
    let init = anzen_ok(owner_dir, &["init"]);
    assert!(init.contains("Heir recovery:  65,535 blocks (~15 months) with Maya's own key"));
    assert!(init.contains(&heir_key));
    anzen_ok(owner_dir, &["savings", "create", "--unlock", "2031-01-01"]);

    // Once the vault exists, its heir cannot be changed or added.
    Command::cargo_bin("anzen")
        .unwrap()
        .args(["--data-dir", owner_dir, "heir", "init", "--name", "Other"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "must be named before `anzen init`",
        ));

    let kit = owner_home.path().join("kit.html");
    anzen_ok(
        owner_dir,
        &[
            "recovery-kit",
            "--output",
            kit.to_str().unwrap(),
            "--owner",
            "Jet",
        ],
    );
    let html = std::fs::read_to_string(&kit).unwrap();
    assert!(html.contains("Maya's own door"));
    assert!(html.contains("You are Maya, the named heir"));
    assert!(html.contains("anzen heir restore"));

    // The heir rebuilds the vault from the descriptors printed in the kit.
    let config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(owner_home.path().join("anzen.json")).unwrap(),
    )
    .unwrap();
    let vault_descriptor = config["vault_descriptor"].as_str().unwrap();
    let savings_address = config["savings_locks"][0]["address"].as_str().unwrap();
    let savings_descriptor = html
        .split(r#"<p class="label">Descriptor</p><span class="mono">"#)
        .nth(2)
        .and_then(|rest| rest.split("</span>").next())
        .unwrap()
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    assert!(savings_descriptor.contains("after("));
    let restored = anzen_ok(
        heir_dir,
        &[
            "heir",
            "restore",
            "--vault-descriptor",
            vault_descriptor,
            "--savings-descriptor",
            &savings_descriptor,
        ],
    );
    assert!(restored.contains(config["vault_address"].as_str().unwrap()));
    let heir_config: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(heir_home.path().join("anzen.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(heir_config["vault_address"], config["vault_address"]);
    assert_eq!(heir_config["savings_locks"][0]["address"], savings_address);
    assert_eq!(heir_config["heir"]["name"], "Maya");

    // A vault that does not name this heir is refused.
    let stranger_home = tempfile::tempdir().unwrap();
    let stranger_dir = stranger_home.path().to_str().unwrap();
    anzen_ok(stranger_dir, &["phone", "init"]);
    anzen_ok(stranger_dir, &["hww", "init"]);
    anzen_ok(stranger_dir, &["init"]);
    let stranger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(stranger_home.path().join("anzen.json")).unwrap(),
    )
    .unwrap();
    let other_heir_home = tempfile::tempdir().unwrap();
    let other_heir_dir = other_heir_home.path().to_str().unwrap();
    anzen_ok(other_heir_dir, &["heir", "init", "--name", "Maya"]);
    Command::cargo_bin("anzen")
        .unwrap()
        .args([
            "--data-dir",
            other_heir_dir,
            "heir",
            "restore",
            "--vault-descriptor",
            stranger["vault_descriptor"].as_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not name this heir's key"));
}
