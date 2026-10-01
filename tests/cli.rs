use std::fs;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn current_reports_an_unmanaged_active_token() {
    let cargo_home = TempDir::new().unwrap();
    fs::write(
        cargo_home.path().join("credentials.toml"),
        "[registries.private]\ntoken = \"active-token\"\n"
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cargo-auth"))
        .args(["current", "--all"])
        .env("CARGO_HOME", cargo_home.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "private\t<unmanaged>\n");
}

#[test]
fn use_all_warns_when_profile_only_contains_one_registry() {
    let cargo_home = TempDir::new().unwrap();
    fs::write(
        cargo_home.path().join("credentials.toml"),
        "[cargo-auth.profiles.personal.credentials]\ncrates-io = \"plain:active-token\"\n"
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cargo-auth"))
        .args(["use", "personal", "--all"])
        .env("CARGO_HOME", cargo_home.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "warning: --all was requested, but profile \"personal\" only has a credential for registry \
         \"crates-io\"\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Using profile \"personal\" for registry \"crates-io\".\n"
    );
}
