use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result, bail};
use cargo_auth::{
    CredentialKind, CredentialStore, credential_kind, credentials_path, decrypt_token,
    encrypt_token, plaintext_credential, validate_profile_name
};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "cargo-auth",
    bin_name = "cargo auth",
    version,
    about = "Manage multiple crates.io credentials"
)]
struct Options {
    #[command(subcommand)]
    command: Command
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Add or replace a credential profile.
    Add {
        /// Profile name, such as "personal" or "work".
        name: String,

        /// Store the token as plaintext instead of encrypting it.
        #[arg(long)]
        plain: bool
    },

    /// Remove a credential profile.
    Remove { name: String },

    /// List saved credential profiles.
    List,

    /// Encrypt a plaintext credential profile.
    Encrypt { name: String },

    /// Decrypt a profile and store it as plaintext.
    Decrypt { name: String },

    /// Make a profile the active crates.io credential.
    Use { name: String },

    /// Remove the active crates.io token using Cargo's native logout command.
    Logout,

    /// Show the active profile.
    Current
}

fn main() {
    let options = Options::parse_from(normalize_cargo_args(std::env::args_os().collect()));
    if let Err(error) = run(options) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn normalize_cargo_args(mut args: Vec<OsString>) -> Vec<OsString> {
    if args.get(1).is_some_and(|argument| argument == "auth") {
        args.remove(1);
    }
    args
}

fn run(options: Options) -> Result<()> {
    let path = credentials_path()?;
    if matches!(&options.command, Command::Logout) {
        return cargo_logout(&path);
    }

    let mut store = CredentialStore::load(&path)?;

    match options.command {
        Command::Add { name, plain } => {
            validate_profile_name(&name)?;
            let token = prompt_secret("Crates.io token: ")?;
            if token.is_empty() {
                bail!("crates.io token cannot be empty");
            }

            let first_profile = !store.has_profiles()?;
            let existing_token = store.registry_token()?;
            if first_profile
                && existing_token.is_some_and(|existing_token| existing_token != token.as_str())
            {
                bail!(
                    "a different unmanaged Cargo token already exists in {}. Add that token as \
                     the first profile, or remove `[registry].token` from that file before adding \
                     a different token",
                    path.display()
                );
            }

            let encoded = if plain {
                eprintln!("warning: this credential will be stored as plaintext");
                plaintext_credential(&token)
            } else {
                let password = prompt_new_password()?;
                encrypt_token(token.as_bytes(), password.as_bytes())?
            };

            let replaced = store.contains(&name)?;
            let matches_registry_token = store.registry_token()? == Some(token.as_str());
            let was_active = store.active_profile()? == Some(name.as_str());
            store.insert(&name, encoded)?;
            if was_active || matches_registry_token {
                store.activate(&name, &token)?;
            }
            store.save()?;
            if replaced {
                println!("Replaced profile {name:?}.");
            } else {
                println!("Added profile {name:?}.");
            }
        }
        Command::Remove { name } => {
            if !store.remove(&name)? {
                bail!("profile {name:?} does not exist");
            }
            store.save()?;
            println!("Removed profile {name:?}.");
        }
        Command::List => {
            let profiles = store.profiles()?;
            if profiles.is_empty() {
                println!("No credential profiles saved.");
            } else {
                for profile in profiles {
                    let marker = if profile.active { "*" } else { " " };
                    println!("{marker} {} ({})", profile.name, profile.kind.label());
                }
            }
        }
        Command::Encrypt { name } => {
            let encoded = Zeroizing::new(store.encoded(&name)?.to_owned());
            if credential_kind(&encoded)? == CredentialKind::Encrypted {
                bail!("profile {name:?} is already encrypted");
            }
            let token = decrypt_token(&encoded, b"")?;
            let password = prompt_new_password()?;
            let encrypted = encrypt_token(&token, password.as_bytes())?;
            store.insert(&name, encrypted)?;
            store.save()?;
            println!("Encrypted profile {name:?}.");
        }
        Command::Decrypt { name } => {
            let encoded = Zeroizing::new(store.encoded(&name)?.to_owned());
            if credential_kind(&encoded)? == CredentialKind::Plaintext {
                bail!("profile {name:?} is already plaintext");
            }
            let password = prompt_secret("Master password: ")?;
            let token = decrypt_token(&encoded, password.as_bytes())?;
            let token = std::str::from_utf8(&token).context("credential is not valid UTF-8")?;
            store.insert(&name, plaintext_credential(token))?;
            store.save()?;
            eprintln!("warning: profile {name:?} is now stored as plaintext");
        }
        Command::Use { name } => {
            let encoded = Zeroizing::new(store.encoded(&name)?.to_owned());
            let token = match credential_kind(&encoded)? {
                CredentialKind::Encrypted => {
                    let password = prompt_secret("Master password: ")?;
                    decrypt_token(&encoded, password.as_bytes())?
                }
                CredentialKind::Plaintext => decrypt_token(&encoded, b"")?
            };
            let token = std::str::from_utf8(&token).context("credential is not valid UTF-8")?;
            if store.would_overwrite_unmanaged_token(token)? {
                bail!(
                    "a different unmanaged Cargo token is active; save it with `cargo auth add \
                     <name>` before switching profiles"
                );
            }
            store.activate(&name, token)?;
            store.save()?;
            println!("Using profile {name:?}.");
        }
        Command::Logout => unreachable!("logout is handled before loading credentials"),
        Command::Current => match store.active_profile()? {
            Some(name) => println!("{name}"),
            None => println!("No active profile.")
        }
    }

    Ok(())
}

fn cargo_logout(path: &std::path::Path) -> Result<()> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let status = ProcessCommand::new(cargo)
        .args(["logout", "--registry", "crates-io"])
        .status()
        .context("failed to run Cargo's logout command")?;
    if !status.success() {
        bail!("Cargo logout failed with {status}");
    }

    let mut store = CredentialStore::load(path)?;
    if store.clear_active_profile()? {
        store.save()?;
    }
    Ok(())
}

fn prompt_new_password() -> Result<Zeroizing<String>> {
    let password = prompt_secret("Master password: ")?;
    if password.is_empty() {
        bail!("master password cannot be empty");
    }
    let confirmation = prompt_secret("Confirm master password: ")?;
    if password.as_str() != confirmation.as_str() {
        bail!("master passwords do not match");
    }
    Ok(password)
}

fn prompt_secret(prompt: &str) -> Result<Zeroizing<String>> {
    if !io::stdin().is_terminal() {
        bail!("interactive terminal input is required");
    }
    io::stderr().flush().context("failed to flush prompt")?;
    rpassword::prompt_password(prompt).map(Zeroizing::new).context("failed to read hidden input")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_cargo_external_subcommand_argument() {
        let args = ["cargo-auth", "auth", "list"].into_iter().map(OsString::from).collect();

        let options = Options::try_parse_from(normalize_cargo_args(args)).unwrap();
        assert!(matches!(options.command, Command::List));
    }

    #[test]
    fn also_accepts_direct_invocation() {
        let args = ["cargo-auth", "list"].into_iter().map(OsString::from).collect();

        let options = Options::try_parse_from(normalize_cargo_args(args)).unwrap();
        assert!(matches!(options.command, Command::List));
    }

    #[test]
    fn accepts_logout_command() {
        let args = ["cargo-auth", "logout"].into_iter().map(OsString::from).collect();

        let options = Options::try_parse_from(normalize_cargo_args(args)).unwrap();
        assert!(matches!(options.command, Command::Logout));
    }
}
