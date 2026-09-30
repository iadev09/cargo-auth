use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result, bail};
use cargo_auth::{
    CredentialKind, CredentialStore, DEFAULT_REGISTRY, credential_kind, credentials_path,
    decrypt_token, encrypt_token, plaintext_credential, validate_profile_name,
    validate_registry_name
};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "cargo-auth",
    bin_name = "cargo auth",
    version,
    about = "Manage multiple Cargo registry credentials"
)]
struct Options {
    #[command(subcommand)]
    command: Command
}

#[derive(Debug, Clone, Args)]
struct RegistryArg {
    /// Cargo registry name. Defaults to crates.io.
    #[arg(long, default_value = DEFAULT_REGISTRY)]
    registry: String
}

#[derive(Debug, Clone, Args)]
struct RegistrySelection {
    /// Select one Cargo registry. Defaults to crates.io.
    #[arg(long, value_name = "NAME", conflicts_with = "all")]
    registry: Option<String>,

    /// Select every applicable registry.
    #[arg(long, conflicts_with = "registry")]
    all: bool
}

impl RegistrySelection {
    fn registry(&self) -> &str {
        self.registry.as_deref().unwrap_or(DEFAULT_REGISTRY)
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Add or replace a credential for a profile and registry.
    Add {
        /// Profile name, such as "personal" or "work".
        name: String,

        #[command(flatten)]
        target: RegistryArg,

        /// Store the token as plaintext instead of encrypting it.
        #[arg(long)]
        plain: bool
    },

    /// Remove credentials from a profile.
    Remove {
        name: String,

        #[command(flatten)]
        target: RegistrySelection
    },

    /// List saved credential profiles.
    List {
        #[command(flatten)]
        target: RegistrySelection
    },

    /// Encrypt plaintext credentials in a profile.
    Encrypt {
        name: String,

        #[command(flatten)]
        target: RegistrySelection
    },

    /// Decrypt credentials in a profile and store them as plaintext.
    Decrypt {
        name: String,

        #[command(flatten)]
        target: RegistrySelection
    },

    /// Make a profile active for one or every registry it contains.
    Use {
        name: String,

        #[command(flatten)]
        target: RegistrySelection
    },

    /// Remove active registry tokens using Cargo's native logout command.
    Logout {
        #[command(flatten)]
        target: RegistrySelection
    },

    /// Show active profiles by registry.
    Current {
        #[command(flatten)]
        target: RegistrySelection
    }
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
    let mut store = CredentialStore::load(&path)?;

    match options.command {
        Command::Add { name, target, plain } => {
            validate_profile_name(&name)?;
            validate_registry_name(&target.registry)?;
            let registry = target.registry;
            let token = prompt_secret(&format!("Token for registry {registry:?}: "))?;
            if token.is_empty() {
                bail!("token for registry {registry:?} cannot be empty");
            }

            let first_profile = !store.has_profiles_for_registry(&registry)?;
            let existing_token = store.registry_token(&registry)?;
            if first_profile
                && existing_token.is_some_and(|existing_token| existing_token != token.as_str())
            {
                bail!(
                    "a different unmanaged Cargo token for registry {registry:?} already exists in \
                     {}. Add that token as the first profile, or remove its token from that file \
                     before adding a different token",
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

            let replaced = store.contains(&name, &registry)?;
            let matches_registry_token = store.registry_token(&registry)? == Some(token.as_str());
            let was_active = store.active_profile(&registry)? == Some(name.as_str());
            store.insert(&name, &registry, encoded)?;
            if was_active || matches_registry_token {
                store.activate(&name, &registry, &token)?;
            }
            store.save()?;
            let action = if replaced { "Replaced" } else { "Added" };
            println!("{action} profile {name:?} for registry {registry:?}.");
        }
        Command::Remove { name, target } => {
            let registries = profile_targets(&store, &name, &target)?;
            for registry in &registries {
                if !store.remove(&name, registry)? {
                    bail!("profile {name:?} has no credential for registry {registry:?}");
                }
            }
            store.save()?;
            print_registry_action("Removed", &name, &registries);
        }
        Command::List { target } => {
            let registry = (!target.all).then(|| target.registry());
            if let Some(registry) = registry {
                validate_registry_name(registry)?;
            }
            let profiles = store.profiles(registry)?;
            if profiles.is_empty() {
                if target.all {
                    println!("No credential profiles saved.");
                } else {
                    println!("No credential profiles saved for registry {:?}.", target.registry());
                }
            } else {
                for profile in profiles {
                    let marker = if profile.active { "*" } else { " " };
                    println!(
                        "{marker} {} [{}] ({})",
                        profile.name,
                        profile.registry,
                        profile.kind.label()
                    );
                }
            }
        }
        Command::Encrypt { name, target } => {
            let registries = profile_targets(&store, &name, &target)?;
            let mut plaintext = Vec::new();
            for registry in &registries {
                let encoded = Zeroizing::new(store.encoded(&name, registry)?.to_owned());
                if credential_kind(&encoded)? == CredentialKind::Plaintext {
                    plaintext.push((registry.clone(), decrypt_token(&encoded, b"")?));
                } else if !target.all {
                    bail!("profile {name:?} is already encrypted for registry {registry:?}");
                }
            }
            if plaintext.is_empty() {
                bail!("profile {name:?} has no plaintext credentials");
            }
            let password = prompt_new_password()?;
            let encrypted = plaintext
                .iter()
                .map(|(registry, token)| {
                    Ok((registry.clone(), encrypt_token(token, password.as_bytes())?))
                })
                .collect::<Result<Vec<_>>>()?;
            for (registry, encoded) in encrypted {
                store.insert(&name, &registry, encoded)?;
            }
            store.save()?;
            print_registry_action("Encrypted", &name, &registries);
        }
        Command::Decrypt { name, target } => {
            let registries = profile_targets(&store, &name, &target)?;
            let mut plaintext = Vec::new();
            for registry in &registries {
                let encoded = Zeroizing::new(store.encoded(&name, registry)?.to_owned());
                if credential_kind(&encoded)? == CredentialKind::Plaintext {
                    if !target.all {
                        bail!("profile {name:?} is already plaintext for registry {registry:?}");
                    }
                    continue;
                }
                let password = prompt_secret(&format!(
                    "Master password for profile {name:?}, registry {registry:?}: "
                ))?;
                let token = decrypt_token(&encoded, password.as_bytes())?;
                std::str::from_utf8(&token).context("credential is not valid UTF-8")?;
                plaintext.push((registry.clone(), token));
            }
            if plaintext.is_empty() {
                bail!("profile {name:?} has no encrypted credentials");
            }
            for (registry, token) in &plaintext {
                let token = std::str::from_utf8(token).context("credential is not valid UTF-8")?;
                store.insert(&name, registry, plaintext_credential(token))?;
            }
            store.save()?;
            eprintln!(
                "warning: selected credentials in profile {name:?} are now stored as plaintext"
            );
        }
        Command::Use { name, target } => {
            let registries = profile_targets(&store, &name, &target)?;
            let mut tokens = Vec::new();
            for registry in &registries {
                let encoded = Zeroizing::new(store.encoded(&name, registry)?.to_owned());
                let token = match credential_kind(&encoded)? {
                    CredentialKind::Encrypted => {
                        let password = prompt_secret(&format!(
                            "Master password for profile {name:?}, registry {registry:?}: "
                        ))?;
                        decrypt_token(&encoded, password.as_bytes())?
                    }
                    CredentialKind::Plaintext => decrypt_token(&encoded, b"")?
                };
                let token_str =
                    std::str::from_utf8(&token).context("credential is not valid UTF-8")?;
                if store.would_overwrite_unmanaged_token(registry, token_str)? {
                    bail!(
                        "a different unmanaged Cargo token is active for registry {registry:?}; \
                         save it with `cargo auth add <name> --registry {registry}` before \
                         switching profiles"
                    );
                }
                tokens.push((registry.clone(), token));
            }
            for (registry, token) in &tokens {
                let token = std::str::from_utf8(token).context("credential is not valid UTF-8")?;
                store.activate(&name, registry, token)?;
            }
            store.save()?;
            print_registry_action("Using", &name, &registries);
        }
        Command::Logout { target } => {
            let registries = if target.all {
                store.active_registries()?
            } else {
                validate_registry_name(target.registry())?;
                vec![target.registry().to_owned()]
            };
            if registries.is_empty() {
                println!("No active profiles.");
                return Ok(());
            }
            drop(store);
            for registry in &registries {
                cargo_logout(registry)?;
                let mut current = CredentialStore::load(&path)?;
                if current.clear_active_profile(registry)? {
                    current.save()?;
                }
            }
        }
        Command::Current { target } => {
            if target.all {
                let active = store.active_profiles()?;
                if active.is_empty() {
                    println!("No active profiles.");
                } else {
                    for (registry, name) in active {
                        println!("{registry}\t{name}");
                    }
                }
            } else {
                let registry = target.registry();
                validate_registry_name(registry)?;
                match store.active_profile(registry)? {
                    Some(name) => println!("{name}"),
                    None => println!("No active profile for registry {registry:?}.")
                }
            }
        }
    }

    Ok(())
}

fn profile_targets(
    store: &CredentialStore,
    name: &str,
    target: &RegistrySelection
) -> Result<Vec<String>> {
    validate_profile_name(name)?;
    if target.all {
        let registries = store.registries_for_profile(name)?;
        if registries.is_empty() {
            bail!("profile {name:?} does not exist");
        }
        Ok(registries)
    } else {
        validate_registry_name(target.registry())?;
        Ok(vec![target.registry().to_owned()])
    }
}

fn print_registry_action(
    action: &str,
    name: &str,
    registries: &[String]
) {
    if registries.len() == 1 {
        println!("{action} profile {name:?} for registry {:?}.", registries[0]);
    } else {
        println!("{action} profile {name:?} for registries {}.", registries.join(", "));
    }
}

fn cargo_logout(registry: &str) -> Result<()> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let status = ProcessCommand::new(cargo)
        .args(["logout", "--registry", registry])
        .status()
        .with_context(|| format!("failed to run Cargo logout for registry {registry:?}"))?;
    if !status.success() {
        bail!("Cargo logout for registry {registry:?} failed with {status}");
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
        assert!(matches!(options.command, Command::List { .. }));
    }

    #[test]
    fn also_accepts_direct_invocation() {
        let args = ["cargo-auth", "list"].into_iter().map(OsString::from).collect();

        let options = Options::try_parse_from(normalize_cargo_args(args)).unwrap();
        assert!(matches!(options.command, Command::List { .. }));
    }

    #[test]
    fn registry_defaults_to_crates_io() {
        let options = Options::try_parse_from(["cargo-auth", "use", "personal"]).unwrap();
        let Command::Use { target, .. } = options.command else {
            panic!("expected use command");
        };
        assert_eq!(target.registry(), DEFAULT_REGISTRY);
        assert!(!target.all);
    }

    #[test]
    fn accepts_registry_and_all_selectors() {
        let options =
            Options::try_parse_from(["cargo-auth", "use", "personal", "--registry", "de02"])
                .unwrap();
        let Command::Use { target, .. } = options.command else {
            panic!("expected use command");
        };
        assert_eq!(target.registry(), "de02");

        let options = Options::try_parse_from(["cargo-auth", "current", "--all"]).unwrap();
        let Command::Current { target } = options.command else {
            panic!("expected current command");
        };
        assert!(target.all);
    }

    #[test]
    fn registry_and_all_are_mutually_exclusive() {
        assert!(
            Options::try_parse_from([
                "cargo-auth",
                "use",
                "personal",
                "--registry",
                "de02",
                "--all"
            ])
            .is_err()
        );
    }

    #[test]
    fn add_does_not_accept_all() {
        assert!(Options::try_parse_from(["cargo-auth", "add", "personal", "--all"]).is_err());
    }
}
