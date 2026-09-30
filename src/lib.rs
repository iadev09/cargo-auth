use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, Item, Table, value};
use zeroize::Zeroizing;

const ENCRYPTED_PREFIX: &str = "enc:v1:";
const PLAINTEXT_PREFIX: &str = "plain:";
pub const DEFAULT_REGISTRY: &str = "crates-io";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const RESERVED_PROFILE_NAMES: &[&str] =
    &["add", "remove", "list", "encrypt", "decrypt", "use", "logout", "current", "help"];

pub fn credentials_path() -> Result<PathBuf> {
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(cargo_home).join("credentials.toml"));
    }

    let home = home_dir().context("could not determine the home directory")?;
    Ok(home.join(".cargo").join("credentials.toml"))
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }

    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Encrypted,
    Plaintext
}

impl CredentialKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Plaintext => "plain"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub registry: String,
    pub kind: CredentialKind,
    pub active: bool
}

pub struct CredentialStore {
    path: PathBuf,
    document: DocumentMut
}

impl CredentialStore {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let document = match fs::read_to_string(&path) {
            Ok(contents) => Zeroizing::new(contents)
                .parse::<DocumentMut>()
                .with_context(|| format!("failed to parse {}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => DocumentMut::new(),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {}", path.display()));
            }
        };

        let mut store = Self { path, document };
        store.migrate_legacy_format()?;
        Ok(store)
    }

    pub fn profiles(
        &self,
        registry: Option<&str>
    ) -> Result<Vec<Profile>> {
        let Some(profiles) = self.profiles_table()? else {
            return Ok(Vec::new());
        };

        let mut result = Vec::new();
        for (name, profile_item) in profiles {
            let profile = profile_item
                .as_table()
                .ok_or_else(|| anyhow!("profile {name:?} must be a TOML table"))?;
            let Some(credentials) = optional_table(profile, "credentials")? else {
                continue;
            };
            for (registry_name, item) in credentials {
                if registry.is_some_and(|selected| selected != registry_name) {
                    continue;
                }
                let encoded = item.as_str().ok_or_else(|| {
                    anyhow!("credential {name:?} for registry {registry_name:?} is not a string")
                })?;
                let kind = credential_kind(encoded).with_context(|| {
                    format!(
                        "credential {name:?} for registry {registry_name:?} has an unsupported format"
                    )
                })?;
                result.push(Profile {
                    name: name.to_owned(),
                    registry: registry_name.to_owned(),
                    kind,
                    active: self.active_profile(registry_name)? == Some(name)
                });
            }
        }

        result.sort_unstable_by(|left, right| {
            left.registry.cmp(&right.registry).then_with(|| left.name.cmp(&right.name))
        });
        Ok(result)
    }

    pub fn registries_for_profile(
        &self,
        name: &str
    ) -> Result<Vec<String>> {
        let mut registries: Vec<String> = self
            .profile_table(name)?
            .map(|profile| optional_table(profile, "credentials"))
            .transpose()?
            .flatten()
            .map(|credentials| credentials.iter().map(|(name, _)| name.to_owned()).collect())
            .unwrap_or_default();
        registries.sort_unstable();
        Ok(registries)
    }

    pub fn active_registries(&self) -> Result<Vec<String>> {
        let mut registries: Vec<String> = self
            .active_table()?
            .map(|active| active.iter().map(|(name, _)| name.to_owned()).collect())
            .unwrap_or_default();
        registries.sort_unstable();
        Ok(registries)
    }

    pub fn active_profiles(&self) -> Result<Vec<(String, String)>> {
        let mut active = Vec::new();
        for registry in self.active_registries()? {
            if let Some(profile) = self.active_profile(&registry)? {
                active.push((registry, profile.to_owned()));
            }
        }
        Ok(active)
    }

    pub fn active_profile(
        &self,
        registry: &str
    ) -> Result<Option<&str>> {
        if self.registry_token(registry)?.is_none() {
            return Ok(None);
        }

        Ok(self.active_table()?.and_then(|table| table.get(registry)).and_then(Item::as_str))
    }

    pub fn registry_token(
        &self,
        registry: &str
    ) -> Result<Option<&str>> {
        if registry == DEFAULT_REGISTRY {
            return Ok(optional_table(self.document.as_table(), "registry")?
                .and_then(|table| table.get("token"))
                .and_then(Item::as_str));
        }

        Ok(optional_table(self.document.as_table(), "registries")?
            .map(|registries| optional_table(registries, registry))
            .transpose()?
            .flatten()
            .and_then(|table| table.get("token"))
            .and_then(Item::as_str))
    }

    pub fn has_profiles_for_registry(
        &self,
        registry: &str
    ) -> Result<bool> {
        Ok(!self.profiles(Some(registry))?.is_empty())
    }

    pub fn would_overwrite_unmanaged_token(
        &self,
        registry: &str,
        token: &str
    ) -> Result<bool> {
        if self.active_profile(registry)?.is_some() {
            return Ok(false);
        }

        Ok(self.registry_token(registry)?.is_some_and(|current| current != token))
    }

    pub fn contains(
        &self,
        name: &str,
        registry: &str
    ) -> Result<bool> {
        Ok(self
            .profile_table(name)?
            .map(|profile| optional_table(profile, "credentials"))
            .transpose()?
            .flatten()
            .is_some_and(|credentials| credentials.contains_key(registry)))
    }

    pub fn insert(
        &mut self,
        name: &str,
        registry: &str,
        encoded: String
    ) -> Result<()> {
        validate_profile_name(name)?;
        validate_registry_name(registry)?;
        credential_kind(&encoded)?;
        table_mut(self.profile_table_mut(name)?, "credentials")?.insert(registry, value(encoded));
        Ok(())
    }

    pub fn remove(
        &mut self,
        name: &str,
        registry: &str
    ) -> Result<bool> {
        if !self.contains(name, registry)? {
            return Ok(false);
        }
        let removed = self
            .profile_table_mut(name)?
            .get_mut("credentials")
            .and_then(Item::as_table_mut)
            .is_some_and(|credentials| credentials.remove(registry).is_some());

        if removed && self.stored_active_profile(registry)? == Some(name) {
            self.clear_active_profile(registry)?;
            self.remove_registry_token(registry)?;
        }

        self.remove_empty_profile(name)?;
        Ok(removed)
    }

    pub fn encoded(
        &self,
        name: &str,
        registry: &str
    ) -> Result<&str> {
        self.profile_table(name)?
            .map(|profile| optional_table(profile, "credentials"))
            .transpose()?
            .flatten()
            .and_then(|credentials| credentials.get(registry))
            .and_then(Item::as_str)
            .ok_or_else(|| anyhow!("profile {name:?} has no credential for registry {registry:?}"))
    }

    pub fn activate(
        &mut self,
        name: &str,
        registry: &str,
        token: &str
    ) -> Result<()> {
        if !self.contains(name, registry)? {
            bail!("profile {name:?} has no credential for registry {registry:?}");
        }

        self.registry_table_mut(registry)?.insert("token", value(token));
        self.active_table_mut()?.insert(registry, value(name));
        Ok(())
    }

    pub fn clear_active_profile(
        &mut self,
        registry: &str
    ) -> Result<bool> {
        Ok(optional_table_mut(self.auth_table_mut()?, "active")?
            .is_some_and(|active| active.remove(registry).is_some()))
    }

    pub fn remove_registry_token(
        &mut self,
        registry: &str
    ) -> Result<bool> {
        Ok(self.registry_table_mut(registry)?.remove("token").is_some())
    }

    pub fn save(&self) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            anyhow!("credentials path {} has no parent directory", self.path.display())
        })?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;

        let mut temporary = NamedTempFile::new_in(parent).with_context(|| {
            format!("failed to create a temporary file in {}", parent.display())
        })?;
        use std::io::Write;
        let contents = Zeroizing::new(self.document.to_string());
        temporary.write_all(contents.as_bytes()).context("failed to write credentials")?;
        temporary.as_file().sync_all().context("failed to sync credentials")?;
        temporary
            .persist(&self.path)
            .map_err(|error| error.error)
            .with_context(|| format!("failed to replace {}", self.path.display()))?;
        Ok(())
    }

    fn migrate_legacy_format(&mut self) -> Result<()> {
        let legacy_active = match self.auth_table_mut()?.get("active") {
            Some(item) if item.is_str() => self
                .auth_table_mut()?
                .remove("active")
                .and_then(|item| item.as_str().map(str::to_owned)),
            Some(item) if item.is_table() => None,
            Some(_) => bail!("cargo-auth active profiles must be a string or TOML table"),
            None => None
        };
        if let Some(name) = legacy_active {
            let active = self.active_table_mut()?;
            if !active.contains_key(DEFAULT_REGISTRY) {
                active.insert(DEFAULT_REGISTRY, value(name));
            }
        }

        let legacy_credentials = self
            .auth_table_mut()?
            .remove("credentials")
            .map(|item| {
                item.into_table()
                    .map_err(|_| anyhow!("legacy cargo-auth credentials must be a TOML table"))
            })
            .transpose()?;
        if let Some(credentials) = legacy_credentials {
            for (name, item) in credentials {
                let target = table_mut(self.profile_table_mut(&name)?, "credentials")?;
                if !target.contains_key(DEFAULT_REGISTRY) {
                    target.insert(DEFAULT_REGISTRY, item);
                }
            }
        }

        Ok(())
    }

    fn auth_table(&self) -> Result<Option<&Table>> {
        optional_table(self.document.as_table(), "cargo-auth")
    }

    fn auth_table_mut(&mut self) -> Result<&mut Table> {
        table_mut(self.document.as_table_mut(), "cargo-auth")
    }

    fn active_table(&self) -> Result<Option<&Table>> {
        self.auth_table()?
            .map(|auth| optional_table(auth, "active"))
            .transpose()
            .map(Option::flatten)
    }

    fn active_table_mut(&mut self) -> Result<&mut Table> {
        table_mut(self.auth_table_mut()?, "active")
    }

    fn profiles_table(&self) -> Result<Option<&Table>> {
        self.auth_table()?
            .map(|auth| optional_table(auth, "profiles"))
            .transpose()
            .map(Option::flatten)
    }

    fn profiles_table_mut(&mut self) -> Result<&mut Table> {
        table_mut(self.auth_table_mut()?, "profiles")
    }

    fn profile_table(
        &self,
        name: &str
    ) -> Result<Option<&Table>> {
        self.profiles_table()?
            .and_then(|profiles| profiles.get(name))
            .map(|item| {
                item.as_table().ok_or_else(|| anyhow!("profile {name:?} must be a TOML table"))
            })
            .transpose()
    }

    fn profile_table_mut(
        &mut self,
        name: &str
    ) -> Result<&mut Table> {
        table_mut(self.profiles_table_mut()?, name)
    }

    fn registry_table_mut(
        &mut self,
        registry: &str
    ) -> Result<&mut Table> {
        if registry == DEFAULT_REGISTRY {
            return table_mut(self.document.as_table_mut(), "registry");
        }
        table_mut(table_mut(self.document.as_table_mut(), "registries")?, registry)
    }

    fn stored_active_profile(
        &self,
        registry: &str
    ) -> Result<Option<&str>> {
        Ok(self.active_table()?.and_then(|active| active.get(registry)).and_then(Item::as_str))
    }

    fn remove_empty_profile(
        &mut self,
        name: &str
    ) -> Result<()> {
        let empty = self
            .profile_table(name)?
            .map(|profile| optional_table(profile, "credentials"))
            .transpose()?
            .flatten()
            .is_none_or(Table::is_empty);
        if empty {
            self.profiles_table_mut()?.remove(name);
        }
        Ok(())
    }
}

pub fn encrypt_token(
    token: &[u8],
    password: &[u8]
) -> Result<String> {
    let mut salt = [0_u8; SALT_LEN];
    getrandom::fill(&mut salt).context("failed to generate encryption salt")?;

    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).context("failed to generate encryption nonce")?;

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow!("invalid encryption key length"))?;
    let nonce = XNonce::try_from(nonce.as_slice())
        .map_err(|_| anyhow!("invalid encryption nonce length"))?;
    let ciphertext =
        cipher.encrypt(&nonce, token).map_err(|_| anyhow!("failed to encrypt credential"))?;

    Ok(format!(
        "{ENCRYPTED_PREFIX}{}:{}:{}",
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

pub fn decrypt_token(
    encoded: &str,
    password: &[u8]
) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(token) = encoded.strip_prefix(PLAINTEXT_PREFIX) {
        return Ok(Zeroizing::new(token.as_bytes().to_vec()));
    }

    let payload = encoded
        .strip_prefix(ENCRYPTED_PREFIX)
        .ok_or_else(|| anyhow!("unsupported credential format"))?;
    let mut parts = payload.split(':');
    let salt = decode_part(parts.next(), "salt")?;
    let nonce = decode_part(parts.next(), "nonce")?;
    let ciphertext = decode_part(parts.next(), "ciphertext")?;
    if parts.next().is_some() {
        bail!("invalid encrypted credential format");
    }
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        bail!("invalid encrypted credential parameters");
    }

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow!("invalid encryption key length"))?;
    let nonce = XNonce::try_from(nonce.as_slice())
        .map_err(|_| anyhow!("invalid encryption nonce length"))?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("could not decrypt credential; the password may be incorrect"))?;
    Ok(Zeroizing::new(plaintext))
}

pub fn plaintext_credential(token: &str) -> String {
    format!("{PLAINTEXT_PREFIX}{token}")
}

pub fn credential_kind(encoded: &str) -> Result<CredentialKind> {
    if encoded.starts_with(ENCRYPTED_PREFIX) {
        Ok(CredentialKind::Encrypted)
    } else if encoded.starts_with(PLAINTEXT_PREFIX) {
        Ok(CredentialKind::Plaintext)
    } else {
        bail!("unsupported credential format")
    }
}

fn derive_key(
    password: &[u8],
    salt: &[u8]
) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0_u8; 32]);
    // These parameters are part of the enc:v1 on-disk format and must remain stable.
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|error| anyhow!("invalid Argon2id parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|error| anyhow!("failed to derive encryption key: {error}"))?;
    Ok(key)
}

fn decode_part(
    part: Option<&str>,
    name: &str
) -> Result<Vec<u8>> {
    let part = part.ok_or_else(|| anyhow!("encrypted credential is missing {name}"))?;
    URL_SAFE_NO_PAD.decode(part).with_context(|| format!("encrypted credential has invalid {name}"))
}

pub fn validate_profile_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("profile name cannot be empty");
    }
    if RESERVED_PROFILE_NAMES.iter().any(|reserved| name.eq_ignore_ascii_case(reserved)) {
        bail!("profile name {name:?} is reserved by cargo-auth");
    }
    Ok(())
}

pub fn validate_registry_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("registry name cannot be empty");
    }
    if name.chars().any(char::is_control) {
        bail!("registry name cannot contain control characters");
    }
    Ok(())
}

fn optional_table<'a>(
    parent: &'a Table,
    name: &str
) -> Result<Option<&'a Table>> {
    parent
        .get(name)
        .map(|item| item.as_table().ok_or_else(|| anyhow!("{name:?} must be a TOML table")))
        .transpose()
}

fn optional_table_mut<'a>(
    parent: &'a mut Table,
    name: &str
) -> Result<Option<&'a mut Table>> {
    parent
        .get_mut(name)
        .map(|item| item.as_table_mut().ok_or_else(|| anyhow!("{name:?} must be a TOML table")))
        .transpose()
}

fn table_mut<'a>(
    parent: &'a mut Table,
    name: &str
) -> Result<&'a mut Table> {
    if !parent.contains_key(name) {
        parent.insert(name, Item::Table(Table::new()));
    }
    parent
        .get_mut(name)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| anyhow!("{name:?} must be a TOML table"))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn encrypted_credentials_round_trip() {
        let encrypted = encrypt_token(b"secret-token", b"master-password").unwrap();

        assert!(encrypted.starts_with("enc:v1:"));
        assert_eq!(
            decrypt_token(&encrypted, b"master-password").unwrap().as_slice(),
            b"secret-token"
        );
    }

    #[test]
    fn wrong_password_does_not_decrypt() {
        let encrypted = encrypt_token(b"secret-token", b"right-password").unwrap();

        let error = decrypt_token(&encrypted, b"wrong-password").unwrap_err();
        assert!(error.to_string().contains("password may be incorrect"));
    }

    #[test]
    fn command_names_are_reserved_for_profiles() {
        for name in RESERVED_PROFILE_NAMES {
            let error = validate_profile_name(name).unwrap_err();
            assert!(error.to_string().contains("is reserved"));
        }
        assert!(validate_profile_name("CURRENT").is_err());
        assert!(validate_profile_name("personal").is_ok());
    }

    #[test]
    fn store_preserves_existing_cargo_credentials() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("credentials.toml");
        fs::write(&path, "[registries.private]\ntoken = \"existing-token\"\n").unwrap();

        let mut store = CredentialStore::load(&path).unwrap();
        store.insert("personal", DEFAULT_REGISTRY, plaintext_credential("new-token")).unwrap();
        store.activate("personal", DEFAULT_REGISTRY, "new-token").unwrap();
        store.save().unwrap();

        let saved = fs::read_to_string(path).unwrap();
        let document = saved.parse::<DocumentMut>().unwrap();
        assert_eq!(document["registries"]["private"]["token"].as_str(), Some("existing-token"));
        assert_eq!(document["registry"]["token"].as_str(), Some("new-token"));
        assert_eq!(document["cargo-auth"]["active"][DEFAULT_REGISTRY].as_str(), Some("personal"));
    }

    #[test]
    fn registry_token_can_be_checked_before_adding_the_first_profile() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("credentials.toml");
        fs::write(&path, "[registry]\ntoken = \"existing-token\"\n").unwrap();

        let store = CredentialStore::load(path).unwrap();

        assert!(!store.has_profiles_for_registry(DEFAULT_REGISTRY).unwrap());
        assert_eq!(store.registry_token(DEFAULT_REGISTRY).unwrap(), Some("existing-token"));
    }

    #[test]
    fn store_reports_when_profiles_exist() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("credentials.toml");
        fs::write(&path, "[registry]\ntoken = \"existing-token\"\n").unwrap();
        let mut store = CredentialStore::load(path).unwrap();
        store.insert("work", DEFAULT_REGISTRY, plaintext_credential("work-token")).unwrap();

        assert!(store.has_profiles_for_registry(DEFAULT_REGISTRY).unwrap());
    }

    #[test]
    fn unmanaged_different_token_is_not_safe_to_overwrite() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("credentials.toml");
        fs::write(&path, "[registry]\ntoken = \"existing-token\"\n").unwrap();
        let store = CredentialStore::load(path).unwrap();

        assert!(
            !store.would_overwrite_unmanaged_token(DEFAULT_REGISTRY, "existing-token").unwrap()
        );
        assert!(
            store.would_overwrite_unmanaged_token(DEFAULT_REGISTRY, "different-token").unwrap()
        );
    }

    #[test]
    fn removing_active_profile_clears_active_token() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("credentials.toml");
        let mut store = CredentialStore::load(path).unwrap();
        store.insert("work", DEFAULT_REGISTRY, plaintext_credential("work-token")).unwrap();
        store.activate("work", DEFAULT_REGISTRY, "work-token").unwrap();

        assert!(store.remove("work", DEFAULT_REGISTRY).unwrap());
        assert_eq!(store.active_profile(DEFAULT_REGISTRY).unwrap(), None);
        assert!(store.document["registry"].get("token").is_none());
    }

    #[test]
    fn clearing_active_profile_keeps_saved_profiles() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("credentials.toml");
        let mut store = CredentialStore::load(path).unwrap();
        store.insert("work", DEFAULT_REGISTRY, plaintext_credential("work-token")).unwrap();
        store.activate("work", DEFAULT_REGISTRY, "work-token").unwrap();

        assert!(store.clear_active_profile(DEFAULT_REGISTRY).unwrap());

        assert_eq!(store.active_profile(DEFAULT_REGISTRY).unwrap(), None);
        assert!(store.contains("work", DEFAULT_REGISTRY).unwrap());
    }

    #[test]
    fn profiles_are_sorted_and_mark_the_active_one() {
        let temporary = TempDir::new().unwrap();
        let mut store = CredentialStore::load(temporary.path().join("credentials.toml")).unwrap();
        store.insert("work", DEFAULT_REGISTRY, plaintext_credential("work-token")).unwrap();
        store.insert("personal", DEFAULT_REGISTRY, plaintext_credential("personal-token")).unwrap();
        store.activate("work", DEFAULT_REGISTRY, "work-token").unwrap();

        let profiles = store.profiles(Some(DEFAULT_REGISTRY)).unwrap();
        assert_eq!(profiles[0].name, "personal");
        assert!(!profiles[0].active);
        assert_eq!(profiles[1].name, "work");
        assert!(profiles[1].active);
    }

    #[test]
    fn one_profile_can_hold_independent_registry_credentials() {
        let temporary = TempDir::new().unwrap();
        let mut store = CredentialStore::load(temporary.path().join("credentials.toml")).unwrap();
        store.insert("personal", DEFAULT_REGISTRY, plaintext_credential("crates-token")).unwrap();
        store.insert("personal", "de02", plaintext_credential("de02-token")).unwrap();
        store.activate("personal", DEFAULT_REGISTRY, "crates-token").unwrap();
        store.activate("personal", "de02", "de02-token").unwrap();

        assert_eq!(store.registries_for_profile("personal").unwrap(), vec!["crates-io", "de02"]);
        assert_eq!(store.registry_token(DEFAULT_REGISTRY).unwrap(), Some("crates-token"));
        assert_eq!(store.registry_token("de02").unwrap(), Some("de02-token"));
        assert_eq!(store.active_profile(DEFAULT_REGISTRY).unwrap(), Some("personal"));
        assert_eq!(store.active_profile("de02").unwrap(), Some("personal"));
    }

    #[test]
    fn removing_one_registry_keeps_the_rest_of_the_profile() {
        let temporary = TempDir::new().unwrap();
        let mut store = CredentialStore::load(temporary.path().join("credentials.toml")).unwrap();
        store.insert("personal", DEFAULT_REGISTRY, plaintext_credential("crates-token")).unwrap();
        store.insert("personal", "de02", plaintext_credential("de02-token")).unwrap();

        assert!(store.remove("personal", "de02").unwrap());
        assert!(store.contains("personal", DEFAULT_REGISTRY).unwrap());
        assert!(!store.contains("personal", "de02").unwrap());
    }

    #[test]
    fn legacy_profiles_are_migrated_to_crates_io() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("credentials.toml");
        fs::write(
            &path,
            "[registry]\ntoken = \"work-token\"\n\
             [cargo-auth]\nactive = \"work\"\n\
             [cargo-auth.credentials]\nwork = \"plain:work-token\"\n"
        )
        .unwrap();

        let store = CredentialStore::load(path).unwrap();

        assert_eq!(store.active_profile(DEFAULT_REGISTRY).unwrap(), Some("work"));
        assert_eq!(store.encoded("work", DEFAULT_REGISTRY).unwrap(), "plain:work-token");
        assert_eq!(store.registries_for_profile("work").unwrap(), vec!["crates-io"]);
    }

    #[test]
    fn alternate_registry_activation_preserves_other_cargo_entries() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("credentials.toml");
        fs::write(
            &path,
            "[registry]\ntoken = \"crates-token\"\n\
             [registries.existing]\ntoken = \"existing-token\"\n"
        )
        .unwrap();
        let mut store = CredentialStore::load(&path).unwrap();
        store.insert("work", "de02", plaintext_credential("de02-token")).unwrap();
        store.activate("work", "de02", "de02-token").unwrap();
        store.save().unwrap();

        let saved = fs::read_to_string(path).unwrap();
        let document = saved.parse::<DocumentMut>().unwrap();
        assert_eq!(document["registry"]["token"].as_str(), Some("crates-token"));
        assert_eq!(document["registries"]["existing"]["token"].as_str(), Some("existing-token"));
        assert_eq!(document["registries"]["de02"]["token"].as_str(), Some("de02-token"));
    }

    #[test]
    fn registry_names_must_not_be_empty_or_contain_controls() {
        assert!(validate_registry_name("").is_err());
        assert!(validate_registry_name("de02\nother").is_err());
        assert!(validate_registry_name("de02").is_ok());
        assert!(validate_registry_name("company-registry").is_ok());
    }
}
