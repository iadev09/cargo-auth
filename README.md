# cargo-auth

`cargo-auth` is a Cargo external subcommand for keeping multiple encrypted
credential profiles for crates.io and alternate Cargo registries.

## Installation

Install the latest release from crates.io:

```console
cargo install cargo-auth
```

Use `cargo install cargo-auth --locked` when you specifically want to install
with the dependency versions pinned by the published package.

Or install the current source checkout:

```console
cargo install --path .
```

## Usage

```console
cargo auth add personal
cargo auth add work
cargo auth add personal --registry de02
cargo auth list
cargo auth use personal
cargo auth use personal --registry de02
cargo auth current --all
cargo auth current
cargo auth logout
```

When the first profile is added, `cargo-auth` checks whether its token matches
Cargo's existing active `[registry].token`. A different unmanaged token is not
overwritten: the command exits with the `credentials.toml` path and asks you to
add the existing token first or remove it before adding a different one. A
matching token is saved normally and marked active.

Tokens are encrypted by default with a key derived from an interactively
entered master password. The password is never accepted as a command-line
argument or stored on disk.

Profiles are stored in Cargo's user-level `credentials.toml`. Each profile can
hold a separate credential for crates.io and for any number of named alternate
registries. Running `cargo auth use NAME` decrypts the crates.io credential and
writes it to `[registry].token`. Running `cargo auth use NAME --registry REGISTRY`
writes the selected alternate credential to `[registries.REGISTRY].token`.
Active tokens are therefore present as plaintext while they are active.

`cargo-auth` manages credentials only. It does not add, remove, or validate
registry definitions and does not need to run inside a Cargo project. Named
registries remain configured through Cargo, usually in `.cargo/config.toml`:

```toml
[registries.de02]
index = "sparse+https://example.invalid/api/packages/developer/cargo/"
```

Registry names passed to `cargo-auth` must match the names used by Cargo.
crates.io is selected when neither `--registry` nor `--all` is supplied.

## Commands

- `add NAME [--registry REGISTRY] [--plain]`
- `remove NAME [--registry REGISTRY | --all]`
- `list [--registry REGISTRY | --all]`
- `encrypt NAME [--registry REGISTRY | --all]`
- `decrypt NAME [--registry REGISTRY | --all]`
- `use NAME [--registry REGISTRY | --all]`
- `logout [--registry REGISTRY | --all]`
- `current [--registry REGISTRY | --all]`

`--all` applies an operation to every applicable registry. For `use`, it
activates only the credentials present in the selected profile; registries not
present in that profile are left unchanged. `add` intentionally accepts only
one registry because registry tokens are independent credentials.

`--plain` and `decrypt` deliberately store a profile without encryption and
print a warning when used.

Command names such as `add`, `remove`, `use`, `current`, and `logout` are
reserved and cannot be used as profile names.

`cargo auth logout` delegates to Cargo's native `cargo logout --registry
crates-io` command to remove the active plaintext token, then clears that
registry's active profile marker. `--registry REGISTRY` targets one alternate
registry and `--all` logs out every registry currently managed as active by
`cargo-auth`. Encrypted profiles remain available for later use.

## Verify the active credential

Cargo does not provide a native `whoami` command. To verify that the active
token is accepted by crates.io, list the owners of a crate that the token can
access:

```console
cargo auth use personal
cargo owner --list <crate-you-own>
```

A successful response confirms that the token is valid for that operation. It
lists every owner of the crate; it does not identify which owner the active
token belongs to. The crate must already exist on crates.io.

## License

Licensed under the MIT License. See [LICENSE-MIT](LICENSE-MIT).
