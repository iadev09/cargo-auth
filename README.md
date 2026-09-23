# cargo-auth

`cargo-auth` is a Cargo external subcommand for keeping multiple crates.io
credentials and selecting the active one.

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
cargo auth list
cargo auth use personal
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

Profiles are stored in Cargo's `credentials.toml` under
`[cargo-auth.credentials]`. Running `cargo auth use NAME` decrypts the selected
profile and writes its token to `[registry].token` for compatibility with
Cargo. This means the active token is present as plaintext while it is active.

## Commands

- `add NAME [--plain]`
- `remove NAME`
- `list`
- `encrypt NAME`
- `decrypt NAME`
- `use NAME`
- `logout`
- `current`

`--plain` and `decrypt` deliberately store a profile without encryption and
print a warning when used.

Command names such as `add`, `remove`, `use`, `current`, and `logout` are
reserved and cannot be used as profile names.

`cargo auth logout` delegates to Cargo's native `cargo logout --registry
crates-io` command to remove the active plaintext token, then clears the active
profile marker. Encrypted profiles remain available for a later `use NAME`.

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
