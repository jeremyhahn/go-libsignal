# libsignal-interop Rust CLI

A Rust CLI for SPQR wire-format interop testing between Go and Rust libsignal.

## Build

```
cargo build --release --manifest-path tests/interop/rust/Cargo.toml
```

Or via the project Makefile:

```
make interop-live-build
```

## Subcommands

All subcommands emit JSON to stdout on success and `{"error":"..."}` to
stderr with a non-zero exit status on failure.

### `spqr-init --seed <u64> --direction <a2b|b2a>`

Initialises SPQR state from the hardcoded shared auth key.
Emits: `{"state_hex":"..."}`.

### `spqr-send --seed <u64> --state-hex <hex>`

Runs one `spqr::send` step using a `ChaCha20Rng` seeded from `--seed`.
Emits: `{"state_hex":"...","key_hex":"...","msg_hex":"..."}`.
`key_hex` is empty when negotiation is pending.

### `spqr-recv --state-hex <hex> --msg-hex <hex>`

Runs one `spqr::recv` step. Emits: `{"state_hex":"...","key_hex":"..."}`.
`key_hex` is empty when negotiation is pending.

## Auth key

All subcommands share the hardcoded auth key `interop-shared-auth-key-32bytes!`
(32 bytes). The Go test driver uses the same value.
