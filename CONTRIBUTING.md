# Contributing to go-libsignal

Thank you for your interest in contributing. This document describes the
process, standards, and constraints that keep go-libsignal correct,
secure, and wire-compatible with the Rust libsignal upstream.

## Code of Conduct

All participants are expected to follow the project's
[Code of Conduct](CODE_OF_CONDUCT.md). Please read it before
interacting with the community.

## Upstream-Pin Policy

This is the most important section of this document.

go-libsignal is a **byte-wire-compatible pure-Go port** of Rust
libsignal. Every public Go symbol must trace to a corresponding Rust
libsignal symbol at the commit pinned in `/RUST_REV` (repository root),
or to the documented standalone-crate equivalent:

| Package | Rust / standalone crate source |
|---|---|
| `pkg/spqr` | `sparsepostquantumratchet v1.5.1` |
| `pkg/mlkembraid` | `sparsepostquantumratchet v1.5.1` |
| All others | Rust libsignal at `RUST_REV` |

**Rules**

1. Document the Rust source path in the doc comment of every new public
   API symbol. Example: `// EncryptMessage implements the Rust
   session_cipher::encrypt in signal-protocol/src/session_cipher.rs`.

2. Test vectors must match upstream byte-for-byte. The authoritative
   fixtures live under `tests/interop/fixtures/wire/*.json` and are
   emitted by the Rust binary at
   `tests/interop/rust/src/bin/wire_emitter.rs`.

3. **Bumping `RUST_REV`** requires:
   - Regenerating all wire fixtures via `make interop-wire-emit`
   - Re-running the full cross-implementation suite via
     `make interop-live`
   - All existing tests continuing to pass with zero byte-level
     divergence

4. Never introduce a symbol, algorithm, or wire-format extension that
   has no counterpart in the pinned Rust upstream without prior
   discussion and explicit approval in the PR.

## Development Setup

### Toolchain

- **Go 1.27.1 exactly** — `go.mod` and `toolchain` directives are
  pinned; do not upgrade without a coordinated bump of `RUST_REV`.
- **`GOWORK=off` is mandatory** for every `go` command. The parent
  workspace at `/mnt/vm-host-1/go.work` pins a different toolchain
  version and will break the build if the workspace is active.

  ```
  GOWORK=off go test ./...
  GOWORK=off go build ./...
  ```

- Add `export GOWORK=off` to your shell profile when working primarily
  on this repository.

### Fixture regeneration dependencies

The following are required only when regenerating Rust-emitted interop
fixtures (`make interop-wire-emit`):

- Rust stable toolchain + `cargo` (version compatible with the pinned
  `RUST_REV`)
- `protoc` (Protocol Buffers compiler)
- `protoc-gen-go` and `protoc-gen-go-grpc`

### Locked-memory requirement (`RLIMIT_MEMLOCK`)

`pkg/util/crypto/secret` uses `github.com/jeremyhahn/go-enclave`, which
`mlock(2)`s every secret it holds. go-enclave surrounds each buffer with a
canary and guard pages that are mapped `PROT_NONE` and never mlock'd, so a
32-byte message key costs one locked page, and the test
suite holds thousands of them at once: `TestGroupCipherDecryptTooFarInFuture`
alone drives a sender chain 25,002 messages forward to exercise the
`maxForwardJumps` limit.

**Run the suite with `ulimit -l` of at least 2 GiB**, or `unlimited`.
Measured on go1.26.6 with `-race`, 2026-08-14:

| `ulimit -l` | Result |
|---|---|
| 8 MiB (Docker's default) | fails at chain iteration ~511 |
| 64 MiB | fails at ~4074 |
| 256 MiB / 512 MiB | still fails in `pkg/groups` and `pkg/session` |
| 2 GiB | passes |

The failure is not a flake and not a leak — `GOGC=1` fails at the exact
same iteration, so the buffers are genuinely live. It surfaces as:

```
secret: allocation failed: <memcall> could not acquire lock on 0x...,
limit reached? [Err: cannot allocate memory]
```

Container runtimes are the usual culprit: Docker defaults `memlock` to
8 MiB, hard limit included, and `RLIMIT_MEMLOCK` cannot be raised past
its hard limit without `CAP_SYS_RESOURCE`. Run containers with an
explicit budget, e.g. `--ulimit memlock=4294967296:4294967296`. The
GitHub-hosted VM starts at 8 MiB, and the CI jobs raise it to 4 GiB with
`sudo prlimit` before the tests (Company Agent m2286 (2)). Local runs
still need the limit raised by hand.

Prefer a bounded figure to `-1:-1`. Locked pages are unswappable, so an
unlimited job can pin all of a shared runner's RAM. The company's Gitea
runners grant 4 GiB (ratified 2026-08-14, `infra/gitea/docs/lessons.md`):
2x the measured requirement, raised deliberately if a suite ever
outgrows it.

## Commit Conventions

- **Subject**: short imperative sentence, ≤ 72 characters, no period.
  Example: `Add constant-time MAC comparison to pkg/cipher`
- **Body**: explain *why* the change is made, not just what. Reference
  the Rust symbol or issue being addressed.
- **DCO sign-off**: every commit must carry a `Signed-off-by` line.
  Use `git commit -s` to add it automatically.
- Every commit must leave the repository in a state where `make ci`
  passes in full.

## Testing Requirements

The following gates must all pass before a PR is merged:

| Command | What it runs |
|---|---|
| `make test` | Unit tests for all packages |
| `make integration-test` | End-to-end integration tests |
| `make interop-fixtures-check` | Byte-level diff against Rust-emitted vectors |
| `make fips` | Build + unit tests under `GODEBUG=fips140=only` |

`make fips` runs the suite against the Go Cryptographic Module with every
non-approved operation set to fail. `tests/fipsaudit` backs it with a static
scan of all production source, so a non-approved primitive is caught whether or
not a gated test reaches it. If either goes red, read `docs/FIPS.md` before
doing anything else: the answer is normally to fix the call site or the
fixture, and only a primitive an external protocol or conformance vector fixes
earns an entry in that document's exemption register. Reverting the flag,
skipping the job or narrowing its scope are not options.

**Coverage targets (minimum per package)**

| Package | Minimum coverage |
|---|---|
| All others | 90% |
| `pkg/groups/ratchet` | Declared exemption — document per-PR |
| `pkg/mlkembraid` | Declared exemption — document per-PR |
| `pkg/util/crypto/secret` | Declared exemption — document per-PR |
| `pkg/tripleratchet` | Declared exemption — document per-PR |

**Error handling**: all error conditions must use typed error values
declared in the package's `errors.go`. Never use `fmt.Errorf` to
construct a new error type, and never suppress errors with `_`.

## Security-Sensitive Pull Requests

Any PR that touches the following packages must be flagged for explicit
security review by including the label `security-review` and a
**forensic-audit-style description** in the PR body:

```
pkg/cipher    pkg/kdf       pkg/kem        pkg/ecc
pkg/mlkembraid pkg/spqr     pkg/session    pkg/ratchet
pkg/sealed    pkg/backup    pkg/svr        pkg/zkgroup
pkg/zkcredential pkg/poksho pkg/protocol
```

The forensic-audit description must cover:

- Which Rust symbol(s) the change corresponds to
- Why the current behavior is incorrect or incomplete
- What invariants the new code preserves (and how you verified them)
- Whether test vectors were regenerated or extended
- Any constant-time properties asserted or relied upon

Security-sensitive PRs will not be merged without at least one explicit
approving review from a maintainer who has read the audit notes.

## Branching Model

- `main` is the release branch. It must always be releasable.
- All work happens on short-lived feature branches named
  `<scope>/<short-description>`, e.g., `kem/mlkem768-keygen-fix`.
- Merge via PR only; direct pushes to `main` are not permitted.
- Rebase onto `main` before requesting review; merge commits are not
  accepted.

## Developer Certificate of Origin (DCO)

By contributing to this project you certify, under the terms of the
[Developer Certificate of Origin v1.1](https://developercertificate.org/),
that you have the right to submit the contribution. Add a sign-off to
every commit:

```
git commit -s -m "Your commit message"
```

This produces:

```
Signed-off-by: Your Name <you@example.com>
```

PRs that contain unsigned commits will not be merged.
