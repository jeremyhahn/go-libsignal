# Bumping the Pinned Rust libsignal Commit

Bumping `RUST_REV` is the most security-sensitive maintainer operation in the repo — every
byte-level test depends on `RUST_REV`. Follow this checklist exactly. Do not skip or reorder
steps; each gate protects the one after it.

The value currently pinned is recorded in `/RUST_REV` (first line: SHA, second line: tag,
followed by an explanatory comment). The canonical Rust upstream lives at
`/mnt/vm-host-1/libsignal/` on the build host.

---

## Prerequisites

Before starting, confirm all of the following are true:

- **Clean working tree.** No uncommitted changes outside this bump. Stash or commit everything
  else first.
- **Local Rust libsignal checkout** at `/mnt/vm-host-1/libsignal/` (or adjust
  `LIBSIGNAL_UPSTREAM` to wherever yours lives).
- **Toolchain present:** `cargo`, `rustc`, `protoc`, and `protoc-gen-go` are on `PATH`.
- **Target commit known.** You have a specific upstream SHA you want to pin to. Write it down
  before you begin:

  ```
  NEW_SHA=<paste 40-char SHA here>
  NEW_TAG=<paste tag, e.g. v0.93.0, or "unreleased" if none>
  ```

- **`GOWORK=off` set** for every `go` command in this repo (the parent workspace at
  `/mnt/vm-host-1/go.work` requires Go 1.26.3 but this repo pins 1.26.2; see
  `memory/env_gowork_mismatch.md`).

---

## Step 1 — Validate the New Commit Against Current Fixtures

Check out the target commit in the Rust upstream and run the drift check against the
currently-committed fixtures. This tells you what actually changed before you touch anything.

```sh
cd /mnt/vm-host-1/libsignal
git checkout <new-sha>

cd /mnt/vm-host-1/go-libsignal
LIBSIGNAL_UPSTREAM=/mnt/vm-host-1/libsignal \
  tests/interop/scripts/check_fixtures.sh
```

Expected output: a drift report listing every fixture whose upstream source byte-hash no longer
matches the value in `tests/interop/fixtures/MANIFEST.toml`.

**Record the complete drift list.** This is your change surface — every item on it requires
review in Step 5.

If the drift list is empty the new commit is wire-identical to the current pin for all tracked
fixtures. You still must complete Steps 3–8 (version metadata, CI gates, changelog).

---

## Step 2 — Regenerate Fixtures

Rebuild the `wire_emitter` binary against the new upstream and write fresh JSON fixtures.

```sh
# From go-libsignal root
GOWORK=off make interop-wire-emit
```

This target:
1. Compiles `tests/interop/rust/src/bin/wire_emitter.rs` against the checked-out upstream.
2. Executes the binary and writes output files under `tests/interop/fixtures/`.

After it completes, update `tests/interop/fixtures/MANIFEST.toml` for every file that was
regenerated:

- `sha256` — recompute with `sha256sum tests/interop/fixtures/<path>`.
- `size` — update to the new byte count.
- `purpose` — **human-edited**; update only if the semantic purpose of the fixture changed
  (e.g., a new field was added to the proto, or the fixture now covers an additional code path).
  Do not touch `purpose` for a pure byte-level refresh with identical semantics.

Re-run the drift check to confirm it is now clean:

```sh
LIBSIGNAL_UPSTREAM=/mnt/vm-host-1/libsignal \
  tests/interop/scripts/check_fixtures.sh
```

The output must be empty (no drift). Do not proceed to Step 3 until it is.

---

## Step 3 — Update RUST_REV

Overwrite `/mnt/vm-host-1/go-libsignal/RUST_REV` with the new commit hash and tag, preserving
the existing comment block format:

```
<new-sha>
<new-tag>
# Upstream Rust libsignal pinned at /mnt/vm-host-1/libsignal
# This commit is the source of truth for every byte-wire format,
# constant, DST, KDF info string, and serialization layout in this repo.
# Bump only after regenerating tests/interop/ vectors and confirming
# the full Go test suite passes against the new fixtures.
```

If the version number (second line) changed, also update the `# Pinned upstream` line in
`CLAUDE.md` to reflect the new tag.

---

## Step 4 — Run All Gates

All four targets must pass before you continue.

```sh
# Full CI suite (unit tests, linters, vet, race detector)
GOWORK=off make ci

# Build and run the live interop binary
GOWORK=off make interop-live-build && GOWORK=off make interop-live

# Sanity-check fixtures without a live upstream checkout
GOWORK=off make interop-fixtures-check

# Coverage — must remain >= 90% total; per-package minimums must be met
GOWORK=off make coverage
```

If any target fails, do not proceed. Diagnose and fix; do not skip.

---

## Step 5 — Wire-Format Regression Triage

For every fixture that appeared in the Step 1 drift list, read the upstream Rust diff to
understand why it drifted. Common causes:

| Cause | What to look for in the Go port |
|---|---|
| Constant rename (KDF info string, DST, version byte) | Grep `pkg/` for the old literal; update to new value |
| Field added to a proto | Check `pkg/proto/wirepb/wire.pb.go`; regenerate if needed |
| Wire layout reshuffled | Compare serialization order in `pkg/serialize/` and relevant `pkg/` packages |
| Crypto primitive parameter changed | Review the relevant `pkg/cipher`, `pkg/kdf`, `pkg/ecc`, or `pkg/kem` implementation |

For each drifted fixture, confirm the corresponding Go implementation in `pkg/` matches the new
Rust behavior. If it does not, that discrepancy is the port work for this bump — fix it before
moving to Step 6.

---

## Step 6 — Forensic Re-Audit (Security-Critical)

For every package whose Go-side implementation changed in Step 5, run the forensic-audit
checklist. If the project maintains a live copy at `docs/maintainer/forensic-audit-checklist.md`
or `/tmp/go-libsignal-audit/FORENSIC_AUDIT.md`, use that. At minimum verify:

- **KDF input order** — key material, salt, and info arguments are concatenated in the same order
  as the Rust implementation.
- **Concatenation byte order** — no endianness inversion relative to upstream.
- **Domain-separation strings** — every DST and KDF info string matches the Rust constant
  byte-for-byte, including length prefix conventions.
- **MAC inputs** — the data committed to HMAC or Poly1305 is identical in scope and order.
- **Constant-time comparisons preserved** — any comparison introduced or modified uses
  `subtle.ConstantTimeCompare`; no early-exit path was added.

Document your findings per package as inline comments referencing the Rust source path, following
the existing convention in the codebase.

---

## Step 7 — Live Interop Confirmation

```sh
GOWORK=off make interop-live
```

All 10 tests must pass. A failure here means the corresponding Go-side code did not fully
converge with the new upstream behavior. Fix the divergence and re-run Steps 4–7 before
continuing.

---

## Step 8 — Documentation

Update `CHANGELOG.md`. Add an entry under `## [Unreleased]` (or open a new version block if this
bump accompanies a release):

```markdown
### Changed

- **RUST_REV bump**: `98915c442d814cd420f4e1a15630ade0d48e66ae` (v0.92.2) →
  `<new-sha>` (<new-tag>).
  - Fixtures regenerated: <list each fixture path from the Step 1 drift list>
  - Go-side changes: <one line per package changed in Step 5, describing what changed and why>
  - New typed errors added: <list or "none">
  - New public symbols: <list or "none">
  - Removed or renamed public symbols: <list or "none">
```

If the version number in `RUST_REV` changed and the README carries a version badge, update the
badge link to point at the new tag.

---

## Step 9 — Tag and Release

If this bump accompanies a Go module release (new semver tag):

1. Finalize the `## [Unreleased]` section in `CHANGELOG.md` by replacing it with the new version
   header, e.g. `## [0.2.0] - YYYY-MM-DD`.
2. Create an annotated tag:

   ```sh
   # Example only — adjust version and message
   git tag -a v0.2.0 -m "go-libsignal v0.2.0 — RUST_REV bumped to <new-tag>"
   ```

3. Push the tag and draft a GitHub release. Use the `CHANGELOG.md` entry as the release body.
   See the format established in the initial release for style guidance.

For a non-release bump (fixtures updated, no Go semver change), skip tagging. Merge to `main`
via the normal PR process.

---

## Rollback Procedure

If any step fails irrecoverably and you need to return to the previous pin:

```sh
git checkout HEAD -- RUST_REV \
  tests/interop/fixtures/MANIFEST.toml \
  tests/interop/fixtures/
```

Then confirm the rollback is clean:

```sh
GOWORK=off make interop-fixtures-check
```

The target must exit 0. If it does not, the fixtures directory has additional untracked files
from the aborted regeneration — remove them and re-run.

Also re-checkout the Rust upstream to the previous SHA recorded in `RUST_REV` before
re-running any interop builds.

---

## Cadence

- **Quarterly** is a reasonable cadence for non-security-driven bumps.
- **Immediately** for any upstream commit that addresses a CVE or security advisory in a
  primitive used by this repo. Coordinate with the Signal security team before publishing.
- Security-driven bumps follow the same checklist; do not abbreviate Steps 5 and 6 under time
  pressure — those are the steps most likely to introduce a silent regression.

---

## Cross-References

| Document | Purpose |
|---|---|
| `/RUST_REV` | Single source of truth for the pinned commit and tag |
| `tests/interop/fixtures/MANIFEST.toml` | Fixture registry; updated in Step 2 |
| `CHANGELOG.md` | Release history; updated in Step 8 |
| `CLAUDE.md` | Project-level AI context; `# Pinned upstream` line updated in Step 3 |
| `memory/env_gowork_mismatch.md` | Explains why `GOWORK=off` is required |
| `memory/wire_emitter_workflow.md` | Details on `make interop-wire-emit` internals |
| `tests/interop/scripts/check_fixtures.sh` | Drift detection script used in Steps 1 and 2 |
