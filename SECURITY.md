# Security Policy

## Scope

**In scope**

- All Go source code in this repository (`pkg/`, `tests/`, `cmd/`)
- Test fixtures and interop vectors under `tests/interop/`
- Build and release infrastructure (`Makefile`, CI workflows, `go.mod`)

**Out of scope**

- Downstream applications that consume go-libsignal as a library
- The Rust libsignal upstream (report those directly to Signal Messenger)
- Third-party dependencies (report to respective upstream maintainers)
- Vulnerabilities requiring physical access to the host machine

## Reporting a Vulnerability

Preferred channel: open a **GitHub Security Advisory** at
<https://github.com/jeremyhahn/go-libsignal/security/advisories/new>

Alternate contact: `mail@jeremyhahn.com`

Encrypted email is strongly encouraged. GPG fingerprint:
`(TBD — see release notes)`

Please include:

- A concise description of the vulnerability and its impact
- Affected package(s) and version(s)
- Reproduction steps or a minimal proof-of-concept
- Whether you believe the issue also affects the Rust libsignal upstream

Do **not** open a public GitHub issue for security-sensitive findings.

## Disclosure Timeline

| Milestone | Target |
|---|---|
| Acknowledgment of report | 5 business days |
| Fix or remediation plan communicated | 30 days from acknowledgment |
| Coordinated public disclosure | 90 days from acknowledgment |

If a fix requires coordinated disclosure with Signal Messenger (see
[Reference](#reference) below), the timeline may be extended by mutual
agreement with the reporter.

## Supported Versions

| Version series | Support status |
|---|---|
| v0.x (current) | Active — security fixes applied to the latest minor release only |

**Note**: go-libsignal is pre-1.0. Breaking API changes may land in any
`v0.x` release. There is no long-term-support branch at this time.

## What We Consider a Vulnerability

The following categories are treated as security vulnerabilities:

1. **Cryptographic weaknesses** — incorrect algorithm implementation,
   weak key generation, IV/nonce reuse, or broken authentication in any
   package under `pkg/{cipher,kdf,kem,ecc,sealed,backup,svr}`.

2. **Key-derivation divergence from Rust upstream** — any deviation from
   the byte-wire-compatible output of the pinned Rust libsignal commit
   (recorded in `RUST_REV`) that affects encrypted message compatibility
   or session establishment.

3. **Panic on untrusted input** — any `panic` reachable by providing
   attacker-controlled data to a public API.

4. **Constant-time comparison violations on secret material** — use of
   variable-time comparison (e.g., `bytes.Equal` on HMAC tags or private
   keys) where constant-time comparison is required.

5. **Deserializer crashes or hangs** — unbounded memory allocation,
   infinite loops, or crashes triggered by malformed protocol buffers,
   serialized session state, or interop fixture data.

6. **Zero-knowledge proof soundness failures** — forged proofs accepted
   as valid in `pkg/{poksho,zkcredential,zkgroup}`.

## What We Don't Consider a Vulnerability

The following are **not** treated as security vulnerabilities:

- Defensive `panic` calls guarding OOM or programmer-error conditions
  that are explicitly exempted in coverage reports
- Performance degradation without a demonstrable denial-of-service impact
- Build system, CI, or test infrastructure issues that do not affect
  production binaries
- Issues already disclosed and tracked in the upstream Rust libsignal
  repository that have not yet been ported to this Go implementation

## Bounty / Acknowledgment Policy

There is no bug-bounty program at this time.

Reporters are credited by name (or handle) in the relevant `CHANGELOG`
entry unless they request anonymity. Reporters who prefer not to be named
should state so in their initial report.

## Reference

go-libsignal mirrors **Rust libsignal v0.92.2** (commit `98915c44`).
Vulnerabilities that affect both this library and the Rust upstream
should also be reported to Signal Messenger via their coordinated
disclosure process at <https://signal.org/security/>.
