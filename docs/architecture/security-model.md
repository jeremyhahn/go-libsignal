# Security Model

This document describes the security properties, threat model, key management, and side-channel protections in go-libsignal.

## Security Properties

### Forward Secrecy

Each message is encrypted with a unique message key derived from a chain key. After use, message keys are deleted and chain keys are ratcheted forward via HMAC. Compromising the current chain key does not reveal past message keys, since HMAC is a one-way function.

The Double Ratchet provides per-message forward secrecy through the symmetric ratchet, and periodic forward secrecy through the DH ratchet (new ephemeral EC key pairs on each send turn).

SPQR adds post-quantum forward secrecy. When a Braid round completes, the SPQR advances to a new epoch with fresh chain keys derived from the ML-KEM output. Old epoch keys are destroyed.

### Post-Compromise Security

If an attacker compromises a session's current keys, the DH ratchet restores security after the next interactive message exchange. Each ratchet step generates a fresh ephemeral key pair, making the attacker's knowledge of old keys useless.

SPQR provides post-compromise security against quantum adversaries. When the Braid completes a round, both parties contribute fresh Kyber key material. The derived epoch key is independent of any previously compromised state.

### Sender Authentication

Signal messages authenticate the sender through the session's identity key binding. The receiver verifies that the message was encrypted under a session established with a known identity.

Sealed Sender v1 and v2 provide sender anonymity to the server while still authenticating the sender to the recipient. The sender's identity is encrypted inside the message payload and verified during decryption using sender certificates.

### Deniability

Signal Protocol messages are deniable. The symmetric keys used for encryption are derived from shared secrets that both parties can compute. A message cannot be cryptographically attributed to a specific sender by a third party, because either party could have produced it.

## Threat Model

### What the library protects against

- **Passive network observers**: All messages use authenticated encryption (AES-CBC + HMAC-SHA256 for Signal messages, AES-256-GCM-SIV for sealed sender/SVR).
- **Server compromise**: The server never holds plaintext or long-term session keys. Sealed Sender hides the sender identity from the server.
- **Key compromise (limited)**: Forward secrecy limits the damage to messages encrypted after the last ratchet step. Post-compromise security restores confidentiality after the next interactive exchange.
- **Quantum adversaries (future)**: PQXDH key exchange and SPQR ratcheting use Kyber-768/1024 for quantum resistance in session establishment and ongoing messaging.
- **Memory forensics**: Private keys are stored in mlock'd memory with guard pages. Destruction zeroizes the memory. Stack-local copies use defer-based zeroization.

### What the library does not protect against

- **Endpoint compromise**: If the device is fully compromised (root access, debugger attached), the attacker can read keys from process memory regardless of mlock.
- **Side-channel attacks on the host**: The library uses constant-time comparisons and avoids secret-dependent branches where feasible, but does not defend against hardware-level side channels (cache timing, power analysis).
- **Store implementation bugs**: The library defines store interfaces but does not implement persistence. Bugs in the caller's store implementation (unencrypted database, missing access controls) are out of scope.
- **Application-level metadata**: The library encrypts message content but does not hide message timing or communication patterns.

## Key Zeroization Strategy

Key material passes through three zones during its lifecycle, each with a different zeroization mechanism:

### Zone 1: Guarded Heap Memory (go-enclave)

Long-lived private keys and shared secrets are stored in `secret.Secret` or `secret.Secret32`, backed by the locked-memory buffer from `github.com/jeremyhahn/go-enclave`. Protections:

- **mlock**: Memory is locked into RAM and cannot be paged to swap.
- **Guard pages**: Read/write-protected pages surround the buffer. Overflows or underflows trigger a segfault.
- **Canary values**: go-enclave places a canary ahead of the buffer and verifies it when the region is released; detected corruption panics after wiping and unmapping.
- **Secure zeroization**: `Destroy()` overwrites the memory with zeros on destruction (not optimizable away by the compiler).
- **Read-only**: secrets created via `New` and `NewRandom` are frozen read-only, so any write attempt segfaults; `NewEmpty` returns a writable buffer to be filled in place.

There is no at-rest encryption in this layer: go-enclave holds material as plaintext in locked memory, protected by the guard pages and canary above.

Packages that store keys in guarded memory: `keys/chain`, `keys/root`, `keys/message`, `keys/session`, `ratchet`, `session`, `state/record`, `spqr`, `tripleratchet`, `mlkembraid`, `sealed`, `groups/ratchet`, `accountkeys`, `backup`, `svr`, `cipher`, `ecc`, `kem`, `zkcredential`, `zkgroup`.

### Zone 2: Stack-Local Copies

Cryptographic operations sometimes need stack-local copies of key material (for passing to functions that expect arrays or slices). These are zeroized via `defer`:

```go
var dhSecret [32]byte
defer crypto.ZeroizeArray32(&dhSecret)
// ... use dhSecret ...
```

`crypto.Zeroize` calls `runtime.KeepAlive` on the buffer after zeroing to prevent the compiler from eliminating the stores as dead writes. Three size-specific variants exist:

- `Zeroize([]byte)` -- variable-length slices
- `ZeroizeArray32(*[32]byte)` -- 32-byte arrays (EC keys, chain keys, shared secrets)
- `ZeroizeArray64(*[64]byte)` -- 64-byte arrays (XEdDSA randomness)

### Zone 3: Intermediate Buffers

When key material passes through non-guarded buffers (e.g., HKDF output, KEM decapsulation result), the library zeroizes the intermediate buffer immediately after moving the data into guarded memory:

```go
result, _ := curve25519.X25519(privateBytes, peerPublic[:])
shared, allocErr := secret.NewSecret32FromSlice(result) // zeroizes result
if allocErr != nil {
    crypto.Zeroize(result) // manual zeroize on allocation failure
}
```

### Known Limitations

- **circl HPKE**: The `cloudflare/circl` HPKE implementation holds private key material internally. There is no API to zeroize it without modifying the library.
- **Go runtime copies**: The Go garbage collector may copy memory during compaction. mlock'd buffers (go-enclave) are excluded from GC management, but stack-local arrays may be copied by the runtime before defer-zeroization runs.
- **Serialized state**: When session state is serialized for storage (via `State.Serialize()`), the serialized bytes contain key material. The caller's store implementation is responsible for encrypting this data at rest.

## Side-Channel Protections

### Constant-Time Comparisons

The library uses `crypto/subtle.ConstantTimeCompare` for all security-sensitive comparisons:

| Location | What is compared |
|----------|-----------------|
| `state/record.Session.HasSessionState` | Sender base keys |
| `sealed/sealed_sender.go` | HMAC tags |
| `ecc.GuardedECPrivateKey.Agreement` | All-zero shared secret rejection |
| `cipher/aesgcmsiv.go` | Authentication tags |
| `cipher/aesctr.go` | Padding validation |
| `incrementalmac` | Finalize MAC comparison |
| `fingerprint/scannable.go` | Fingerprint comparison |
| `zkcredential` | Credential validation |
| `zkgroup` | Group credential checks |
| `keytrans/vrf.go` | VRF output verification |
| `backup/frame.go` | Frame HMAC verification |
| `accountkeys` | PIN hash comparison |
| `secret.Secret.EqualTo` | Guarded secret comparison (delegates to go-enclave) |

### Constant-Time Elligator

The Elligator inverse map (`crypto/elligator`) uses `field.Element.Select` (constant-time conditional select) instead of branching on secret-dependent values. No early returns occur on paths where the selected branch could leak information.

### All-Zero Shared Secret Rejection

`ecc.GuardedECPrivateKey.Agreement` rejects all-zero X25519 shared secrets in constant time. An all-zero result indicates a low-order peer public key (a small-subgroup attack), which would produce a predictable shared secret regardless of the private key. The rejection uses `subtle.ConstantTimeCompare` against a zero buffer.

### HMAC Verification

MAC verification throughout the library (Sealed Sender, backup frames, incremental MAC) follows the pattern:

1. Compute the expected MAC
2. Compare with received MAC using `hmac.Equal` (constant-time)
3. Zeroize intermediate key material

The incremental MAC (`incrementalmac`) defers mismatch detection to `Finalize()` rather than returning per-chunk. This is timing-safe but delays error detection.

## Authentication Tag Truncation

Sealed Sender v1 truncates HMAC-SHA256 tags to 10 bytes (`macTruncateLen`), matching the Rust reference. This is sufficient given the online-only attack model (no offline brute force against the MAC). Full 32-byte tags are used elsewhere (backup frames, incremental MAC).

## Bounded Resource Consumption

Hard limits prevent denial-of-service through resource exhaustion:

| Component | Limit | Value |
|-----------|-------|-------|
| Session message keys | Per-session | 2000 |
| Session receiver chains | Per-session | 5 |
| Archived session states | Per-record | 40 |
| Forward message jumps | Per-decrypt | 25000 |
| SenderKey states | Per-record | 5 |
| SPQR skipped keys | Per-ratchet | 2000 |
| SPQR max jump | Per-decrypt | 25000 |
| SPQR epoch chains (deserialization) | Per-state | 100 |
| SPQR skipped keys (deserialization) | Per-state | 5000 |
| Backup frame size | Per-frame | 10 MiB |

## Attestation and Enclave Verification

The `attest` package verifies SGX/DCAP attestation evidence before establishing encrypted channels to server-side enclaves (CDSi, SVR). Verification steps:

1. Parse DCAP evidence (SGX quote + QE report)
2. Verify the certificate chain against Intel's root CA
3. Check CRL validity periods
4. Verify the enclave measurement (MRENCLAVE) against expected values
5. Establish a Noise NK handshake using the attested enclave public key

Only enclave identity v2 format is accepted. Successful attestation confirms the server-side code inside the enclave matches the expected binary, so the server cannot access plaintext data.

## Key Transparency

The `keytrans` package verifies that identity keys published to the key directory are consistent and append-only:

- **VRF (Verifiable Random Function)**: Maps usernames to deterministic, verifiable directory positions using VXEdDSA
- **Merkle tree verification**: Proves inclusion of identity keys in the global tree
- **Monitoring**: Detects unauthorized key changes by verifying tree consistency across epochs

VRF verification includes cofactor multiplication (`MultByCofactor`) to ensure the VRF output point is in the prime-order subgroup.
