# Secure Value Recovery (SVR) v4

Package: `svr/`

Source files: `svr.go`, `backup.go`, `restore.go`, `query.go`, `remove.go`, `crypto.go`, `errors.go`

## Overview

SVR lets users back up and restore secrets (such as master keys) using a PIN. The server-side rate limits PIN guessing attempts. SVR v4 uses an Oblivious Pseudorandom Function (OPRF) protocol with Ristretto255 to distribute trust across multiple servers, so no single server can learn the PIN or the stored secret.

The client-side operations produce serialized protobuf `Request4` messages that are sent to each server, and process serialized `Response4` messages received back.

## Core Types

```go
type Secret [32]byte       // 32-byte SVR secret

type Backup4 struct {
    RequestID []byte       // 32 bytes, random
    Entropy   []byte       // 32 bytes, random
    Secret    Secret
    MaxTries  uint32       // server-side rate limit
}
```

## OPRF Backup Flow

`NewOPRFBackup4` creates backup requests for a set of servers. The protocol distributes three types of secret shares across the servers:

1. **OPRF key shares** (`kOprf`): Ristretto255 scalars that sum to the OPRF key. Each server holds one share.
2. **Encryption key shares** (`sEnc`): byte slices that XOR together to the encryption secret. Each server holds one share.
3. **Zero key shares**: Ristretto255 scalars that sum to zero. Used for blinding during restore.

The flow:

```
password  -->  passwordToUniformInput()  -->  64-byte uniform input
                                              |
                                              v
                                         inputHashPt()  -->  Ristretto255 Element (P)
                                              |
                                              v
                                         authPt(input, kOprf)  -->  P * kOprf
                                              |
                                              v
                                         authCommitments()  -->  per-server (scalar, point)
                                              |
                                              v
                                         authSecret()  -->  master auth key (guarded)
                                              |
                                              v
                                         encryptionKey(sEnc, kAuth)  -->  output key (guarded)
```

Each server receives a `Request4_Create` containing:
- A random version identifier
- `maxTries` rate limit
- Its OPRF secret share
- Its auth commitment point
- Its encryption secret share
- Its zero secret share

`FinalizeBackup4` processes server responses, verifying all returned OK status, and returns the minimum `triesRemaining`.

### Intermediate Zeroization

- The 64-byte uniform input is stored in `secret.Secret` (guarded memory) and destroyed after use.
- Random scalars (`kOprf`) are zeroized via `zeroScalar` (calls `Scalar.Zero()` with `runtime.KeepAlive`).
- Encryption secret (`sEnc`) is stored in guarded memory and destroyed.
- The auth secret is stored in guarded memory and destroyed.
- The `kdf` helper protects its concatenated IKM in guarded memory.
- `bytesXORingTo` zeroizes intermediate random buffers after copying.

### Output Key

The `OPRFBackup4.Output` field is a `*secret.Secret` in guarded memory. The caller must call `Zeroize()` when done.

## OPRF Restore Flow

Restore is a two-phase protocol:

### Phase 1 (Restore1)

`NewRestore1` sends a blinded point to each server:

1. Derive the 64-byte uniform input from the password (stored in guarded memory).
2. Generate a random blinding scalar.
3. Compute `blinded = inputHashPt(input) * blind`.
4. Send `Request4_Restore1{Blinded: blindedBytes}` to each server.

### Phase 2 (Restore2)

`Restore1.Restore2` processes Phase 1 responses:

1. Parse all `Response4_Restore1` messages.
2. Determine the minimum `triesRemaining` from responses that would have decremented.
3. Check all statuses are OK (returns `RestoreFailed` error with tries remaining on failure).
4. Find a version number present in all responses.
5. Sum the OPRF elements from all servers: `SUM = sum(P*k_i + H*z_i) = P*kOprf` (the zero shares cancel).
6. Unblind: `authPt = SUM * (1/blind)`.
7. Compute Schnorr-like authentication proofs using `SHA-512(proofPt || blindedPt || handshakeHash)` as the challenge. The handshake hash provides TLS channel binding.
8. Send `Request4_Restore2{AuthPoint, AuthScalar, Version}` to each server.

### Phase 2 Completion

`Restore2Result.Restore` processes Phase 2 responses:

1. Verify all statuses are OK.
2. XOR all encryption secret shares in guarded memory.
3. Derive the auth secret, then the encryption key.

`RestoreFull` wraps the two-phase process with a callback for the second-phase network round-trip.

## Master Key Derivation

`MasterKey` derives a 32-byte master key from a PIN and an SVR secret:

1. Hash the PIN with SHA-256.
2. Use HKDF-SHA256 with the SHA-256 hash as IKM, the secret as salt, and info `"20221003_Signal_SVR_MasterKey"`.

The SHA-256 intermediate is zeroized after use (`defer crypto.ZeroizeArray32`).

## Storage Key Derivation

`DeriveStorageKey` derives a 32-byte storage key from a master secret using HKDF-SHA256 with no salt and info `"20231003_Signal_SVR_StorageKey"`.

## Secret Encryption

SVR encrypts secrets with AES-256-GCM-SIV (RFC 8452) using a zero nonce:

- `EncryptSecret(key, secret)`: encrypts with a zero nonce. Safe because the key is one-time derived, and GCM-SIV is misuse-resistant.
- `DecryptSecret(key, encrypted)`: decrypts and validates the secret is exactly 32 bytes. The decrypted plaintext is zeroized after copying.

## Query

`Query4` checks whether a backup exists on the servers. `Requests()` produces an identical query request for each server. `Finalize` parses responses and returns the minimum `triesRemaining`.

## Remove

`Remove4` deletes a backup from all servers. The same remove request is sent to each server. No finalization is needed.

## Cryptographic Primitives (crypto.go)

| Function | Purpose |
|----------|---------|
| `passwordToUniformInput` | HKDF-SHA256 with info `"Signal_SVR_InputFromPassword_20240823"` producing 64 bytes |
| `inputHashPt` | Maps 64-byte input to a Ristretto255 element via `SetUniformBytes` |
| `authPt` | `inputHashPt(input) * kOprf` |
| `authSecret` | HKDF-SHA256 with info `"Signal_SVR_MasterAuthorizationKey_20240823"` producing 32 bytes |
| `authCommitments` | Per-server HKDF-SHA256 with info `"Signal_SVR_ServerAuthorizationKey_20240823"`, then SHA-512 hash, then `SetUniformBytes` for mod-order reduction |
| `encryptionKey` | HKDF-SHA256 with info `"Signal_SVR_EncryptionKey_20240823"` producing 32 bytes |
| `scalarsSummingTo` | Creates n random scalars summing to a target |
| `bytesXORingTo` | Creates n random byte slices XORing to a target |

All KDF intermediate buffers are protected in guarded memory.

## Error Types

```go
var ErrBadData         // invalid protobuf data
var ErrBadResponse     // unexpected or missing server response
var ErrNoUsableVersion // no auth version usable across all servers
var ErrEmptyPIN        // PIN must not be empty
var ErrHKDFExpansion   // HKDF expansion failed
var ErrCipherCreate    // cipher creation failed
var ErrDecryption      // decryption failed
var ErrSecretSize      // decrypted secret has wrong size
```

`Error.Is` matches by `errorKind`, allowing `errors.Is(err, svr.ErrBadData)` patterns.

`ResponseStatus` values: `StatusUnset`, `StatusOK`, `StatusInvalidRequest`, `StatusMissing`, `StatusError`, `StatusRestore1Missing`, `StatusVersionMismatch`.

Restore failures include the number of tries remaining via `Error.TriesRemaining()`.
