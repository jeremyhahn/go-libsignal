# Triple Ratchet

The Triple Ratchet combines the EC Double Ratchet with the Sparse Post-Quantum Ratchet (SPQR) to provide hybrid EC+PQ forward secrecy. Each message is encrypted using keys derived from both the EC ratchet and the PQ ratchet via `KDFHybrid`. The PQ chain epoch advances when the ML-KEM Braid SCKA produces an output key.

Source: `tripleratchet/` package.

## Architecture

The `TripleRatchet` struct wraps:

- `ecCipher` (`ECCipher`): the EC Double Ratchet, providing EC message keys and headers
- `braid` (`*mlkembraid.Braid`): the ML-KEM Braid SCKA state machine
- `rootKey` (`*secret.Secret`): current SPQR root key, used as salt in `KdfSckaRK`
- `sendChainKey`, `recvChainKey` (`*secret.Secret`): current epoch's chain keys
- `sendCounter`, `recvCounter` (uint32): per-epoch message counters
- `pqEpoch` (uint64): current PQ chain epoch
- `isResponder` (bool): true for Bob, controls chain key assignment
- `braidHandshakeComplete` (bool): set after the first epoch advancement
- `skippedPQKeys` (`map[pqSkippedKeyID]*secret.Secret`): out-of-order PQ message keys

All sensitive key material is stored in locked-memory-backed `secret.Secret` values.

## ECCipher interface

The `ECCipher` interface (in `tripleratchet/triple_ratchet.go`) abstracts the EC Double Ratchet:

```go
type ECCipher interface {
    SendKey() (ecHeader []byte, messageKey []byte, err error)
    ReceiveKey(ecHeader []byte) (messageKey []byte, err error)
    EncryptGetKey(plaintext []byte) (ciphertext, ecHeader, messageKey []byte, err error)
    DecryptGetKey(ecHeader, ciphertext []byte) (plaintext, messageKey []byte, err error)
}
```

The Triple Ratchet uses `SendKey()` and `ReceiveKey()` rather than `EncryptGetKey()` and `DecryptGetKey()`. This avoids an AES encryption/decryption in the EC cipher that would be immediately discarded, since the Triple Ratchet re-encrypts with hybrid keys.

## ECCipherSnapshotable interface

`ECCipherSnapshotable` is an optional interface for atomic rollback of EC ratchet state:

```go
type ECCipherSnapshotable interface {
    TakeECSnapshot() ([]byte, error)
    RestoreECSnapshot(data []byte) error
}
```

When the `ECCipher` implements this interface, the Triple Ratchet snapshots EC state before `ReceiveKey()` and restores it if MAC verification or any subsequent step fails. Without this interface, a forged message with a valid-looking EC header can permanently advance the EC receive chain, even when decryption fails.

## Key derivation

### KDFHybrid

Defined in `tripleratchet/kdf.go`. Combines the EC message key and PQ message key:

```
HKDF(salt=pqMK, ikm=ecMK, info="WhisperMessageKeys", length=80)
```

Output split: `CipherKey(32) || MacKey(32) || IV(16)`

The PQ key is used as the HKDF salt and the EC key as the input key material, so both contribute to the output.

### KDFHybridECOnly

Fallback when the SPQR has not yet produced a PQ key (epoch 0, counter 0):

```
HKDF(salt=zeros(32), ikm=ecMK, info="WhisperMessageKeys", length=80)
```

Same output split. The Rust reference uses the same info string for both paths; only the salt differs.

### HybridKeys

The output of both KDF functions is a `HybridKeys` struct:

| Field       | Size     | Use                        |
|-------------|----------|----------------------------|
| `CipherKey` | 32 bytes | AES-256 encryption key     |
| `MacKey`    | 32 bytes | HMAC-SHA256 key            |
| `IV`        | 16 bytes | AES initialization vector  |

All fields are `*secret.Secret` and cleaned up via `Zeroize()`.

## Encrypt

`Encrypt(plaintext)` performs:

1. Calls `ecCipher.SendKey()` to get an EC message key and serialized EC header.
2. Calls `braid.Send()` to advance the Braid SCKA and get an outbound SCKA message.
3. If the Braid produces an `OutputKey`, advances the PQ epoch via `advancePQEpoch()`.
4. Increments `sendCounter` (first key is at index 1) and derives a PQ message key via `spqr.KdfSckaCK(sendChainKey, counter)`.
5. Combines EC and PQ keys via `KDFHybrid` (or `KDFHybridECOnly` if the PQ key is nil).
6. Encrypts plaintext with AES-CBC using the hybrid cipher key and IV.
7. Computes HMAC-SHA256 over the encrypted payload using the hybrid MAC key.
8. Constructs the authenticated ciphertext: `encrypted_payload || mac(32 bytes)`.
9. Builds a `CompositeHeader` containing the EC header, PQ counter, and SCKA message.
10. Serializes the composite message: `headerLen(4 BE) + header + ciphertextLen(4 BE) + ciphertext`.

## Decrypt

`Decrypt(compositeMessage)` performs:

1. Parses the composite message into header and ciphertext.
2. Takes a snapshot of all mutable state (PQ chain, braid, and EC state if snapshotable).
3. Calls `ecCipher.ReceiveKey(ecHeader)` to get the EC message key.
4. Feeds the SCKA message to `braid.Receive()`. Braid errors during the initial handshake phase are suppressed (only `ErrInvalidState` and `ErrInvalidEpoch`). After `braidHandshakeComplete` is set, all braid errors propagate to prevent silent downgrade to EC-only security.
5. If the Braid produces an `OutputKey`, advances the PQ epoch.
6. Derives the PQ message key via `receivePQKey(pqCounter)`, which handles out-of-order delivery.
7. Combines EC and PQ keys via `KDFHybrid` (or `KDFHybridECOnly`).
8. Verifies HMAC-SHA256 using `hmac.Equal` (constant-time comparison).
9. On MAC failure: restores the snapshot (both PQ and EC state), returns `ErrMACVerificationFailed`.
10. On MAC success: decrypts with AES-CBC. If decryption fails (e.g., PKCS7 padding error), also restores the snapshot.
11. On full success: destroys the snapshot and returns plaintext.

## Snapshot and restore

The `decryptSnapshot` struct captures:

- Serialized braid data
- Cloned `rootKey`, `sendChainKey`, `recvChainKey`
- Counter values (`sendCounter`, `recvCounter`)
- `pqEpoch` and `braidHandshakeComplete`
- Deep-copied `skippedPQKeys` map
- Serialized EC state (if `ECCipherSnapshotable` is implemented)

`takeSnapshot()` is called before any mutation in `Decrypt()`. All secrets in the snapshot are independent clones, so destroying the snapshot does not affect the live state.

`restoreSnapshot()` replaces the entire mutable state, destroying the current values first and then installing the snapshot. The braid is reconstructed via `mlkembraid.DeserializeBraid()`.

`destroySnapshot()` cleans up a snapshot on the success path, zeroizing all secrets and serialized data.

## Out-of-order PQ key handling

`receivePQKey(counter)` handles these cases:

- **Epoch 0, counter 0**: returns nil (pre-negotiation state, EC-only).
- **Previously skipped key**: removes from `skippedPQKeys` and returns.
- **Counter behind current position**: returns error (counter already consumed).
- **Counter ahead**: enforces `maxPQJump = 25000`, then skips forward storing intermediate keys. The buffer is capped at `maxSkippedPQKeys = 2000`.

Counter overflow is guarded with `math.MaxUint32` checks.

## Epoch advancement

`advancePQEpoch(epochSecret)` calls `spqr.KdfSckaRK(rootKey, epochSecret)` to derive:

- New root key (retained for the next epoch)
- New send and receive chain keys

For the responder (Bob), send and receive chain keys are swapped (matching Rust's `Chain` direction handling).

After epoch advancement:

- Counters reset to 0
- `braidHandshakeComplete` is set to true
- Skipped keys from epochs older than the retention window (`pqEpoch - epochsToKeepPriorToSendEpoch`, where `epochsToKeepPriorToSendEpoch = 1`) are purged

## Composite header

`CompositeHeader` (in `tripleratchet/composite_header.go`) carries:

- `ECHeader` ([]byte): serialized EC Signal message header
- `PQCounter` (uint32): SPQR chain counter for out-of-order support
- `SCKAMsg` (`*mlkembraid.Message`): SCKA chunk from the Braid

Serialized format:

```
ecHeaderLen(4 BE) + ecHeader(N) + sckaWireMessage(M)
```

The SCKA wire message uses the Rust-compatible format: `version(1) + varint(epoch) + varint(chain_index) + msg_type(1) + [chunk_data]`.

## Composite message

The full wire message is:

```
headerLen(4 BE)
header(N)
ciphertextLen(4 BE)
ciphertext(M)
```

Where ciphertext is `encrypted_payload || hmac_tag(32)`.

## Constants

| Constant                          | Value | Description                                    |
|-----------------------------------|-------|------------------------------------------------|
| `maxSkippedPQKeys`                | 2000  | Max out-of-order PQ keys retained              |
| `maxPQJump`                       | 25000 | Max forward jump in PQ counters                |
| `epochsToKeepPriorToSendEpoch`    | 1     | Epoch retention window                         |
| `HMACSize`                        | 32    | HMAC-SHA256 tag size                           |
| `HybridKeySize`                   | 80    | KDF output: `CipherKey(32) + MacKey(32) + IV(16)` |

## Error types

| Error                       | Condition                                              |
|-----------------------------|--------------------------------------------------------|
| `ErrHybridKDFFailed`        | Hybrid KDF failed to produce valid output              |
| `ErrECRatchetFailed`        | EC Double Ratchet operation failed                     |
| `ErrSPQRFailed`             | SPQR operation failed (wraps inner error)              |
| `ErrInvalidCompositeMessage`| Composite message structural issues                    |
| `ErrMACVerificationFailed`  | HMAC tag does not match                                |
| `ErrInvalidInput`           | Input validation failure                               |

## Initialization

```go
tr, err := tripleratchet.NewAlice(ecCipher, sharedSecret, kemImpl, chunkSize)
tr, err := tripleratchet.NewBob(ecCipher, sharedSecret, kemImpl, chunkSize)
```

Both constructors initialize the Braid (via `mlkembraid.InitAlice`/`InitBob`) and derive initial SPQR chain keys from the shared secret (via `spqr.KdfSckaInit`). Bob's send and receive chain keys are swapped relative to Alice's.

## Concurrency

The `TripleRatchet` struct is NOT safe for concurrent use. Like SPQR and Braid, the session-level serialization pattern provides synchronization.
