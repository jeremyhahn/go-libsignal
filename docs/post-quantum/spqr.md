# Sparse Post-Quantum Ratchet (SPQR)

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

SPQR adds epoch-based post-quantum key derivation on top of the EC Double Ratchet. Each epoch corresponds to a completed round of the ML-KEM Braid SCKA protocol. Within each epoch, a symmetric chain key ratchet derives per-message keys. The SPQR output is used as HKDF salt for message key derivation, augmenting the EC key with post-quantum material.

Source: `spqr/` package.

## Core data structures

### SPQR

The top-level `SPQR` struct (in `spqr/spqr.go`) holds:

- `rootKey` (`*secret.Secret`): current root key, used as salt in `KdfSckaRK`
- `epoch` (uint64): current epoch number (0-indexed)
- `sendEpoch` (uint64): tracks the last epoch used for sending
- `chains` (`map[uint64]*EpochChain`): per-epoch send/receive chain keys
- `skippedKeys` (`map[SkippedKeyID]*secret.Secret`): out-of-order message keys
- `direction` (`Direction`): `DirectionA2B` or `DirectionB2A`, determines chain key assignment
- `maxJump` (uint32): maximum forward counter jump allowed
- `braid` (`*mlkembraid.Braid`): optional ML-KEM Braid SCKA state machine

### EpochChain

Each `EpochChain` (in `spqr/chain.go`) contains:

- `sendKey`, `recvKey` (`*secret.Secret`): chain keys for the current epoch
- `sendCounter`, `recvCounter` (uint32): message counters within the epoch

### SkippedKeyID

A composite key `{Epoch uint64, Counter uint32}` used to index the skipped keys map.

## Constants

| Constant                    | Value  | Description                                          |
|-----------------------------|--------|------------------------------------------------------|
| `maxSkippedKeys`            | 2000   | Max out-of-order message keys retained               |
| `maxJump`                   | 25000  | Max forward jump in receive counter (normal sessions) |
| `trimSize`                  | 2201   | GC threshold: `maxSkippedKeys * 11/10 + 1`           |
| `maxDeserializedChains`     | 100    | Upper bound on deserialized epoch chains              |
| `maxDeserializedSkippedKeys`| 5000   | Upper bound on deserialized skipped keys              |

For self-sessions (where local and remote identity keys are identical), `maxJump` is set to `math.MaxUint32`.

## KDF functions

All KDF functions are in `spqr/kdf.go`. They use HKDF-SHA256 via `kdf.DeriveSecrets`.

### KdfSckaInit

Derives initial keys from a shared secret:

```
HKDF(ikm=sharedSecret, salt=zeros(32), info="Signal PQ Ratchet V1 Chain  Start", length=96)
```

Note the double space before "Start", which matches the Rust reference.

Output split: `rootKey(32) || sendChainKey(32) || recvChainKey(32)`

For `DirectionB2A`, send and receive chain keys are swapped.

### KdfSckaRK

Derives new epoch keys from the current root key and an SCKA output:

```
HKDF(ikm=sckaOutput, salt=rootKey, info="Signal PQ Ratchet V1 Chain Add Epoch", length=96)
```

Output split: `newRootKey(32) || newSendChainKey(32) || newRecvChainKey(32)`

### KdfSckaCK

Derives a per-message key and next chain key:

```
HKDF(ikm=chainKey, salt=zeros(32), info=counter_be32 || "Signal PQ Ratchet V1 Chain Next", length=64)
```

Output split: `nextChainKey(32) || messageKey(32)`

The counter is included in the info string as a 4-byte big-endian prefix.

## Version negotiation

SPQR supports version negotiation between peers. The `Version` type has two values:

- `VersionV0` (0): PQR disabled (fallback for older clients)
- `VersionV1` (1): PQR enabled

During session setup, the SPQR starts in `negotiationPending` state. The `minVersion` field controls whether fallback to V0 is acceptable:

- If `minVersion` is `VersionV0`, the session gracefully downgrades when the remote peer sends empty PQR data.
- If `minVersion` is `VersionV1`, version negotiation fails with `ErrVersionNegotiationFailed` when the remote peer does not support PQR.

Version resolution happens on the first `Recv()` call. Non-empty PQR data resolves to V1, empty data resolves to V0. Once resolved, the negotiation state becomes `negotiationResolved`.

During pending negotiation, `Send()` returns an empty PQR message (`[]byte{}`) and nil message key, signaling the caller to include an empty PQR field on the wire.

## Encrypt and Decrypt

### Encrypt

`Encrypt(epoch)` on the `SPQR` struct:

1. Checks that `epoch >= sendEpoch` (send epoch monotonicity).
2. Looks up the `EpochChain` for the given epoch.
3. Checks for `math.MaxUint32` counter overflow.
4. Increments `sendCounter` before use (first message key is at index 1).
5. Calls `KdfSckaCK(sendKey, counter)` to derive message key and next chain key.
6. Destroys the old send key and installs the new one.
7. Returns the message key and counter.

### Decrypt

`Decrypt(epoch, counter)`:

1. Checks the skipped keys map for a previously stored key at `{epoch, counter}`.
2. If found, removes and returns it (transfer of ownership).
3. If the counter equals the current `recvCounter`, returns `ErrKeyAlreadyRequested`.
4. If the counter is behind `recvCounter`, returns either `ErrKeyTrimmed` (if the key was likely garbage-collected) or `ErrKeyAlreadyRequested`.
5. If the counter is ahead by more than `maxJump`, returns `ErrMaxJump`.
6. Skips forward, storing intermediate keys in `skippedKeys`. A pre-check calculates the total number of keys that would be stored and rejects the operation if it exceeds `maxSkippedKeys`. This is more restrictive than the Rust reference (which checks after storing) but provides stronger DoS protection.
7. Derives and returns the target message key.

Counter overflow is checked at each increment with `math.MaxUint32` guards, returning `ErrCounterExhausted`.

## Epoch management

### ReceiveKey

`ReceiveKey(sckaOutput, newEpoch)` handles epoch advancement from external SCKA outputs:

1. Validates `newEpoch > epoch` (rejects old or duplicate epochs).
2. Calls `KdfSckaRK(rootKey, sckaOutput)` for new keys.
3. Swaps send/recv for `DirectionB2A`.
4. Installs the new root key and epoch chain.
5. Calls `clearOldEpochs()`.

### advanceEpoch

`advanceEpoch(outputKey)` is the internal path used when the attached braid produces an output key. It increments the epoch by 1 and derives new chain keys via `KdfSckaRK`.

### clearOldEpochs

Epoch retention follows a window: epochs from `min(sendEpoch, epoch) - 1` through the current epoch are kept. Chains below this window are zeroized and removed. Send keys on retained chains below `sendEpoch` are also destroyed.

Skipped keys for epochs below the retention window are destroyed.

## Amortized garbage collection

GC on skipped keys runs only when `len(skippedKeys) > trimSize` (2201), matching the Rust reference's amortized approach. When triggered, `gcSkippedKeys(epoch, currentCounter)` removes keys for the given epoch with counters below `currentCounter - maxSkippedKeys`.

This avoids O(n) scans on every decrypt while bounding memory growth.

## Braid integration

When a `Braid` is attached (via `InitWithBraid` or `SetBraid`), the `SendBraid()` and `RecvBraid()` methods handle the combined chain key + SCKA flow.

### SendBraid

Follows the Rust reference ordering:

1. Call `braid.Send()` to produce an outbound SCKA chunk.
2. If the braid produces an `OutputKey`, advance the epoch via `advanceEpoch` before deriving the message key.
3. Derive the per-message key from the (potentially new) epoch's send chain.
4. Build a variable-length wire message using `Message.SerializeSCKA(counter)`.

### RecvBraid

1. Parse the wire message via `DeserializeSCKA`.
2. Feed the braid message to `braid.Receive()` first.
3. If the braid produces an `OutputKey`, advance the epoch before deriving the message key.
4. Map braid epoch to chain epoch: `chain_epoch = braid_epoch - 1` (braid epochs are 1-indexed).
5. Special case: `epoch 0, counter 0` returns nil message key (pre-negotiation state).
6. Derive per-message key from the receive chain.

Legacy 12-byte messages (`epoch(8 BE) + counter(4 BE)`) are handled via `recvLegacy()` for backward compatibility.

## Session API

The package-level `Send()` and `Recv()` functions operate on serialized state bytes, providing a stateless API for session store patterns (load, mutate, serialize, store):

```go
func Send(serializedState []byte) (newState, pqrMsg []byte, messageKey MessageKey, err error)
func Recv(serializedState []byte, pqrMsg []byte) (newState []byte, messageKey MessageKey, err error)
```

These functions dispatch between the braid-integrated path (V4 format with braid state) and the legacy chain-only path (V3 or earlier).

## Serialization (V4 format)

The current serialization format is V4 (`serializeVersionV4 = 0x04`). The format supports backward-compatible reading of V1, V2, and V3 data.

### V4 resolved layout

```
version(1) = 0x04
negotiated(1) = 0x01
resolvedVersion(1) = 0x01

direction(1)
epoch(8 BE)
sendEpoch(8 BE)
rootKey(32)
maxJump(4 BE)
numChains(4 BE)

For each chain (sorted by epoch):
  epoch(8 BE)
  sendCounter(4 BE)
  recvCounter(4 BE)
  hasSendKey(1)
  [sendKey(32)]        -- only if hasSendKey == 1
  hasRecvKey(1)
  [recvKey(32)]        -- only if hasRecvKey == 1

numSkippedKeys(4 BE)
For each skipped key (sorted by epoch, counter):
  epoch(8 BE)
  counter(4 BE)
  key(32)

hasBraid(1)
[braidLen(4 BE) + braidState(N)]  -- only if hasBraid == 1
```

### V4 pending layout

```
version(1) = 0x04
negotiated(1) = 0x00
authKey(32)
minVersion(1)
direction(1)
maxJump(4 BE)
hasBraid(1)
[braidLen(4 BE) + braidState(N)]
```

### V4 disabled layout

```
version(1) = 0x04
negotiated(1) = 0x01
resolvedVersion(1) = 0x00
```

### Bounded deserialization

Deserialization enforces upper bounds to prevent unbounded allocation from malformed data:

- `maxDeserializedChains = 100`: rejects chain counts above this
- `maxDeserializedSkippedKeys = 5000`: rejects skipped key counts above this

On any deserialization error, all partially-constructed secrets are destroyed via `destroyChains()` and `destroySkippedKeys()` before returning.

### Version compatibility

| Format | maxJump field | Version negotiation | Braid state |
|--------|--------------|---------------------|-------------|
| V1     | No (default 25000) | No             | No          |
| V2     | Yes          | No                  | No          |
| V3     | Yes          | Yes                 | No          |
| V4     | Yes          | Yes                 | Yes         |

V1/V2 data is deserialized as `negotiationResolved` with `VersionV1`.

## Wire format

Two wire formats exist:

### Legacy (12 bytes)

```
epoch(8 BE) + counter(4 BE)
```

Used by chain-only SPQR without braid integration.

### Variable-length (braid-integrated)

```
version(1) = 0x01
varint(epoch)
varint(counter)
message_type(1)
[chunk_data]          -- only for types: Hdr, Ek, EkCt1Ack, Ct1, Ct2
```

The chunk data is in Rust-compatible wire format: `varint(chunk_index) + data(32 bytes)`.

Message types without chunk data (`MessageTypeNone`, `MessageTypeCt1Ack`) omit the chunk payload.

## Error types

All errors are typed structs in `spqr/errors.go`:

| Error                         | Condition                                    |
|-------------------------------|----------------------------------------------|
| `ErrUnknownEpoch`             | Epoch not in chain map                       |
| `ErrOldEpoch`                 | New epoch not strictly greater than current   |
| `ErrMaxSkippedKeys`           | Skipped keys would exceed limit              |
| `ErrKeyAlreadyRequested`      | Counter already consumed                     |
| `ErrKeyTrimmed`               | Counter was garbage-collected                |
| `ErrMaxJump`                  | Forward jump exceeds maxJump                 |
| `ErrSendEpochDecreased`       | Send epoch monotonicity violated             |
| `ErrCounterExhausted`         | Counter reached math.MaxUint32               |
| `ErrSendKeyDestroyed`         | Send key already cleared                     |
| `ErrVersionNegotiationFailed` | Remote version below MinVersion              |
| `ErrInvalidInput`             | Input validation failure                     |
| `ErrNoBraid`                  | Braid operation called without attached braid|
| `ErrBraidSend` / `ErrBraidRecv` | Wrapped braid operation errors             |
| `ErrEpochAdvance`             | Wrapped KdfSckaRK failure                    |
| `ErrSerialize` / `ErrDeserialize` | Serialization format errors               |
| `ErrPQRMessage`               | Malformed PQR wire message                   |

## Concurrency

SPQR is NOT safe for concurrent use by multiple goroutines. The session-level serialization pattern (load, mutate, store) provides implicit synchronization when used through the session cipher. There are no mutexes or atomics in the SPQR implementation.
