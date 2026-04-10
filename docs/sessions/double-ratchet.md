# Double Ratchet Implementation

The `ratchet/`, `keys/`, and `session/` packages implement the Double Ratchet algorithm.

Source files: `ratchet/Ratchet.go`, `keys/root/RootKey.go`, `keys/chain/ChainKey.go`, `keys/message/MessageKey.go`, `keys/session/DerivedSecrets.go`, `session/SessionCipher.go`

## Overview

The Double Ratchet combines two ratchet mechanisms:

1. **DH Ratchet**: a new Diffie-Hellman key exchange on each message turn, producing a new root key and receiver chain key. Implemented in `RootKey.CreateChain()`.
2. **Symmetric Ratchet**: HMAC-SHA256-based chain key derivation for each message in a turn. Implemented in `chain.Key.NextKey()` and `chain.Key.MessageKeys()`.

Together these provide forward secrecy (compromised keys cannot decrypt past messages) and break-in recovery (compromised keys cannot decrypt future messages after a DH ratchet step).

## Initial Key Derivation

Session establishment (via PQXDH) produces a master secret that is fed through HKDF to derive three 32-byte keys:

```
HKDF(master_secret, salt=nil, info=KdfInfoPQXDH) -> [RootKey][ChainKey][InitialPQRKey]
```

- `DerivedSecretsSize = 96` bytes (3 x 32), defined in `keys/root/RootKey.go`
- `KdfInfoPQXDH = "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"` (defined in `keys/root/RootKey.go`)
- The `InitialPQRKey` (bytes 64-96) seeds the SPQR post-quantum ratchet

The `session.DerivedSecrets` struct holds these three keys in memguard-protected memory. All key material is zeroized from the source after splitting.

For the per-message chain ratchet step (not the initial session), `CreateChain` uses `ChainDerivedSecretsSize = 64` bytes (2 x 32), producing only `RootKey + ChainKey`.

## DH Ratchet

When a new ratchet key arrives from the remote party, `getOrCreateChainKey()` in `session/SessionCipher.go` performs a double DH ratchet step:

1. Compute a DH shared secret between the sender's new ratchet key and our current ratchet private key.
2. Derive a new root key and receiver chain key from the shared secret and current root key using `RootKey.CreateChain()`.
3. Generate a fresh ephemeral key pair for our next sender chain.
4. Compute another DH shared secret using the sender's new ratchet key and our new ephemeral private key.
5. Derive a new root key and sender chain key.
6. Update the session state with the new root key, receiver chain, and sender chain.

The `RootKey.CreateChain()` method in `keys/root/RootKey.go`:

```go
func (k *Key) CreateChain(theirRatchetKey, ourRatchetKey) (*session.KeyPair, error)
```

- Performs X25519 DH agreement
- Rejects all-zero shared secrets (constant-time check)
- Derives `ChainDerivedSecretsSize` (64) bytes via HKDF using the current root key as salt and `KdfInfo = "WhisperRatchet"` as info
- Returns a `session.KeyPair` containing the new `RootKey` and `ChainKey`
- All intermediate DH secrets are zeroized via `defer`

## Symmetric Chain Ratchet

Each chain key ratchets forward to produce message keys and the next chain key:

### Chain Key Derivation

`chain.Key.NextKey()` in `keys/chain/ChainKey.go`:

```go
func (c *Key) NextKey() *Key
```

Computes `HMAC-SHA256(chain_key, 0x02)` to produce the next chain key. The old chain key material is destroyed via memguard after derivation. The index increments by 1.

### Message Key Derivation

`chain.Key.MessageKeys()` in `keys/chain/ChainKey.go`:

```go
func (c *Key) MessageKeys() (*message.Keys, error)
```

1. Computes `HMAC-SHA256(chain_key, 0x01)` to produce input key material
2. Feeds it through HKDF with salt (PQR key if SPQR is active, nil otherwise) and info `"WhisperMessageKeys"` to produce 80 bytes:
   - Bytes 0-31: AES-256 cipher key
   - Bytes 32-63: HMAC-SHA256 MAC key
   - Bytes 64-79: AES-CTR IV

The seeds `0x01` and `0x02` are defined as `messageKeySeed` and `chainKeySeed` in `keys/chain/ChainKey.go`.

### SPQR-Enhanced Derivation

When SPQR is active, `MessageKeysWithSalt(pqrSalt)` passes the PQR key as the HKDF salt instead of nil. This binds message key derivation to the post-quantum ratchet state.

For skipped message keys in SPQR sessions, `MessageKeysWithSeed()` stores the raw HMAC output (seed material) alongside the derived keys. When the actual message arrives with PQR data, the seed is re-derived with the correct PQR salt via `DeriveMessageKeysFromSeed()`.

## Message Limits and Forward Jump Bounds

Defined in `session/SessionCipher.go` and `state/record/SessionState.go`:

| Constant | Value | Description |
|----------|-------|-------------|
| `maxFutureMessages` | 25,000 | Maximum forward jump allowed per chain |
| `maxSkippedKeys` | 2,000 | Global limit on stored skipped message keys across all receiver chains |
| `maxMessageKeys` | 2,000 | Per-chain message key storage limit (`state/record/SessionState.go`) |
| `maxReceiverChains` | 5 | Maximum receiver chains kept per session state |

### Forward Jump Check

When receiving a message with counter `C` and current chain index `I`:

- If `C - I > maxFutureMessages`, the message is rejected with `ErrTooFarIntoFuture`. Self-sessions (linked device sync) bypass this check to accommodate large counter gaps from multi-device message ordering.
- Before storing skipped keys, the total existing skipped keys plus the gap (`C - I`) is checked against `maxSkippedKeys`. If exceeded, `ErrMaxSkippedKeysExceeded` is returned.

### Duplicate Message Detection

If `chain_index > counter` and no stored message key exists for that counter, the key was already consumed. This returns `ErrDuplicateMessage`. The error is short-circuited (no fallback to previous sessions) to prevent timing attacks on duplicate detection.

### Message Key Storage

When fast-forwarding a chain to catch up to a received counter, each skipped message key is stored via `SetMessageKeys()`. If the per-chain count exceeds `maxMessageKeys` (2000), the oldest key is removed via `PopFirstMessageKeys()`.

## Key Memory Protection

All key material (`RootKey`, `chain.Key`, message key components) is stored in memguard-protected memory via the `secret.New()` function, which:

- Allocates the key in a guarded memory region
- Zeroizes the source slice after copying
- Provides `Destroy()` for explicit cleanup

Key lifecycle:
- `chain.Key.NextKey()` destroys the old chain key after deriving the next one
- `root.Key.Zeroize()` and `chain.Key.Zeroize()` provide explicit cleanup
- `DerivedSecrets.Zeroize()` destroys all three keys (root, chain, PQR)
- All DH shared secret intermediates use `defer crypto.ZeroizeArray32()`

## Decryption Flow for Chain Key Advancement

The full decrypt path in `decryptWithClonedState()`:

1. Check for a stored skipped message key matching the sender's ratchet key and counter. If found, use it directly.
2. If no receiver chain exists for the sender's ratchet key, perform a DH ratchet step via `getOrCreateChainKey()`.
3. If the chain index is behind the message counter, fast-forward the chain, storing each skipped key along the way.
4. Derive the message key for the target counter.
5. Verify the MAC against the derived MAC key.
6. Decrypt the ciphertext with the derived cipher key and IV.
7. On success, commit the cloned state back to the original via `CopyFrom()`.
