# SenderKey Group Messaging

SenderKey is Signal's group messaging protocol. Each group member maintains a sender key that encrypts messages to the group. Unlike 1:1 sessions, SenderKey sessions are unidirectional: a sender key can be used either for sending or receiving, but not both. Sessions are constructed per `(groupId, senderId, deviceId)` tuple.

## Package layout

```
groups/
  GroupCipher.go          - Encrypt/decrypt entry point
  GroupSessionBuilder.go  - Session creation and processing
  errors.go               - Typed error values

groups/ratchet/
  SenderChainKey.go       - HMAC-SHA256 chain key ratchet
  SenderMessageKey.go     - Per-message key derivation via HKDF

groups/state/record/
  SenderKeyRecord.go      - Multi-state record with dedup
  SenderKeyState.go       - Chain key + signing key + message key buffer

groups/state/store/
  SenderKeyStore.go       - Persistence interface
```

## Chain ratchet

The sender chain key ratchet uses HMAC-SHA256 with two seeds to derive message keys and advance the chain.

`SenderChainKey` holds the chain iteration counter and the chain key bytes in guarded memory (`secret.Secret`). Two constants define the HMAC seeds:

```
messageKeySeed = []byte{0x01}
chainKeySeed   = []byte{0x02}
```

`SenderMessageKey()` derives a message key by computing `HMAC-SHA256(chainKey, messageKeySeed)`, then expanding that 32-byte seed via `kdf.DeriveSecrets(seed, nil, "WhisperGroup", 48)`. The 48-byte output is split into:

- IV: first 16 bytes
- CipherKey: last 32 bytes

The KDF info string is `"WhisperGroup"`, defined as `ratchet.KdfInfo`.

`Next()` advances the chain: `HMAC-SHA256(chainKey, chainKeySeed)` produces the next chain key. The iteration counter increments by 1. If the counter reaches `math.MaxUint32`, `Next()` returns `ErrChainTooLong`, matching the Rust reference's `checked_add` behavior.

Both `SenderChainKey` and `SenderMessageKey` store key material in locked-memory-backed `secret.Secret` and provide `Zeroize()` methods for explicit cleanup.

## Message keys

`SenderMessageKey` contains three fields, all in guarded memory:

| Field     | Size     | Source                          |
|-----------|----------|---------------------------------|
| iv        | 16 bytes | HKDF output bytes [0:16]        |
| cipherKey | 32 bytes | HKDF output bytes [16:48]       |
| seed      | 32 bytes | Raw HMAC output (before HKDF)   |

The `iteration` field (uint32) matches the chain key's iteration at the time of derivation.

## SenderKeyState

Each `SenderKeyState` (in `groups/state/record/SenderKeyState.go`) holds:

- `keyID` (uint32): the chain identifier
- `messageVersion` (uint32): protocol version (defaults to 3 when stored as 0, matching Rust)
- `senderChainKey`: current chain position
- `signingKeyPair`: EC key pair for message signing (private key for sender, public-only for receiver)
- `keys`: buffer of out-of-order `SenderMessageKey` values

The message key buffer is capped at `maxMessageKeys = 2000`. When a new key is added via `AddSenderMessageKey()` and the buffer exceeds this limit, the oldest key is zeroized and evicted (FIFO).

`RemoveSenderMessageKey(iteration)` performs a linear scan and removes the matching key from the buffer, returning it to the caller. The caller owns the returned key and is responsible for cleanup.

## SenderKeyRecord

`SenderKey` (in `groups/state/record/SenderKeyRecord.go`) manages a list of `SenderKeyState` values. The maximum number of states is `maxSenderKeyStates = 5`, matching the Rust reference `MAX_SENDER_KEY_STATES`.

`SenderKeyState()` returns the first (most recent) state. `GetSenderKeyStateByID(keyID)` searches by chain ID.

`AddSenderKeyState()` implements the Rust reference deduplication logic:

1. If a state with matching `(chain_id, signing_key)` exists, remove it and re-insert at the front (preserving the existing state's data, not the incoming data).
2. Remove states with matching `chain_id` but a different signing key.
3. If exceeding `maxSenderKeyStates`, evict the oldest (last) state.
4. Push the new state to index 0.

`SetSenderKeyState()` replaces all states with a single new state. This is used during initial session creation.

## GroupSessionBuilder

`SessionBuilder` (in `groups/GroupSessionBuilder.go`) provides two operations:

### Create

`Create(distributionID, senderKeyName)` generates a new sender key distribution message for the local sender:

1. If no record exists or it is empty, generates a fresh signing key pair and sender key via `keyhelper.GenerateSenderSigningKey()` and `keyhelper.GenerateSenderKey()`.
2. Calls `SetSenderKeyState()` with `SenderKeyCurrentVersion` (3), a random key ID, iteration 0, and the generated keys.
3. Returns a `SenderKeyDistributionMessage` containing the key ID, iteration, chain key seed, and signing public key.

The `distributionID` is a 16-byte UUID that identifies the SenderKey distribution for routing.

### Process

`Process(senderKeyName, msg)` installs a received distribution message:

1. Loads or creates a new `SenderKey` record.
2. Calls `AddSenderKeyState()` with the message's version, ID, iteration, chain key, and signature public key.
3. Stores the updated record.

## GroupCipher

`GroupCipher` (in `groups/GroupCipher.go`) performs encrypt and decrypt operations on established sessions.

### Encrypt

`Encrypt(distributionID, plaintext)`:

1. Loads the sender key record by `senderKeyID`.
2. Gets the current chain key from the first state.
3. Derives a `SenderMessageKey` from the chain.
4. Encrypts plaintext using `cipher.Encrypt(iv, cipherKey, plaintext)` (AES-CBC with PKCS7 padding).
5. Constructs a `SenderKeyMessage` with the distribution ID, key ID, iteration, ciphertext, and signature.
6. Advances the chain to the next key.
7. Stores the updated record.

The `SenderKeyMessage` is signed with the state's private signing key (XEdDSA signature over the serialized message body).

### Decrypt

`Decrypt(senderKeyMessage)`:

1. Extracts the distribution ID from the incoming message and formats it as a UUID string for the store lookup, matching the Rust reference `group_decrypt` which uses `skm.distribution_id()`.
2. Loads the sender key record using the derived lookup name.
3. Finds the state by `keyID` via `GetSenderKeyStateByID()`.
4. Validates that the message version matches the state's version.
5. Verifies the XEdDSA signature against the state's public signing key.
6. Retrieves the message key via `getSenderKey()`.
7. Decrypts the ciphertext.

### Out-of-order message handling

`getSenderKey()` handles three cases:

- **Current counter**: the chain iteration matches the requested iteration. Derive and return the key.
- **Past counter**: the iteration is behind the chain. Check `HasSenderMessageKey(iteration)` for a previously stored key. If found, `RemoveSenderMessageKey()` returns it. If not found, return `ErrOldCounter`.
- **Future counter**: the iteration is ahead. Guard against jumps exceeding `maxForwardJumps = 25000`. Iterate the chain forward, storing each intermediate key via `AddSenderMessageKey()` (which enforces the 2000-key buffer cap). Then derive and return the target key.

## SenderKeyStore interface

The `store.SenderKey` interface (in `groups/state/store/SenderKeyStore.go`) defines two methods:

```go
type SenderKey interface {
    StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *record.SenderKey) error
    LoadSenderKey(senderKeyName *protocol.SenderKeyName) (*record.SenderKey, error)
}
```

Both methods return errors, matching the Rust reference `SenderKeyStore` trait. `LoadSenderKey` returns nil when no record exists (not an error), which signals the caller to create a new record.

## Constants

| Constant              | Value | Location                           |
|-----------------------|-------|------------------------------------|
| maxForwardJumps       | 25000 | `groups/GroupCipher.go`             |
| maxMessageKeys        | 2000  | `groups/state/record/SenderKeyState.go` |
| maxSenderKeyStates    | 5     | `groups/state/record/SenderKeyState.go` |
| SenderKeyCurrentVersion | 3   | `protocol/CiphertextMessage.go`    |
| macLength             | 8     | `protocol/SignalMessage.go`        |
| KdfInfo               | "WhisperGroup" | `groups/ratchet/SenderMessageKey.go` |

## Wire format

The `SenderKeyMessage` carries:

- Version header: `(messageVersion << 4) | SenderKeyCurrentVersion` (1 byte)
- Distribution ID (16 bytes)
- Key ID (uint32, protobuf-encoded)
- Iteration (uint32, protobuf-encoded)
- Ciphertext (variable)
- MAC: 8-byte truncated HMAC (`macLength = 8`)
- Signature: XEdDSA signature over the serialized body (appended after MAC)

The `SenderKeyDistributionMessage` carries the key ID, iteration, chain key seed (32 bytes), and signing public key for initial session setup.

## Security properties

- Forward secrecy within a group: old chain keys cannot be recovered from current keys (HMAC one-wayness).
- Message authentication: XEdDSA signature per message prevents forgery by group members who do not hold the signing private key.
- Replay protection: `getSenderKey()` removes consumed keys from the buffer. Duplicate messages with already-consumed counters return `ErrOldCounter`.
- DoS mitigation: `maxForwardJumps` caps the HMAC iterations per message at 25,000. The message key buffer cap of 2,000 bounds memory usage.
