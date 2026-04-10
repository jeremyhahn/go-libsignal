# Session State Management

The `state/record/` and `state/store/` packages handle session records, session states, chain states, and pre-key record types.

Source files: `state/record/SessionRecord.go`, `state/record/SessionState.go`, `state/record/ChainState.go`, `state/record/PreKeyRecord.go`, `state/record/SignedPreKeyRecord.go`, `state/record/KyberPreKeyRecord.go`, `state/store/*.go`

## Session Record

`record.Session` (in `state/record/SessionRecord.go`) is the top-level container for a remote address's session data. It holds:

- `sessionState`: the current active `State`
- `previousStates`: a list of archived `State` entries (up to `archivedStatesMaxLength = 40`)
- `fresh`: whether this record was just created (no session established yet)
- `serializer`: the `SessionSerializer` used for persistence

### Lifecycle

A `Session` begins as "fresh" (`fresh = true`) when created via `NewSession()`. Once a session is established through PQXDH key agreement, `MarkEstablished()` sets `fresh = false`. Subsequent session re-negotiations on the same record archive the current state before replacing it.

### Archived States

The protocol keeps up to 40 previous session states. This allows decryption of messages sent under an older session (e.g., when messages arrive out of order during a session renegotiation).

`ArchiveCurrentState()` pushes the current state to the front of `previousStates` and replaces it with a fresh `State`. Before archiving, `ClearUnackPreKeyMessage()` is called on the current state to strip pending pre-key information, matching the Rust `archive_current_state_inner` behavior.

If `previousStates` exceeds `archivedStatesMaxLength` (40), the oldest entry is dropped.

### Session Promotion

When decryption succeeds against a previous session state, that state is promoted to current via `PromoteOldSession(index, state)`:

1. The entry at `index` is removed from `previousStates`.
2. `PromoteState()` pushes the current state into `previousStates` and installs the promoted state as current.

This prevents the same state from appearing in both the current and previous lists.

`HasSessionState(version, senderBaseKey)` searches the current and previous states for a match. If found in a previous state, it promotes the match to current. Base key comparison uses `subtle.ConstantTimeCompare` to prevent timing side channels.

### Deep Copy

`Session.Copy()` creates a full deep copy by cloning the current state and all previous states via `State.Clone()`. If any clone fails, an error is returned (no fallback to unsafe shallow copy). A panic recovery wraps the operation.

### Serialization

`Session.Serialize()` converts the record to bytes via the configured `SessionSerializer`. The internal `structure()` method converts the session into `SessionStructure`, which has `SessionState` and `PreviousStates` as serializable structures.

## Session State

`record.State` (in `state/record/SessionState.go`) holds all the cryptographic state for a single session version:

| Field | Type | Description |
|-------|------|-------------|
| `sessionVersion` | `int` | Protocol version (3 or 4). 0 is mapped to 2 on read. |
| `rootKey` | `*root.Key` | Current root key (memguard-protected) |
| `senderChain` | `*Chain` | Our sending chain (ratchet key pair + chain key) |
| `receiverChains` | `[]*Chain` | Receiver chains (up to `maxReceiverChains = 5`) |
| `previousCounter` | `uint32` | Counter of the last message in the previous sender chain |
| `localIdentityPublic` | `*identity.Key` | Our identity public key |
| `remoteIdentityPublic` | `*identity.Key` | Their identity public key |
| `senderBaseKey` | `ECPublicKeyable` | The ephemeral base key from session setup |
| `pendingPreKey` | `*PendingPreKey` | Unacknowledged pre-key info (cleared on first response) |
| `pendingKeyExchange` | `*PendingKeyExchange` | Pending symmetric key exchange state |
| `localRegistrationID` | `uint32` | Our registration ID |
| `remoteRegistrationID` | `uint32` | Their registration ID |
| `pqRatchetState` | `[]byte` | Serialized SPQR ratchet state (opaque) |

### Receiver Chain Management

`AddReceiverChain()` appends a new chain. If the count exceeds `maxReceiverChains` (5), the oldest chain (index 0) is removed. Each receiver chain is keyed by the sender's ratchet public key.

`receiverChain(senderEphemeral)` performs a linear scan comparing ratchet key public bytes. Returns a `ReceiverChainPair` with the chain and its index.

### Message Key Storage

Message keys for skipped messages are stored per receiver chain:

- `HasMessageKeys(senderEphemeral, counter)`: checks if a key exists for the given ratchet key and counter
- `SetMessageKeys(senderEphemeral, messageKeys)`: adds keys to the chain. If the chain exceeds `maxMessageKeys` (2000), the oldest key is popped.
- `RemoveMessageKeys(senderEphemeral, counter)`: removes and returns the key at the given counter. Copies key material out of guarded memory before returning.
- `TotalSkippedMessageKeys()`: sums message keys across all receiver chains (used for global `maxSkippedKeys` enforcement)

### Self-Session Detection

`SessionWithSelf()` returns true if the local and remote identity public keys are byte-equal. Self-sessions are used for linked device message sync and receive special treatment (e.g., no forward jump limit, `math.MaxUint32` SPQR jump limit).

### Clone and CopyFrom

`Clone()` serializes the state and deserializes it back, producing a deep copy. This is used for speculative decryption where mutations must be rolled back on failure.

`CopyFrom(source)` replaces all fields in the receiver with those from the source. This commits a successfully-modified clone back to the original state.

### Unacknowledged Pre-Key Messages

When a session is established via PQXDH but the remote party has not yet responded, the session tracks the pre-key information:

- `SetUnacknowledgedPreKeyMessageWithKyber(preKeyID, signedPreKeyID, baseKey, kyberPreKeyID, kyberCiphertext)` stores the pending info
- `HasUnacknowledgedPreKeyMessage()` returns true if pending info exists
- `UnackPreKeyMessageItems()` returns the items for constructing a `PreKeySignalMessage`
- `ClearUnackPreKeyMessage()` clears the pending info (called after the first successful decrypt from the remote party)
- `UnacknowledgedTimestamp()` returns the creation timestamp for stale session detection

Pending pre-key info is cleared from a state before it is archived to prevent stale pre-key data from leaking into previous sessions.

## Chain State

`record.Chain` (in `state/record/ChainState.go`) represents a single ratchet chain:

```go
type Chain struct {
    senderRatchetKeyPair *ecc.ECKeyPair
    chainKey             *chain.Key
    messageKeys          []*message.Keys
}
```

- `senderRatchetKeyPair`: for sender chains, holds both public and private keys. For receiver chains, only the public key is stored.
- `chainKey`: the current chain key (memguard-protected, advances with each message)
- `messageKeys`: stored skipped message keys

`ChainStructure` is the serializable form, with key bytes for the ratchet key pair, a `chain.KeyStructure` for the chain key, and `message.KeysStructure` entries for stored message keys.

`NewChainFromStructure()` reconstructs a `Chain` from the serialized form, converting private key bytes into a `GuardedECPrivateKey` for memguard protection.

## Pre-Key Records

### PreKeyRecord

`record.PreKey` (in `state/record/PreKeyRecord.go`) stores a one-time pre-key:

```go
type PreKeyStructure struct {
    ID         uint32
    PublicKey  []byte
    PrivateKey []byte
}
```

One-time pre-keys are consumed during session establishment and removed from the store after successful decryption.

### SignedPreKeyRecord

`record.SignedPreKey` (in `state/record/SignedPreKeyRecord.go`) stores a signed pre-key:

```go
type SignedPreKeyStructure struct {
    ID         uint32
    PublicKey  []byte
    PrivateKey []byte
    Signature  []byte
    Timestamp  int64
}
```

Signed pre-keys are long-lived and rotated periodically. The signature is verified by the remote party during session establishment.

### KyberPreKeyRecord

`record.KyberPreKey` (in `state/record/KyberPreKeyRecord.go`) stores a Kyber-1024 pre-key for PQXDH:

- `ID`: the key identifier
- `PublicKey`: the Kyber public key bytes
- `PrivateKey`: the Kyber secret key bytes (moved into memguard on load)
- `Signature`: Ed25519 signature over the public key bytes

`GuardedKeyPair()` returns a `kem.GuardedKeyPair` with the secret key in memguard-protected memory. The caller must call `Destroy()` on the guarded key pair after use.

## Store Interfaces

All store interfaces are defined in `state/store/`.

### store.Session

```go
type Session interface {
    LoadSession(address *protocol.SignalAddress) *record.Session
    GetSubDeviceSessions(name string) []uint32
    StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session)
    ContainsSession(remoteAddress *protocol.SignalAddress) bool
    DeleteSession(remoteAddress *protocol.SignalAddress)
    DeleteAllSessions()
}
```

`LoadSession` returns a fresh `Session` if none exists for the address. `StoreSession` persists the session after encrypt/decrypt operations. The store implementation is responsible for thread safety if the same address is accessed concurrently.

### store.IdentityKey

```go
type IdentityKey interface {
    GetIdentityKeyPair() *identity.KeyPair
    GetLocalRegistrationId() uint32
    SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key)
    IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction Direction) bool
    GetIdentity(address *protocol.SignalAddress) (*identity.Key, error)
}
```

Trust is based on "trust on first use" (TOFU). `Direction` is either `DirectionSending` (1) or `DirectionReceiving` (2), allowing implementations to apply different policies per direction.

### store.PreKey

Provides `LoadPreKey(id)`, `StorePreKey(id, record)`, `ContainsPreKey(id)`, and `RemovePreKey(id)`.

### store.SignedPreKey

Provides `LoadSignedPreKey(id)`, `LoadSignedPreKeys() []record.SignedPreKey`, `StoreSignedPreKey(id, record)`, and `ContainsSignedPreKey(id)`.

### store.KyberPreKey

```go
type KyberPreKey interface {
    LoadKyberPreKey(kyberPreKeyID uint32) (*record.KyberPreKey, error)
    StoreKyberPreKey(kyberPreKeyID uint32, record *record.KyberPreKey) error
    MarkKyberPreKeyUsed(kyberPreKeyID uint32, signedPreKeyID uint32, baseKey ecc.ECPublicKeyable) error
    ContainsKyberPreKey(kyberPreKeyID uint32) bool
}
```

`MarkKyberPreKeyUsed` marks a Kyber pre-key as consumed. The `signedPreKeyID` and `baseKey` parameters support last-resort key replay detection, matching the Rust reference signature.

### store.SignalProtocol

Combines all store interfaces into a single composite:

```go
type SignalProtocol interface {
    IdentityKey
    PreKey
    Session
    SignedPreKey
    KyberPreKey
    store.SenderKey
}
```

Used by `session.NewBuilderFromSignal()` to accept a single store object.
