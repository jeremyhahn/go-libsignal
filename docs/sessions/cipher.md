# Session Cipher and Builder

The `session.Cipher` and `session.Builder` types provide the encrypt/decrypt API and PQXDH key agreement for session establishment.

Source files: `session/SessionCipher.go`, `session/Session.go`, `session/errors.go`

## Session Builder

`session.Builder` establishes encrypted sessions. It requires access to all key stores and is constructed per remote address (recipientId + deviceId tuple).

### Constructors

```go
func NewBuilder(sessionStore, preKeyStore, signedStore, identityStore, remoteAddress, serializer) *Builder
func NewBuilderWithKyber(sessionStore, preKeyStore, signedStore, identityStore, kyberStore, remoteAddress, serializer) *Builder
func NewBuilderFromSignal(signalStore, remoteAddress, serializer) *Builder
```

- `NewBuilder`: standard constructor without Kyber store (legacy path)
- `NewBuilderWithKyber`: includes `store.KyberPreKey` for PQXDH
- `NewBuilderFromSignal`: accepts a `store.SignalProtocol` composite that implements all store interfaces

### ProcessBundle (Sender-Side Session Setup)

`Builder.ProcessBundle(preKey *prekey.Bundle) error` establishes a session from a pre-key bundle fetched from the server. This is the sender (Alice) side of PQXDH.

Steps:

1. Verify trust of the remote identity key via `IsTrustedIdentity(address, key, DirectionSending)`.
2. Verify the signed pre-key has a valid signature.
3. Verify the Kyber pre-key signature if present. Reject bundles with a Kyber key but missing signature.
4. Reject bundles missing a Kyber pre-key (PQXDH is mandatory for v4 sessions).
5. Generate an ephemeral base key pair.
6. Call `ratchet.CalculateSenderSession(parameters)` to perform the PQXDH DH agreement and Kyber encapsulation.
7. Zeroize the ephemeral base key's private key immediately after the calculation.
8. Perform a DH ratchet step to derive the sender chain.
9. Initialize SPQR state from the `InitialPQRKey` with `DirectionA2B`.
10. Store the unacknowledged pre-key message info (including Kyber pre-key ID and ciphertext).
11. Store the session and save the remote identity key.

The session version is set to `CurrentVersion` (4) since PQXDH is mandatory.

### Process (Receiver-Side Session Setup)

`Builder.Process(message *protocol.PreKeySignalMessage) (*DeferredActions, error)` establishes a session from an incoming `PreKeySignalMessage`. This is the receiver (Bob) side of PQXDH.

The return value is a `DeferredActions` struct. The caller must decrypt the inner `SignalMessage` and only call `DeferredActions.Complete()` on success. If decryption fails, the deferred actions are discarded, preserving pre-keys from being burned.

Steps:

1. Verify trust of the sender's identity key via `IsTrustedIdentity(address, key, DirectionReceiving)`.
2. Check for an existing session with the same version and base key. If found, return nil deferred actions (session already exists).
3. Reject X3DH (version 3) messages: `ErrX3DHNoLongerSupported`.
4. Require Kyber pre-key ID and ciphertext for v4+ messages: `ErrMissingPQPreKey`.
5. Load the signed pre-key and optionally the one-time pre-key.
6. Load the Kyber pre-key pair into locked memory.
7. Call `ratchet.CalculateReceiverSession(parameters)` to perform PQXDH DH agreement and Kyber decapsulation.
8. Destroy the guarded Kyber key pair immediately after the calculation.
9. Set up the session state with the derived keys.
10. Initialize SPQR state from the `InitialPQRKey` with `DirectionB2A`.
11. Return `DeferredActions` containing the session record, unsigned pre-key ID, Kyber pre-key ID, and identity key.

### DeferredActions

```go
type DeferredActions struct {
    SessionRecord    *record.Session
    UnsignedPreKeyID *optional.Uint32
    KyberPreKeyID    *optional.Uint32
    TheirIdentityKey *identity.Key
}
```

`Complete()` executes the deferred side effects:

1. `StoreSession`: persists the new session record
2. `SaveIdentity`: saves the remote identity key
3. `MarkKyberPreKeyUsed`: marks the Kyber pre-key as consumed (if present)
4. `RemovePreKey`: removes the one-time pre-key (if present)

## PQXDH Key Agreement

Both `CalculateSenderSession` and `CalculateReceiverSession` in `ratchet/Ratchet.go` perform the same DH calculations in symmetric order:

### Sender (Alice) DH Components

1. `DH(our_identity_private, their_signed_prekey)`: identity-to-signed-prekey
2. `DH(our_base_private, their_identity_public)`: base-to-identity
3. `DH(our_base_private, their_signed_prekey)`: base-to-signed-prekey
4. `DH(our_base_private, their_one_time_prekey)`: optional one-time pre-key
5. `Kyber.Encapsulate(their_kyber_prekey)`: Kyber-1024 KEM encapsulation

### Receiver (Bob) DH Components

1. `DH(their_identity_public, our_signed_prekey_private)`: identity-to-signed-prekey
2. `DH(their_base_public, our_identity_private)`: base-to-identity
3. `DH(their_base_public, our_signed_prekey_private)`: base-to-signed-prekey
4. `DH(their_base_public, our_one_time_prekey_private)`: optional one-time pre-key
5. `Kyber.Decapsulate(our_kyber_secret, their_ciphertext)`: Kyber-1024 KEM decapsulation

The master secret is constructed as:

```
master_secret = 0xFF*32 || DH1 || DH2 || DH3 || [DH4] || KEM_shared_secret
```

The leading 32 bytes of `0xFF` form a "discontinuity" value that separates protocol versions.

Both paths validate inputs before DH operations. The receiver checks that the sender's base key is canonical (`IsCanonical()`), matching the Rust `initialize_bob_session` check.

All DH agreements reject all-zero shared secrets (constant-time check) to prevent invalid curve attacks.

## Session Cipher

`session.Cipher` provides the encrypt and decrypt API. It operates on an established session and is constructed after a `Builder` has set up the session.

### Constructors

```go
func NewCipher(builder *Builder, remoteAddress *protocol.SignalAddress) *Cipher
func NewCipherFromSession(session, remoteAddress, sessionStore, preKeyStore, preKeyMsgSerializer, signalMsgSerializer) *Cipher
func NewCipherWithIdentity(builder *Builder, remoteAddress *protocol.SignalAddress, identityStore store.IdentityKey) *Cipher
```

`NewCipherWithIdentity` is the recommended constructor as it enables identity trust checks on both encrypt and decrypt, matching the Rust reference.

A `Cipher` instance is not safe for concurrent use. Callers must synchronize access for the same address.

### Encrypt

`Cipher.Encrypt(plaintext []byte) (protocol.CiphertextMessage, error)`

1. Load the session record for the remote address.
2. Get the sender chain key from the current session state.
3. If SPQR is active (`PqRatchetState` is non-empty), advance the SPQR ratchet via `spqr.Send()` and derive message keys with the PQR salt.
4. Encrypt the plaintext with AES-256-CBC using the message key's cipher key and IV.
5. Build a `SignalMessage` with the ciphertext, ratchet key, counters, MAC, and optional PQR ratchet key.
6. If the session has an unacknowledged pre-key message:
   - Check the stale session age (max 30 days, `maxUnacknowledgedSessionAge`). If exceeded, return `ErrStaleSession`.
   - Wrap the `SignalMessage` in a `PreKeySignalMessage` with the pending pre-key info.
7. Advance the sender chain key via `NextKey()`.
8. If an identity store is configured, verify trust via `IsTrustedIdentity(address, key, DirectionSending)`. If untrusted, the in-memory session with the advanced chain key is discarded (never persisted).
9. Store the updated session record.

### Decrypt

The decrypt path has several entry points:

**`Decrypt(ciphertextMessage *protocol.SignalMessage) ([]byte, error)`**: decrypts a `SignalMessage` using the stored session.

**`DecryptAndGetKey(ciphertextMessage) ([]byte, *message.Keys, error)`**: same as `Decrypt` but also returns the message keys used.

**`DecryptPreKeyMessage(builder, preKeyMessage) ([]byte, *DeferredActions, error)`**: full `PreKeySignalMessage` flow:
1. Call `builder.Process()` to establish the session (without persisting)
2. Decrypt the inner `SignalMessage`
3. On success only: call `DeferredActions.Complete()` to commit side effects

**`DecryptWithRecord(sessionRecord, ciphertext) ([]byte, *message.Keys, error)`**: tries decryption against the current session state first, then falls back to previous states.

### Decrypt Fallback Logic

`decryptWithRecordAndType()` implements the session state search:

1. Try the current session state.
2. On failure:
   - `ErrDuplicateMessage`: short-circuit, return immediately (no fallback).
   - `PREKEY_TYPE` messages: short-circuit, return `ErrNoValidSessions` (pre-key messages create fresh sessions, so previous states are irrelevant).
   - Other errors: iterate through `previousStates`, trying each one.
3. If a previous state succeeds, promote it to current via `PromoteOldSession()`.
4. If no state succeeds, return `ErrNoValidSessions`.

### Clone-on-Decrypt (Snapshot/Restore)

`DecryptWithState()` clones the session state before attempting decryption:

```go
workingState, err := sessionState.Clone()
// ... attempt decrypt on workingState ...
sessionState.CopyFrom(workingState) // commit on success
```

Per the Double Ratchet spec (section 3.5): "If an exception is raised then the message is discarded and changes to the state object are discarded."

The clone is created via `State.Clone()`, which serializes the state to bytes and deserializes it back. On success, `CopyFrom()` copies all fields from the working copy back to the original. On failure, the clone is dropped.

The decrypt path mutates state by advancing chain keys, storing skipped message keys, and advancing SPQR state. Without cloning, a failed MAC verification would leave the session in a corrupted state.

### Identity Trust Checks

When an identity store is configured:

- **Encrypt**: Trust is checked after chain key advancement but before `StoreSession`. If the check fails, the advanced session is discarded.
- **Decrypt**: Trust is checked after successful decryption but before `StoreSession`. If the check fails, the plaintext is not returned.

In both cases, `SaveIdentity` is called after a successful trust check.

## Error Types

All session errors use `session.Error` with `errors.Is` support:

| Sentinel | Condition |
|----------|-----------|
| `ErrNoSession` | No session exists for the address |
| `ErrNoValidSessions` | No session state could decrypt the message |
| `ErrUninitializedSession` | Session state has no sender chain |
| `ErrWrongMessageVersion` | Message version does not match session version |
| `ErrTooFarIntoFuture` | Message counter exceeds `maxFutureMessages` (25000) |
| `ErrMaxSkippedKeysExceeded` | Global skipped keys limit (2000) would be exceeded |
| `ErrDuplicateMessage` | Message key already consumed |
| `ErrUntrustedIdentity` | Remote identity key failed trust check |
| `ErrMissingPQPreKey` | v4+ message missing Kyber pre-key |
| `ErrX3DHNoLongerSupported` | X3DH (v3) PreKey message rejected |
| `ErrStaleSession` | Unacknowledged session older than 30 days |
| `ErrNoSignedPreKey` | Pre-key bundle missing signed pre-key |
| `ErrInvalidSignature` | Invalid signature on signed pre-key |
| `ErrInvalidKyberSignature` | Invalid Kyber pre-key signature |
| `ErrMissingKyberSignature` | Kyber pre-key present but signature missing |
| `ErrNilOneTimePreKey` | Pre-key store returned nil for one-time pre-key |
| `ErrMissingKyberPreKey` | Pre-key bundle missing Kyber pre-key |
