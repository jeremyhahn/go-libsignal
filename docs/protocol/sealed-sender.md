# Sealed Sender Protocol

Package `sealed` implements Signal's Sealed Sender protocol, which hides the sender's identity from the server during message delivery. The server routes messages to recipients without learning who sent them.

Two protocol versions exist: v1 (single-recipient, version byte `0x11`) and v2 (multi-recipient, version bytes `0x22`/`0x23`). Both versions encrypt an `UnidentifiedSenderMessageContent` (USMC) that carries the sender's certificate and the inner Signal Protocol message.

## Certificate Chain

Sealed Sender relies on a two-level certificate hierarchy to authenticate senders without revealing their identity to the server.

### ServerCertificate

A `ServerCertificate` contains a server's EC public key, signed by the trust root private key. The struct holds:

- `keyID` (uint32): identifies which server key was used
- `key` (ecc.ECPublicKeyable): the server's public key
- `certificate` ([]byte): inner protobuf bytes (the signed payload)
- `signature` ([]byte): 64-byte Ed25519 signature from the trust root

Validation (`ServerCertificate.Validate`) checks two things:
1. The `keyID` is not in the `revokedServerCertificateKeyIDs` list (currently contains `0xDEADC357`, a test ID).
2. The `signature` verifies against the provided trust root public key.

A revoked certificate returns `(false, nil)`, not an error, matching the Rust reference behavior.

### SenderCertificate

A `SenderCertificate` binds a sender's identity key to their UUID, optional E164 phone number, device ID, and an expiration timestamp. It is signed by a server certificate's key.

Fields:
- `senderUUID` (string): the sender's UUID
- `senderE164` (*string): optional phone number
- `key` (ecc.ECPublicKeyable): sender's identity public key
- `senderDevice` (uint32): device ID (must be > 0, matching Rust's `NonZeroU8`)
- `expiration` (uint64): milliseconds since epoch
- `signer` (senderCertificateSigner): either an embedded `ServerCertificate` or a reference ID

The signer field uses a union type (`senderCertificateSigner`). When the protobuf carries an embedded server certificate, `embedded` is non-nil. When it carries only a key ID, `Signer()` resolves the ID through the known server certificates table.

`SenderCertificate.Validate(trustRoot, timestamp)` performs three checks:
1. Resolves and validates the server certificate against `trustRoot`.
2. Verifies the sender certificate's signature using the server certificate's key.
3. Confirms `timestamp <= expiration`.

### Known Server Certificates

The file `known_server_certificates.go` contains a static table (`knownServerCertificateData`) of pre-provisioned server certificates keyed by ID. Three entries exist:

| Key ID | Environment |
|--------|------------|
| `2` | Staging |
| `3` | Production |
| `0x7357C357` | Test (never used in production) |

Each entry stores the trust root public key (33 bytes with `0x05` type prefix) and the serialized `ServerCertificate` protobuf. The table is lazily deserialized via `sync.Once` in `resolvedKnownCertificates()` and cached for the process lifetime.

`lookupKnownServerCertificate(id)` returns the resolved `ServerCertificate` or an `ErrUnknownServerCertificateID` error.

## UnidentifiedSenderMessageContent (USMC)

`UnidentifiedSenderMessageContent` is the inner payload that both v1 and v2 encrypt. It wraps:

- `msgType` (uint32): message type from the protobuf enum
  - `1` = `PREKEY_MESSAGE`
  - `2` = `MESSAGE` (regular Whisper message)
  - `7` = `SENDERKEY_MESSAGE` (not valid in sealed sender decrypt)
  - `8` = `PLAINTEXT_CONTENT` (not valid in sealed sender decrypt)
- `sender` (*SenderCertificate): the sender's certificate
- `contents` ([]byte): the inner encrypted message bytes
- `contentHint` (ContentHint): error handling hint
  - `ContentHintDefault` (0): sender will not resend
  - `ContentHintResendable` (1): sender will try to resend
  - `ContentHintImplicit` (2): no error UI
- `groupID` ([]byte): optional group identifier

Construct with `NewUnidentifiedSenderMessageContent(...)`, deserialize with `DeserializeUnidentifiedSenderMessageContent(data)`. Both serialize to/from the `UnidentifiedSenderMessage.Message` protobuf.

## Sealed Sender v1

### Protocol Overview

v1 uses two sequential ECDH exchanges to encrypt the USMC for a single recipient. The version byte is `SealedSenderV1Version = 0x11`.

The HKDF derivation in v1 has a specific convention that differs from typical usage:
- The **salt** parameter is `"UnidentifiedDelivery" || their_pub || ephemeral_pub`
- The **info** parameter is `nil` (empty)

The string `"UnidentifiedDelivery"` appears only in salt construction, not as the HKDF info. The constant `hkdfInfo` in the source is named for its role in the protocol, not its HKDF parameter position.

Each HKDF derivation produces 96 bytes (`hkdfOutputLen`), split into three 32-byte keys:
- `chain_key` (bytes 0-31)
- `cipher_key` (bytes 32-63)
- `mac_key` (bytes 64-95)

### Encryption (SealedSenderEncryptFromUSMC)

The encryption performs six steps:

1. Generate an ephemeral X25519 key pair `E`.
2. First ECDH: `shared1 = DH(E.private, recipient.identity_pub)`. Derive `keys1` via HKDF with salt = `"UnidentifiedDelivery" || recipient_pub || E.pub`, info = nil.
3. Encrypt the sender's identity public key (33 bytes with `0x05` prefix) using AES-CTR with `cipher_key1`. Append a 10-byte truncated HMAC-SHA256 using `mac_key1`.
4. Second ECDH: `shared2 = DH(sender.identity_priv, recipient.identity_pub)`. Derive `keys2` via HKDF with salt = `chain_key1 || encrypted_static_with_mac`, info = nil.
5. Encrypt the serialized USMC using AES-CTR with `cipher_key2`. Append a 10-byte truncated HMAC-SHA256 using `mac_key2`.
6. Build a protobuf envelope (`UnidentifiedSenderMessage`) with `ephemeral_public`, `encrypted_static`, and `encrypted_message`. Prepend version byte `0x11`.

The `truncatedHMAC` function computes HMAC-SHA256 and returns only the first `macTruncateLen` (10) bytes.

### Decryption (SealedSenderDecryptToUSMC)

Decryption reverses the process. After extracting the protobuf fields:

1. Compute `shared1 = DH(E.pub, our.identity_priv)` and derive `keys1`.
2. Verify the MAC on `encrypted_static` using constant-time comparison (`subtle.ConstantTimeCompare`), then decrypt to recover the sender's identity public key.
3. Compute `shared2 = DH(sender.identity_pub, our.identity_priv)` and derive `keys2`.
4. Verify the MAC on `encrypted_message`, then decrypt to recover the serialized USMC.
5. Deserialize the USMC and perform a constant-time comparison of the decrypted static key against the sender's identity key from the certificate. This check (`ErrSenderKeyMismatch`) prevents an attacker from substituting a different sender certificate inside the encrypted USMC.

### Full Decryption (SealedSenderDecrypt)

`SealedSenderDecrypt` and `SealedSenderDecryptWithKyber` add three layers on top of `SealedSenderDecryptToUSMC`:

1. Certificate validation against the trust root with expiration checking.
2. Self-send detection: if the sender's UUID or E164 matches the local identity AND the device ID matches, the function returns `ErrSelfSend`.
3. Inner session cipher decryption of the USMC contents, handling both `PREKEY_MESSAGE` and `MESSAGE` types.

The `SealedSenderDecryptWithKyber` variant accepts an optional `store.KyberPreKey` for PQXDH session support.

### Convenience Entry Point

`SealedSenderEncrypt` handles the full encryption flow: it encrypts plaintext through a session cipher, wraps the result in a USMC, and calls `SealedSenderEncryptFromUSMC`. This is the typical entry point for senders.

## Sealed Sender v2

v2 adds multi-recipient support. A single encrypted payload is shared across all recipients, with per-recipient key material that allows each recipient to independently decrypt.

### Version Bytes

- `SealedSenderV2VersionUUID = 0x22`: addresses recipients by raw 16-byte UUID
- `SealedSenderV2VersionServiceId = 0x23`: addresses recipients by 17-byte fixed-width ServiceId

### HKDF Info Strings

v2 uses labeled HKDF info strings (unlike v1 which passes nil):

| Constant | Value | Purpose |
|----------|-------|---------|
| `v2HKDFRInfo` | `"Sealed Sender v2: r (2023-08)"` | Derive ephemeral private key `r` from `M` |
| `v2HKDFKInfo` | `"Sealed Sender v2: K"` | Derive payload encryption key `K` from `M` |
| `v2HKDFDHInfo` | `"Sealed Sender v2: DH"` | Derive per-recipient DH key from ECDH result |
| `v2HKDFDHSenderInfo` | `"Sealed Sender v2: DH-sender"` | Derive sender authentication tag |

All v2 HKDF calls pass `salt = nil` and use the info strings above.

### Encryption (SealedSenderMultiRecipientEncrypt)

1. Generate 32 random bytes `M`.
2. Derive `r = HKDF(ikm=M, salt=nil, info="Sealed Sender v2: r (2023-08)", len=32)`.
3. Derive `K = HKDF(ikm=M, salt=nil, info="Sealed Sender v2: K", len=32)`.
4. Clamp `r` as an X25519 private key and compute the ephemeral public key `E.pub`.
5. Encrypt the serialized USMC with AES-256-GCM-SIV using key `K` and a 12-byte all-zero nonce.
6. Group destinations by ServiceId. For each unique recipient identity key:
   - `shared = DH(E.priv, recipient.identity_pub)`
   - Build `ikm = shared || E.pub.Serialize() || recipient.pub.Serialize()` (using 33-byte serialized keys with `0x05` prefix)
   - `dhKey = HKDF(ikm, salt=nil, info="Sealed Sender v2: DH", len=32)`
   - `C_i = dhKey XOR M` (the encrypted M for this recipient)
   - Compute sender authentication tag `AT_i`:
     - `senderShared = DH(our.identity_priv, recipient.identity_pub)`
     - `senderIkm = senderShared || E.pub.Serialize() || C_i || our.pub.Serialize() || recipient.pub.Serialize()`
     - `AT_i = HKDF(senderIkm, salt=nil, info="Sealed Sender v2: DH-sender", len=16)`
7. Serialize into the binary wire format.

#### Loop Zeroization

DH shared secrets within the per-recipient loop are zeroized at the end of each iteration using direct `crypto.ZeroizeArray32(&shared)` calls. Using `defer` inside the loop body would be wrong because `defer` executes at function return, not at the end of the loop iteration. That would leave secret material in memory across all subsequent iterations.

### Wire Format

The binary layout of a v2 multi-recipient message:

```
version (1 byte)
recipient_count (varint, includes excluded recipients)
for each recipient:
    ServiceId (17 bytes for 0x23, or 16 bytes UUID for 0x22)
    for each device:
        device_id (1 byte, u8)
        registration_id (2 bytes, u16 big-endian)
            bit 15 (0x8000) = has_more_devices flag
            bits 0-13 = registration ID (masked with 0x3FFF)
    C_i (32 bytes, encrypted M)
    AT_i (16 bytes, authentication tag)
for each excluded recipient:
    ServiceId (17 bytes)
    device_id = 0 (1 byte, signals exclusion)
ephemeral_public (32 bytes)
encrypted_payload (remaining bytes)
```

A `device_id` of 0 as the first entry for a recipient signals an excluded recipient (no `C_i`/`AT_i` follow). Device IDs are limited to a single byte (max 255), enforced by `ErrDeviceIDOverflow`.

### Received Format

The server fans out the multi-recipient message to individual clients by extracting per-recipient data. The received (single-recipient) format is:

```
version (1 byte, always 0x22)
C (32 bytes)
AT (16 bytes)
E.pub (32 bytes)
ciphertext (remaining bytes)
```

`V2BuildReceivedMessage` constructs this format. The version byte is always `0x22` regardless of the input version, matching the Rust reference behavior (`SEALED_SENDER_V2_UUID_FULL_VERSION`).

`v2ParseReceivedMessage` parses this format, requiring at least `v2ReceivedMinSize` (81) bytes after the version byte.

### Decryption

Two decryption paths exist:

**SealedSenderV2DecryptToUSMC**: decrypts the multi-recipient sent format. Requires the recipient's `ServiceId` to locate the correct `C_i` and `AT_i` in the recipient list.

**SealedSenderV2DecryptReceivedToUSMC**: decrypts the single-recipient received format (what clients normally receive from the server). Does not require a `ServiceId` because the per-recipient data is already extracted.

Both follow the same cryptographic steps:

1. `shared = DH(E.pub, our.identity_priv)`
2. Build `ikm = shared || E.pub.Serialize() || our.pub.Serialize()`, derive `dhKey` via HKDF with info `"Sealed Sender v2: DH"`.
3. `M = dhKey XOR C_i`
4. Derive `r` from `M`, clamp it, compute `E'.pub`. Verify `E'.pub == E.pub` using constant-time comparison. This proves the message was constructed correctly.
5. Derive `K` from `M`. Decrypt the payload with AES-256-GCM-SIV (key=K, nonce=zeros).
6. Deserialize the USMC.
7. **ServiceId consistency check**: validate that the sender's UUID from the decrypted certificate is a well-formed ACI ServiceId. This prevents a malformed certificate from passing the auth tag check (which only binds the identity key) while carrying an invalid sender UUID.
8. Verify the sender authentication tag `AT_i`:
   - `senderShared = DH(our.identity_priv, sender.identity_pub)`
   - Build `senderIkm = senderShared || E.pub.Serialize() || C_i || sender.pub.Serialize() || our.pub.Serialize()`
   - `expectedAT = HKDF(senderIkm, salt=nil, info="Sealed Sender v2: DH-sender", len=16)`
   - Constant-time compare `expectedAT` against `AT_i`.

### Version Dispatch

`SealedSenderDecryptToUSMC` acts as the top-level dispatcher. It inspects the version byte:

- `0x22` or `0x23`: dispatches to v2. If a `recipientServiceId` argument is provided, uses `SealedSenderV2DecryptToUSMC` (sent format). Otherwise, uses `SealedSenderV2DecryptReceivedToUSMC` (received format).
- Major version 0 or 1 (high nibble): processes as v1.
- Anything else: returns `ErrUnsupportedVersion`.

## Key Zeroization

All cryptographic secrets are zeroized after use:

- Stack-local `[32]byte` arrays holding DH shared secrets or private key copies use `defer crypto.ZeroizeArray32(&variable)`.
- Heap-allocated key material uses `secret.New(data)` to create guarded memory regions, destroyed via `defer secret.Destroy()`.
- Private key serializations are moved into guarded memory immediately (`secret.New(privArr[:])` consumes the source).
- In v2 encryption loops, shared secrets are zeroized with immediate `crypto.ZeroizeArray32()` calls at the end of each iteration, not with `defer`.

## Error Types

| Type | Usage |
|------|-------|
| `Error` | Sentinel errors matched by `kind` via `errors.Is`. Covers `ErrSenderKeyMismatch`, `ErrSelfSend`, `ErrUnsupportedVersion`, `ErrInvalidDeviceID`, `ErrDeviceIDOverflow`, and v2 received-format errors. |
| `V1StructureError` | Structural problems in v1 messages (short ciphertext, MAC failure). |
| `V2InputError` | Invalid inputs to v2 operations (missing recipient, bad key size). |
| `V2ParseError` | Wire format parsing failures (truncated fields, bad varints). Wraps an underlying error. |
| `V2OperationError` | Cryptographic operation failures in v2 (HKDF, ECDH, AES-GCM-SIV). Wraps an underlying error. |
| `CertificateError` | Certificate structure problems (missing fields, nil sender). |
| `IdentityStoreError` | The identity store does not support loading remote identities. |

## API Reference

### Encryption Functions

```go
func SealedSenderEncrypt(
    destination *protocol.SignalAddress,
    senderCert *SenderCertificate,
    plaintext []byte,
    sessionStore store.Session,
    identityStore store.IdentityKey,
) ([]byte, error)

func SealedSenderEncryptFromUSMC(
    destination *protocol.SignalAddress,
    usmc *UnidentifiedSenderMessageContent,
    identityStore store.IdentityKey,
) ([]byte, error)

func SealedSenderMultiRecipientEncrypt(
    destinations []*protocol.SignalAddress,
    destinationSessions []*record.Session,
    excludedRecipients []protocol.ServiceId,
    usmc *UnidentifiedSenderMessageContent,
    identityStore store.IdentityKey,
) ([]byte, error)
```

### Decryption Functions

```go
func SealedSenderDecryptToUSMC(
    ciphertext []byte,
    identityStore store.IdentityKey,
    recipientServiceId ...protocol.ServiceId,
) (*UnidentifiedSenderMessageContent, error)

func SealedSenderDecrypt(
    ciphertext []byte,
    trustRoot ecc.ECPublicKeyable,
    timestamp uint64,
    localUUID string,
    localE164 *string,
    localDeviceID uint32,
    sessionStore store.Session,
    identityStore store.IdentityKey,
    preKeyStore store.PreKey,
    signedPreKeyStore store.SignedPreKey,
) (*SealedSenderDecryptionResult, error)

func SealedSenderDecryptWithKyber(
    ciphertext []byte,
    trustRoot ecc.ECPublicKeyable,
    timestamp uint64,
    localUUID string,
    localE164 *string,
    localDeviceID uint32,
    sessionStore store.Session,
    identityStore store.IdentityKey,
    preKeyStore store.PreKey,
    signedPreKeyStore store.SignedPreKey,
    kyberPreKeyStore store.KyberPreKey,
) (*SealedSenderDecryptionResult, error)

func SealedSenderV2DecryptToUSMC(
    ciphertext []byte,
    recipientServiceId protocol.ServiceId,
    identityStore store.IdentityKey,
) (*UnidentifiedSenderMessageContent, error)

func SealedSenderV2DecryptReceivedToUSMC(
    ciphertext []byte,
    identityStore store.IdentityKey,
) (*UnidentifiedSenderMessageContent, error)
```

### Certificate Types

```go
func NewServerCertificate(keyID uint32, key ecc.ECPublicKeyable, trustRoot ecc.ECPrivateKeyable) (*ServerCertificate, error)
func DeserializeServerCertificate(data []byte) (*ServerCertificate, error)
func (sc *ServerCertificate) Validate(trustRoot ecc.ECPublicKeyable) (bool, error)

func NewSenderCertificate(senderUUID string, senderE164 *string, key ecc.ECPublicKeyable, senderDevice uint32, expiration uint64, signer *ServerCertificate, signerKey ecc.ECPrivateKeyable) (*SenderCertificate, error)
func DeserializeSenderCertificate(data []byte) (*SenderCertificate, error)
func (sc *SenderCertificate) Validate(trustRoot ecc.ECPublicKeyable, validationTime uint64) (bool, error)
```

### Result Types

```go
type SealedSenderDecryptionResult struct {
    SenderUUID string
    SenderE164 *string
    DeviceID   uint32
    Message    []byte
}
```
