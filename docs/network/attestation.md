# Attestation

Package: `attest/`

Source files: `sgx_session.go`, `enclave.go`, `dcap.go`, `dcap_evidence.go`, `dcap_endorsements.go`, `cds2.go`, `svr2.go`, `hsm_enclave.go`, `client_connection.go`, `errors.go`

## SGX Attestation Entry Point

`ForSGX` is the primary entry point for SGX DCAP attestation. It verifies remote attestation evidence and endorsements, then initiates a Noise NK handshake with the attested enclave.

```go
func ForSGX(
    mrenclave []byte,
    evidence []byte,
    endorsements []byte,
    acceptableSWAdvisories []string,
    currentTime time.Time,
    handshakeType HandshakeType,
) (*UnvalidatedHandshake, error)
```

The `currentTime` is adjusted by 24 hours (`skewAdjustment`) to account for client clock skew during certificate validity checks. `MREnclaveSize` is 32 bytes.

The function returns an `UnvalidatedHandshake` that must be validated against a `RaftConfig` (for SVR2) or skipped (for CDS2).

## DCAP Verification

The `dcapAttest` function performs the full DCAP verification pipeline:

### 1. Evidence and Endorsement Parsing

- `parseEvidence` extracts the SGX quote (v3, ECDSA-P256), custom claims, and supporting material from raw bytes.
- `parseEndorsements` extracts certificate chains, CRLs, TCB info, and QE identity from OE endorsements (v1 format with 9 fields).

### 2. Time Validity

Both evidence and endorsements are checked against the adjusted current time. Expiration failures produce `DcapValidationError`.

### 3. Certificate Chain Verification

`verifyCertificates` performs:

- **Root verification**: The root CA certificate must be self-signed and its public key must match Intel's DCAP root key (P-256, uncompressed point in `IntelRootPubKey`).
- **Chain verification**: Three certificate chains are verified against the root CA:
  - PCK certificate chain
  - TCB issuer chain
  - QE ID issuer chain
- **CRL verification** (`verifyCRLs`):
  - Root CRL signature is verified against Intel's root public key (`verifyRootCRLAgainstIntelKey`). A synthetic `x509.Certificate` is constructed from the Intel root key with `IsCA=true` and `KeyUsage=KeyUsageCRLSign` to satisfy `CheckSignatureFrom`.
  - PCK cert CRL is verified against the PCK CRL issuer chain.
  - PCK certificates are checked against the PCK cert CRL.
  - TCB issuer chain and QE ID issuer chain certificates are checked against the root CRL.

Revoked certificates produce `CRLVerificationError` with the serial number and issuer.

### 4. Enclave Source Verification

`verifyEnclaveSource` validates the quoting enclave:

- Enclave identity type must be `"QE"` (enclave identity version 2 only).
- QE vendor ID must match Intel's UUID (`93 9a 72 33 f7 9c 4c a9 94 0a 0d b3 95 7f 06 07`).
- `mrsigner` must match between evidence and endorsements.
- `isvprodid` must match.
- `miscselect` is compared after applying the endorsement's mask.
- `attributes` are compared byte-by-byte after applying the endorsement's mask.
- QE TCB status is checked: the QE ISVSVN must produce an `"UpToDate"` status from the endorsement's TCB levels.

### 5. Signature Verification

`verifyEnclaveSignatures` verifies two ECDSA-P256 signatures:

- **QE report signature**: The QE report body (SHA-256 hashed) is verified against the PCK leaf certificate's public key using the QE report signature (converted from raw 64-byte r||s to DER format).
- **QE report data**: `SHA-256(attestPubKey || authData)` must match the first 32 bytes of the QE report data; the remaining 32 bytes must be zeros.
- **ISV report signature**: The quote body (SHA-256 hashed) is verified against the attest public key (64-byte uncompressed P-256 point without 0x04 prefix).

### 6. TCB Status Verification

`verifyTCBStatus` determines the TCB standing:

1. Parse the PCK extension from the leaf certificate (OID `1.2.840.113741.1.13.1`) to extract FMSPC (6 bytes), PCEID (2 bytes), 16 component SVNs, and PCESVN.
2. Cross-validate FMSPC and PCEID between the PCK extension and TCB info.
3. Parse TCB levels from the endorsement JSON. Both v2 (individual `sgxtcbcompXXsvn` fields) and v3 (`sgxtcbcomponents` array) formats are supported. Format version consistency is enforced across all levels.
4. Find the first matching TCB level where all 16 PCK component SVNs are >= the level's values and PCESVN >= the level's value.
5. Only `"UpToDate"` and `"SWHardeningNeeded"` statuses are accepted. For `"SWHardeningNeeded"`, all advisory IDs must be in the `acceptableSWAdvisories` list.

### 7. Claims Hash Verification

`verifyClaimsHash` validates that `SHA-256(claimsRawData)` matches the first 32 bytes of the ISV report data. The last 32 bytes must be zeros. All-zero hashes are rejected.

### 8. Debug Mode Rejection

The ISV report body's `sgxAttributes` flags are checked; the `SGX_FLAG_DEBUG` (0x02) bit must not be set.

## CDS2 (Contact Discovery Service v2)

`CDS2NewHandshake` creates a handshake for the Contact Discovery Service:

1. Decode the `ClientHandshakeStart` protobuf (fields: `pubkey=1`, `evidence=2`, `endorsement=3`).
2. Look up acceptable SW advisories for the given MRENCLAVE via `GetSWAdvisories`.
3. Call `ForSGX` with `PostQuantum` handshake type (falls back to pre-quantum since Go's `flynn/noise` does not support HFS patterns).
4. Skip Raft validation (CDS2 does not use Raft).

`CDS2ExtractMetrics` extracts QE report metrics (ISVSVN, ISV Product ID) without performing a full handshake.

## SVR2 (Secure Value Recovery v2)

`SVR2NewHandshake` creates a handshake for SVR2:

1. Decode the `ClientHandshakeStart` protobuf (same structure as CDS2, with field 1 reserved).
2. Look up acceptable SW advisories.
3. Call `ForSGX`.
4. Validate the `RaftConfig` from the attestation claims against the expected config.

`SVR2NewHandshakeWithRaftConfigLookup` uses a built-in lookup table (`expectedRaftConfigSVR2`) to find the Raft config by MRENCLAVE, for bridging code that does not expose environment configuration.

`SVR2LookupGroupID` returns the Raft group ID associated with an MRENCLAVE, if known.

### RaftConfig Validation

```go
type RaftConfig struct {
    MinVotingReplicas  uint32
    MaxVotingReplicas  uint32
    SuperMajority      uint32
    GroupID            uint64
    DBVersion          int32
    AttestationTimeout uint32
    Simulated          bool
}
```

The `Validate` method on `UnvalidatedHandshake` compares each field of the actual `RaftConfig` (from attestation claims) against the expected config. All fields must match exactly.

## Noise NK Handshake

### Cipher Suite

The pre-quantum cipher suite is `Noise_NK_25519_ChaChaPoly_SHA256`:
- DH: Curve25519
- Cipher: ChaChaPoly
- Hash: SHA256

PostQuantum handshake type is defined but returns `PostQuantumUnsupportedError` since Go's `flynn/noise` does not support HFS (Hybrid Forward Secrecy) patterns.

### Handshake Flow

`newHandshakeWithClaims` creates the Noise NK handshake:

1. Configure `noise.HandshakeState` with the verified public key from attestation claims as `PeerStatic`.
2. Write the initial handshake message (empty payload for NK pattern).
3. Return an `UnvalidatedHandshake`.

`Handshake.InitialRequest()` returns the initial message to send to the server.

`Handshake.Complete(initialReceived)` completes the handshake:
1. Read the server's response via `ReadMessage`.
2. Both cipher states (`cs0` for send, `cs1` for receive) must be non-nil.
3. Return a `ClientConnection` with the handshake hash for channel binding.

### Claims Extraction

Claims can be extracted from:
- `ClaimsFromCustomClaims`: extracts `"pk"` for the public key and `"config"` for the Raft config from the custom claims map.
- `ClaimsFromAttestationData`: directly from a public key and Raft config.

## HSM Enclave

`NewHSMClientConnectionEstablishment` creates a connection to an HSM-resident enclave:

1. Accept a trusted public key (32 bytes) and a list of trusted code hashes (32 bytes each).
2. Configure a Noise NK handshake with the trusted public key as `PeerStatic`.
3. Write the initial message with all code hashes concatenated as the payload.

`Complete(initialReceived)` finishes the handshake:
1. Read the server's response; the payload must be exactly 32 bytes (one code hash).
2. Verify the received hash against all trusted code hashes using `crypto/subtle.ConstantTimeCompare`.
3. Return a `ClientConnection`.

## ClientConnection

`ClientConnection` provides encrypted transport over an established Noise session.

```go
type ClientConnection struct {
    HandshakeHash []byte
    sendCipher    *noise.CipherState
    recvCipher    *noise.CipherState
}
```

- `Send(plaintext)`: splits plaintext into chunks of `NoiseTransportPerPayloadMax` (65519 bytes = 65535 - 16 AEAD overhead), encrypts each chunk, and concatenates.
- `Recv(ciphertext)`: splits ciphertext into chunks of `NoiseTransportPerPacketMax` (65535 bytes), decrypts each chunk, and concatenates.

The `HandshakeHash` field provides the channel binding used in SVR restore's Schnorr proof.

## Error Types

The attestation package defines typed errors for each verification step:

| Error Type | Description |
|------------|-------------|
| `AttestationError` | General attestation failure |
| `EnclaveError` | Enclave noise session error (with `EnclaveErrorKind`) |
| `ClientConnectionError` | Noise transport layer error |
| `HSMError` | HSM enclave operation error (with `HSMErrorKind`) |
| `DcapOperationError` | DCAP verification step failure (wraps underlying error) |
| `DcapValidationError` | Specific DCAP validation check failure |
| `CertChainError` | Certificate chain verification failure |
| `CRLVerificationError` | Certificate found on revocation list |
| `CRLSignatureError` | CRL failed signature verification |
| `RootCRLVerificationError` | Root CRL failed verification against Intel root key |
| `FMSPCMismatchError` | FMSPC mismatch between PCK extension and TCB info |
| `PCEIDMismatchError` | PCEID mismatch |
| `TCBStatusUnacceptableError` | TCB status not acceptable (not UpToDate or SWHardeningNeeded) |
| `TCBUnsupportedError` | No matching TCB level in PCK extension |
| `QETCBStatusError` | QE TCB status not UpToDate |
| `EnclaveIdentityTypeError` | Enclave identity type is not QE |
| `EnclaveIdentityVersionError` | Unsupported enclave identity version |
| `PostQuantumUnsupportedError` | PostQuantum Noise not supported in Go |
| `HandshakeIncompleteError` | Noise handshake did not produce cipher states |
