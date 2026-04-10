# Network Transport

Package: `net/`

Source files: `auth.go`, `certs.go`, `enclave.go`, `svrb.go`, `errors.go`

## Authentication

### Auth Credentials

The `Auth` struct holds a username/password pair for Signal service authentication:

```go
type Auth struct {
    Username string  // hex(uid)
    Password string  // "timestamp:hex(otp)"
}
```

`AuthFromUIDAndSecret` creates an `Auth` from a 16-byte UID and a 32-byte shared secret. The password is a time-based OTP:

1. The username is hex-encoded from the UID.
2. `computeOTP` computes HMAC-SHA256 over `"username:unix_timestamp"` keyed by the shared secret.
3. The hex-encoded digest is truncated to 20 characters.
4. The password is formatted as `"timestamp:truncated_hex"`.

The secret copy is zeroized after HMAC computation to prevent the material from remaining on the stack.

`Auth.SetAuthHeader` sets the HTTP `Authorization` header for basic authentication. `Auth.BasicAuthHeader` returns the header value directly.

## Certificate Pinning

### Certificate Types

```go
const (
    RootCertificatesNative  // system certificate store
    RootCertificatesSignal  // Signal's pinned root certificates
    RootCertificatesProxyG  // Google proxy root certificates (GIAG2 + pki.goog)
)
```

### CertificatePinner Interface

```go
type CertificatePinner interface {
    PinCertificates(certs RootCertificates) *tls.Config
}
```

For `RootCertificatesNative`, implementations return `nil` to use the system root store. For Signal and proxy types, they return a `tls.Config` with a pinned `RootCAs` pool and `MinVersion: tls.VersionTLS12`.

### DefaultCertificatePinner (Fail-Closed)

`DefaultCertificatePinner` deliberately fails closed for Signal and proxy certificate types. For `RootCertificatesSignal` and `RootCertificatesProxyG`, it returns a `tls.Config` with an empty certificate pool, causing all TLS handshakes to fail.

This is intentional: it prevents silent fallback to system roots when no pinned certificates are configured. The default rejects connections rather than allowing unverified ones.

For production use, callers must replace this with a `StaticCertificatePinner` or custom implementation.

### StaticCertificatePinner (Production)

`StaticCertificatePinner` uses caller-provided DER-encoded root certificates:

```go
type StaticCertificatePinner struct {
    SignalCerts [][]byte  // DER certs for Signal services
    ProxyCerts  [][]byte  // DER certs for Google proxy connections
}
```

The Rust reference (`libsignal/rust/net/src/certs.rs`) embeds these certificates at compile time:
- Signal: `signal.cer`
- Proxy G: `GIAG2.cer`, `GSR2.cer`, `GSR4.cer`, `GTSR1.cer`, `GTSR2.cer`, `GTSR3.cer`, `GTSR4.cer`

Go callers should embed the same DER files using `go:embed`:

```go
//go:embed res/signal.cer
var signalRootCert []byte

pinner := &net.StaticCertificatePinner{
    SignalCerts: [][]byte{signalRootCert},
    ProxyCerts:  [][]byte{giag2, gsr2, gsr4, gtsr1, gtsr2, gtsr3, gtsr4},
}
```

If `NewCertPoolFromDER` fails to parse the provided certificates, `StaticCertificatePinner` also fails closed by returning a config with an empty pool.

### NewCertPoolFromDER

`NewCertPoolFromDER` creates an `x509.CertPool` from one or more DER-encoded certificates. Returns `CertPinError` with `CertPinErrorNoCertificates` if no certs are provided, or `CertPinErrorParseFailed` if any DER certificate cannot be parsed.

## Enclave Connection Management

### Enclave Types

```go
const (
    EnclaveKindCDSI   // Contact Discovery Service
    EnclaveKindSvrSgx // Secure Value Recovery SGX enclave
)
```

`EnclaveKind.URLPath` returns the WebSocket endpoint path:
- CDSI: `/v1/<mrenclave_hex>/discovery`
- SVR SGX: `/v1/<mrenclave_hex>`

### Endpoint Configuration

```go
type EnclaveEndpoint struct {
    DomainConfig DomainConfig      // connection configuration
    WSConfig     WSConfig          // WebSocket settings
    Params       EndpointParams    // attestation parameters
}

type EndpointParams struct {
    MrEnclave  MrEnclave           // expected MRENCLAVE measurement
    RaftConfig *attest.RaftConfig  // Raft config for SVR (nil for CDSI)
}
```

### Handshake Dispatch

The `NewHandshaker` interface dispatches to the appropriate attestation handshake:

- `CDSIHandshaker`: calls `attest.CDS2NewHandshake`, skips Raft validation.
- `SvrSgxHandshaker`: calls `attest.SVR2NewHandshake`, requires a non-nil `RaftConfig`.

Both pass `time.Now()` as the current time for validity checks.

## SVR Backend (SVRB)

The SVRB layer connects the `svr` package's cryptographic operations to actual network transports. It manages parallel connections to multiple SVR enclave backends.

### Transport Interface

```go
type SvrBTransport interface {
    SendBytes(ctx context.Context, data []byte) error
    ReceiveBytes(ctx context.Context) ([]byte, error)
    HandshakeHash() []byte
    Close() error
}
```

Implementations encrypt outgoing data through the Noise session before sending over the wire, and decrypt received wire bytes through the Noise session. `HandshakeHash` returns the Noise handshake hash for channel binding in Schnorr proofs during restore.

### SVRB Client

`SvrBNetClient` implements the full `SvrBClient` interface:

```go
type SvrBClient interface {
    SvrBPreparer   // Prepare(password, maxTries) -> OPRFBackup4
    SvrBBackuper   // Finalize(ctx, backup) -> error
    SvrBRestorer   // Restore(ctx, password) -> *secret.Secret
    SvrBQuerier    // Query(ctx) -> tries remaining
    SvrBRemover    // Remove(ctx) -> error
}
```

Connection management:
- `connectAll` calls the `SvrBConnector` to establish attested connections.
- `sendAll` sends one request per transport in parallel using goroutines and collects responses.
- `closeTransports` closes all transports, ignoring errors.

`BackupConnectionDelay` (50ms) is the recommended stagger between initiating parallel connections to avoid a thundering herd.

### Backup Flow

1. `Prepare` creates `svr.OPRFBackup4` with OPRF secret shares.
2. `Finalize` connects to all servers, sends each request, and calls `svr.FinalizeBackup4` on the responses.

### Restore Flow

1. Connect to all servers.
2. Phase 1: `svr.NewRestore1` creates blinded points, send to each server.
3. Collect handshake hashes from each transport for channel binding.
4. Phase 2: `Restore1.Restore2` processes Phase 1 responses and creates Schnorr proofs, send to each server.
5. `Restore2Result.Restore` XORs encryption shares and derives the final key.

### Error Prioritization

SVRB errors use a priority system. When multiple errors occur across servers, the highest-priority error is reported:

| Priority | Error Kind | Description |
|----------|------------|-------------|
| 12 | `PreviousBackupDataInvalid` | Structural error |
| 11 | `MetadataInvalid` | Structural error |
| 10 | `Decryption` | Data error |
| 9 | `Attestation` | Connection error |
| 8 | `Protocol` | Connection error |
| 7 | `RateLimited` | Connection error (includes `RetryAfter` duration) |
| 6 | `Service` | Network error |
| 5 | `Connect` | Connection error |
| 4 | `AllConnectionAttemptsFailed` | Connection error |
| 3 | `RestoreFailed` | Content error (includes `TriesRemaining`) |
| 2 | `DataMissing` | Content error |

`SvrBError.Is` matches by `Kind`, allowing `errors.Is` patterns.
