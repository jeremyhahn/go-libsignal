# Device Transfer

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of go-libsignal code owned by this repository.

Package: `devicetransfer/`

Source files: `devicetransfer.go`, `errors.go`

## RSA Key Generation

`CreateRSAPrivateKey` generates an RSA private key and returns it as DER-encoded bytes.

- Default key size: 4096 bits (`DefaultKeyBits`).
- Minimum key size: 2048 bits (`MinKeyBits`). Requests below this return an error.
- If `bits <= 0`, the default (4096) is used.
- Supports two encoding formats: `KeyFormatPKCS8` and `KeyFormatPKCS1`.

### Key Material Zeroization

After generating the key and serializing it, `CreateRSAPrivateKey` zeroizes all RSA private key material:

- Private exponent `D`
- CRT parameters `Dp`, `Dq`, `Qinv`
- All prime factors
- All precomputed CRT values

`zeroizeBigInt` overwrites the backing word slice of each `big.Int` with zeros before calling `SetInt64(0)`. This prevents sensitive data from remaining in freed memory, unlike `SetInt64(0)` alone which merely replaces the value pointer without clearing the old backing array.

The caller is responsible for zeroizing the returned DER bytes when they are no longer needed.

### PEM Output

`CreateRSAPrivateKeyPEM` wraps `CreateRSAPrivateKey` and returns PEM-encoded output. The PEM block type is `"PRIVATE KEY"` for PKCS#8 or `"RSA PRIVATE KEY"` for PKCS#1. The intermediate DER bytes are zeroized after PEM encoding.

### RSASigner

`GenerateRSASigner` generates an RSA key pair and returns it as a `keyops.RSASigner`. If the requested bit size is below `MinKeyBits`, `DefaultKeyBits` (4096) is used. The `RSASigner` interface provides `crypto.Signer` and `Destroy()` for lifecycle management.

## X.509 Self-Signed Certificates

`CreateSelfSignedCert` generates a self-signed X.509 certificate from a DER-encoded RSA private key, a common name, and a validity period in days.

### Certificate Template

The certificate template has these fields:

```go
template := &x509.Certificate{
    SerialNumber: randomSerialNumber,  // 128-bit random
    Subject: pkix.Name{
        CommonName:         name,
        Organization:       []string{"Signal Foundation"},
        OrganizationalUnit: []string{"Device Transfer"},
    },
    NotBefore:          now - 24h,
    NotAfter:           now + validDays,
    SignatureAlgorithm: x509.SHA256WithRSA,
}
```

The template intentionally omits `KeyUsage`, `ExtKeyUsage`, and `BasicConstraintsValid`. This matches the Rust reference implementation, which does not set these fields on device transfer certificates.

### Private Key Parsing

The private key is parsed by trying PKCS#8 first (`x509.ParsePKCS8PrivateKey`), then falling back to PKCS#1 (`x509.ParsePKCS1PrivateKey`). The parsed key is wrapped in an `RSASigner` for signing and the signer is destroyed after use.

### Variants

| Function | Input | Output | Signer Lifecycle |
|----------|-------|--------|------------------|
| `CreateSelfSignedCert` | DER private key bytes | DER certificate | signer created and destroyed internally |
| `CreateSelfSignedCertWithSigner` | `RSASigner` | DER certificate | caller manages signer lifecycle |
| `CreateSelfSignedCertPEM` | PEM private key bytes | PEM certificate | signer created and destroyed internally |

`CreateSelfSignedCertPEM` decodes the PEM block, delegates to `CreateSelfSignedCert`, and re-encodes the result as PEM with block type `"CERTIFICATE"`. The decoded PEM block bytes are zeroized after use.

## Error Types

All errors use typed structs via constructor functions:

| Constructor | Description |
|-------------|-------------|
| `newInvalidKeySizeError` | Key size below minimum |
| `newKeyGenerationError` | RSA key generation failed |
| `newUnsupportedFormatError` | Unknown key format |
| `newKeyParsingError` | Private key parsing failed |
| `newCertCreationError` | Certificate creation failed |
| `Error{kind: errPEMDecode}` | PEM decoding failed |
