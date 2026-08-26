// Package keyops defines operation-based interfaces for cryptographic key
// operations used throughout the Signal Protocol. These interfaces abstract
// over the underlying key storage and execution mechanism, enabling both
// software-backed implementations (using locked memory) and
// hardware-backed implementations (using HSM, TPM, or secure enclave APIs).
//
// The interfaces are organized by operation type:
//
//   - [Signer] and [VRFSigner] for XEdDSA and VXEdDSA signing operations
//   - [KeyAgreement] for X25519 Diffie-Hellman key agreement
//   - [PrivateKey] combining signing and key agreement for Curve25519 keys
//   - [Decapsulator] and [Encapsulator] for KEM (Kyber-1024) operations
//   - [RSASigner] for RSA signing (device transfer certificates)
//
// Design principles:
//
//   - Interfaces expose only operations, never raw key material
//   - Hardware implementations never export private keys
//   - Shared secrets are returned as guarded [secret.Secret32] values
//   - Destroy is always idempotent and safe to call on hardware keys (no-op)
//   - Interfaces are minimal and composable
package keyops
