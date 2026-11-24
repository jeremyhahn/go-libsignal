package keyops

import "io"

// Signer abstracts EC private key signing operations.
// Software implementations use locked-memory-backed keys and perform XEdDSA
// signing in protected memory. Hardware implementations delegate to
// crypto.Signer, HSM, or secure enclave APIs without exposing raw key
// material.
type Signer interface {
	// Sign performs XEdDSA signing over the message.
	// The rand parameter provides randomness (64 bytes needed for XEdDSA).
	// Returns a 64-byte signature or an error.
	Sign(rand io.Reader, message []byte) ([64]byte, error)

	// PublicKey returns the corresponding EC public key (32 bytes for Curve25519).
	PublicKey() [32]byte

	// Destroy zeroizes the private key material. This method is idempotent
	// and safe to call multiple times. For hardware-backed keys, this is a
	// no-op since the hardware manages key lifecycle.
	Destroy()
}

// VRFSigner extends Signer with VXEdDSA support for verifiable random
// functions. VRF signatures provide a deterministic, verifiable output
// bound to the signer's private key, used in key transparency proofs.
type VRFSigner interface {
	Signer

	// VRFSign produces a VXEdDSA signature and VRF output for the given message.
	// The rand parameter provides randomness for the signature.
	// Returns the signature, the VRF output, or an error.
	VRFSign(rand io.Reader, message []byte) (signature []byte, vrfOutput []byte, err error)
}
