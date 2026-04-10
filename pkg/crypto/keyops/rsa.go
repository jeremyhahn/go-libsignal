package keyops

import "crypto"

// RSASigner wraps crypto.Signer for RSA operations used in device transfer
// certificate generation. By embedding crypto.Signer, this interface is
// directly compatible with Go's standard library, PKCS#11 tokens, TPM2
// key handles, and other hardware security modules that implement
// crypto.Signer.
type RSASigner interface {
	crypto.Signer

	// Destroy zeroizes the private key material. This method is idempotent
	// and safe to call multiple times. For hardware-backed keys, this is a
	// no-op since the hardware manages key lifecycle.
	Destroy()
}
