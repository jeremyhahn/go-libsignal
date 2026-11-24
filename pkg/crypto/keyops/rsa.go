package keyops

import "crypto"

// RSASigner is a crypto.Signer for device transfer certificates, so PKCS#11, TPM2 and HSM signers fit.
type RSASigner interface {
	crypto.Signer

	// Destroy zeroizes the private key material. This method is idempotent
	// and safe to call multiple times. For hardware-backed keys, this is a
	// no-op since the hardware manages key lifecycle.
	Destroy()
}
