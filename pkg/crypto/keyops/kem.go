package keyops

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// Decapsulator abstracts KEM secret key operations, typically backed by
// Kyber-1024 in the Signal protocol. Software implementations hold the
// secret key in locked memory. Hardware implementations
// delegate decapsulation to the secure element.
type Decapsulator interface {
	// Decapsulate recovers the shared secret from the given ciphertext
	// using the secret key. Returns the shared secret in a guarded Secret32.
	// The caller is responsible for destroying the returned secret.
	Decapsulate(ciphertext []byte) (*secret.Secret32, error)

	// Destroy zeroizes the secret key material. This method is idempotent
	// and safe to call multiple times. For hardware-backed keys, this is a
	// no-op since the hardware manages key lifecycle.
	Destroy()
}

// Encapsulator abstracts KEM public key operations. Encapsulation generates
// a fresh shared secret and the corresponding ciphertext that only the
// holder of the matching secret key can decapsulate.
type Encapsulator interface {
	// Encapsulate generates a shared secret and ciphertext for the public key.
	// Returns the shared secret (guarded) and the ciphertext. The caller is
	// responsible for destroying the returned secret.
	Encapsulate() (*secret.Secret32, []byte, error)
}
