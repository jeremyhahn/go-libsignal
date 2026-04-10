package ecc

// NewECKeyPair returns a new elliptic curve keypair given the specified public and private keys.
func NewECKeyPair(publicKey ECPublicKeyable, privateKey ECPrivateKeyable) *ECKeyPair {
	keypair := ECKeyPair{
		publicKey:  publicKey,
		privateKey: privateKey,
	}

	return &keypair
}

// ECKeyPair is a combination of both public and private elliptic curve keys.
type ECKeyPair struct {
	publicKey  ECPublicKeyable
	privateKey ECPrivateKeyable
}

// PublicKey returns the public key from the key pair.
func (e *ECKeyPair) PublicKey() ECPublicKeyable {
	return e.publicKey
}

// PrivateKey returns the private key from the key pair.
func (e *ECKeyPair) PrivateKey() ECPrivateKeyable {
	return e.privateKey
}

// ZeroizePrivateKey overwrites the private key material with zeros.
// Per the X3DH/PQXDH spec, ephemeral private keys must be deleted
// after the shared secret is calculated.
func (e *ECKeyPair) ZeroizePrivateKey() {
	if e.privateKey == nil {
		return
	}
	switch z := e.privateKey.(type) {
	case *GuardedECPrivateKey:
		z.Zeroize()
	case *DjbECPrivateKey:
		z.Zeroize()
	}
}
