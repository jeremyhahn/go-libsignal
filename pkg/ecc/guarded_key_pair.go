package ecc

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-libsignal/pkg/crypto/keyops"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"golang.org/x/crypto/curve25519"
)

// GuardedECKeyPair holds an EC public key and a locked-memory-protected private key.
// It provides the same interface as ECKeyPair but with the private key stored
// in mlock'd, guard-page protected memory.
//
// Note: GuardedECKeyPair does not directly implement keyops.PrivateKey because
// its PublicKey() method returns ECPublicKeyable (for backward compatibility)
// which conflicts with keyops.PrivateKey's PublicKey() [32]byte. Use
// GuardedPrivateKey() to access the keyops.PrivateKey interface.
type GuardedECKeyPair struct {
	publicKey  ECPublicKeyable
	privateKey *GuardedECPrivateKey
}

// NewGuardedECKeyPair creates a GuardedECKeyPair from an existing public key
// and guarded private key.
func NewGuardedECKeyPair(pub ECPublicKeyable, priv *GuardedECPrivateKey) *GuardedECKeyPair {
	return &GuardedECKeyPair{
		publicKey:  pub,
		privateKey: priv,
	}
}

// PublicKey returns the public key from the key pair.
func (g *GuardedECKeyPair) PublicKey() ECPublicKeyable {
	return g.publicKey
}

// PrivateKey returns the guarded private key as an ECPrivateKeyable.
// The returned value implements ECPrivateKeyable for backward compatibility.
func (g *GuardedECKeyPair) PrivateKey() ECPrivateKeyable {
	return g.privateKey
}

// GuardedPrivateKey returns direct access to the GuardedECPrivateKey,
// which implements keyops.Signer, keyops.VRFSigner, keyops.KeyAgreement,
// and keyops.PrivateKey for forward-looking key operations.
func (g *GuardedECKeyPair) GuardedPrivateKey() *GuardedECPrivateKey {
	return g.privateKey
}

// KeyOps returns the guarded private key as a keyops.PrivateKey, providing
// access to signing and key agreement operations without exposing raw key
// material.
func (g *GuardedECKeyPair) KeyOps() keyops.PrivateKey {
	return g.privateKey
}

// ZeroizePrivateKey destroys the guarded private key memory.
// This method is idempotent and safe to call multiple times.
func (g *GuardedECKeyPair) ZeroizePrivateKey() {
	if g.privateKey != nil {
		g.privateKey.Zeroize()
	}
}

// GenerateGuardedKeyPair generates a random Curve25519 key pair with the
// private key stored in locked memory.
//
// Uses the same clamping logic as GenerateKeyPair:
//
//	private[0] &= 248
//	private[31] &= 127
//	private[31] |= 64
func GenerateGuardedKeyPair() (kp *GuardedECKeyPair, err error) {
	defer func() {
		if r := recover(); r != nil {
			kp = nil
			err = &ErrGuardedKeyAllocation{Operation: "guarded key pair generation", Err: fmt.Errorf("%v", r)}
		}
	}()

	// Generate 32 bytes of random data for the private key.
	var private [32]byte
	_, readErr := io.ReadFull(rand.Reader, private[:])
	if readErr != nil {
		return nil, &ErrGeneratingKeyMaterial{Err: readErr}
	}

	// Apply Curve25519 clamping (same as Curve.go:GenerateKeyPair).
	// http://cr.yp.to/ecdh.html
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	// Derive the public key before moving private key into guarded memory.
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)

	// Move the private key into guarded memory (zeroizes the source array).
	guardedPriv, allocErr := secret.NewSecret32(private)
	if allocErr != nil {
		crypto.Zeroize(private[:])
		return nil, &ErrGuardedKeyAllocation{Operation: "guarded key pair generation", Err: allocErr}
	}

	pub := NewDjbECPublicKey(public)
	priv := NewGuardedECPrivateKeyFromSecret(guardedPriv)

	return NewGuardedECKeyPair(pub, priv), nil
}
