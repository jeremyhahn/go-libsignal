package ecc

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-libsignal/pkg/crypto/keyops"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"golang.org/x/crypto/curve25519"
)

// Compile-time interface assertions.
var (
	_ ECPrivateKeyable    = (*GuardedECPrivateKey)(nil)
	_ keyops.Signer       = (*GuardedECPrivateKey)(nil)
	_ keyops.VRFSigner    = (*GuardedECPrivateKey)(nil)
	_ keyops.KeyAgreement = (*GuardedECPrivateKey)(nil)
	_ keyops.PrivateKey   = (*GuardedECPrivateKey)(nil)
)

// GuardedECPrivateKey stores an EC private key in locked memory.
// It implements ECPrivateKeyable for backward compatibility, and also
// implements keyops.Signer, keyops.VRFSigner, and keyops.KeyAgreement
// for forward-looking key operations that avoid exposing raw key material.
type GuardedECPrivateKey struct {
	key *secret.Secret32
}

// NewGuardedECPrivateKey creates a GuardedECPrivateKey from a 32-byte array
// after applying Curve25519 clamping.  Rust PrivateKey::From<[u8;32]> and
// PrivateKey::deserialize both call scalar::clamp_integer before storing the
// key; this constructor matches that behaviour so that round-trip serialization
// produces byte-for-byte identical output to the Rust reference.
//
// Rust source: rust/core/src/curve/curve25519.rs:170-175; rust/core/src/curve.rs:246-247.
//
// The source array is zeroized after the data is moved into guarded memory.
func NewGuardedECPrivateKey(data [32]byte) (k *GuardedECPrivateKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			k = nil
			err = &ErrGuardedKeyAllocation{Operation: "guarded key allocation", Err: fmt.Errorf("%v", r)}
		}
	}()
	clampCurve25519(&data)
	s, sErr := secret.NewSecret32(data)
	if sErr != nil {
		return nil, &ErrGuardedKeyAllocation{Operation: "guarded key allocation", Err: sErr}
	}
	return &GuardedECPrivateKey{key: s}, nil
}

// NewGuardedECPrivateKeyFromSecret creates a GuardedECPrivateKey by taking
// ownership of an existing Secret32. The caller must not use the Secret32
// after this call.
func NewGuardedECPrivateKeyFromSecret(s *secret.Secret32) *GuardedECPrivateKey {
	return &GuardedECPrivateKey{key: s}
}

// Serialize returns a copy of the 32-byte private key material.
// Callers should prefer using Sign or Agreement operations instead
// of extracting raw key bytes.
//
// Implements ECPrivateKeyable.
func (g *GuardedECPrivateKey) Serialize() [32]byte {
	// The array is the value that leaves the borrow: it is copied inside it,
	// and the caller zeroizes it after use.
	//
	// A destroyed (or missing) key is rejected: Serialize has no error
	// return, and handing back zeros would let a caller sign or agree with
	// an all-zero scalar. The generic consumers in this package check
	// IsDestroyed first and return ErrGuardedKeyDestroyed instead.
	var out [32]byte
	if err := g.key.WithBytes(func(b []byte) error {
		if len(b) != len(out) {
			return ErrGuardedKeyDestroyed
		}
		copy(out[:], b)
		return nil
	}); err != nil {
		panic(ErrGuardedKeyDestroyed)
	}
	return out
}

// privateKeyArray returns the serialized private key of key, rejecting a
// nil key and a destroyed guarded key with an error rather than letting
// the caller run on zero key material. The caller zeroizes the result.
func privateKeyArray(key ECPrivateKeyable) ([32]byte, error) {
	if key == nil {
		return [32]byte{}, ErrNilPrivateKey
	}
	if d, ok := key.(interface{ IsDestroyed() bool }); ok && d.IsDestroyed() {
		return [32]byte{}, ErrGuardedKeyDestroyed
	}
	return key.Serialize(), nil
}

// Type returns the EC key type identifier (DjbType = 0x05).
//
// Implements ECPrivateKeyable.
func (g *GuardedECPrivateKey) Type() int {
	return DjbType
}

// Zeroize destroys the guarded memory holding the private key.
// This method is idempotent and safe to call multiple times.
func (g *GuardedECPrivateKey) Zeroize() {
	if g.key != nil {
		g.key.Destroy()
	}
}

// Destroy is an alias for Zeroize, matching the keyops interface convention.
func (g *GuardedECPrivateKey) Destroy() {
	g.Zeroize()
}

// IsDestroyed reports whether the guarded key has been destroyed.
func (g *GuardedECPrivateKey) IsDestroyed() bool {
	return g == nil || g.key == nil || g.key.IsDestroyed()
}

// Sign performs XEdDSA signing over the message using the guarded private key.
// The rand parameter provides 64 bytes of randomness needed for XEdDSA.
//
// Implements keyops.Signer.
func (g *GuardedECPrivateKey) Sign(rand io.Reader, message []byte) ([64]byte, error) {
	if g.IsDestroyed() {
		return [64]byte{}, ErrGuardedKeyDestroyed
	}

	var random [64]byte
	defer crypto.Zeroize(random[:])
	_, err := io.ReadFull(rand, random[:])
	if err != nil {
		return [64]byte{}, &ErrReadingRandomness{Operation: "signing", Err: err}
	}

	var signature *[64]byte
	if err := g.key.WithArray(func(privateKey *[32]byte) error {
		signature = sign(privateKey, message, random)
		return nil
	}); err != nil {
		return [64]byte{}, ErrGuardedKeyDestroyed
	}
	if signature == nil {
		return [64]byte{}, ErrSignFailed
	}
	return *signature, nil
}

// VRFSign produces a VXEdDSA signature and VRF output for the given message.
// The rand parameter provides 64 bytes of randomness for the signature.
//
// Implements keyops.VRFSigner.
func (g *GuardedECPrivateKey) VRFSign(rand io.Reader, message []byte) ([]byte, []byte, error) {
	if g.IsDestroyed() {
		return nil, nil, ErrGuardedKeyDestroyed
	}

	var random [64]byte
	defer crypto.Zeroize(random[:])
	_, err := io.ReadFull(rand, random[:])
	if err != nil {
		return nil, nil, &ErrReadingRandomness{Operation: "VRF signing", Err: err}
	}

	var sig *[96]byte
	var vrf []byte
	var signErr error
	if err := g.key.WithArray(func(privateKey *[32]byte) error {
		sig, vrf, signErr = vxeddsaSign(privateKey, message, random)
		return nil
	}); err != nil {
		return nil, nil, ErrGuardedKeyDestroyed
	}
	if signErr != nil {
		return nil, nil, signErr
	}
	return sig[:], vrf, nil
}

// Agreement performs X25519 Diffie-Hellman key agreement with the peer's
// public key. Returns the 32-byte shared secret in a guarded Secret32.
//
// Implements keyops.KeyAgreement.
func (g *GuardedECPrivateKey) Agreement(peerPublic [32]byte) (ss *secret.Secret32, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss = nil
			err = &ErrGuardedKeyAllocation{Operation: "agreement allocation", Err: fmt.Errorf("%v", r)}
		}
	}()

	if g.IsDestroyed() {
		return nil, ErrGuardedKeyDestroyed
	}

	var result []byte
	var dhErr error
	if err := g.key.WithBytes(func(privateBytes []byte) error {
		result, dhErr = curve25519.X25519(privateBytes, peerPublic[:])
		return nil
	}); err != nil {
		return nil, ErrGuardedKeyDestroyed
	}
	if dhErr != nil {
		return nil, &ErrX25519Agreement{Err: dhErr}
	}

	// Reject all-zero shared secrets in constant time. An all-zero result
	// indicates a low-order peer public key, which would compromise security.
	var allZero [32]byte
	if subtle.ConstantTimeCompare(result, allZero[:]) == 1 {
		crypto.Zeroize(result)
		return nil, ErrInvalidKeyAgreement
	}

	shared, allocErr := secret.NewSecret32FromSlice(result)
	if allocErr != nil {
		// Zeroize the result slice on allocation failure.
		crypto.Zeroize(result)
		return nil, &ErrAllocatingSharedSecret{Err: allocErr}
	}
	return shared, nil
}

// PublicKey derives and returns the corresponding Curve25519 public key
// (32 bytes) from the guarded private key.
//
// Implements keyops.Signer and keyops.KeyAgreement.
func (g *GuardedECPrivateKey) PublicKey() [32]byte {
	if g.IsDestroyed() {
		return [32]byte{}
	}
	var public [32]byte
	if err := g.key.WithArray(func(privateKey *[32]byte) error {
		curve25519.ScalarBaseMult(&public, privateKey)
		return nil
	}); err != nil {
		return [32]byte{}
	}
	return public
}

// Clone creates an independent deep copy of the guarded private key in
// new guarded memory.
func (g *GuardedECPrivateKey) Clone() (k *GuardedECPrivateKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			k = nil
			err = &ErrGuardedKeyClone{Err: fmt.Errorf("%v", r)}
		}
	}()

	if g.IsDestroyed() {
		return nil, ErrGuardedKeyDestroyed
	}

	cloned, cloneErr := g.key.Clone()
	if cloneErr != nil {
		return nil, &ErrGuardedKeyClone{Err: cloneErr}
	}
	return &GuardedECPrivateKey{key: cloned}, nil
}

// Secret32 returns the underlying Secret32 for direct access to guarded
// memory operations. The caller must not destroy the returned Secret32
// unless they are finished with the GuardedECPrivateKey.
func (g *GuardedECPrivateKey) Secret32() *secret.Secret32 {
	return g.key
}
