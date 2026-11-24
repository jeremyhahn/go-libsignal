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

// GuardedECPrivateKey stores an EC private key in locked memory and implements ECPrivateKeyable and the keyops interfaces.
type GuardedECPrivateKey struct {
	key *secret.Secret32
}

// NewGuardedECPrivateKey clamps the 32-byte key as Rust does, moves it into guarded memory and zeroizes the source.
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

// Serialize returns a copy of the 32-byte private key; prefer Sign or Agreement.
func (g *GuardedECPrivateKey) Serialize() [32]byte {
	// The caller zeroizes the copy; a destroyed key is rejected rather than returned as zeros.
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

// Sign returns an XEdDSA signature using 64 bytes of randomness from rand.
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

// VRFSign returns a VXEdDSA signature and VRF output using 64 bytes of randomness from rand.
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

// Agreement returns the X25519 shared secret with peer in a guarded Secret32.
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

// PublicKey returns the 32-byte Curve25519 public key of the guarded private key.
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
