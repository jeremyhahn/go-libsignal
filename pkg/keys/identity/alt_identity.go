package identity

import (
	"crypto/rand"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// alternateIdentityPrefix1 is the first domain-separation prefix for
// alternate-identity signatures: 32 bytes of 0xFF.
// Mirrors Rust ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1 in
// rust/protocol/src/identity_key.rs.
var alternateIdentityPrefix1 = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0xFF
	}
	return b
}()

// alternateIdentityPrefix2 is the second domain-separation prefix:
// the ASCII bytes of "Signal_PNI_Signature".
// Mirrors Rust ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2 in
// rust/protocol/src/identity_key.rs.
var alternateIdentityPrefix2 = []byte("Signal_PNI_Signature")

// buildAltIdentityMessage constructs the message to sign/verify for alternate-identity
// operations: prefix1 || prefix2 || other.Serialize().
// other.Serialize() returns [0x05][32 raw key bytes] = 33 bytes.
func buildAltIdentityMessage(other *Key) []byte {
	otherBytes := other.Serialize()
	msg := make([]byte, 0, len(alternateIdentityPrefix1)+len(alternateIdentityPrefix2)+len(otherBytes))
	msg = append(msg, alternateIdentityPrefix1...)
	msg = append(msg, alternateIdentityPrefix2...)
	msg = append(msg, otherBytes...)
	return msg
}

// SignAlternateIdentity signs the other identity's serialized public key with
// this keypair using the Signal_PNI_Signature DST. Mirrors Rust
// IdentityKeyPair::sign_alternate_identity (rust/protocol/src/identity_key.rs:138).
//
// randomness must be 64 bytes of cryptographically secure random data.
// Use SignAlternateIdentityRandom for automatic randomness.
func (kp *KeyPair) SignAlternateIdentity(other *Key, randomness [64]byte) ([]byte, error) {
	if other == nil {
		return nil, ErrNilOtherKey
	}
	msg := buildAltIdentityMessage(other)
	sig, err := ecc.CalculateSignatureWithRandomness(kp.privateKey, msg, randomness)
	if err != nil {
		return nil, &ErrAltIdentitySignOperation{Err: err}
	}
	return sig[:], nil
}

// SignAlternateIdentityRandom is a convenience wrapper that reads randomness
// from crypto/rand automatically.
func (kp *KeyPair) SignAlternateIdentityRandom(other *Key) ([]byte, error) {
	var randomness [64]byte
	if _, err := rand.Read(randomness[:]); err != nil {
		return nil, &ErrReadingAltIdentityRandomness{Err: err}
	}
	return kp.SignAlternateIdentity(other, randomness)
}

// VerifyAlternateIdentity verifies a signature produced by SignAlternateIdentity.
// Returns nil on a valid signature, a typed error on any mismatch.
// Mirrors Rust IdentityKey::verify_alternate_identity
// (rust/protocol/src/identity_key.rs:60).
func (k *Key) VerifyAlternateIdentity(other *Key, signature []byte) error {
	if other == nil {
		return ErrNilOtherKey
	}
	if len(signature) != 64 {
		return &ErrAltIdentityInvalidSignatureLength{Got: len(signature)}
	}
	var sig [64]byte
	copy(sig[:], signature)
	msg := buildAltIdentityMessage(other)
	if !ecc.VerifySignature(k.publicKey, msg, sig) {
		return ErrAltIdentityVerificationFailed
	}
	return nil
}
