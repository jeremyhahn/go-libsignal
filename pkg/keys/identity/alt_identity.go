package identity

import (
	"crypto/rand"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// alternateIdentityPrefix1 is 32 bytes of 0xFF (Rust ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1).
var alternateIdentityPrefix1 = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0xFF
	}
	return b
}()

// alternateIdentityPrefix2 is "Signal_PNI_Signature" (Rust ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2).
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

// SignAlternateIdentity signs the other identity's public key with 64 bytes of randomness (Rust sign_alternate_identity).
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

// VerifyAlternateIdentity verifies a SignAlternateIdentity signature (Rust verify_alternate_identity).
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
