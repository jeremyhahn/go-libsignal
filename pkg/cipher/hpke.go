// Package cipher provides symmetric encryption primitives used by the Signal
// protocol. This file implements Hybrid Public Key Encryption (HPKE) using
// X25519 + HKDF-SHA256 + AES-256-GCM in Base mode, matching the Rust
// libsignal implementation.
//
// The implementation follows RFC 9180 and uses the cloudflare/circl library
// for the HPKE primitives.
//
// The wire format prepends a type byte to the ciphertext:
//
//	[type_byte | encapsulated_key | AEAD_ciphertext]
//
// Currently only one ciphertext type is defined:
//
//	0x01 = Base_X25519_HkdfSha256_Aes256Gcm
package cipher

import (
	"crypto/rand"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// hpkeCiphertextType identifies the HPKE suite used for a ciphertext.
type hpkeCiphertextType uint8

const (
	// hpkeBaseX25519HkdfSha256Aes256Gcm is the only ciphertext type
	// currently supported, matching the Rust libsignal implementation.
	hpkeBaseX25519HkdfSha256Aes256Gcm hpkeCiphertextType = 0x01
)

// x25519EncapsulatedKeySize is the size of an X25519 encapsulated key (32 bytes).
const x25519EncapsulatedKeySize = 32

// HPKE sentinel errors for use with errors.Is matching.
var (
	// ErrHPKEInvalidPublicKey indicates the recipient public key is invalid.
	ErrHPKEInvalidPublicKey = &ErrHPKE{kind: hpkeErrInvalidPublicKey}

	// ErrHPKEInvalidPrivateKey indicates the recipient private key is invalid.
	ErrHPKEInvalidPrivateKey = &ErrHPKE{kind: hpkeErrInvalidPrivateKey}

	// ErrHPKESealFailed indicates the HPKE seal operation failed.
	ErrHPKESealFailed = &ErrHPKE{kind: hpkeErrSealFailed}

	// ErrHPKEOpenFailed indicates the HPKE open (unseal) operation failed.
	ErrHPKEOpenFailed = &ErrHPKE{kind: hpkeErrOpenFailed}

	// ErrHPKEInvalidCiphertext indicates the ciphertext is too short or malformed.
	ErrHPKEInvalidCiphertext = &ErrHPKE{kind: hpkeErrInvalidCiphertext}

	// ErrHPKEUnknownType indicates an unrecognized ciphertext type byte.
	ErrHPKEUnknownType = &ErrHPKE{kind: hpkeErrUnknownType}

	// ErrHPKEReceiverZeroized indicates the receiver's key material has been
	// destroyed and it can no longer perform decryption.
	ErrHPKEReceiverZeroized = &ErrHPKE{kind: hpkeErrReceiverZeroized}
)

// hpkeErrKind identifies the specific HPKE error type.
type hpkeErrKind int

const (
	hpkeErrInvalidPublicKey  hpkeErrKind = iota + 1
	hpkeErrInvalidPrivateKey
	hpkeErrSealFailed
	hpkeErrOpenFailed
	hpkeErrInvalidCiphertext
	hpkeErrUnknownType
	hpkeErrReceiverZeroized
)

// ErrHPKE is a typed error for HPKE operations.
type ErrHPKE struct {
	kind hpkeErrKind
}

func (e *ErrHPKE) Error() string {
	switch e.kind {
	case hpkeErrInvalidPublicKey:
		return "hpke: invalid recipient public key"
	case hpkeErrInvalidPrivateKey:
		return "hpke: invalid recipient private key"
	case hpkeErrSealFailed:
		return "hpke: seal failed"
	case hpkeErrOpenFailed:
		return "hpke: open failed"
	case hpkeErrInvalidCiphertext:
		return "hpke: invalid ciphertext"
	case hpkeErrUnknownType:
		return "hpke: unknown ciphertext type"
	case hpkeErrReceiverZeroized:
		return "hpke: receiver has been zeroized"
	default:
		return "hpke: unknown error"
	}
}

// Is implements errors.Is matching by kind.
func (e *ErrHPKE) Is(target error) bool {
	t, ok := target.(*ErrHPKE)
	if !ok {
		return false
	}
	return e.kind == t.kind
}

// HPKESender defines the interface for HPKE encryption.
type HPKESender interface {
	// Seal encrypts plaintext for the recipient, returning the complete
	// ciphertext including the type byte and encapsulated key prefix.
	Seal(info, aad, plaintext []byte) ([]byte, error)
}

// HPKEReceiver defines the interface for HPKE decryption.
type HPKEReceiver interface {
	// Open decrypts a ciphertext produced by Seal, parsing the type byte
	// and encapsulated key from the prefix.
	Open(info, aad, ciphertext []byte) ([]byte, error)

	// Zeroize overwrites private key material held by the receiver. After
	// calling Zeroize, subsequent Open calls will fail.
	Zeroize()
}

// hpkeSender holds a parsed recipient public key for sealing.
type hpkeSender struct {
	publicKey kem.PublicKey
}

// hpkeReceiver holds a parsed recipient private key for opening.
// Call Zeroize when the receiver is no longer needed to clear private key
// material from memory.
type hpkeReceiver struct {
	privateKey    kem.PrivateKey
	privKeyBytes  []byte
}

// newSuite returns the HPKE suite matching the Rust libsignal configuration:
// X25519 + HKDF-SHA256 + AES-256-GCM.
func newSuite() hpke.Suite {
	return hpke.NewSuite(
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES256GCM,
	)
}

// kemScheme returns the KEM scheme for X25519.
func kemScheme() kem.Scheme {
	return hpke.KEM_X25519_HKDF_SHA256.Scheme()
}

// NewHPKESender creates an HPKESender for the given recipient public key.
// The recipientPub must be a 32-byte X25519 public key.
func NewHPKESender(recipientPub []byte) (HPKESender, error) {
	scheme := kemScheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		return nil, ErrHPKEInvalidPublicKey
	}
	return &hpkeSender{publicKey: pk}, nil
}

// Seal encrypts plaintext for the recipient using HPKE Base mode.
//
// The returned ciphertext has the format:
//
//	[0x01 | enc (32 bytes) | AEAD_ciphertext]
//
// where enc is the encapsulated key and AEAD_ciphertext is the AES-256-GCM
// encrypted plaintext with authentication tag.
func (s *hpkeSender) Seal(info, aad, plaintext []byte) ([]byte, error) {
	suite := newSuite()
	sender, err := suite.NewSender(s.publicKey, info)
	if err != nil {
		return nil, ErrHPKESealFailed
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, ErrHPKESealFailed
	}

	ct, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, ErrHPKESealFailed
	}

	// Build the wire format: type_byte + enc + ciphertext.
	result := make([]byte, 0, 1+len(enc)+len(ct))
	result = append(result, byte(hpkeBaseX25519HkdfSha256Aes256Gcm))
	result = append(result, enc...)
	result = append(result, ct...)

	return result, nil
}

// NewHPKEReceiver creates an HPKEReceiver for the given recipient private key.
// The recipientPriv must be a 32-byte X25519 private key. The input bytes are
// copied; the caller remains responsible for zeroizing the original slice.
// Call Zeroize on the returned receiver when it is no longer needed.
func NewHPKEReceiver(recipientPriv []byte) (HPKEReceiver, error) {
	scheme := kemScheme()

	// Copy the private key bytes so we own the memory for zeroization.
	privCopy := make([]byte, len(recipientPriv))
	copy(privCopy, recipientPriv)

	sk, err := scheme.UnmarshalBinaryPrivateKey(privCopy)
	if err != nil {
		crypto.Zeroize(privCopy)
		return nil, ErrHPKEInvalidPrivateKey
	}
	return &hpkeReceiver{privateKey: sk, privKeyBytes: privCopy}, nil
}

// Open decrypts a ciphertext produced by Seal using HPKE Base mode.
//
// It parses the type byte and encapsulated key from the ciphertext prefix,
// then decrypts using AES-256-GCM.
func (r *hpkeReceiver) Open(info, aad, ciphertext []byte) ([]byte, error) {
	if r.privateKey == nil {
		return nil, ErrHPKEReceiverZeroized
	}

	// Need at least type byte + encapsulated key + AES-256-GCM tag (16 bytes).
	const aes256GCMTagSize = 16
	if len(ciphertext) < 1+x25519EncapsulatedKeySize+aes256GCMTagSize {
		return nil, ErrHPKEInvalidCiphertext
	}

	typeByte := hpkeCiphertextType(ciphertext[0])
	if typeByte != hpkeBaseX25519HkdfSha256Aes256Gcm {
		return nil, ErrHPKEUnknownType
	}

	enc := ciphertext[1 : 1+x25519EncapsulatedKeySize]
	ct := ciphertext[1+x25519EncapsulatedKeySize:]

	suite := newSuite()
	receiver, err := suite.NewReceiver(r.privateKey, info)
	if err != nil {
		return nil, ErrHPKEOpenFailed
	}

	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, ErrHPKEOpenFailed
	}

	plaintext, err := opener.Open(ct, aad)
	if err != nil {
		return nil, ErrHPKEOpenFailed
	}

	return plaintext, nil
}

// Zeroize overwrites the stored private key material with zeros. After calling
// Zeroize, any subsequent Open calls will fail. This method is idempotent.
//
// Note: The circl library's kem.PrivateKey may retain an internal copy of
// the key material that we cannot zeroize from outside the library. We clear
// our own copy (privKeyBytes) and nil out the reference, but the circl object
// itself may still hold key bytes in memory until garbage collected. This is a
// known limitation of the circl HPKE implementation.
func (r *hpkeReceiver) Zeroize() {
	if r.privKeyBytes != nil {
		crypto.Zeroize(r.privKeyBytes)
		r.privKeyBytes = nil
	}
	r.privateKey = nil
}

// HPKESeal is a convenience function that encrypts plaintext for a recipient
// public key using HPKE (X25519 + HKDF-SHA256 + AES-256-GCM) in Base mode.
//
// The recipientPub must be a 32-byte X25519 public key.
//
// Returns the encapsulated key (enc) and the AEAD ciphertext separately.
// To produce the wire format used by Signal (with type byte prefix), use
// NewHPKESender instead.
func HPKESeal(recipientPub []byte, info, aad, plaintext []byte) (enc, ciphertext []byte, err error) {
	scheme := kemScheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		return nil, nil, ErrHPKEInvalidPublicKey
	}

	suite := newSuite()
	sender, err := suite.NewSender(pk, info)
	if err != nil {
		return nil, nil, ErrHPKESealFailed
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, ErrHPKESealFailed
	}

	ct, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, ErrHPKESealFailed
	}

	return enc, ct, nil
}

// HPKEOpen is a convenience function that decrypts ciphertext using HPKE
// (X25519 + HKDF-SHA256 + AES-256-GCM) in Base mode.
//
// The recipientPriv must be a 32-byte X25519 private key. The enc parameter
// is the encapsulated key returned by HPKESeal. The caller is responsible for
// zeroizing recipientPriv when it is no longer needed.
func HPKEOpen(recipientPriv, enc []byte, info, aad, ciphertext []byte) ([]byte, error) {
	// Make a local copy for parsing; zeroize it when done regardless of outcome.
	privCopy := make([]byte, len(recipientPriv))
	copy(privCopy, recipientPriv)
	defer crypto.Zeroize(privCopy)

	scheme := kemScheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(privCopy)
	if err != nil {
		return nil, ErrHPKEInvalidPrivateKey
	}

	suite := newSuite()
	receiver, err := suite.NewReceiver(sk, info)
	if err != nil {
		return nil, ErrHPKEOpenFailed
	}

	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, ErrHPKEOpenFailed
	}

	plaintext, err := opener.Open(ciphertext, aad)
	if err != nil {
		return nil, ErrHPKEOpenFailed
	}

	return plaintext, nil
}

// HPKEGenerateKeyPair generates a new X25519 key pair for use with HPKE.
// Returns the private key (32 bytes) and public key (32 bytes).
//
// The caller is responsible for zeroizing the returned privateKey slice
// (e.g., via crypto.Zeroize) when it is no longer needed.
//
// Note: the circl kem.PrivateKey object produced internally during key
// generation cannot be zeroized externally. Callers must zeroize the
// returned privateKey slice to clear their copy of the key material.
// The internal circl object will persist in memory until garbage collected.
// This is a known limitation of the circl HPKE implementation; see also
// the Zeroize method on hpkeReceiver for the same constraint.
func HPKEGenerateKeyPair() (privateKey, publicKey []byte, err error) {
	scheme := kemScheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		crypto.Zeroize(skBytes)
		return nil, nil, err
	}

	return skBytes, pkBytes, nil
}
