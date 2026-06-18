package ratchet

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
)

func TestNewReceiverParameters(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourOneTimePreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirBaseKey := genKP(t)

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		ourOneTimePreKey,
		ourRatchetKey,
		theirBaseKey.PublicKey(),
		theirIdentity.PublicKey(),
	)

	if params.OurIdentityKeyPair() != ourIdentity {
		t.Fatal("identity key pair mismatch")
	}
	if params.OurSignedPreKey() != ourSignedPreKey {
		t.Fatal("signed pre key mismatch")
	}
	if params.OurOneTimePreKey() != ourOneTimePreKey {
		t.Fatal("one time pre key mismatch")
	}
	if params.OurRatchetKey() != ourRatchetKey {
		t.Fatal("ratchet key mismatch")
	}
	if params.TheirBaseKey() != theirBaseKey.PublicKey() {
		t.Fatal("their base key mismatch")
	}
	if params.TheirIdentityKey() != theirIdentity.PublicKey() {
		t.Fatal("their identity key mismatch")
	}
}

func TestNewEmptyReceiverParameters(t *testing.T) {
	params := NewEmptyReceiverParameters()
	if params == nil {
		t.Fatal("params should not be nil")
	}
	if params.OurIdentityKeyPair() != nil {
		t.Fatal("identity key pair should be nil")
	}
	if params.OurSignedPreKey() != nil {
		t.Fatal("signed pre key should be nil")
	}
	if params.OurOneTimePreKey() != nil {
		t.Fatal("one time pre key should be nil")
	}
	if params.OurRatchetKey() != nil {
		t.Fatal("ratchet key should be nil")
	}
	if params.TheirBaseKey() != nil {
		t.Fatal("their base key should be nil")
	}
	if params.TheirIdentityKey() != nil {
		t.Fatal("their identity key should be nil")
	}
	if params.OurKyberPreKeyPair() != nil {
		t.Fatal("kyber pre key pair should be nil")
	}
	if params.TheirKyberCiphertext() != nil {
		t.Fatal("kyber ciphertext should be nil")
	}
}

func TestReceiverParametersSetters(t *testing.T) {
	params := NewEmptyReceiverParameters()

	ourIdentity := genIDKeyPair(t)
	params.SetOurIdentityKeyPair(ourIdentity)
	if params.OurIdentityKeyPair() != ourIdentity {
		t.Fatal("SetOurIdentityKeyPair failed")
	}

	ourSignedPreKey := genKP(t)
	params.SetOurSignedPreKey(ourSignedPreKey)
	if params.OurSignedPreKey() != ourSignedPreKey {
		t.Fatal("SetOurSignedPreKey failed")
	}

	ourOneTimePreKey := genKP(t)
	params.SetOurOneTimePreKey(ourOneTimePreKey)
	if params.OurOneTimePreKey() != ourOneTimePreKey {
		t.Fatal("SetOurOneTimePreKey failed")
	}

	ourRatchetKey := genKP(t)
	params.SetOurRatchetKey(ourRatchetKey)
	if params.OurRatchetKey() != ourRatchetKey {
		t.Fatal("SetOurRatchetKey failed")
	}

	theirBaseKey := genKP(t)
	params.SetTheirBaseKey(theirBaseKey.PublicKey())
	if params.TheirBaseKey() != theirBaseKey.PublicKey() {
		t.Fatal("SetTheirBaseKey failed")
	}

	theirIdentity := genIDKeyPair(t)
	params.SetTheirIdentityKey(theirIdentity.PublicKey())
	if params.TheirIdentityKey() != theirIdentity.PublicKey() {
		t.Fatal("SetTheirIdentityKey failed")
	}
}

func TestReceiverParametersKyberSetters(t *testing.T) {
	params := NewEmptyReceiverParameters()

	// Test guarded Kyber pre-key pair setter.
	kyberKP := genGuardedKyberKP(t)
	params.SetOurKyberPreKeyPair(kyberKP)
	if params.OurKyberPreKeyPair() != kyberKP {
		t.Fatal("SetOurKyberPreKeyPair failed")
	}

	// Test Kyber ciphertext setter.
	kemImpl := kem.NewKyber1024KEM()
	_, ct, err := kemImpl.Encapsulate(kyberKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	params.SetTheirKyberCiphertext(ct)
	if params.TheirKyberCiphertext() != ct {
		t.Fatal("SetTheirKyberCiphertext failed")
	}
}

func TestReceiverParametersNilOneTimePreKey(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirBaseKey := genKP(t)

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		theirBaseKey.PublicKey(),
		theirIdentity.PublicKey(),
	)

	if params.OurOneTimePreKey() != nil {
		t.Fatal("one time pre key should be nil")
	}
}

// Helper re-exports for tests in this package.
var _ *ecc.ECKeyPair
var _ *identity.KeyPair
