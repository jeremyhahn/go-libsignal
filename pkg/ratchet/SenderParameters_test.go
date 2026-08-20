//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 3 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the Double Ratchet specification (section 5.2, DH ratchet) requires
// it, so the fips140only build tag drops this file from the FIPS gate. `make
// test` and `make coverage` still run it.

package ratchet

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
)

func TestNewSenderParameters(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourBaseKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirSignedPreKey := genKP(t)
	theirRatchetKey := genKP(t)
	theirOneTimePreKey := genKP(t)

	params := NewSenderParameters(
		ourIdentity,
		ourBaseKey,
		theirIdentity.PublicKey(),
		theirSignedPreKey.PublicKey(),
		theirRatchetKey.PublicKey(),
		theirOneTimePreKey.PublicKey(),
	)

	if params.OurIdentityKey() != ourIdentity {
		t.Fatal("identity key mismatch")
	}
	if params.OurBaseKey() != ourBaseKey {
		t.Fatal("base key mismatch")
	}
	if params.TheirIdentityKey() != theirIdentity.PublicKey() {
		t.Fatal("their identity key mismatch")
	}
	if params.TheirSignedPreKey() != theirSignedPreKey.PublicKey() {
		t.Fatal("their signed pre key mismatch")
	}
	if params.TheirRatchetKey() != theirRatchetKey.PublicKey() {
		t.Fatal("their ratchet key mismatch")
	}
	if params.TheirOneTimePreKey() != theirOneTimePreKey.PublicKey() {
		t.Fatal("their one time pre key mismatch")
	}
	if params.TheirKyberPreKey() != nil {
		t.Fatal("kyber pre key should be nil")
	}
}

func TestNewEmptySenderParameters(t *testing.T) {
	params := NewEmptySenderParameters()
	if params == nil {
		t.Fatal("params should not be nil")
	}
	if params.OurIdentityKey() != nil {
		t.Fatal("identity key should be nil")
	}
	if params.OurBaseKey() != nil {
		t.Fatal("base key should be nil")
	}
	if params.TheirIdentityKey() != nil {
		t.Fatal("their identity key should be nil")
	}
	if params.TheirSignedPreKey() != nil {
		t.Fatal("their signed pre key should be nil")
	}
	if params.TheirRatchetKey() != nil {
		t.Fatal("their ratchet key should be nil")
	}
	if params.TheirOneTimePreKey() != nil {
		t.Fatal("their one time pre key should be nil")
	}
	if params.TheirKyberPreKey() != nil {
		t.Fatal("kyber pre key should be nil")
	}
}

func TestSenderParametersSetters(t *testing.T) {
	params := NewEmptySenderParameters()

	ourIdentity := genIDKeyPair(t)
	params.SetOurIdentityKey(ourIdentity)
	if params.OurIdentityKey() != ourIdentity {
		t.Fatal("SetOurIdentityKey failed")
	}

	ourBaseKey := genKP(t)
	params.SetOurBaseKey(ourBaseKey)
	if params.OurBaseKey() != ourBaseKey {
		t.Fatal("SetOurBaseKey failed")
	}

	theirIdentity := genIDKeyPair(t)
	params.SetTheirIdentityKey(theirIdentity.PublicKey())
	if params.TheirIdentityKey() != theirIdentity.PublicKey() {
		t.Fatal("SetTheirIdentityKey failed")
	}

	theirSignedPreKey := genKP(t)
	params.SetTheirSignedPreKey(theirSignedPreKey.PublicKey())
	if params.TheirSignedPreKey() != theirSignedPreKey.PublicKey() {
		t.Fatal("SetTheirSignedPreKey failed")
	}

	theirOneTimePreKey := genKP(t)
	params.SetTheirOneTimePreKey(theirOneTimePreKey.PublicKey())
	if params.TheirOneTimePreKey() != theirOneTimePreKey.PublicKey() {
		t.Fatal("SetTheirOneTimePreKey failed")
	}

	theirRatchetKey := genKP(t)
	params.SetTheirRatchetKey(theirRatchetKey.PublicKey())
	if params.TheirRatchetKey() != theirRatchetKey.PublicKey() {
		t.Fatal("SetTheirRatchetKey failed")
	}
}

func TestSenderParametersKyberSetter(t *testing.T) {
	params := NewEmptySenderParameters()

	kemImpl := kem.NewKyber1024KEM()
	kyberKP, err := kemImpl.Generate()
	if err != nil {
		t.Fatal(err)
	}

	params.SetTheirKyberPreKey(kyberKP.Public)
	if params.TheirKyberPreKey() != kyberKP.Public {
		t.Fatal("SetTheirKyberPreKey failed")
	}
}

func TestSenderParametersNilOneTimePreKey(t *testing.T) {
	params := NewSenderParameters(
		genIDKeyPair(t),
		genKP(t),
		genIDKeyPair(t).PublicKey(),
		genKP(t).PublicKey(),
		genKP(t).PublicKey(),
		nil,
	)

	if params.TheirOneTimePreKey() != nil {
		t.Fatal("one time pre key should be nil")
	}
}
