package prekey

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

func makeTestBundle(t *testing.T) *Bundle {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	signedKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	identityKey := identity.NewKey(kp.PublicKey())
	preKeyID := optional.NewOptionalUint32(1)
	var sig [64]byte
	sig[0] = 0xAA

	return NewBundle(
		100, 1,
		preKeyID, 2,
		kp.PublicKey(), signedKP.PublicKey(),
		sig, identityKey,
	)
}

func TestNewBundle_AllFields(t *testing.T) {
	bundle := makeTestBundle(t)

	if bundle.RegistrationID() != 100 {
		t.Fatalf("expected registrationID 100, got %d", bundle.RegistrationID())
	}
	if bundle.DeviceID() != 1 {
		t.Fatalf("expected deviceID 1, got %d", bundle.DeviceID())
	}
	if bundle.PreKeyID() == nil || bundle.PreKeyID().Value != 1 {
		t.Fatal("PreKeyID mismatch")
	}
	if bundle.SignedPreKeyID() != 2 {
		t.Fatalf("expected signedPreKeyID 2, got %d", bundle.SignedPreKeyID())
	}
	if bundle.PreKey() == nil {
		t.Fatal("PreKey should not be nil")
	}
	if bundle.SignedPreKey() == nil {
		t.Fatal("SignedPreKey should not be nil")
	}
	sig := bundle.SignedPreKeySignature()
	if sig[0] != 0xAA {
		t.Fatalf("expected signature first byte 0xAA, got 0x%02x", sig[0])
	}
	if bundle.IdentityKey() == nil {
		t.Fatal("IdentityKey should not be nil")
	}
}

func TestNewBundle_NilPreKeyID(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	identityKey := identity.NewKey(kp.PublicKey())
	bundle := NewBundle(1, 1, nil, 1, kp.PublicKey(), kp.PublicKey(), [64]byte{}, identityKey)
	if bundle.PreKeyID() != nil {
		t.Fatal("expected nil PreKeyID")
	}
}

func TestNewBundle_KyberFieldsNilByDefault(t *testing.T) {
	bundle := makeTestBundle(t)
	if bundle.KyberPreKeyID() != nil {
		t.Fatal("expected nil KyberPreKeyID for non-Kyber bundle")
	}
	if bundle.KyberPreKey() != nil {
		t.Fatal("expected nil KyberPreKey for non-Kyber bundle")
	}
	if bundle.KyberPreKeySignature() != nil {
		t.Fatal("expected nil KyberPreKeySignature for non-Kyber bundle")
	}
}

func TestNewBundleWithKyber(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	identityKey := identity.NewKey(kp.PublicKey())
	kyberPreKeyID := optional.NewOptionalUint32(42)
	kyberSig := []byte("kyber-sig")

	bundle := NewBundleWithKyber(
		200, 2,
		optional.NewOptionalUint32(5), 10,
		kp.PublicKey(), kp.PublicKey(),
		[64]byte{}, identityKey,
		kyberPreKeyID, nil, kyberSig,
	)

	if bundle.RegistrationID() != 200 {
		t.Fatalf("expected registrationID 200, got %d", bundle.RegistrationID())
	}
	if bundle.KyberPreKeyID() == nil || bundle.KyberPreKeyID().Value != 42 {
		t.Fatal("KyberPreKeyID mismatch")
	}
	if bundle.KyberPreKey() != nil {
		t.Fatal("expected nil KyberPreKey when not provided")
	}
	if string(bundle.KyberPreKeySignature()) != "kyber-sig" {
		t.Fatal("KyberPreKeySignature mismatch")
	}
}

func TestNewBundleWithKyber_NilKyberFields(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	identityKey := identity.NewKey(kp.PublicKey())

	bundle := NewBundleWithKyber(
		1, 1,
		nil, 1,
		kp.PublicKey(), kp.PublicKey(),
		[64]byte{}, identityKey,
		nil, nil, nil,
	)

	if bundle.KyberPreKeyID() != nil {
		t.Fatal("expected nil KyberPreKeyID")
	}
	if bundle.KyberPreKeySignature() != nil {
		t.Fatal("expected nil KyberPreKeySignature")
	}
}
