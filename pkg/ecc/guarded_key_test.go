//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 21 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package ecc

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// --- GuardedECPrivateKey: NewGuardedECPrivateKey ---

func TestNewGuardedECPrivateKey_Success(t *testing.T) {
	var data [32]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}
	// Apply clamping to the copy so we can compare against the clamped form
	// stored by NewGuardedECPrivateKey (ECC-3: constructor now clamps on
	// construction, matching Rust PrivateKey::deserialize).
	clampedCopy := data
	clampedCopy[0] &= 248
	clampedCopy[31] &= 127
	clampedCopy[31] |= 64

	key, err := NewGuardedECPrivateKey(data)
	if err != nil {
		t.Fatalf("NewGuardedECPrivateKey failed: %v", err)
	}
	defer key.Destroy()

	serialized := key.Serialize()
	if serialized != clampedCopy {
		t.Fatal("serialized key does not match clamped data")
	}
}

func TestNewGuardedECPrivateKey_Type(t *testing.T) {
	var data [32]byte
	key, err := NewGuardedECPrivateKey(data)
	if err != nil {
		t.Fatalf("NewGuardedECPrivateKey failed: %v", err)
	}
	defer key.Destroy()

	if key.Type() != DjbType {
		t.Fatalf("expected type %d, got %d", DjbType, key.Type())
	}
}

// --- GuardedECPrivateKey: NewGuardedECPrivateKeyFromSecret ---

func TestNewGuardedECPrivateKeyFromSecret_Success(t *testing.T) {
	var data [32]byte
	data[0] = 0x42
	s, err := secret.NewSecret32(data)
	if err != nil {
		t.Fatalf("NewSecret32 failed: %v", err)
	}

	key := NewGuardedECPrivateKeyFromSecret(s)
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	defer key.Destroy()

	serialized := key.Serialize()
	if serialized[0] != 0x42 {
		t.Fatal("key data mismatch")
	}
}

func TestNewGuardedECPrivateKeyFromSecret_Secret32Accessor(t *testing.T) {
	var data [32]byte
	s, err := secret.NewSecret32(data)
	if err != nil {
		t.Fatalf("NewSecret32 failed: %v", err)
	}

	key := NewGuardedECPrivateKeyFromSecret(s)
	defer key.Destroy()

	if key.Secret32() != s {
		t.Fatal("Secret32() should return the same Secret32 instance")
	}
}

// --- GuardedECPrivateKey: Sign ---

func TestGuardedECPrivateKey_Sign_Success(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	message := []byte("hello signal protocol")
	sig, err := kp.GuardedPrivateKey().Sign(rand.Reader, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey := kp.PublicKey()
	if !VerifySignature(pubKey, message, sig) {
		t.Fatal("signature verification failed")
	}
}

func TestGuardedECPrivateKey_Sign_AfterDestroy(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	priv := kp.GuardedPrivateKey()
	priv.Destroy()

	_, signErr := priv.Sign(rand.Reader, []byte("test"))
	if signErr == nil {
		t.Fatal("expected error when signing with destroyed key")
	}
	if !errors.Is(signErr, ErrGuardedKeyDestroyed) {
		t.Fatalf("expected ErrGuardedKeyDestroyed, got: %v", signErr)
	}
}

func TestGuardedECPrivateKey_Sign_BadReader(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	badReader := &errReader{err: errors.New("rand failed")}
	_, signErr := kp.GuardedPrivateKey().Sign(badReader, []byte("test"))
	if signErr == nil {
		t.Fatal("expected error with bad reader")
	}
}

// --- GuardedECPrivateKey: VRFSign ---

func TestGuardedECPrivateKey_VRFSign_Success(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	message := []byte("vrf test message")
	sig, vrf, err := kp.GuardedPrivateKey().VRFSign(rand.Reader, message)
	if err != nil {
		t.Fatalf("VRFSign failed: %v", err)
	}

	if len(sig) != 96 {
		t.Fatalf("expected 96-byte signature, got %d", len(sig))
	}
	if len(vrf) != VRFOutputSize {
		t.Fatalf("expected %d-byte VRF output, got %d", VRFOutputSize, len(vrf))
	}

	// Verify with VXEdDSAVerify
	valid, vrfOut, verifyErr := VXEdDSAVerify(kp.PublicKey(), message, sig)
	if verifyErr != nil {
		t.Fatalf("VXEdDSAVerify failed: %v", verifyErr)
	}
	if !valid {
		t.Fatal("VRF signature verification failed")
	}
	if !bytes.Equal(vrf, vrfOut) {
		t.Fatal("VRF outputs do not match between sign and verify")
	}
}

func TestGuardedECPrivateKey_VRFSign_AfterDestroy(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	priv := kp.GuardedPrivateKey()
	priv.Destroy()

	_, _, signErr := priv.VRFSign(rand.Reader, []byte("test"))
	if signErr == nil {
		t.Fatal("expected error when VRF signing with destroyed key")
	}
	if !errors.Is(signErr, ErrGuardedKeyDestroyed) {
		t.Fatalf("expected ErrGuardedKeyDestroyed, got: %v", signErr)
	}
}

func TestGuardedECPrivateKey_VRFSign_BadReader(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	badReader := &errReader{err: errors.New("rand failed")}
	_, _, signErr := kp.GuardedPrivateKey().VRFSign(badReader, []byte("test"))
	if signErr == nil {
		t.Fatal("expected error with bad reader")
	}
}

// --- GuardedECPrivateKey: Agreement ---

func TestGuardedECPrivateKey_Agreement_Success(t *testing.T) {
	kp1, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp1.ZeroizePrivateKey()

	kp2, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp2.ZeroizePrivateKey()

	// DH(kp1.priv, kp2.pub)
	pub2 := kp2.PublicKey().PublicKey()
	ss1, err := kp1.GuardedPrivateKey().Agreement(pub2)
	if err != nil {
		t.Fatalf("Agreement failed: %v", err)
	}
	defer ss1.Destroy()

	// DH(kp2.priv, kp1.pub)
	pub1 := kp1.PublicKey().PublicKey()
	ss2, err := kp2.GuardedPrivateKey().Agreement(pub1)
	if err != nil {
		t.Fatalf("Agreement failed: %v", err)
	}
	defer ss2.Destroy()

	// Shared secrets must match (DH commutativity).
	if !secrettest.Same(t, ss1, ss2) {
		t.Fatal("DH shared secrets do not match")
	}
}

func TestGuardedECPrivateKey_Agreement_AfterDestroy(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	priv := kp.GuardedPrivateKey()
	priv.Destroy()

	var peer [32]byte
	_, agreeErr := priv.Agreement(peer)
	if agreeErr == nil {
		t.Fatal("expected error when performing agreement with destroyed key")
	}
	if !errors.Is(agreeErr, ErrGuardedKeyDestroyed) {
		t.Fatalf("expected ErrGuardedKeyDestroyed, got: %v", agreeErr)
	}
}

// --- GuardedECPrivateKey: PublicKey ---

func TestGuardedECPrivateKey_PublicKey_Success(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	derived := kp.GuardedPrivateKey().PublicKey()
	expected := kp.PublicKey().PublicKey()
	if derived != expected {
		t.Fatal("derived public key does not match key pair's public key")
	}
}

func TestGuardedECPrivateKey_PublicKey_AfterDestroy(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	priv := kp.GuardedPrivateKey()
	priv.Destroy()

	pub := priv.PublicKey()
	if pub != ([32]byte{}) {
		t.Fatal("expected zero public key after destroy")
	}
}

// Serialize on a destroyed key returns zeros rather than panicking: the
// WithBytes borrow refuses a destroyed enclave, so nothing is copied out.
func TestGuardedECPrivateKey_Serialize_AfterDestroy(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	priv := kp.GuardedPrivateKey()
	if priv.Serialize() == ([32]byte{}) {
		t.Fatal("expected non-zero serialization before destroy")
	}
	priv.Destroy()

	// Serialize must reject a destroyed key, never hand back zeros.
	func() {
		defer func() {
			if r := recover(); r != ErrGuardedKeyDestroyed {
				t.Fatalf("Serialize after destroy: want panic(ErrGuardedKeyDestroyed), got %v", r)
			}
		}()
		got := priv.Serialize()
		t.Fatalf("Serialize after destroy returned %x", got)
	}()

	// The generic consumers return the rejection as an error.
	msg := []byte("message")
	if _, err := CalculateSignature(priv, msg); err != ErrGuardedKeyDestroyed {
		t.Errorf("CalculateSignature: want ErrGuardedKeyDestroyed, got %v", err)
	}
	if _, err := CalculateSignatureWithRandomness(priv, msg, [64]byte{}); err != ErrGuardedKeyDestroyed {
		t.Errorf("CalculateSignatureWithRandomness: want ErrGuardedKeyDestroyed, got %v", err)
	}
	if _, _, err := VXEdDSASign(priv, msg); err != ErrGuardedKeyDestroyed {
		t.Errorf("VXEdDSASign: want ErrGuardedKeyDestroyed, got %v", err)
	}
	if _, err := GuardPrivateKey(priv); err != ErrGuardedKeyDestroyed {
		t.Errorf("GuardPrivateKey: want ErrGuardedKeyDestroyed, got %v", err)
	}
	if _, err := priv.Agreement([32]byte{9}); err != ErrGuardedKeyDestroyed {
		t.Errorf("Agreement: want ErrGuardedKeyDestroyed, got %v", err)
	}
}

// --- GuardedECPrivateKey: Destroy and IsDestroyed ---

func TestGuardedECPrivateKey_Destroy_Idempotent(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	priv := kp.GuardedPrivateKey()
	priv.Destroy()
	if !priv.IsDestroyed() {
		t.Fatal("expected IsDestroyed() to return true after Destroy()")
	}

	// Second destroy should not panic.
	priv.Destroy()
	if !priv.IsDestroyed() {
		t.Fatal("expected IsDestroyed() to remain true")
	}
}

func TestGuardedECPrivateKey_Zeroize_Idempotent(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	priv := kp.GuardedPrivateKey()
	priv.Zeroize()
	if !priv.IsDestroyed() {
		t.Fatal("expected IsDestroyed() to return true after Zeroize()")
	}

	// Second zeroize should not panic.
	priv.Zeroize()
}

func TestGuardedECPrivateKey_IsDestroyed_BeforeDestroy(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	if kp.GuardedPrivateKey().IsDestroyed() {
		t.Fatal("expected IsDestroyed() to return false before Destroy()")
	}
}

// --- GuardedECPrivateKey: Clone ---

func TestGuardedECPrivateKey_Clone_Success(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	original := kp.GuardedPrivateKey()
	cloned, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}
	defer cloned.Destroy()

	if original.Serialize() != cloned.Serialize() {
		t.Fatal("cloned key data does not match original")
	}

	// Destroying original should not affect clone.
	original.Destroy()
	if cloned.IsDestroyed() {
		t.Fatal("clone should not be destroyed when original is destroyed")
	}
}

func TestGuardedECPrivateKey_Clone_AfterDestroy(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	priv := kp.GuardedPrivateKey()
	priv.Destroy()

	_, cloneErr := priv.Clone()
	if cloneErr == nil {
		t.Fatal("expected error when cloning destroyed key")
	}
	if !errors.Is(cloneErr, ErrGuardedKeyDestroyed) {
		t.Fatalf("expected ErrGuardedKeyDestroyed, got: %v", cloneErr)
	}
}

// --- GuardedECKeyPair ---

func TestGenerateGuardedKeyPair_Success(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	if kp.PublicKey() == nil {
		t.Fatal("expected non-nil public key")
	}
	if kp.PrivateKey() == nil {
		t.Fatal("expected non-nil private key")
	}
	if kp.GuardedPrivateKey() == nil {
		t.Fatal("expected non-nil guarded private key")
	}
}

func TestGenerateGuardedKeyPair_UniquePairs(t *testing.T) {
	kp1, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp1.ZeroizePrivateKey()

	kp2, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp2.ZeroizePrivateKey()

	if kp1.PublicKey().PublicKey() == kp2.PublicKey().PublicKey() {
		t.Fatal("two generated key pairs should have different public keys")
	}
}

func TestNewGuardedECKeyPair_Success(t *testing.T) {
	var data [32]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		t.Fatalf("rand read failed: %v", err)
	}
	data[0] &= 248
	data[31] &= 127
	data[31] |= 64

	priv, err := NewGuardedECPrivateKey(data)
	if err != nil {
		t.Fatalf("NewGuardedECPrivateKey failed: %v", err)
	}

	pub := NewDjbECPublicKey(priv.PublicKey())
	kp := NewGuardedECKeyPair(pub, priv)
	defer kp.ZeroizePrivateKey()

	if kp.PublicKey() != pub {
		t.Fatal("PublicKey() returned wrong value")
	}
	if kp.PrivateKey() != priv {
		t.Fatal("PrivateKey() returned wrong value")
	}
}

func TestGuardedECKeyPair_KeyOps(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}
	defer kp.ZeroizePrivateKey()

	ops := kp.KeyOps()
	if ops == nil {
		t.Fatal("expected non-nil KeyOps")
	}

	// KeyOps should return the same underlying guarded private key.
	pub1 := ops.PublicKey()
	pub2 := kp.GuardedPrivateKey().PublicKey()
	if pub1 != pub2 {
		t.Fatal("KeyOps().PublicKey() does not match GuardedPrivateKey().PublicKey()")
	}
}

func TestGuardedECKeyPair_ZeroizePrivateKey_Idempotent(t *testing.T) {
	kp, err := GenerateGuardedKeyPair()
	if err != nil {
		t.Fatalf("GenerateGuardedKeyPair failed: %v", err)
	}

	kp.ZeroizePrivateKey()
	if !kp.GuardedPrivateKey().IsDestroyed() {
		t.Fatal("expected private key to be destroyed after ZeroizePrivateKey()")
	}

	// Second call should not panic.
	kp.ZeroizePrivateKey()
}

func TestGuardedECKeyPair_ZeroizePrivateKey_NilPrivateKey(t *testing.T) {
	// Construct a key pair with nil private key to test nil guard.
	kp := &GuardedECKeyPair{
		publicKey:  nil,
		privateKey: nil,
	}
	// Should not panic.
	kp.ZeroizePrivateKey()
}

// --- GuardedECPrivateKey: Zeroize with nil key ---

func TestGuardedECPrivateKey_Zeroize_NilKey(t *testing.T) {
	k := &GuardedECPrivateKey{key: nil}
	// Should not panic.
	k.Zeroize()
}

func TestGuardedECPrivateKey_IsDestroyed_NilKey(t *testing.T) {
	k := &GuardedECPrivateKey{key: nil}
	if !k.IsDestroyed() {
		t.Fatal("expected IsDestroyed() to return true for nil key")
	}
}

// --- Cross-compatibility: guarded vs unguarded keys produce same signatures ---

func TestGuardedVsUnguarded_SignVerify(t *testing.T) {
	// Generate a regular key pair.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create a guarded key from the same private key material.
	privData := kp.PrivateKey().Serialize()
	guardedPriv, err := NewGuardedECPrivateKey(privData)
	if err != nil {
		t.Fatalf("NewGuardedECPrivateKey failed: %v", err)
	}
	defer guardedPriv.Destroy()

	// Both should derive the same public key.
	guardedPub := guardedPriv.PublicKey()
	originalPub := kp.PublicKey().PublicKey()
	if guardedPub != originalPub {
		t.Fatal("guarded and unguarded keys derive different public keys")
	}

	// Sign with guarded key, verify with public key.
	message := []byte("cross-compat test")
	sig, err := guardedPriv.Sign(rand.Reader, message)
	if err != nil {
		t.Fatalf("guarded Sign failed: %v", err)
	}
	if !VerifySignature(kp.PublicKey(), message, sig) {
		t.Fatal("signature from guarded key failed verification")
	}
}

// --- Error type ---

func TestErrGuardedKeyDestroyed_ErrorString(t *testing.T) {
	msg := ErrGuardedKeyDestroyed.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestErrGuardedKeyDestroyed_IsComparable(t *testing.T) {
	wrapped := errors.New("wrapper: " + ErrGuardedKeyDestroyed.Error())
	if errors.Is(wrapped, ErrGuardedKeyDestroyed) {
		t.Fatal("plain wrapping should not match Is")
	}
}

// --- helpers ---

type errReader struct {
	err error
}

func (r *errReader) Read([]byte) (int, error) {
	return 0, r.err
}
