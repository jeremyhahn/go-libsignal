package kem

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

func TestNewGuardedSecretKey(t *testing.T) {
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}

	gsk, err := NewGuardedSecretKey(KeyTypeKyber1024, data)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}
	defer gsk.Destroy()

	if gsk.Type() != KeyTypeKyber1024 {
		t.Errorf("Type() = 0x%02x, want 0x%02x", gsk.Type(), KeyTypeKyber1024)
	}

	keyData := gsk.Data()
	if len(keyData) != 64 {
		t.Errorf("Data() length = %d, want 64", len(keyData))
	}

	if gsk.IsDestroyed() {
		t.Error("key should not be destroyed after creation")
	}
}

func TestNewGuardedSecretKeyNilInput(t *testing.T) {
	_, err := NewGuardedSecretKey(KeyTypeKyber1024, nil)
	if err == nil {
		t.Fatal("NewGuardedSecretKey(nil) should return error")
	}
}

func TestNewGuardedSecretKeyFromSecret(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i + 1)
	}

	s, err := secret.New(data)
	if err != nil {
		t.Fatalf("secret.New() error: %v", err)
	}

	gsk := NewGuardedSecretKeyFromSecret(KeyTypeKyber1024, s)
	defer gsk.Destroy()

	if gsk.Type() != KeyTypeKyber1024 {
		t.Errorf("Type() = 0x%02x, want 0x%02x", gsk.Type(), KeyTypeKyber1024)
	}

	if gsk.IsDestroyed() {
		t.Error("key should not be destroyed after creation")
	}
}

func TestGuardedSecretKeyDestroy(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	gsk, err := NewGuardedSecretKey(KeyTypeKyber1024, data)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}

	gsk.Destroy()

	if !gsk.IsDestroyed() {
		t.Error("key should be destroyed after Destroy()")
	}

	// Destroy should be idempotent.
	gsk.Destroy()
	if !gsk.IsDestroyed() {
		t.Error("key should remain destroyed after second Destroy()")
	}
}

func TestGuardedSecretKeyDestroyNilKey(t *testing.T) {
	gsk := &GuardedSecretKey{keyType: KeyTypeKyber1024, key: nil}
	// Should not panic.
	gsk.Destroy()

	if !gsk.IsDestroyed() {
		t.Error("key with nil inner should report as destroyed")
	}
}

func TestGuardedSecretKeyClone(t *testing.T) {
	data := make([]byte, 48)
	for i := range data {
		data[i] = byte(i * 2)
	}

	original, err := NewGuardedSecretKey(KeyTypeKyber1024, data)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}
	defer original.Destroy()

	cloned, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone() error: %v", err)
	}
	defer cloned.Destroy()

	if cloned.Type() != original.Type() {
		t.Error("cloned key type should match original")
	}

	if !bytes.Equal(cloned.Data(), original.Data()) {
		t.Error("cloned key data should match original")
	}

	// Destroying the clone should not affect the original.
	cloned.Destroy()
	if original.IsDestroyed() {
		t.Error("original should not be destroyed after cloned is destroyed")
	}
}

func TestGuardedSecretKeyCloneDestroyed(t *testing.T) {
	data := make([]byte, 32)
	gsk, err := NewGuardedSecretKey(KeyTypeKyber1024, data)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}
	gsk.Destroy()

	_, err = gsk.Clone()
	if err == nil {
		t.Fatal("Clone() on destroyed key should return error")
	}
	var destroyed *GuardedKeyDestroyedError
	if !errors.As(err, &destroyed) {
		t.Errorf("Clone() error should wrap GuardedKeyDestroyedError, got: %v", err)
	}
}

func TestGuardedSecretKeyIsDestroyedNilInner(t *testing.T) {
	gsk := &GuardedSecretKey{keyType: KeyTypeKyber1024, key: nil}
	if !gsk.IsDestroyed() {
		t.Error("key with nil inner should report as destroyed")
	}
}

func TestNewGuardedSharedSecret(t *testing.T) {
	var data [32]byte
	for i := range data {
		data[i] = byte(i + 10)
	}

	gss, err := NewGuardedSharedSecret(data)
	if err != nil {
		t.Fatalf("NewGuardedSharedSecret() error: %v", err)
	}
	defer gss.Destroy()

	result := gss.Bytes()
	if len(result) != 32 {
		t.Errorf("Bytes() length = %d, want 32", len(result))
	}

	if gss.IsDestroyed() {
		t.Error("shared secret should not be destroyed after creation")
	}
}

func TestNewGuardedSharedSecretArray(t *testing.T) {
	var data [32]byte
	for i := range data {
		data[i] = byte(i + 5)
	}

	gss, err := NewGuardedSharedSecret(data)
	if err != nil {
		t.Fatalf("NewGuardedSharedSecret() error: %v", err)
	}
	defer gss.Destroy()

	arr := gss.Array()
	if arr == ([32]byte{}) {
		t.Error("Array() returned all-zero value for non-zero input")
	}
}

func TestNewGuardedSharedSecretFromSlice(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i + 20)
	}

	gss, err := NewGuardedSharedSecretFromSlice(data)
	if err != nil {
		t.Fatalf("NewGuardedSharedSecretFromSlice() error: %v", err)
	}
	defer gss.Destroy()

	result := gss.Bytes()
	if len(result) != 32 {
		t.Errorf("Bytes() length = %d, want 32", len(result))
	}
}

func TestNewGuardedSharedSecretFromSliceWrongSize(t *testing.T) {
	data := make([]byte, 16)
	_, err := NewGuardedSharedSecretFromSlice(data)
	if err == nil {
		t.Fatal("NewGuardedSharedSecretFromSlice() with wrong size should return error")
	}
}

func TestNewGuardedSharedSecretFromSliceNil(t *testing.T) {
	_, err := NewGuardedSharedSecretFromSlice(nil)
	if err == nil {
		t.Fatal("NewGuardedSharedSecretFromSlice(nil) should return error")
	}
}

func TestNewGuardedSharedSecretFromSecret32(t *testing.T) {
	var data [32]byte
	for i := range data {
		data[i] = byte(i)
	}

	s32, err := secret.NewSecret32(data)
	if err != nil {
		t.Fatalf("NewSecret32() error: %v", err)
	}

	gss := NewGuardedSharedSecretFromSecret32(s32)
	defer gss.Destroy()

	if gss.IsDestroyed() {
		t.Error("shared secret should not be destroyed after creation")
	}

	if gss.Secret32() != s32 {
		t.Error("Secret32() should return the same underlying Secret32")
	}
}

func TestGuardedSharedSecretDestroy(t *testing.T) {
	var data [32]byte
	for i := range data {
		data[i] = byte(i)
	}

	gss, err := NewGuardedSharedSecret(data)
	if err != nil {
		t.Fatalf("NewGuardedSharedSecret() error: %v", err)
	}

	gss.Destroy()

	if !gss.IsDestroyed() {
		t.Error("shared secret should be destroyed after Destroy()")
	}

	// Idempotent.
	gss.Destroy()
	if !gss.IsDestroyed() {
		t.Error("shared secret should remain destroyed after second Destroy()")
	}
}

func TestGuardedSharedSecretDestroyNilInner(t *testing.T) {
	gss := &GuardedSharedSecret{inner: nil}
	// Should not panic.
	gss.Destroy()

	if !gss.IsDestroyed() {
		t.Error("shared secret with nil inner should report as destroyed")
	}
}

func TestGuardedSharedSecretIsDestroyedNilInner(t *testing.T) {
	gss := &GuardedSharedSecret{inner: nil}
	if !gss.IsDestroyed() {
		t.Error("shared secret with nil inner should report as destroyed")
	}
}

func TestGuardedKeyPairDestroy(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	gsk, err := NewGuardedSecretKey(KeyTypeKyber1024, data)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}

	pk := NewPublicKey(KeyTypeKyber1024, []byte{1, 2, 3})
	gkp := &GuardedKeyPair{Public: pk, Secret: gsk}

	gkp.Destroy()

	if !gkp.Secret.IsDestroyed() {
		t.Error("secret key should be destroyed after GuardedKeyPair.Destroy()")
	}
}

func TestGuardedKeyPairDestroyNilSecret(t *testing.T) {
	pk := NewPublicKey(KeyTypeKyber1024, []byte{1, 2, 3})
	gkp := &GuardedKeyPair{Public: pk, Secret: nil}

	// Should not panic.
	gkp.Destroy()
}
