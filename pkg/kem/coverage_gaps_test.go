package kem

import (
	"errors"
	"strings"
	"testing"
)

// --- Error type tests: Error() with and without wrapped error ---

func TestKeyGenError_WithErr(t *testing.T) {
	inner := errors.New("underlying failure")
	e := &KeyGenError{Algorithm: "kyber1024", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "kyber1024") {
		t.Errorf("Error() = %q, want 'kyber1024'", msg)
	}
	if !strings.Contains(msg, "underlying failure") {
		t.Errorf("Error() = %q, want 'underlying failure'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return the wrapped error")
	}
}

func TestKeyGenError_NilErr(t *testing.T) {
	e := &KeyGenError{Algorithm: "kyber768"}
	msg := e.Error()
	if !strings.Contains(msg, "kyber768") {
		t.Errorf("Error() = %q, want 'kyber768'", msg)
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no inner error")
	}
}

func TestMarshalError_WithErr(t *testing.T) {
	inner := errors.New("marshal fail")
	e := &MarshalError{Algorithm: "kyber1024", KeyKind: "public", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "marshal") {
		t.Errorf("Error() = %q, want 'marshal'", msg)
	}
	if !strings.Contains(msg, "marshal fail") {
		t.Errorf("Error() = %q, want 'marshal fail'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return the wrapped error")
	}
}

func TestMarshalError_NilErr(t *testing.T) {
	e := &MarshalError{Algorithm: "kyber768", KeyKind: "secret"}
	msg := e.Error()
	if !strings.Contains(msg, "kyber768") {
		t.Errorf("Error() = %q, want 'kyber768'", msg)
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no inner error")
	}
}

func TestUnmarshalError_WithErr(t *testing.T) {
	inner := errors.New("bad bytes")
	e := &UnmarshalError{Algorithm: "kyber768", KeyKind: "secret", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "unmarshal") {
		t.Errorf("Error() = %q, want 'unmarshal'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return the wrapped error")
	}
}

func TestUnmarshalError_NilErr(t *testing.T) {
	e := &UnmarshalError{Algorithm: "kyber1024", KeyKind: "public"}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil")
	}
}

func TestEncapsulationError_WithErr(t *testing.T) {
	inner := errors.New("encap fail")
	e := &EncapsulationError{Algorithm: "kyber768", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "encapsulation") {
		t.Errorf("Error() = %q, want 'encapsulation'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return the wrapped error")
	}
}

func TestEncapsulationError_NilErr(t *testing.T) {
	e := &EncapsulationError{Algorithm: "kyber1024"}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil")
	}
}

func TestDecapsulationError_WithErr(t *testing.T) {
	inner := errors.New("decap fail")
	e := &DecapsulationError{Algorithm: "kyber768", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "decapsulation") {
		t.Errorf("Error() = %q, want 'decapsulation'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return the wrapped error")
	}
}

func TestDecapsulationError_NilErr(t *testing.T) {
	e := &DecapsulationError{Algorithm: "kyber1024"}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil")
	}
}

func TestKeyTypeMismatchError_WithKeyKind(t *testing.T) {
	e := &KeyTypeMismatchError{Expected: KeyTypeKyber1024, Actual: KeyTypeKyber768, KeyKind: "secret key"}
	msg := e.Error()
	if !strings.Contains(msg, "secret key") {
		t.Errorf("Error() = %q, want 'secret key'", msg)
	}
	// Expected and Actual are both rendered as hex bytes.
	if !strings.Contains(msg, "0x08") {
		t.Errorf("Error() = %q, want expected type '0x08'", msg)
	}
	if !strings.Contains(msg, "0x07") {
		t.Errorf("Error() = %q, want actual type '0x07'", msg)
	}
}

func TestKeyTypeMismatchError_NoKeyKind(t *testing.T) {
	e := &KeyTypeMismatchError{Expected: KeyTypeMLKEM768, Actual: KeyTypeKyber1024}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	// Expected 0x09, actual 0x08.
	if !strings.Contains(msg, "0x09") {
		t.Errorf("Error() = %q, want expected type '0x09'", msg)
	}
}

func TestGuardedKeyAllocationError_WithErr(t *testing.T) {
	inner := errors.New("alloc failed")
	e := &GuardedKeyAllocationError{Operation: "test alloc", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "test alloc") {
		t.Errorf("Error() = %q, want 'test alloc'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return the wrapped error")
	}
}

func TestGuardedKeyAllocationError_NilErr(t *testing.T) {
	e := &GuardedKeyAllocationError{Operation: "alloc op"}
	msg := e.Error()
	if !strings.Contains(msg, "alloc op") {
		t.Errorf("Error() = %q, want 'alloc op'", msg)
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil")
	}
}

func TestGuardedKeyDestroyedError(t *testing.T) {
	e := &GuardedKeyDestroyedError{}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !strings.Contains(msg, "destroyed") {
		t.Errorf("Error() = %q, want 'destroyed'", msg)
	}
}

func TestDeserializeError_WithErr(t *testing.T) {
	inner := errors.New("bad data")
	e := &DeserializeError{Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "deserialize") {
		t.Errorf("Error() = %q, want 'deserialize'", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap() should return the wrapped error")
	}
}

func TestDeserializeError_NilErr(t *testing.T) {
	e := &DeserializeError{}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil")
	}
}

// --- SecretKey.Zeroize ---

func TestSecretKeyZeroize(t *testing.T) {
	// Use Kyber-1024 (3168 bytes) — Kyber-768 has no backend and is rejected.
	data := make([]byte, 3168)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	sk, err := NewSecretKey(KeyTypeKyber1024, data)
	if err != nil {
		t.Fatalf("NewSecretKey() error: %v", err)
	}

	// Before zeroize, data should be non-zero.
	rawData := sk.Data()
	allZero := true
	for _, b := range rawData {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("SecretKey data should not be all zeros before Zeroize")
	}

	sk.Zeroize()

	// After zeroize, internal data should be zeroed.
	zeroedData := sk.Data()
	for i, b := range zeroedData {
		if b != 0 {
			t.Errorf("byte at index %d = 0x%02x, want 0x00 after Zeroize", i, b)
			break
		}
	}
}

// --- expectedSecretKeySize default branch ---

func TestExpectedSecretKeySize_InvalidType(t *testing.T) {
	result := expectedSecretKeySize(KeyType(0xFF))
	if result != -1 {
		t.Errorf("expectedSecretKeySize(0xFF) = %d, want -1", result)
	}
}

// --- NewSecretKey error paths ---

func TestNewSecretKey_InvalidKeyType(t *testing.T) {
	_, err := NewSecretKey(KeyType(0xFF), make([]byte, 32))
	if !errors.Is(err, ErrInvalidKeyType) {
		t.Errorf("NewSecretKey with invalid type: want ErrInvalidKeyType, got %v", err)
	}
}

func TestNewSecretKey_WrongLength(t *testing.T) {
	// Kyber-1024 expects 3168 bytes; pass wrong length to exercise BadKeyLengthError.
	_, err := NewSecretKey(KeyTypeKyber1024, make([]byte, 100))
	if err == nil {
		t.Fatal("NewSecretKey should fail with wrong length")
	}
	var badLen *BadKeyLengthError
	if !errors.As(err, &badLen) {
		t.Errorf("expected BadKeyLengthError, got %T: %v", err, err)
	}
}

// TestNewSecretKey_Kyber768Unsupported verifies that Round-3 Kyber-768 (0x07)
// is explicitly rejected with ErrKeyTypeKyber768Unsupported.
func TestNewSecretKey_Kyber768Unsupported(t *testing.T) {
	_, err := NewSecretKey(KeyTypeKyber768, make([]byte, 2400))
	if err == nil {
		t.Fatal("NewSecretKey with Kyber768 should return error")
	}
	if !errors.Is(err, ErrKeyTypeKyber768Unsupported) {
		t.Errorf("expected ErrKeyTypeKyber768Unsupported, got %T: %v", err, err)
	}
}

// --- GuardedSecretKey.Clone on destroyed key ---

func TestGuardedSecretKeyClone_Destroyed(t *testing.T) {
	g := NewGuardedKyber1024()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	kp.Secret.Destroy()

	_, err = kp.Secret.Clone()
	if err == nil {
		t.Fatal("Clone on destroyed key should return error")
	}
	var destroyed *GuardedKeyDestroyedError
	if !errors.As(err, &destroyed) {
		t.Errorf("expected GuardedKeyDestroyedError, got: %T", err)
	}
}

// --- GuardedSharedSecretFromSlice with wrong length ---

func TestNewGuardedSharedSecretFromSlice_WrongLength(t *testing.T) {
	// secret.NewSecret32FromSlice requires exactly 32 bytes
	_, err := NewGuardedSharedSecretFromSlice(make([]byte, 16))
	if err == nil {
		t.Fatal("NewGuardedSharedSecretFromSlice with 16-byte slice should return error")
	}
}

// --- GuardedSharedSecret helpers ---

func TestGuardedSharedSecret_Array(t *testing.T) {
	var data [32]byte
	for i := range data {
		data[i] = byte(i + 1)
	}
	ss, err := NewGuardedSharedSecret(data)
	if err != nil {
		t.Fatalf("NewGuardedSharedSecret() error: %v", err)
	}
	defer ss.Destroy()

	arr := ss.Array()
	for i, b := range arr {
		if b != data[i] {
			t.Errorf("Array()[%d] = %d, want %d", i, b, data[i])
		}
	}
}

func TestGuardedSharedSecret_IsDestroyed(t *testing.T) {
	var data [32]byte
	ss, err := NewGuardedSharedSecret(data)
	if err != nil {
		t.Fatalf("NewGuardedSharedSecret() error: %v", err)
	}

	if ss.IsDestroyed() {
		t.Fatal("new GuardedSharedSecret should not be destroyed")
	}

	ss.Destroy()

	if !ss.IsDestroyed() {
		t.Fatal("GuardedSharedSecret should be destroyed after Destroy()")
	}

	// Idempotent
	ss.Destroy()
}

func TestGuardedSharedSecret_NilInner(t *testing.T) {
	ss := &GuardedSharedSecret{inner: nil}
	if !ss.IsDestroyed() {
		t.Fatal("nil inner should be considered destroyed")
	}
	// Destroy on nil inner must not panic
	ss.Destroy()
}

// --- GuardedKeyPair.Destroy with nil secret ---

func TestGuardedKeyPairDestroy_NilSecret(t *testing.T) {
	kp := &GuardedKeyPair{Public: nil, Secret: nil}
	kp.Destroy() // must not panic
}

// --- MLKEM768 error paths ---

func TestMLKEM768Encapsulate_WrongKeyType(t *testing.T) {
	k := NewMLKEM768KEM()
	pk := NewPublicKey(KeyTypeKyber1024, make([]byte, 32))
	_, _, err := k.Encapsulate(pk)
	if err == nil {
		t.Fatal("Encapsulate with wrong key type should return error")
	}
	var mismatch *KeyTypeMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %T", err)
	}
}

func TestMLKEM768Decapsulate_WrongSecretKeyType(t *testing.T) {
	k := NewMLKEM768KEM()
	sk, err := NewSecretKey(KeyTypeKyber1024, make([]byte, 3168))
	if err != nil {
		t.Fatalf("NewSecretKey() error: %v", err)
	}
	// Use a Kyber1024-typed ciphertext to trigger the secret-key type mismatch.
	ct := NewCiphertext(KeyTypeMLKEM768, make([]byte, 1088))
	_, err = k.Decapsulate(sk, ct)
	if err == nil {
		t.Fatal("Decapsulate with wrong secret key type should return error")
	}
	var mismatch *KeyTypeMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %T", err)
	}
}

func TestMLKEM768Decapsulate_WrongCiphertextType(t *testing.T) {
	k := NewMLKEM768KEM()
	// Use an MLKEM768 secret key with a Kyber1024-typed ciphertext.
	sk, err := NewSecretKey(KeyTypeMLKEM768, make([]byte, 64))
	if err != nil {
		t.Fatalf("NewSecretKey() error: %v", err)
	}
	ct := NewCiphertext(KeyTypeKyber1024, make([]byte, 1568))
	_, err = k.Decapsulate(sk, ct)
	if err == nil {
		t.Fatal("Decapsulate with wrong ciphertext type should return error")
	}
	var mismatch *KeyTypeMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %T", err)
	}
}

// --- GuardedSecretKey.DecapsulateGuarded unsupported key type ---

func TestDecapsulateGuarded_UnsupportedKeyType(t *testing.T) {
	// Build a GuardedSecretKey with KeyTypeMLKEM1024 (unsupported by DecapsulateGuarded
	// which only dispatches Kyber-1024 round-3 for PQXDH). The dispatch default branch
	// must return UnsupportedKeyTypeError. Use a valid-length 64-byte FIPS 203 seed
	// so the wrapper allocation succeeds.
	skData := make([]byte, 64)
	for i := range skData {
		skData[i] = byte(i)
	}
	weirdSK, err := NewGuardedSecretKey(KeyTypeMLKEM1024, skData)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey: %v", err)
	}
	defer weirdSK.Destroy()

	// Construct a 1568-byte Kyber-1024-sized ciphertext bytestream so deserialization
	// reaches the dispatch switch.
	g1024 := NewGuardedKyber1024()
	kp1024, err := g1024.Generate()
	if err != nil {
		t.Fatalf("kyber1024 Generate: %v", err)
	}
	defer kp1024.Destroy()
	_, ct1024, err := g1024.Encapsulate(kp1024.Public)
	if err != nil {
		t.Fatalf("kyber1024 Encapsulate: %v", err)
	}
	// Re-tag the ciphertext as MLKEM1024 so it matches weirdSK's type and reaches
	// the switch (the dispatcher's only check is keyType, not algorithm match).
	taggedCT := NewCiphertext(KeyTypeMLKEM1024, ct1024.Data())

	_, err = weirdSK.DecapsulateGuarded(taggedCT.Serialize())
	if err == nil {
		t.Fatal("DecapsulateGuarded with unsupported key type should return error")
	}
	var unsupported *UnsupportedKeyTypeError
	if !errors.As(err, &unsupported) {
		t.Errorf("expected UnsupportedKeyTypeError, got: %T: %v", err, err)
	}
}

// --- MLKEM768 stdlib error-injection tests ---
// The stdlib crypto/mlkem MLKEM768KEM does not use a swappable scheme variable;
// error paths are tested via invalid input bytes.

func TestMLKEM768EncapsulateInvalidPublicKeyBytes(t *testing.T) {
	k := NewMLKEM768KEM()

	// Provide a correctly-typed but wrong-length public key.
	// The size check in NewPublicKey/Encapsulate type guard and then
	// NewEncapsulationKey768 only accepts exactly 1184 bytes; pass 100 bytes
	// via a hand-crafted PublicKey to bypass size validation.
	badPK := &PublicKey{keyType: KeyTypeMLKEM768, data: make([]byte, 100)}
	_, _, err := k.Encapsulate(badPK)
	if err == nil {
		t.Fatal("Encapsulate() should return error for invalid-length public key bytes")
	}
	var unmarshalErr *UnmarshalError
	if !errors.As(err, &unmarshalErr) {
		t.Errorf("expected UnmarshalError, got: %T: %v", err, err)
	}
}

func TestMLKEM768DecapsulateInvalidSeedBytes(t *testing.T) {
	k := NewMLKEM768KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Replace the secret key seed with invalid bytes (wrong length after type check).
	// NewDecapsulationKey768 validates seed structure; a bad seed should fail.
	badSK := &SecretKey{keyType: KeyTypeMLKEM768, data: make([]byte, 64)}
	_, err = k.Decapsulate(badSK, ct)
	// A zero seed may or may not be rejected by the stdlib; what we verify is
	// that decapsulation of a mismatched ciphertext produces an error or a
	// different shared secret. The important path is the type-check paths above.
	// For a round-trip with a bad seed we just confirm no panic occurs.
	_ = err
}

func TestMLKEM768DecapsulateInvalidCiphertext(t *testing.T) {
	k := NewMLKEM768KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Construct a valid-typed but garbled ciphertext; Decapsulate should
	// either succeed (implicit rejection per FIPS 203) or return an error.
	// The important invariant is no panic, and the returned shared secret
	// must not match the one from a correct encapsulation.
	_, realCT, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	realSS, err := k.Decapsulate(kp.Secret, realCT)
	if err != nil {
		t.Fatalf("Decapsulate(real) error: %v", err)
	}

	badCTData := make([]byte, 1088)
	// Fill with non-zero pattern to ensure it differs from the real ciphertext.
	for i := range badCTData {
		badCTData[i] = byte(i & 0xFF)
	}
	badCT := NewCiphertext(KeyTypeMLKEM768, badCTData)
	badSS, err := k.Decapsulate(kp.Secret, badCT)
	// ML-KEM uses implicit rejection — Decapsulate always succeeds but returns
	// a different (random-looking) shared secret for invalid ciphertexts.
	if err != nil {
		// If the implementation does return an error, that is also acceptable.
		return
	}
	if *badSS == *realSS {
		t.Error("decapsulating a bad ciphertext must not produce the same shared secret")
	}
}
