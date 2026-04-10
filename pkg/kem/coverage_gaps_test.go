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
	e := &KeyTypeMismatchError{Expected: "Kyber1024", Actual: KeyTypeKyber768, KeyKind: "secret key"}
	msg := e.Error()
	if !strings.Contains(msg, "secret key") {
		t.Errorf("Error() = %q, want 'secret key'", msg)
	}
	if !strings.Contains(msg, "Kyber1024") {
		t.Errorf("Error() = %q, want 'Kyber1024'", msg)
	}
}

func TestKeyTypeMismatchError_NoKeyKind(t *testing.T) {
	e := &KeyTypeMismatchError{Expected: "Kyber768", Actual: KeyTypeKyber1024}
	msg := e.Error()
	if !strings.Contains(msg, "Kyber768") {
		t.Errorf("Error() = %q, want 'Kyber768'", msg)
	}
	if msg == "" {
		t.Error("Error() returned empty string")
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
	data := make([]byte, 2400)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	sk, err := NewSecretKey(KeyTypeKyber768, data)
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
	// Kyber768 expects 2400 bytes; pass wrong length
	_, err := NewSecretKey(KeyTypeKyber768, make([]byte, 100))
	if err == nil {
		t.Fatal("NewSecretKey should fail with wrong length")
	}
	var badLen *BadKeyLengthError
	if !errors.As(err, &badLen) {
		t.Errorf("expected BadKeyLengthError, got %T: %v", err, err)
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
	ct := NewCiphertext(KeyTypeKyber768, make([]byte, 1088))
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
	sk, err := NewSecretKey(KeyTypeKyber768, make([]byte, 2400))
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

// --- GuardedKyber768 error paths ---

func TestGuardedKyber768_EncapsulateWrongKeyType(t *testing.T) {
	g := NewGuardedKyber768()
	pk := NewPublicKey(KeyTypeKyber1024, make([]byte, 32))
	_, _, err := g.Encapsulate(pk)
	if err == nil {
		t.Fatal("Encapsulate with wrong key type should return error")
	}
	var mismatch *KeyTypeMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %T", err)
	}
}

func TestGuardedKyber768_DecapsulateDestroyed(t *testing.T) {
	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	kp.Secret.Destroy()
	_, err = g.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate on destroyed key should return error")
	}
	var destroyed *GuardedKeyDestroyedError
	if !errors.As(err, &destroyed) {
		t.Errorf("expected GuardedKeyDestroyedError, got: %T", err)
	}
}

func TestGuardedKyber768_DecapsulateWrongSecretKeyType(t *testing.T) {
	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	skData := kp.Secret.Data()
	skCopy := make([]byte, len(skData))
	copy(skCopy, skData)
	wrongSK, err := NewGuardedSecretKey(KeyTypeKyber1024, skCopy)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}
	defer wrongSK.Destroy()

	_, err = g.Decapsulate(wrongSK, ct)
	if err == nil {
		t.Fatal("Decapsulate with wrong key type should return error")
	}
	var mismatch *KeyTypeMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %T", err)
	}
}

func TestGuardedKyber768_DecapsulateWrongCiphertextType(t *testing.T) {
	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	wrongCT := NewCiphertext(KeyTypeKyber1024, ct.Data())
	_, err = g.Decapsulate(kp.Secret, wrongCT)
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
	// Create a GuardedSecretKey with an unsupported key type by using
	// NewGuardedSecretKeyFromSecret after constructing a raw secret.
	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Build a GuardedSecretKey with an unsupported KeyType (MLKEM1024)
	// but valid Kyber768-sized data so deserialization passes.
	skData := kp.Secret.Data()
	skCopy := make([]byte, len(skData))
	copy(skCopy, skData)
	weirdSK, err := NewGuardedSecretKey(KeyTypeMLKEM1024, skCopy)
	if err != nil {
		t.Fatalf("NewGuardedSecretKey() error: %v", err)
	}
	defer weirdSK.Destroy()

	// Serialize a Kyber768 ciphertext but the SK has MLKEM1024 type,
	// so the switch default branch triggers UnsupportedKeyTypeError.
	_, err = weirdSK.DecapsulateGuarded(ct.Serialize())
	if err == nil {
		t.Fatal("DecapsulateGuarded with unsupported key type should return error")
	}
	var unsupported *UnsupportedKeyTypeError
	if !errors.As(err, &unsupported) {
		t.Errorf("expected UnsupportedKeyTypeError, got: %T: %v", err, err)
	}
}

// --- GuardedKyber768 scheme-error injection tests ---

func TestGuardedKyber768GenerateKeyPairError(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	guardedKyber768Scheme = &errScheme{real: orig, generateErr: errInjected}
	g := NewGuardedKyber768()
	_, err := g.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when GenerateKeyPair fails")
	}
	if !strings.Contains(err.Error(), "key generation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber768GenerateMarshalPublicKeyError(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	guardedKyber768Scheme = &errScheme{real: orig, marshalPKErr: errInjected}
	g := NewGuardedKyber768()
	_, err := g.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when MarshalBinary(pk) fails")
	}
}

func TestGuardedKyber768GenerateMarshalSecretKeyError(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	guardedKyber768Scheme = &errScheme{real: orig, marshalSKErr: errInjected}
	g := NewGuardedKyber768()
	_, err := g.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when MarshalBinary(sk) fails")
	}
}

func TestGuardedKyber768EncapsulateSchemeError(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	guardedKyber768Scheme = &errScheme{real: orig, encapsulateErr: errInjected}
	_, _, err = g.Encapsulate(kp.Public)
	if err == nil {
		t.Fatal("Encapsulate() should return error when scheme.Encapsulate fails")
	}
	if !strings.Contains(err.Error(), "encapsulation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber768EncapsulateUnmarshalPKError(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	guardedKyber768Scheme = &errScheme{real: orig, unmarshalPKErr: errInjected}
	_, _, err = g.Encapsulate(kp.Public)
	if err == nil {
		t.Fatal("Encapsulate() should return error when UnmarshalBinaryPublicKey fails")
	}
}

func TestGuardedKyber768DecapsulateSchemeDecapError(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	guardedKyber768Scheme = &errScheme{real: orig, decapsulateErr: errInjected}
	_, err = g.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate() should return error when scheme.Decapsulate fails")
	}
	if !strings.Contains(err.Error(), "decapsulation failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGuardedKyber768DecapsulateUnmarshalSKError(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	guardedKyber768Scheme = &errScheme{real: orig, unmarshalSKErr: errInjected}
	_, err = g.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate() should return error when UnmarshalBinaryPrivateKey fails")
	}
}

func TestGuardedKyber768GeneratePanicRecovery(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	guardedKyber768Scheme = &panicScheme{real: orig, panicOnGenerate: true}
	g := NewGuardedKyber768()
	_, err := g.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when panic is recovered")
	}
}

func TestGuardedKyber768EncapsulatePanicRecovery(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	guardedKyber768Scheme = &panicScheme{real: orig, panicOnEncap: true}
	_, _, err = g.Encapsulate(kp.Public)
	if err == nil {
		t.Fatal("Encapsulate() should return error when panic is recovered")
	}
}

func TestGuardedKyber768DecapsulatePanicRecovery(t *testing.T) {
	orig := guardedKyber768Scheme
	defer func() { guardedKyber768Scheme = orig }()

	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	_, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	guardedKyber768Scheme = &panicScheme{real: orig, panicOnDecap: true}
	_, err = g.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate() should return error when panic is recovered")
	}
}

// --- MLKEM768 scheme-error injection tests ---

func TestMLKEM768EncapsulateUnmarshalPKError(t *testing.T) {
	orig := kyber768Scheme
	defer func() { kyber768Scheme = orig }()

	k := NewMLKEM768KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	kyber768Scheme = &errScheme{real: orig, unmarshalPKErr: errInjected}
	_, _, err = k.Encapsulate(kp.Public)
	if err == nil {
		t.Fatal("Encapsulate() should return error when UnmarshalBinaryPublicKey fails")
	}
}

func TestMLKEM768DecapsulateUnmarshalSKError(t *testing.T) {
	orig := kyber768Scheme
	defer func() { kyber768Scheme = orig }()

	k := NewMLKEM768KEM()
	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	kyber768Scheme = &errScheme{real: orig, unmarshalSKErr: errInjected}
	_, err = k.Decapsulate(kp.Secret, ct)
	if err == nil {
		t.Fatal("Decapsulate() should return error when UnmarshalBinaryPrivateKey fails")
	}
}

func TestMLKEM768GenerateKeyPairError(t *testing.T) {
	orig := kyber768Scheme
	defer func() { kyber768Scheme = orig }()

	kyber768Scheme = &errScheme{real: orig, generateErr: errInjected}
	k := NewMLKEM768KEM()
	_, err := k.Generate()
	if err == nil {
		t.Fatal("Generate() should return error when GenerateKeyPair fails")
	}
}

// --- GuardedKyber768 full round-trip ---

func TestGuardedKyber768_RoundTrip(t *testing.T) {
	g := NewGuardedKyber768()
	kp, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	defer kp.Destroy()

	if kp.Public.Type() != KeyTypeKyber768 {
		t.Errorf("public key type = 0x%02x, want Kyber768", kp.Public.Type())
	}

	ss, ct, err := g.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	defer ss.Destroy()

	ss2, err := g.Decapsulate(kp.Secret, ct)
	if err != nil {
		t.Fatalf("Decapsulate() error: %v", err)
	}
	defer ss2.Destroy()

	for i, b := range ss.Bytes() {
		if b != ss2.Bytes()[i] {
			t.Errorf("shared secrets differ at byte %d", i)
			break
		}
	}
}
