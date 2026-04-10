package kem

import (
	"bytes"
	"errors"
	"testing"
)

func TestMLKEM1024_NewReturnsNonNil(t *testing.T) {
	k := NewMLKEM1024KEM()
	if k == nil {
		t.Fatal("NewMLKEM1024KEM() returned nil")
	}
}

func TestMLKEM1024_KeyType(t *testing.T) {
	k := NewMLKEM1024KEM()
	if k.KeyType() != KeyTypeMLKEM1024 {
		t.Errorf("KeyType() = 0x%02x, want 0x%02x", k.KeyType(), KeyTypeMLKEM1024)
	}
}

func TestMLKEM1024_Generate(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if kp.Public == nil {
		t.Fatal("Generate() returned nil public key")
	}
	if kp.Secret == nil {
		t.Fatal("Generate() returned nil secret key")
	}
	if kp.Public.Type() != KeyTypeMLKEM1024 {
		t.Errorf("public key type = 0x%02x, want KeyTypeMLKEM1024", kp.Public.Type())
	}
	if kp.Secret.Type() != KeyTypeMLKEM1024 {
		t.Errorf("secret key type = 0x%02x, want KeyTypeMLKEM1024", kp.Secret.Type())
	}
}

func TestMLKEM1024_KeySizes(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// ML-KEM-1024 (FIPS 203): pk=1568 bytes, sk=64-byte seed, ct=1568 bytes.
	pkData := kp.Public.Data()
	if len(pkData) != 1568 {
		t.Errorf("public key size = %d, want 1568 (ML-KEM-1024 encapsulation key)", len(pkData))
	}

	skData := kp.Secret.Data()
	if len(skData) != 64 {
		t.Errorf("secret key size = %d, want 64 (ML-KEM-1024 seed)", len(skData))
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	ctData := ct.Data()
	if len(ctData) != 1568 {
		t.Errorf("ciphertext size = %d, want 1568 (ML-KEM-1024)", len(ctData))
	}
}

func TestMLKEM1024_GenerateUniqueness(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp1, err := k.Generate()
	if err != nil {
		t.Fatalf("first Generate() error: %v", err)
	}
	kp2, err := k.Generate()
	if err != nil {
		t.Fatalf("second Generate() error: %v", err)
	}

	if bytes.Equal(kp1.Public.Data(), kp2.Public.Data()) {
		t.Error("two generated key pairs should have different public keys")
	}
	if bytes.Equal(kp1.Secret.Data(), kp2.Secret.Data()) {
		t.Error("two generated key pairs should have different secret keys")
	}
}

func TestMLKEM1024_EncapsulateDecapsulate(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	ss1, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}
	if ct.Type() != KeyTypeMLKEM1024 {
		t.Errorf("ciphertext type = 0x%02x, want KeyTypeMLKEM1024", ct.Type())
	}

	ss2, err := k.Decapsulate(kp.Secret, ct)
	if err != nil {
		t.Fatalf("Decapsulate() error: %v", err)
	}

	if *ss1 != *ss2 {
		t.Error("shared secrets from Encapsulate and Decapsulate should match")
	}

	// Verify the shared secret is not all zeros.
	allZero := true
	for _, b := range ss1[:] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("shared secret should not be all zeros")
	}
}

func TestMLKEM1024_SharedSecretSize(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	sharedSecret, _, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// SharedSecret is [32]byte; verify the returned pointer is non-nil
	// and the array length matches the expected ML-KEM shared secret size.
	if sharedSecret == nil {
		t.Fatal("Encapsulate() returned nil shared secret")
	}
	if len(sharedSecret[:]) != 32 {
		t.Errorf("shared secret size = %d, want 32", len(sharedSecret[:]))
	}
}

func TestMLKEM1024_KeyTypeMismatch_Encapsulate(t *testing.T) {
	k := NewMLKEM1024KEM()

	// Pass a Kyber1024 typed public key to the MLKEM1024 KEM.
	wrongPK := NewPublicKey(KeyTypeKyber1024, make([]byte, 1568))

	_, _, err := k.Encapsulate(wrongPK)
	if err == nil {
		t.Fatal("Encapsulate with wrong key type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %T: %v", err, err)
	}
}

func TestMLKEM1024_KeyTypeMismatch_DecapsulateSecretKey(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// A Kyber1024 secret key (3168 bytes) passed to an MLKEM1024 decapsulator.
	wrongSK, skErr := NewSecretKey(KeyTypeKyber1024, make([]byte, 3168))
	if skErr != nil {
		t.Fatalf("NewSecretKey() error: %v", skErr)
	}

	_, err = k.Decapsulate(wrongSK, ct)
	if err == nil {
		t.Fatal("Decapsulate with wrong secret key type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %T: %v", err, err)
	}
}

func TestMLKEM1024_KeyTypeMismatch_DecapsulateCiphertext(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Wrap the same ciphertext bytes as Kyber1024 typed.
	wrongCT := NewCiphertext(KeyTypeKyber1024, ct.Data())
	_, err = k.Decapsulate(kp.Secret, wrongCT)
	if err == nil {
		t.Fatal("Decapsulate with wrong ciphertext type should return error")
	}
	var typeMismatch *KeyTypeMismatchError
	if !errors.As(err, &typeMismatch) {
		t.Errorf("expected KeyTypeMismatchError, got: %T: %v", err, err)
	}
}

func TestMLKEM1024_InvalidPublicKey(t *testing.T) {
	// A serialized public key with wrong data size must be rejected.
	// Note: crypto/mlkem accepts all-zero buffers of the correct size as
	// structurally valid; wrong size is the reliable validation path at
	// the kem layer.
	serialized := make([]byte, 1+100) // type prefix + 100 bytes (wrong size for ML-KEM-1024)
	serialized[0] = byte(KeyTypeMLKEM1024)

	_, err := DeserializePublicKey(serialized)
	if err == nil {
		t.Fatal("DeserializePublicKey with wrong size should return error")
	}
	var badLen *BadKeyLengthError
	if !errors.As(err, &badLen) {
		t.Errorf("expected BadKeyLengthError, got: %T: %v", err, err)
	}
}

func TestMLKEM1024_InvalidSecretKey(t *testing.T) {
	// Verify that NewSecretKey rejects a secret key with a wrong size.
	// Note: crypto/mlkem accepts all-zero seeds of correct size (64 bytes)
	// as structurally valid; wrong size is the reliable validation path.
	_, err := NewSecretKey(KeyTypeMLKEM1024, make([]byte, 32)) // 32 != 64
	if err == nil {
		t.Fatal("NewSecretKey with wrong size should return error")
	}
	var badLen *BadKeyLengthError
	if !errors.As(err, &badLen) {
		t.Errorf("expected BadKeyLengthError, got: %T: %v", err, err)
	}
}

func TestMLKEM1024_Zeroize(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Zeroize should not panic and should overwrite all secret bytes.
	kp.Secret.Zeroize()

	data := kp.Secret.Data()
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d of zeroized secret key = 0x%02x, want 0x00", i, b)
		}
	}
}

func TestMLKEM1024_SerializeDeserialize_PublicKey(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	serialized := kp.Public.Serialize()
	// Serialized form: [type_byte] || [1568 bytes of key data] = 1569 bytes total.
	if len(serialized) != 1569 {
		t.Errorf("serialized public key length = %d, want 1569", len(serialized))
	}
	if serialized[0] != byte(KeyTypeMLKEM1024) {
		t.Errorf("first byte = 0x%02x, want 0x%02x (KeyTypeMLKEM1024)", serialized[0], KeyTypeMLKEM1024)
	}

	pk2, err := DeserializePublicKey(serialized)
	if err != nil {
		t.Fatalf("DeserializePublicKey() error: %v", err)
	}
	if pk2.Type() != KeyTypeMLKEM1024 {
		t.Errorf("deserialized key type = 0x%02x, want KeyTypeMLKEM1024", pk2.Type())
	}
	if !bytes.Equal(pk2.Data(), kp.Public.Data()) {
		t.Error("deserialized public key data does not match original")
	}
}

func TestMLKEM1024_SerializeDeserialize_Ciphertext(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	_, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	serialized := ct.Serialize()
	// Serialized form: [type_byte] || [1568 bytes of ciphertext] = 1569 bytes total.
	if len(serialized) != 1569 {
		t.Errorf("serialized ciphertext length = %d, want 1569", len(serialized))
	}
	if serialized[0] != byte(KeyTypeMLKEM1024) {
		t.Errorf("first byte = 0x%02x, want 0x%02x (KeyTypeMLKEM1024)", serialized[0], KeyTypeMLKEM1024)
	}

	ct2, err := DeserializeCiphertext(serialized)
	if err != nil {
		t.Fatalf("DeserializeCiphertext() error: %v", err)
	}
	if ct2.Type() != KeyTypeMLKEM1024 {
		t.Errorf("deserialized ciphertext type = 0x%02x, want KeyTypeMLKEM1024", ct2.Type())
	}
	if !bytes.Equal(ct2.Data(), ct.Data()) {
		t.Error("deserialized ciphertext data does not match original")
	}
}

func TestMLKEM1024_DecapsulateWithDeserializedObjects(t *testing.T) {
	k := NewMLKEM1024KEM()

	kp, err := k.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	ss1, ct, err := k.Encapsulate(kp.Public)
	if err != nil {
		t.Fatalf("Encapsulate() error: %v", err)
	}

	// Round-trip the ciphertext through serialization before decapsulating.
	ct2, err := DeserializeCiphertext(ct.Serialize())
	if err != nil {
		t.Fatalf("DeserializeCiphertext() error: %v", err)
	}

	ss2, err := k.Decapsulate(kp.Secret, ct2)
	if err != nil {
		t.Fatalf("Decapsulate() with deserialized ciphertext error: %v", err)
	}

	if *ss1 != *ss2 {
		t.Error("shared secrets should match after ciphertext serialization round-trip")
	}
}

func TestMLKEM1024_ImplementsKEMInterface(t *testing.T) {
	// Compile-time assertion that MLKEM1024KEM satisfies the KEM interface.
	var _ KEM = (*MLKEM1024KEM)(nil)
}
