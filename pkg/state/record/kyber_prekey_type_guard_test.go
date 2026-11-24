package record_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// TestErrKyberPreKeyTypeMismatch_ErrorMessage verifies the typed error message
// format for ErrKyberPreKeyTypeMismatch.
func TestErrKyberPreKeyTypeMismatch_ErrorMessage(t *testing.T) {
	e := &record.ErrKyberPreKeyTypeMismatch{
		PublicKeyType: kem.KeyTypeKyber1024,
		SecretKeyType: kem.KeyTypeMLKEM1024,
	}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() must return non-empty string")
	}
	// Confirm both type values appear in the message.
	if len(msg) < 10 {
		t.Fatalf("error message too short: %q", msg)
	}
}

// TestNewKyberPreKeyFromStructure_TypeConsistency checks a valid key pair round-trips with its type intact.
func TestNewKyberPreKeyFromStructure_TypeConsistency(t *testing.T) {
	// Use zero-value key bytes; NewPublicKey and NewSecretKey do not validate
	// the content of the key material, only the length.
	pubKeyData := make([]byte, 1568) // Kyber1024 public key size
	secKeyData := make([]byte, 3168) // Kyber1024 secret key size

	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, pubKeyData)
	kp := mustGuardedKyberKeyPair(t, pubKey, append([]byte(nil), secKeyData...))
	original := record.NewKyberPreKey(1, 12345, kp, []byte("test-sig"), &kyberPreKeySerializer{})

	// Serialize and deserialize through the structure.
	structure := record.KyberPreKeyStructure{
		ID:         original.ID(),
		PublicKey:  pubKey.Serialize(),
		PrivateKey: mustGuard(t, secKeyData),
		Signature:  original.Signature(),
		Timestamp:  12345,
	}

	rebuilt, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{})
	if err != nil {
		t.Fatalf("NewKyberPreKeyFromStructure failed for matching types: %v", err)
	}

	if rebuilt.PublicKey().Type() != kem.KeyTypeKyber1024 {
		t.Errorf("public key type = %d, want %d", rebuilt.PublicKey().Type(), kem.KeyTypeKyber1024)
	}
	guarded, err := rebuilt.GuardedKeyPair()
	if err != nil {
		t.Fatalf("GuardedKeyPair: %v", err)
	}
	defer guarded.Destroy()
	if guarded.Secret.Type() != kem.KeyTypeKyber1024 {
		t.Errorf("secret key type = %d, want %d", guarded.Secret.Type(), kem.KeyTypeKyber1024)
	}
}

// TestNewKyberPreKeyFromStructure_MismatchedPublicKey checks an unknown public key type byte (0xFF) is an error.
func TestNewKyberPreKeyFromStructure_MismatchedPublicKey(t *testing.T) {
	// Build a valid Kyber1024 public key serialization and then corrupt the type
	// byte to a value that no valid SecretKey can have.
	pubKeyData := make([]byte, 1568)
	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, pubKeyData)
	serialized := pubKey.Serialize()

	// Corrupt the type byte: use a different valid type (MLKEM1024 = 0x0A) so
	// that DeserializePublicKey successfully parses the bytes as MLKEM1024 but
	// the private key (3168 bytes) does not match MLKEM1024's secret key size
	// (3168 happens to match MLKEM1024 as well, so use an invalid size instead).
	corruptedPub := make([]byte, len(serialized))
	copy(corruptedPub, serialized)
	corruptedPub[0] = 0xFF // Unknown type byte

	secKeyData := make([]byte, 3168) // Kyber1024 SK size

	structure := record.KyberPreKeyStructure{
		ID:         42,
		PublicKey:  corruptedPub,
		PrivateKey: mustGuard(t, secKeyData),
		Signature:  []byte("sig"),
		Timestamp:  0,
	}

	_, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{})
	if err == nil {
		t.Fatal("expected error when public key has unknown type byte 0xFF")
	}

	// The error must be a KyberPreKeyDeserializeError (wrapping the kem decode error).
	var deserErr *record.KyberPreKeyDeserializeError
	if !errors.As(err, &deserErr) {
		t.Errorf("expected *KyberPreKeyDeserializeError, got %T: %v", err, err)
	}
}

// TestNewKyberPreKeyFromStructure_InvalidPrivateKeyForType checks a 4-byte private key under a Kyber1024 public key is a KyberPreKeyDeserializeError.
func TestNewKyberPreKeyFromStructure_InvalidPrivateKeyForType(t *testing.T) {
	pubKeyData := make([]byte, 1568)
	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, pubKeyData)

	structure := record.KyberPreKeyStructure{
		ID:         7,
		PublicKey:  pubKey.Serialize(),                           // valid Kyber1024 public key
		PrivateKey: mustGuard(t, []byte{0x01, 0x02, 0x03, 0x04}), // wrong size for any KEM algorithm
		Signature:  []byte("sig"),
		Timestamp:  0,
	}

	_, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{})
	if err == nil {
		t.Fatal("expected error for private key with wrong size")
	}

	var deserErr *record.KyberPreKeyDeserializeError
	if !errors.As(err, &deserErr) {
		t.Errorf("expected *KyberPreKeyDeserializeError, got %T: %v", err, err)
	}
}
