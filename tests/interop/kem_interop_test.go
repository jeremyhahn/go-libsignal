// Package interop checks Go accepts and round-trips bytes from Rust libsignal; KEM vectors in fixtures/kem/ are copied from rust/protocol/src/kem/test-data/.
package interop

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
)

// fixtureDir returns the absolute path to the fixtures/kem directory.
// It resolves relative to the location of this source file so the tests
// work regardless of the working directory used to invoke go test.
func fixtureDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "fixtures", "kem")
}

// mustReadFixture reads a fixture file and fails the test if the file cannot
// be opened or read.
func mustReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(fixtureDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mustReadFixture %q: %v", name, err)
	}
	return data
}

// TestKEMInteropKyber1024Serialize round-trips the Rust Kyber-1024 keys with type byte 0x08 (Rust kem.rs test_serialize).
func TestKEMInteropKyber1024Serialize(t *testing.T) {
	rawPK := mustReadFixture(t, "pk.dat")
	rawSK := mustReadFixture(t, "sk.dat")

	// Rust prepends KeyType::Kyber1024.value() == 0x08 before deserializing.
	serializedPK := make([]byte, 1+len(rawPK))
	serializedPK[0] = byte(kem.KeyTypeKyber1024)
	copy(serializedPK[1:], rawPK)

	serializedSK := make([]byte, 1+len(rawSK))
	serializedSK[0] = byte(kem.KeyTypeKyber1024)
	copy(serializedSK[1:], rawSK)

	pk, err := kem.DeserializePublicKey(serializedPK)
	if err != nil {
		t.Fatalf("DeserializePublicKey: %v", err)
	}

	sk, skErr := kem.NewSecretKey(kem.KeyTypeKyber1024, rawSK)
	if skErr != nil {
		t.Fatalf("NewSecretKey: %v", skErr)
	}

	reserializedPK := pk.Serialize()
	if !bytes.Equal(serializedPK, reserializedPK) {
		t.Errorf("public key round-trip mismatch\n  original length:    %d\n  reserialized length: %d",
			len(serializedPK), len(reserializedPK))
	}

	// Secret key serialization: prepend type byte to match Rust behavior.
	reserializedSK := make([]byte, 1+len(sk.Data()))
	reserializedSK[0] = byte(sk.Type())
	copy(reserializedSK[1:], sk.Data())

	if !bytes.Equal(serializedSK, reserializedSK) {
		t.Errorf("secret key round-trip mismatch\n  original length:    %d\n  reserialized length: %d",
			len(serializedSK), len(reserializedSK))
	}
}

// TestKEMInteropKyber1024EncapDecap encapsulates and decapsulates with the Rust Kyber-1024 keys (Rust test_kyber1024_kem).
func TestKEMInteropKyber1024EncapDecap(t *testing.T) {
	rawPK := mustReadFixture(t, "pk.dat")
	rawSK := mustReadFixture(t, "sk.dat")

	serializedPK := make([]byte, 1+len(rawPK))
	serializedPK[0] = byte(kem.KeyTypeKyber1024)
	copy(serializedPK[1:], rawPK)

	pk, err := kem.DeserializePublicKey(serializedPK)
	if err != nil {
		t.Fatalf("DeserializePublicKey: %v", err)
	}
	if pk.Type() != kem.KeyTypeKyber1024 {
		t.Fatalf("public key type = 0x%02x, want 0x%02x", pk.Type(), kem.KeyTypeKyber1024)
	}

	sk, skErr := kem.NewSecretKey(kem.KeyTypeKyber1024, rawSK)
	if skErr != nil {
		t.Fatalf("NewSecretKey: %v", skErr)
	}

	kyber := kem.NewKyber1024KEM()

	ssSender, ct, encErr := kyber.Encapsulate(pk)
	if encErr != nil {
		t.Fatalf("Encapsulate: %v", encErr)
	}

	ssRecipient, decErr := kyber.Decapsulate(sk, ct)
	if decErr != nil {
		t.Fatalf("Decapsulate: %v", decErr)
	}

	if *ssSender != *ssRecipient {
		t.Errorf("shared secrets differ\n  sender:    %x\n  recipient: %x", *ssSender, *ssRecipient)
	}
}

// TestKEMInteropMLKEM1024 parses the Rust ML-KEM-1024 public key and round-trips a fresh key pair; Go cannot import libcrux's expanded secret key (Rust test_mlkem1024_kem).
func TestKEMInteropMLKEM1024(t *testing.T) {
	// mlkem-pk.dat already includes the 0x0A type prefix; pass it directly.
	pkBytes := mustReadFixture(t, "mlkem-pk.dat")

	pk, err := kem.DeserializePublicKey(pkBytes)
	if err != nil {
		t.Fatalf("DeserializePublicKey (fixture pk): %v", err)
	}
	if pk.Type() != kem.KeyTypeMLKEM1024 {
		t.Fatalf("public key type = 0x%02x, want 0x%02x", pk.Type(), kem.KeyTypeMLKEM1024)
	}

	mlkemImpl := kem.NewMLKEM1024KEM()

	// Encapsulate against the Rust fixture public key to verify it is
	// structurally valid and accepted by the Go implementation.
	_, ct, encErr := mlkemImpl.Encapsulate(pk)
	if encErr != nil {
		t.Fatalf("Encapsulate against fixture public key: %v", encErr)
	}
	if ct.Type() != kem.KeyTypeMLKEM1024 {
		t.Errorf("ciphertext type = 0x%02x, want 0x%02x", ct.Type(), kem.KeyTypeMLKEM1024)
	}

	// Full encapsulate/decapsulate round-trip with a fresh Go ML-KEM key pair.
	// The Rust mlkem-sk.dat is in the 3168-byte libcrux expanded format, which
	// is incompatible with Go's 64-byte FIPS 203 seed-based API. The round-trip
	// below confirms the implementation is correct.
	kp, genErr := mlkemImpl.Generate()
	if genErr != nil {
		t.Fatalf("Generate: %v", genErr)
	}

	ssSender, ct2, enc2Err := mlkemImpl.Encapsulate(kp.Public)
	if enc2Err != nil {
		t.Fatalf("Encapsulate (fresh key pair): %v", enc2Err)
	}

	ssRecipient, decErr := mlkemImpl.Decapsulate(kp.Secret, ct2)
	if decErr != nil {
		t.Fatalf("Decapsulate (fresh key pair): %v", decErr)
	}

	if *ssSender != *ssRecipient {
		t.Errorf("shared secrets differ\n  sender:    %x\n  recipient: %x", *ssSender, *ssRecipient)
	}
}
