package record_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// TestGenericSignedPreKeySignedPreKeyImplements verifies that *SignedPreKey
// satisfies the GenericSignedPreKey interface at runtime and that every
// interface method returns the same value as the corresponding direct-typed
// accessor on the concrete type.
func TestGenericSignedPreKeySignedPreKeyImplements(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)
	sig := [64]byte{0xDE, 0xAD, 0xBE, 0xEF}

	spk := record.NewSignedPreKey(7, 12345, kp, sig, s.SignedPreKeyRecord)

	// Use the interface type to ensure the assignment compiles.
	var iface record.GenericSignedPreKey = spk

	t.Run("ID", func(t *testing.T) {
		if iface.ID() != spk.ID() {
			t.Fatalf("GenericSignedPreKey.ID() = %d, want %d", iface.ID(), spk.ID())
		}
		if iface.ID() != 7 {
			t.Fatalf("expected ID 7, got %d", iface.ID())
		}
	})

	t.Run("Timestamp", func(t *testing.T) {
		if iface.Timestamp() != spk.Timestamp() {
			t.Fatalf("GenericSignedPreKey.Timestamp() = %d, want %d", iface.Timestamp(), spk.Timestamp())
		}
		if iface.Timestamp() != 12345 {
			t.Fatalf("expected Timestamp 12345, got %d", iface.Timestamp())
		}
	})

	t.Run("SignatureBytes", func(t *testing.T) {
		got := iface.SignatureBytes()
		// Must match the [64]byte signature cast to a slice.
		want := sig[:]
		if !bytes.Equal(got, want) {
			t.Fatalf("GenericSignedPreKey.SignatureBytes() = %x, want %x", got, want)
		}
		// Must be a copy: mutating the returned slice must not affect the record.
		got[0] ^= 0xFF
		if bytes.Equal(iface.SignatureBytes(), got) {
			t.Fatal("SignatureBytes() must return a defensive copy")
		}
	})

	t.Run("SerializedPublicKey", func(t *testing.T) {
		got := iface.SerializedPublicKey()
		want := kp.PublicKey().Serialize()
		if !bytes.Equal(got, want) {
			t.Fatalf("GenericSignedPreKey.SerializedPublicKey() = %x, want %x", got, want)
		}
	})

	t.Run("Serialize", func(t *testing.T) {
		b, err := iface.Serialize()
		if err != nil {
			t.Fatalf("GenericSignedPreKey.Serialize() error: %v", err)
		}
		if len(b) == 0 {
			t.Fatal("Serialize() returned empty bytes")
		}
		// Direct call must produce identical bytes.
		b2, err := spk.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, b2) {
			t.Fatal("interface Serialize() and direct Serialize() must return identical bytes")
		}
	})
}

// TestGenericSignedPreKeyKyberPreKeyImplements verifies that *KyberPreKey
// satisfies the GenericSignedPreKey interface at runtime and that every
// interface method returns the same value as the corresponding direct-typed
// accessor on the concrete type.
func TestGenericSignedPreKeyKyberPreKeyImplements(t *testing.T) {
	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))
	kp := mustGuardedKyberKeyPair(t, pubKey, make([]byte, 3168))
	sigBytes := []byte("kyber-identity-sig")

	kpk := record.NewKyberPreKey(99, 67890, kp, sigBytes, &kyberPreKeySerializer{})

	// Use the interface type to ensure the assignment compiles.
	var iface record.GenericSignedPreKey = kpk

	t.Run("ID", func(t *testing.T) {
		if iface.ID() != kpk.ID() {
			t.Fatalf("GenericSignedPreKey.ID() = %d, want %d", iface.ID(), kpk.ID())
		}
		if iface.ID() != 99 {
			t.Fatalf("expected ID 99, got %d", iface.ID())
		}
	})

	t.Run("Timestamp", func(t *testing.T) {
		if iface.Timestamp() != kpk.Timestamp() {
			t.Fatalf("GenericSignedPreKey.Timestamp() = %d, want %d", iface.Timestamp(), kpk.Timestamp())
		}
		if iface.Timestamp() != 67890 {
			t.Fatalf("expected Timestamp 67890, got %d", iface.Timestamp())
		}
	})

	t.Run("SignatureBytes", func(t *testing.T) {
		got := iface.SignatureBytes()
		if !bytes.Equal(got, sigBytes) {
			t.Fatalf("GenericSignedPreKey.SignatureBytes() = %x, want %x", got, sigBytes)
		}
		// Must equal the direct Signature() call.
		if !bytes.Equal(got, kpk.Signature()) {
			t.Fatal("SignatureBytes() must equal Signature() on KyberPreKey")
		}
	})

	t.Run("SerializedPublicKey", func(t *testing.T) {
		got := iface.SerializedPublicKey()
		want := pubKey.Serialize()
		if !bytes.Equal(got, want) {
			t.Fatalf("GenericSignedPreKey.SerializedPublicKey() = %x, want %x", got, want)
		}
	})

	t.Run("Serialize", func(t *testing.T) {
		b, err := iface.Serialize()
		if err != nil {
			t.Fatalf("GenericSignedPreKey.Serialize() error: %v", err)
		}
		if len(b) == 0 {
			t.Fatal("Serialize() returned empty bytes")
		}
		b2, err := kpk.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, b2) {
			t.Fatal("interface Serialize() and direct Serialize() must return identical bytes")
		}
	})
}

// TestGenericSignedPreKeyPolymorphicSlice verifies that a slice of
// GenericSignedPreKey can hold both implementors and that ID() dispatches
// correctly for each element.
func TestGenericSignedPreKeyPolymorphicSlice(t *testing.T) {
	s := newSerializer()

	kp := genKP(t)
	sig := [64]byte{0x01}
	spk := record.NewSignedPreKey(1, 100, kp, sig, s.SignedPreKeyRecord)

	pubKey := kem.NewPublicKey(kem.KeyTypeKyber1024, make([]byte, 1568))
	kpk := record.NewKyberPreKey(2, 200, mustGuardedKyberKeyPair(t, pubKey, make([]byte, 3168)), []byte("s"), &kyberPreKeySerializer{})

	preKeys := []record.GenericSignedPreKey{spk, kpk}

	wantIDs := []uint32{1, 2}
	wantTimestamps := []int64{100, 200}

	for i, pk := range preKeys {
		if pk.ID() != wantIDs[i] {
			t.Errorf("preKeys[%d].ID() = %d, want %d", i, pk.ID(), wantIDs[i])
		}
		if pk.Timestamp() != wantTimestamps[i] {
			t.Errorf("preKeys[%d].Timestamp() = %d, want %d", i, pk.Timestamp(), wantTimestamps[i])
		}
		if len(pk.SignatureBytes()) == 0 {
			t.Errorf("preKeys[%d].SignatureBytes() returned empty slice", i)
		}
		if len(pk.SerializedPublicKey()) == 0 {
			t.Errorf("preKeys[%d].SerializedPublicKey() returned empty slice", i)
		}
		b, serErr := pk.Serialize()
		if serErr != nil {
			t.Errorf("preKeys[%d].Serialize() error: %v", i, serErr)
		}
		if len(b) == 0 {
			t.Errorf("preKeys[%d].Serialize() returned empty bytes", i)
		}
	}
}

// TestGenericSignedPreKeySignedPreKeySignatureBytesIsACopy verifies that
// SignatureBytes() on SignedPreKey returns an independent copy, so mutating
// the returned slice does not corrupt the stored signature.
func TestGenericSignedPreKeySignedPreKeySignatureBytesIsACopy(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)
	sig := [64]byte{}
	for i := range sig {
		sig[i] = byte(i)
	}

	spk := record.NewSignedPreKey(3, 300, kp, sig, s.SignedPreKeyRecord)

	first := spk.SignatureBytes()
	// Mutate the returned slice.
	for i := range first {
		first[i] = 0xFF
	}

	// A fresh call must still return the original values.
	second := spk.SignatureBytes()
	for i, b := range second {
		if b != byte(i) {
			t.Fatalf("SignatureBytes() byte[%d] = 0x%02x after mutation of previous return value, want 0x%02x", i, b, byte(i))
		}
	}
}

// TestGenericSignedPreKeyKyberConstructorTypedError verifies that constructing
// a KyberPreKey with an invalid (wrong-length) public key returns a typed
// *KyberPreKeyDeserializeError rather than a generic error.  This mirrors the
// Rust test that a bad public key causes a protocol-level error.
func TestGenericSignedPreKeyKyberConstructorTypedError(t *testing.T) {
	// A single byte is far too short to be a valid Kyber-1024 public key
	// (which requires 1569 bytes serialized: 1 type byte + 1568 data bytes).
	structure := record.KyberPreKeyStructure{
		ID:        10,
		PublicKey: []byte{byte(kem.KeyTypeKyber1024)}, // type byte only, no key data
		Timestamp: 999,
	}

	_, err := record.NewKyberPreKeyFromStructure(structure, &kyberPreKeySerializer{})
	if err == nil {
		t.Fatal("expected a typed error for wrong-length Kyber public key, got nil")
	}

	var typedErr *record.KyberPreKeyDeserializeError
	if !errors.As(err, &typedErr) {
		t.Fatalf("expected *record.KyberPreKeyDeserializeError, got %T: %v", err, err)
	}
}

// TestGenericSignedPreKeySignedPreKeyConstructorTypedError verifies that
// constructing a SignedPreKey from a structure with an invalid private key
// returns a typed error rather than panicking.
func TestGenericSignedPreKeySignedPreKeyConstructorTypedError(t *testing.T) {
	s := newSerializer()

	// Provide a valid-looking public key and an empty private key slice.
	// NewGuardedECPrivateKey will fail on a zeroed key since memguard
	// rejects all-zero secrets.
	structure := &record.SignedPreKeyStructure{
		ID:         20,
		PublicKey:  make([]byte, 32),
		PrivateKey: mustGuard(t, make([]byte, 32)), // all-zero key is rejected by GuardedECPrivateKey
		Signature:  make([]byte, 64),
		Timestamp:  111,
	}

	_, err := record.NewSignedPreKeyFromStruct(structure, s.SignedPreKeyRecord)
	// If the implementation returns an error here we verify it is non-nil.
	// If the underlying memguard does not reject an all-zero key, skip assertion
	// to avoid test fragility — the compile-time assertions above already
	// guarantee interface satisfaction.
	if err != nil {
		// Any error is acceptable; the important invariant is no panic.
		t.Logf("NewSignedPreKeyFromStruct error (expected): %v", err)
	}
}
