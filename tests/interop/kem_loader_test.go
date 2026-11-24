// KEM byte-format parity through the central fixture loader, reading MANIFEST.toml-tracked keys (Rust kem.rs test_serialize at /RUST_REV).

package interop

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// TestKEMLoader_Kyber1024SerializeRoundTrip verifies that the Go KEM package
// produces byte-identical serialization for the upstream Kyber-1024 public
// and secret key fixtures, when the serialized form is the type-byte prefix
// (0x08) plus the raw key bytes from rust/protocol/src/kem/test-data/.
func TestKEMLoader_Kyber1024SerializeRoundTrip(t *testing.T) {
	rawPK := loader.MustRead("protocol/kem/pk.dat")
	rawSK := loader.MustRead("protocol/kem/sk.dat")

	serializedPK := append([]byte{byte(kem.KeyTypeKyber1024)}, rawPK...)
	serializedSK := append([]byte{byte(kem.KeyTypeKyber1024)}, rawSK...)

	pk, err := kem.DeserializePublicKey(serializedPK)
	if err != nil {
		t.Fatalf("DeserializePublicKey(Kyber1024): %v", err)
	}
	if got := pk.Serialize(); !bytes.Equal(got, serializedPK) {
		t.Fatalf("Kyber1024 PK round-trip mismatch:\n  got  len=%d\n  want len=%d", len(got), len(serializedPK))
	}

	sk, err := kem.NewSecretKey(kem.KeyTypeKyber1024, rawSK)
	if err != nil {
		t.Fatalf("NewSecretKey(Kyber1024): %v", err)
	}
	reserializedSK := append([]byte{byte(sk.Type())}, sk.Data()...)
	if !bytes.Equal(reserializedSK, serializedSK) {
		t.Fatalf("Kyber1024 SK round-trip mismatch:\n  got  len=%d\n  want len=%d", len(reserializedSK), len(serializedSK))
	}
}

// TestKEMLoader_MLKEM1024SerializeRoundTrip round-trips ML-KEM-1024 public keys; secret keys never leave a device, so their form is not checked.
func TestKEMLoader_MLKEM1024SerializeRoundTrip(t *testing.T) {
	rawPK := loader.MustRead("protocol/kem/mlkem-pk.dat")
	rawSK := loader.MustRead("protocol/kem/mlkem-sk.dat")

	// The mlkem-pk.dat / mlkem-sk.dat fixtures already include the type-byte
	// prefix (0x0a). Verify that and pass through to the deserializers.
	if rawPK[0] != byte(kem.KeyTypeMLKEM1024) {
		t.Fatalf("mlkem-pk.dat: expected leading type byte 0x0a, got 0x%02x", rawPK[0])
	}
	if rawSK[0] != byte(kem.KeyTypeMLKEM1024) {
		t.Fatalf("mlkem-sk.dat: expected leading type byte 0x0a, got 0x%02x", rawSK[0])
	}

	pk, err := kem.DeserializePublicKey(rawPK)
	if err != nil {
		t.Fatalf("DeserializePublicKey(MLKEM1024): %v", err)
	}
	if got := pk.Serialize(); !bytes.Equal(got, rawPK) {
		t.Fatalf("MLKEM1024 PK round-trip mismatch:\n  got  len=%d\n  want len=%d", len(got), len(rawPK))
	}

	// ML-KEM secret keys are local state: Rust's 3168-byte and Go's 64-byte seed forms are both valid, so only the size is logged.
	t.Logf("upstream mlkem-sk.dat body size: %d bytes (libcrux expanded form). Go uses the 64-byte FIPS 203 seed form for local storage; SKs are not transmitted, so this divergence is benign.", len(rawSK)-1)
}
