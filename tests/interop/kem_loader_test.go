// Conformance test consumer for KEM byte-format parity, using the central
// fixture loader rather than ad-hoc runtime.Caller path resolution.
//
// This test reads the upstream Rust libsignal ML-KEM-1024 and Kyber-1024 test
// keys from tests/interop/fixtures/protocol/kem/ — paths that are tracked by
// MANIFEST.toml and validated in CI via tests/interop/scripts/check_fixtures.sh.
//
// The existing kem_interop_test.go covers the same byte-parity property via
// an ad-hoc loader; this file is the canonical pattern future port waves
// must follow when adopting Rust-sourced fixtures.
//
// Rust reference: rust/protocol/src/kem.rs::test_serialize
//   (https://github.com/signalapp/libsignal at commit pinned in /RUST_REV).

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

// TestKEMLoader_MLKEM1024SerializeRoundTrip verifies the byte-identical
// round trip for ML-KEM-1024 public keys (type byte 0x0a) — which IS a
// wire-relevant property because PKs are transmitted in pre-key bundles.
// The secret-key portion is intentionally skipped: ML-KEM secret keys
// never leave a device, so Rust's libcrux expanded 3168-byte SK form vs
// Go's FIPS 203 64-byte seed form is a local-only representation choice,
// not a wire-compat divergence. See fixtures/MANIFEST.toml for full
// rationale.
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

	// MLKEM1024 secret-key round trip is *intentionally not asserted*. ML-KEM
	// SKs never leave a device, so the libcrux-expanded 3168-byte form Rust
	// uses for local storage and the FIPS 203 64-byte seed form Go uses are
	// both legal representations of the same key material. This is a local
	// state choice, not a wire format. We log the upstream body size as a
	// diagnostic so the picture is recorded next to the test.
	t.Logf("upstream mlkem-sk.dat body size: %d bytes (libcrux expanded form). Go uses the 64-byte FIPS 203 seed form for local storage; SKs are not transmitted, so this divergence is benign.", len(rawSK)-1)
}
