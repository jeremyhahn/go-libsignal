// Conformance tests: profile key credential presentation backward-compatibility.
//
// Mirrors two Rust integration tests in rust/zkgroup/tests/integration_tests.rs:
//
//   test_profile_key_credential_presentation_expiring_as_v1 (line 403):
//     Verifies that a V3 ExpiringProfileKeyCredentialPresentation can be
//     structurally re-encoded as a V1 presentation, and the UUID and profile
//     key ciphertexts are preserved.
//
//   test_profile_key_credential_presentation_v2_as_v1 (implicit):
//     Same structural check for V2.
//
// The key semantic: AnyProfileKeyCredentialPresentation::to_structurally_valid_v1_presentation_bytes
// stamps a 0x00 version byte and 8 Ristretto basepoint proof-point placeholders,
// writes a 320-byte zero proof, then copies the ciphertexts verbatim. The result
// parses as a valid V1 structural frame, with matching ciphertexts.

package interop

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	fixtures "github.com/jeremyhahn/go-libsignal/tests/interop/fixtures/zkgroup"
)

// TestInteropProfileKeyCredentialPresentationV1BackCompat verifies that a V3
// ExpiringProfileKeyCredentialPresentation can be structurally re-encoded as a
// V1 presentation with ciphertexts preserved.
//
// Rust reference: test_profile_key_credential_presentation_expiring_as_v1
// (rust/zkgroup/tests/integration_tests.rs:403)
func TestInteropProfileKeyCredentialPresentationV1BackCompat(t *testing.T) {
	// Parse V3 bytes from the Rust-emitted fixture.
	v3Any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(
		fixtures.ProfileKeyCredentialPresentationV3ResultBytes,
	)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation V3: %v", err)
	}
	if v3Any.Version != zkgroup.PresentationVersion3 {
		t.Fatalf("expected V3 version byte, got 0x%02x", v3Any.Version)
	}

	// Re-encode as structurally valid V1 bytes (matches Rust's
	// to_structurally_valid_v1_presentation_bytes).
	v1Bytes := v3Any.ToStructurallyValidV1PresentationBytes()
	const wantLen = 713 // PROFILE_KEY_CREDENTIAL_PRESENTATION_V1_LEN in Rust
	if len(v1Bytes) != wantLen {
		t.Fatalf("structurally valid V1 bytes length: want %d, got %d", wantLen, len(v1Bytes))
	}
	if v1Bytes[0] != zkgroup.PresentationVersion1 {
		t.Fatalf("first byte must be V1 version (0x00), got 0x%02x", v1Bytes[0])
	}

	// Parse the re-encoded bytes as a V1 presentation.
	v1Any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(v1Bytes)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation on V1 re-encoding: %v", err)
	}
	if v1Any.Version != zkgroup.PresentationVersion1 {
		t.Fatalf("re-encoded version: want V1 (0x00), got 0x%02x", v1Any.Version)
	}

	// Rust assertion: presentation.get_uuid_ciphertext() == presentation_as_v1.get_uuid_ciphertext()
	v3UUID := v3Any.GetUUIDCiphertext()
	v1UUID := v1Any.GetUUIDCiphertext()
	if v3UUID == nil || v1UUID == nil {
		t.Fatal("UUID ciphertext must not be nil")
	}
	if !v3UUID.Ciphertext.Equal(v1UUID.Ciphertext) {
		t.Fatal("UUID ciphertext mismatch between V3 and structurally-valid V1 re-encoding")
	}

	// Rust assertion: presentation.get_profile_key_ciphertext() == presentation_as_v1.get_profile_key_ciphertext()
	v3PK := v3Any.GetProfileKeyCiphertext()
	v1PK := v1Any.GetProfileKeyCiphertext()
	if v3PK == nil || v1PK == nil {
		t.Fatal("ProfileKey ciphertext must not be nil")
	}
	if !v3PK.Ciphertext.Equal(v1PK.Ciphertext) {
		t.Fatal("ProfileKey ciphertext mismatch between V3 and structurally-valid V1 re-encoding")
	}
}

// TestInteropProfileKeyCredentialPresentationV4BackCompat applies the same
// structural re-encoding to a V4 presentation, confirming that the method is
// version-agnostic (extracts ciphertexts from the Any wrapper regardless of
// underlying version).
func TestInteropProfileKeyCredentialPresentationV4BackCompat(t *testing.T) {
	v4Any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(
		fixtures.ProfileKeyCredentialPresentationV4ResultBytes,
	)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation V4: %v", err)
	}

	v1Bytes := v4Any.ToStructurallyValidV1PresentationBytes()
	if len(v1Bytes) != 713 {
		t.Fatalf("V4→V1 bytes length: want 713, got %d", len(v1Bytes))
	}

	v1Any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(v1Bytes)
	if err != nil {
		t.Fatalf("parse V4→V1 re-encoding: %v", err)
	}
	if v1Any.Version != zkgroup.PresentationVersion1 {
		t.Fatalf("expected V1 re-encoding, got version 0x%02x", v1Any.Version)
	}

	v4UUID := v4Any.GetUUIDCiphertext()
	v1UUID := v1Any.GetUUIDCiphertext()
	if !v4UUID.Ciphertext.Equal(v1UUID.Ciphertext) {
		t.Fatal("UUID ciphertext mismatch between V4 and structurally-valid V1 re-encoding")
	}

	v4PK := v4Any.GetProfileKeyCiphertext()
	v1PK := v1Any.GetProfileKeyCiphertext()
	if !v4PK.Ciphertext.Equal(v1PK.Ciphertext) {
		t.Fatal("ProfileKey ciphertext mismatch between V4 and structurally-valid V1 re-encoding")
	}
}
