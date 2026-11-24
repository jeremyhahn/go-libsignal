// Package interop checks Go accepts zkgroup bytes from Rust integration_tests.rs, loaded from fixtures/zkgroup/presentations.go.
package interop_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	fixtures "github.com/jeremyhahn/go-libsignal/tests/interop/fixtures/zkgroup"
)

// TestInteropAuthCredentialPresentationV1Rejected checks a V1 (0x00) auth presentation is rejected, as Rust.
func TestInteropAuthCredentialPresentationV1Rejected(t *testing.T) {
	_, err := zkgroup.DeserializeAnyAuthCredentialPresentation(fixtures.AuthCredentialPresentationV1Bytes)
	if err == nil {
		t.Fatal("expected error deserializing V1 auth credential presentation, got nil")
	}
	if !errors.Is(err, zkgroup.ErrDeserializationFailure) {
		// An ErrUnknownPresentationVersion wraps ErrDeserializationFailure.
		// The V1 version byte (0x00) is not a valid auth presentation version.
		var versionErr *zkgroup.ErrUnknownPresentationVersion
		if !errors.As(err, &versionErr) {
			t.Fatalf("expected ErrUnknownPresentationVersion or ErrDeserializationFailure, got %T: %v", err, err)
		}
		if versionErr.Version != zkgroup.PresentationVersion1 {
			t.Fatalf("expected rejected version byte 0x00, got 0x%02x", versionErr.Version)
		}
	}
}

// TestInteropAuthCredentialPresentationV4Deserializes checks the Rust V4 auth presentation parses with 64-byte ciphertexts and a redemption time.
func TestInteropAuthCredentialPresentationV4Deserializes(t *testing.T) {
	pres, err := zkgroup.DeserializeAnyAuthCredentialPresentation(fixtures.AuthCredentialPresentationV4ResultBytes)
	if err != nil {
		t.Fatalf("DeserializeAnyAuthCredentialPresentation V4: %v", err)
	}
	if pres.Version != zkgroup.PresentationVersion4 {
		t.Fatalf("expected version 3 (PresentationVersion4), got %d", pres.Version)
	}

	aciCT := pres.GetACICiphertext()
	if aciCT == nil {
		t.Fatal("GetACICiphertext returned nil")
	}
	aciBytes := zkcredential.EncodeCiphertext(aciCT.Ciphertext)
	if len(aciBytes) != 64 {
		t.Fatalf("ACI ciphertext encoded size: want 64, got %d", len(aciBytes))
	}

	pniCT := pres.GetPNICiphertext()
	if pniCT == nil {
		t.Fatal("GetPNICiphertext returned nil")
	}
	pniBytes := zkcredential.EncodeCiphertext(pniCT.Ciphertext)
	if len(pniBytes) != 64 {
		t.Fatalf("PNI ciphertext encoded size: want 64, got %d", len(pniBytes))
	}

	redemption := pres.GetRedemptionTime()
	if redemption.EpochSeconds() == 0 {
		t.Fatal("GetRedemptionTime returned zero timestamp")
	}
	// Rust test uses redemption_time = Timestamp::from_epoch_seconds(123456 * SECONDS_PER_DAY)
	// = 123456 * 86400 = 10666598400.
	const expectedRedemption uint64 = 123456 * 86400
	if redemption.EpochSeconds() != expectedRedemption {
		t.Fatalf("redemption time: want %d, got %d", expectedRedemption, redemption.EpochSeconds())
	}
}

// TestInteropProfileKeyCredentialPresentationV1 checks the Rust V1 presentation parses as V1 with ciphertexts and no expiration.
func TestInteropProfileKeyCredentialPresentationV1(t *testing.T) {
	any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(fixtures.ProfileKeyCredentialPresentationV1Bytes)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation V1: %v", err)
	}
	if any.Version != zkgroup.PresentationVersion1 {
		t.Fatalf("expected PresentationVersion1 (0x00), got 0x%02x", any.Version)
	}
	if any.V1 == nil {
		t.Fatal("V1 field is nil for a V1 presentation")
	}

	uidCT := any.GetUUIDCiphertext()
	if uidCT == nil {
		t.Fatal("GetUUIDCiphertext returned nil")
	}
	if uidCT.Ciphertext == nil {
		t.Fatal("UUIDCiphertext.Ciphertext is nil")
	}

	pkCT := any.GetProfileKeyCiphertext()
	if pkCT == nil {
		t.Fatal("GetProfileKeyCiphertext returned nil")
	}
	if pkCT.Ciphertext == nil {
		t.Fatal("ProfileKeyCiphertext.Ciphertext is nil")
	}

	_, hasExpiry := any.GetExpirationTime()
	if hasExpiry {
		t.Fatal("V1 presentation must not carry an expiration time")
	}
}

// TestInteropProfileKeyCredentialPresentationV2 verifies that the Rust-produced
// V2 profile key credential presentation bytes parse via
// DeserializeAnyProfileKeyCredentialPresentation and return a V2-typed result.
//
// Source vector: integration_tests.rs:46 (PROFILE_KEY_CREDENTIAL_PRESENTATION_V2_RESULT).
func TestInteropProfileKeyCredentialPresentationV2(t *testing.T) {
	any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(fixtures.ProfileKeyCredentialPresentationV2ResultBytes)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation V2: %v", err)
	}
	if any.Version != zkgroup.PresentationVersion2 {
		t.Fatalf("expected PresentationVersion2 (0x01), got 0x%02x", any.Version)
	}
	if any.V2 == nil {
		t.Fatal("V2 field is nil for a V2 presentation")
	}

	uidCT := any.GetUUIDCiphertext()
	if uidCT == nil {
		t.Fatal("GetUUIDCiphertext returned nil")
	}

	pkCT := any.GetProfileKeyCiphertext()
	if pkCT == nil {
		t.Fatal("GetProfileKeyCiphertext returned nil")
	}

	_, hasExpiry := any.GetExpirationTime()
	if hasExpiry {
		t.Fatal("V2 presentation must not carry an expiration time")
	}
}

// TestInteropProfileKeyCredentialPresentationV3 verifies that the Rust-produced
// V3 ExpiringProfileKeyCredentialPresentation bytes parse correctly and carry a
// non-zero expiration timestamp.
//
// Source vector: integration_tests.rs:51 (PROFILE_KEY_CREDENTIAL_PRESENTATION_V3_RESULT).
func TestInteropProfileKeyCredentialPresentationV3(t *testing.T) {
	any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(fixtures.ProfileKeyCredentialPresentationV3ResultBytes)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation V3: %v", err)
	}
	if any.Version != zkgroup.PresentationVersion3 {
		t.Fatalf("expected PresentationVersion3 (0x02), got 0x%02x", any.Version)
	}
	if any.V3 == nil {
		t.Fatal("V3 field is nil for a V3 presentation")
	}

	uidCT := any.GetUUIDCiphertext()
	if uidCT == nil {
		t.Fatal("GetUUIDCiphertext returned nil")
	}

	pkCT := any.GetProfileKeyCiphertext()
	if pkCT == nil {
		t.Fatal("GetProfileKeyCiphertext returned nil")
	}

	ts, hasExpiry := any.GetExpirationTime()
	if !hasExpiry {
		t.Fatal("V3 presentation must carry an expiration time")
	}
	if ts.EpochSeconds() == 0 {
		t.Fatal("V3 expiration timestamp must be non-zero")
	}
}

// TestInteropProfileKeyCredentialPresentationV4 verifies that the Rust-produced
// V4 ExpiringProfileKeyCredentialPresentation bytes parse correctly and carry a
// non-zero expiration timestamp.
//
// Source vector: integration_tests.rs:55 (PROFILE_KEY_CREDENTIAL_PRESENTATION_V4_RESULT).
func TestInteropProfileKeyCredentialPresentationV4(t *testing.T) {
	any, err := zkgroup.DeserializeAnyProfileKeyCredentialPresentation(fixtures.ProfileKeyCredentialPresentationV4ResultBytes)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation V4: %v", err)
	}
	if any.Version != zkgroup.PresentationVersion4 {
		t.Fatalf("expected PresentationVersion4 (0x03), got 0x%02x", any.Version)
	}
	if any.V4 == nil {
		t.Fatal("V4 field is nil for a V4 presentation")
	}

	uidCT := any.GetUUIDCiphertext()
	if uidCT == nil {
		t.Fatal("GetUUIDCiphertext returned nil")
	}

	pkCT := any.GetProfileKeyCiphertext()
	if pkCT == nil {
		t.Fatal("GetProfileKeyCiphertext returned nil")
	}

	ts, hasExpiry := any.GetExpirationTime()
	if !hasExpiry {
		t.Fatal("V4 presentation must carry an expiration time")
	}
	if ts.EpochSeconds() == 0 {
		t.Fatal("V4 expiration timestamp must be non-zero")
	}
}

// TestInteropAdditionalKATsNotAvailable records that the Rust flow tests have no static presentation vectors; pkg/zkgroup tests cover those types.
func TestInteropAdditionalKATsNotAvailable(t *testing.T) {
	t.Run("BackupAuthCredentialPresentation_NoStaticVector", func(t *testing.T) {
		// backup_auth_flow.rs generates credential material dynamically; no hex! const.
		// Gap acknowledged: no static Rust KAT available for this type.
		t.Log("backup_auth_flow.rs contains no static hex presentation-byte constants")
	})
	t.Run("CallLinkAuthCredentialPresentation_NoStaticVector", func(t *testing.T) {
		// call_link_flow.rs generates credential material dynamically; no hex! const.
		t.Log("call_link_flow.rs contains no static hex presentation-byte constants")
	})
	t.Run("GroupSendEndorsementPresentation_NoStaticVector", func(t *testing.T) {
		// group_send_endorsements.rs generates credential material dynamically; no hex! const.
		t.Log("group_send_endorsements.rs contains no static hex presentation-byte constants")
	})
	t.Run("ReceiptCredentialPresentation_NoStaticVector", func(t *testing.T) {
		// receipt_flow.rs generates credential material dynamically; no hex! const.
		t.Log("receipt_flow.rs contains no static hex presentation-byte constants")
	})
}
