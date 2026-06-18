// Conformance test: DecryptionErrorMessage wire-format parity vs Rust libsignal.
//
// Rust source: rust/protocol/src/protocol.rs:881 DecryptionErrorMessage::for_original
// (libsignal v0.92.2)
//
// Loads the Rust-emitted wire/decryption_error_message.json fixture and verifies:
//  1. DeserializeDecryptionErrorMessage parses dem_serialized without error.
//  2. Timestamp matches the fixture expected.timestamp_ms.
//  3. DeviceID matches the fixture expected.device_id.
//  4. RatchetKey serializes byte-for-byte to expected.ratchet_key_public.
//  5. Re-serializing produces the original dem_serialized bytes.
//  6. PlaintextContent wrapping: NewPlaintextContentFromBytes parses
//     expected.plaintext_content_serialized and ExtractDecryptionErrorMessageFromSerializedContent
//     recovers the same DEM.

package interop

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type decryptionErrorMessageWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			OriginalTimestampMs uint64 `json:"original_timestamp_ms"`
			OriginalDeviceID    uint32 `json:"original_device_id"`
			OriginalType        string `json:"original_type"`
		} `json:"inputs"`
		Expected struct {
			DemSerialized              string `json:"dem_serialized"`
			RatchetKeyPublic           string `json:"ratchet_key_public"`
			TimestampMs                uint64 `json:"timestamp_ms"`
			DeviceID                   uint32 `json:"device_id"`
			PlaintextContentSerialized string `json:"plaintext_content_serialized"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestDecryptionErrorMessageWire validates DecryptionErrorMessage wire parity with Rust libsignal.
func TestDecryptionErrorMessageWire(t *testing.T) {
	raw := loader.MustRead("wire/decryption_error_message.json")

	var fx decryptionErrorMessageWireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			demBytes := mustHex(t, v.Expected.DemSerialized)
			wantRatchetKey := mustHex(t, v.Expected.RatchetKeyPublic)
			plaintextBytes := mustHex(t, v.Expected.PlaintextContentSerialized)

			// Parse the Rust-emitted DecryptionErrorMessage bytes.
			dem, err := protocol.DeserializeDecryptionErrorMessage(demBytes)
			if err != nil {
				t.Fatalf("DeserializeDecryptionErrorMessage: %v", err)
			}

			// Assert timestamp.
			if got := dem.Timestamp(); got != v.Expected.TimestampMs {
				t.Errorf("Timestamp: got %d, want %d", got, v.Expected.TimestampMs)
			}

			// Assert device ID.
			if got := dem.DeviceID(); got != v.Expected.DeviceID {
				t.Errorf("DeviceID: got %d, want %d", got, v.Expected.DeviceID)
			}

			// Assert ratchet key.
			rk := dem.RatchetKey()
			if rk == nil {
				t.Fatal("RatchetKey: expected non-nil, got nil")
			}
			gotRatchetKey := rk.Serialize()
			if !bytes.Equal(gotRatchetKey, wantRatchetKey) {
				t.Errorf("RatchetKey mismatch:\n  got  %x\n  want %x", gotRatchetKey, wantRatchetKey)
			}

			// Round-trip: Serialize returns the cached bytes.
			gotSerialized, err := dem.Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			if !bytes.Equal(gotSerialized, demBytes) {
				t.Errorf("DEM round-trip mismatch:\n  got  %x\n  want %x", gotSerialized, demBytes)
			}

			// PlaintextContent parsing: parse the wrapping PlaintextContent.
			pc, err := protocol.NewPlaintextContentFromBytes(plaintextBytes)
			if err != nil {
				t.Fatalf("NewPlaintextContentFromBytes: %v", err)
			}

			// PlaintextContent must start with 0xC0.
			pcBytes, err := pc.Serialize()
			if err != nil {
				t.Fatalf("PlaintextContent.Serialize: %v", err)
			}
			if len(pcBytes) < 1 || pcBytes[0] != 0xC0 {
				t.Errorf("PlaintextContent: expected first byte 0xC0, got 0x%02x", pcBytes[0])
			}

			// PlaintextContent must end with 0x80.
			if pcBytes[len(pcBytes)-1] != 0x80 {
				t.Errorf("PlaintextContent: expected last byte 0x80, got 0x%02x", pcBytes[len(pcBytes)-1])
			}

			// PlaintextContent serialized bytes must be byte-for-byte equal to fixture.
			if !bytes.Equal(pcBytes, plaintextBytes) {
				t.Errorf("PlaintextContent bytes mismatch:\n  got  %x\n  want %x", pcBytes, plaintextBytes)
			}

			// Extract DEM from PlaintextContent body; assert it matches the original DEM.
			extracted, err := protocol.ExtractDecryptionErrorMessageFromSerializedContent(pc.Body())
			if err != nil {
				t.Fatalf("ExtractDecryptionErrorMessageFromSerializedContent: %v", err)
			}
			if extracted.Timestamp() != dem.Timestamp() {
				t.Errorf("extracted Timestamp: got %d, want %d", extracted.Timestamp(), dem.Timestamp())
			}
			if extracted.DeviceID() != dem.DeviceID() {
				t.Errorf("extracted DeviceID: got %d, want %d", extracted.DeviceID(), dem.DeviceID())
			}
			if extracted.RatchetKey() == nil {
				t.Fatal("extracted RatchetKey: nil")
			}
			if !bytes.Equal(extracted.RatchetKey().Serialize(), wantRatchetKey) {
				t.Errorf("extracted RatchetKey mismatch:\n  got  %x\n  want %x",
					extracted.RatchetKey().Serialize(), wantRatchetKey)
			}
		})
	}
}
