// Conformance test: PlaintextContent wire-format parity vs Rust libsignal.
//
// Rust source: rust/protocol/src/protocol.rs:837
// From<DecryptionErrorMessage> for PlaintextContent (libsignal v0.92.2)
//
// Wire layout: [0xC0 identifier] || Content proto body || [0x80 padding-boundary]
//
// Loads the Rust-emitted wire/plaintext_content.json fixture and verifies:
//  1. NewPlaintextContentFromBytes parses expected.serialized without error.
//  2. First byte is 0xC0 (PLAINTEXT_CONTEXT_IDENTIFIER_BYTE).
//  3. Last byte is 0x80 (PADDING_BOUNDARY_BYTE).
//  4. Body() returns bytes[1:] (everything after the identifier byte).
//  5. body_hex matches fixture expected.body_hex.
//  6. Serialized bytes round-trip byte-for-byte.
//  7. ExtractDecryptionErrorMessageFromSerializedContent recovers the embedded DEM
//     with the correct timestamp and device_id.

package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type plaintextContentWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			IdentifierByte      string `json:"identifier_byte"`
			PaddingByte         string `json:"padding_byte"`
			OriginalTimestampMs uint64 `json:"original_timestamp_ms"`
			OriginalDeviceID    uint32 `json:"original_device_id"`
		} `json:"inputs"`
		Expected struct {
			Serialized string `json:"serialized"`
			FirstByte  string `json:"first_byte"`
			LastByte   string `json:"last_byte"`
			BodyHex    string `json:"body_hex"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestPlaintextContentWire validates PlaintextContent wire parity with Rust libsignal.
func TestPlaintextContentWire(t *testing.T) {
	raw := loader.MustRead("wire/plaintext_content.json")

	var fx plaintextContentWireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			serialized := mustHex(t, v.Expected.Serialized)
			wantBody, err := hex.DecodeString(v.Expected.BodyHex)
			if err != nil {
				t.Fatalf("hex decode body_hex: %v", err)
			}

			// Parse the Rust-emitted bytes.
			pc, err := protocol.NewPlaintextContentFromBytes(serialized)
			if err != nil {
				t.Fatalf("NewPlaintextContentFromBytes: %v", err)
			}

			// Identifier byte (first byte) must be 0xC0.
			pcBytes, err := pc.Serialize()
			if err != nil {
				t.Fatalf("PlaintextContent.Serialize: %v", err)
			}
			if len(pcBytes) < 2 {
				t.Fatalf("PlaintextContent too short: %d bytes", len(pcBytes))
			}
			if pcBytes[0] != 0xC0 {
				t.Errorf("first byte: got 0x%02x, want 0xC0", pcBytes[0])
			}

			// Padding boundary byte (last byte) must be 0x80.
			if pcBytes[len(pcBytes)-1] != 0x80 {
				t.Errorf("last byte: got 0x%02x, want 0x80", pcBytes[len(pcBytes)-1])
			}

			// Body() must equal serialized[1:] (identifier stripped, padding included).
			gotBody := pc.Body()
			if !bytes.Equal(gotBody, wantBody) {
				t.Errorf("Body mismatch:\n  got  %x\n  want %x", gotBody, wantBody)
			}

			// Body must also equal pcBytes[1:] (direct slice check).
			if !bytes.Equal(gotBody, pcBytes[1:]) {
				t.Errorf("Body != serialized[1:]:\n  Body      %x\n  serial[1] %x", gotBody, pcBytes[1:])
			}

			// Round-trip: serialized bytes must be byte-for-byte identical to fixture.
			if !bytes.Equal(pcBytes, serialized) {
				t.Errorf("round-trip mismatch:\n  got  %x\n  want %x", pcBytes, serialized)
			}

			// Type() must return PLAINTEXT_TYPE (8).
			if got := pc.Type(); got != protocol.PLAINTEXT_TYPE {
				t.Errorf("Type(): got %d, want %d (PLAINTEXT_TYPE)", got, protocol.PLAINTEXT_TYPE)
			}

			// Extract the embedded DecryptionErrorMessage from Body().
			// Body() returns [1:] which includes the Content proto body and trailing 0x80.
			extracted, err := protocol.ExtractDecryptionErrorMessageFromSerializedContent(pc.Body())
			if err != nil {
				t.Fatalf("ExtractDecryptionErrorMessageFromSerializedContent: %v", err)
			}

			// Assert extracted DEM fields match the fixture inputs.
			if got := extracted.Timestamp(); got != v.Inputs.OriginalTimestampMs {
				t.Errorf("extracted Timestamp: got %d, want %d", got, v.Inputs.OriginalTimestampMs)
			}
			if got := extracted.DeviceID(); got != v.Inputs.OriginalDeviceID {
				t.Errorf("extracted DeviceID: got %d, want %d", got, v.Inputs.OriginalDeviceID)
			}
		})
	}
}
