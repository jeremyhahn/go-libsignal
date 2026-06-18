// Conformance test: SenderKeyDistributionMessage wire parity vs Rust libsignal.
//
// Assertion strategy: DIRECT BYTES-EQUAL.
//   The fixture exposes all inputs needed to construct the message deterministically:
//   distribution_id, chain_id (as a varint-encoded field in the protobuf), iteration,
//   chain_key, signing_key_public (public key only — no signature needed), and
//   message_version. We build a SenderKeyDistributionMessage using Go's protocol
//   package and assert that the serialized bytes are byte-identical to the
//   Rust-emitted expected.serialized bytes.
//
// SenderKeyDistributionMessage serialization is fully deterministic given the
// inputs: it contains no random nonces, ephemeral keys, or signatures.
//
// Rust upstream: rust/protocol/src/group_cipher.rs (libsignal v0.92.2)

package interop

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type groupsSKDMWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			AliceDeviceID  int    `json:"alice_device_id"`
			AliceUUID      string `json:"alice_uuid"`
			ChainID        uint32 `json:"chain_id"`
			ChainKey       string `json:"chain_key"`
			DistributionID string `json:"distribution_id"`
			Iteration      uint32 `json:"iteration"`
			MessageVersion uint32 `json:"message_version"`
			SigningKeyPub  string `json:"signing_key_public"`
		} `json:"inputs"`
		Expected struct {
			Serialized string `json:"serialized"`
		} `json:"expected"`
	} `json:"vectors"`
}

// parseUUID parses a hyphenated UUID string into a [16]byte array.
// Format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (8-4-4-4-12 lowercase hex).
func parseUUID(t *testing.T, s string) [16]byte {
	t.Helper()
	// Remove hyphens and decode hex.
	clean := ""
	for _, c := range s {
		if c != '-' {
			clean += string(c)
		}
	}
	b := mustHex(t, clean)
	if len(b) != 16 {
		t.Fatalf("parseUUID: decoded %d bytes from %q, want 16", len(b), s)
	}
	var arr [16]byte
	copy(arr[:], b)
	return arr
}

// TestGroupsSKDMWire builds a SenderKeyDistributionMessage from the fixture
// inputs and asserts byte-identical serialization to the Rust-emitted expected bytes.
func TestGroupsSKDMWire(t *testing.T) {
	raw := loader.MustRead("wire/senderkey_distribution.json")

	var fx groupsSKDMWireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	serializer := serialize.NewProtobufSerializer()

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			wantBytes := mustHex(t, v.Expected.Serialized)

			// Parse the distribution ID UUID.
			distributionID := parseUUID(t, v.Inputs.DistributionID)

			// Decode chain key (32 raw bytes).
			chainKey := mustHex(t, v.Inputs.ChainKey)
			if len(chainKey) != 32 {
				t.Fatalf("chain_key: decoded %d bytes, want 32", len(chainKey))
			}

			// Decode signing public key (33 bytes: 0x05 prefix + 32 key bytes).
			signingKeyBytes := mustHex(t, v.Inputs.SigningKeyPub)
			signingKey, err := ecc.DecodePoint(signingKeyBytes, 0)
			if err != nil {
				t.Fatalf("DecodePoint signing_key_public: %v", err)
			}

			// Build the SenderKeyDistributionMessage.
			msg := protocol.NewSenderKeyDistributionMessage(
				distributionID,
				v.Inputs.ChainID,
				v.Inputs.Iteration,
				chainKey,
				signingKey,
				serializer.SenderKeyDistributionMessage,
				v.Inputs.MessageVersion,
			)

			// Serialize and compare bytes.
			got, err := msg.Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}

			// DIRECT BYTES-EQUAL: the serialized message must match Rust exactly.
			if !bytes.Equal(got, wantBytes) {
				t.Errorf("SenderKeyDistributionMessage bytes mismatch:\n  got  %x\n  want %x",
					got, wantBytes)
			}
		})
	}
}
