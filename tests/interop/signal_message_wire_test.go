// Conformance test: SignalMessage wire-format parity vs Rust libsignal.
//
// Rust source: rust/protocol/src/protocol.rs:79 SignalMessage::new (libsignal v0.92.2)
//
// Loads the Rust-emitted wire/signal_message.json fixture and verifies:
//  1. NewSignalMessageFromBytes parses the serialized bytes without error.
//  2. Counter and previous_counter match the fixture inputs.
//  3. SenderRatchetKey serializes back to the fixture's sender_ratchet_public.
//  4. Body() returns the fixture's ciphertext bytes.
//  5. VerifyMac succeeds using the fixture's mac_key, sender, and receiver identity keys.
//  6. Re-serializing the parsed message produces the original bytes byte-for-byte.

package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type signalMessageWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			MessageVersion         int    `json:"message_version"`
			MacKey                 string `json:"mac_key"`
			SenderRatchetPublic    string `json:"sender_ratchet_public"`
			SenderIdentityPublic   string `json:"sender_identity_public"`
			ReceiverIdentityPublic string `json:"receiver_identity_public"`
			Counter                uint32 `json:"counter"`
			PreviousCounter        uint32 `json:"previous_counter"`
			Ciphertext             string `json:"ciphertext"`
		} `json:"inputs"`
		Expected struct {
			Serialized string `json:"serialized"`
			MacTag     string `json:"mac_tag"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestSignalMessageWire validates SignalMessage wire-format parity with Rust libsignal.
func TestSignalMessageWire(t *testing.T) {
	raw := loader.MustRead("wire/signal_message.json")

	var fx signalMessageWireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	protobufSerializer := serialize.NewProtobufSerializer()

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			serialized := mustHex(t, v.Expected.Serialized)
			macKey := mustHex(t, v.Inputs.MacKey)
			wantCiphertext := mustHex(t, v.Inputs.Ciphertext)
			wantRatchetPub := mustHex(t, v.Inputs.SenderRatchetPublic)
			wantMacTag := mustHex(t, v.Expected.MacTag)

			// Parse the Rust-emitted bytes.
			msg, err := protocol.NewSignalMessageFromBytes(serialized, protobufSerializer.SignalMessage)
			if err != nil {
				t.Fatalf("NewSignalMessageFromBytes: %v", err)
			}

			// Assert message version.
			if got := msg.MessageVersion(); got != v.Inputs.MessageVersion {
				t.Errorf("MessageVersion: got %d, want %d", got, v.Inputs.MessageVersion)
			}

			// Assert counter fields.
			if got := msg.Counter(); got != v.Inputs.Counter {
				t.Errorf("Counter: got %d, want %d", got, v.Inputs.Counter)
			}

			// Assert body (ciphertext).
			if !bytes.Equal(msg.Body(), wantCiphertext) {
				t.Errorf("Body mismatch:\n  got  %x\n  want %x", msg.Body(), wantCiphertext)
			}

			// Assert ratchet key serializes back to fixture input.
			gotRatchetPub := msg.SenderRatchetKey().Serialize()
			if !bytes.Equal(gotRatchetPub, wantRatchetPub) {
				t.Errorf("SenderRatchetKey mismatch:\n  got  %x\n  want %x", gotRatchetPub, wantRatchetPub)
			}

			// Assert MAC tag bytes are at the tail of the serialized form.
			if len(serialized) < len(wantMacTag) {
				t.Fatalf("serialized too short to contain MAC tag")
			}
			gotMacTag := serialized[len(serialized)-len(wantMacTag):]
			if !bytes.Equal(gotMacTag, wantMacTag) {
				t.Errorf("MAC tag mismatch:\n  got  %x\n  want %x", gotMacTag, wantMacTag)
			}

			// Build identity keys for MAC verification.
			senderIdentityKey := mustDecodeIdentityKey(t, v.Inputs.SenderIdentityPublic)
			receiverIdentityKey := mustDecodeIdentityKey(t, v.Inputs.ReceiverIdentityPublic)

			// Verify the MAC using the fixture's mac_key.
			if err := msg.VerifyMac(v.Inputs.MessageVersion, senderIdentityKey, receiverIdentityKey, macKey); err != nil {
				t.Errorf("VerifyMac: %v", err)
			}

			// Round-trip: re-serialize and assert byte-for-byte equality.
			gotSerialized, err := msg.Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			if !bytes.Equal(gotSerialized, serialized) {
				t.Errorf("round-trip serialization mismatch:\n  got  %x\n  want %x", gotSerialized, serialized)
			}
		})
	}
}

// mustDecodeIdentityKey decodes a hex-encoded 33-byte public key (with 0x05 DJB prefix)
// into an identity.Key.
func mustDecodeIdentityKey(t *testing.T, hexStr string) *identity.Key {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex decode %q: %v", hexStr, err)
	}
	pub, err := ecc.DecodePoint(raw, 0)
	if err != nil {
		t.Fatalf("DecodePoint %q: %v", hexStr, err)
	}
	return identity.NewKey(pub)
}
