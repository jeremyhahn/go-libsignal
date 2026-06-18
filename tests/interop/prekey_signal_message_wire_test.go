// Conformance test: PreKeySignalMessage wire-format parity vs Rust libsignal.
//
// Rust source: rust/protocol/src/protocol.rs:352 PreKeySignalMessage::new (libsignal v0.92.2)
//
// Loads the Rust-emitted wire/prekey_signal_message.json fixture and verifies:
//  1. NewPreKeySignalMessageFromBytes parses the serialized bytes without error.
//  2. MessageVersion, RegistrationID, PreKeyID, SignedPreKeyID match fixture inputs.
//  3. BaseKey and IdentityKey serialize back to fixture input bytes.
//  4. The inner WhisperMessage MAC verifies with the fixture's mac_key.
//  5. Re-serializing the parsed message produces the original bytes byte-for-byte.

package interop

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type preKeySignalMessageWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			MessageVersion         int    `json:"message_version"`
			RegistrationID         uint32 `json:"registration_id"`
			PreKeyID               uint32 `json:"pre_key_id"`
			SignedPreKeyID         uint32 `json:"signed_pre_key_id"`
			BaseKeyPublic          string `json:"base_key_public"`
			IdentityKeyPublic      string `json:"identity_key_public"`
			MacKey                 string `json:"mac_key"`
			RatchetKeyPublic       string `json:"ratchet_key_public"`
			SenderIdentityPublic   string `json:"sender_identity_public"`
			ReceiverIdentityPublic string `json:"receiver_identity_public"`
			InnerCounter           uint32 `json:"inner_counter"`
			InnerPreviousCounter   uint32 `json:"inner_previous_counter"`
			InnerCiphertext        string `json:"inner_ciphertext"`
		} `json:"inputs"`
		Expected struct {
			Serialized string `json:"serialized"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestPreKeySignalMessageWire validates PreKeySignalMessage wire parity with Rust libsignal.
func TestPreKeySignalMessageWire(t *testing.T) {
	raw := loader.MustRead("wire/prekey_signal_message.json")

	var fx preKeySignalMessageWireFixture
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
			wantBaseKey := mustHex(t, v.Inputs.BaseKeyPublic)
			wantIdentityKey := mustHex(t, v.Inputs.IdentityKeyPublic)
			wantRatchetPub := mustHex(t, v.Inputs.RatchetKeyPublic)
			wantInnerCiphertext := mustHex(t, v.Inputs.InnerCiphertext)

			// Parse the Rust-emitted bytes.
			msg, err := protocol.NewPreKeySignalMessageFromBytes(
				serialized,
				protobufSerializer.PreKeySignalMessage,
				protobufSerializer.SignalMessage,
			)
			if err != nil {
				t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
			}

			// Assert top-level fields.
			if got := msg.MessageVersion(); got != v.Inputs.MessageVersion {
				t.Errorf("MessageVersion: got %d, want %d", got, v.Inputs.MessageVersion)
			}
			if got := msg.RegistrationID(); got != v.Inputs.RegistrationID {
				t.Errorf("RegistrationID: got %d, want %d", got, v.Inputs.RegistrationID)
			}

			// PreKeyID is optional; the fixture always supplies one.
			if pkid := msg.PreKeyID(); pkid == nil || pkid.IsEmpty {
				t.Error("PreKeyID: expected non-empty optional, got nil or empty")
			} else if got := pkid.Value; got != v.Inputs.PreKeyID {
				t.Errorf("PreKeyID: got %d, want %d", got, v.Inputs.PreKeyID)
			}

			if got := msg.SignedPreKeyID(); got != v.Inputs.SignedPreKeyID {
				t.Errorf("SignedPreKeyID: got %d, want %d", got, v.Inputs.SignedPreKeyID)
			}

			// Assert BaseKey round-trips.
			gotBaseKey := msg.BaseKey().Serialize()
			if !bytes.Equal(gotBaseKey, wantBaseKey) {
				t.Errorf("BaseKey mismatch:\n  got  %x\n  want %x", gotBaseKey, wantBaseKey)
			}

			// Assert IdentityKey round-trips.
			gotIdentityKey := msg.IdentityKey().PublicKey().Serialize()
			if !bytes.Equal(gotIdentityKey, wantIdentityKey) {
				t.Errorf("IdentityKey mismatch:\n  got  %x\n  want %x", gotIdentityKey, wantIdentityKey)
			}

			// Assert the inner WhisperMessage fields.
			inner := msg.WhisperMessage()
			if inner == nil {
				t.Fatal("WhisperMessage: nil")
			}
			if got := inner.Counter(); got != v.Inputs.InnerCounter {
				t.Errorf("inner Counter: got %d, want %d", got, v.Inputs.InnerCounter)
			}

			// Assert inner ratchet key.
			gotRatchetPub := inner.SenderRatchetKey().Serialize()
			if !bytes.Equal(gotRatchetPub, wantRatchetPub) {
				t.Errorf("inner RatchetKey mismatch:\n  got  %x\n  want %x", gotRatchetPub, wantRatchetPub)
			}

			// Assert inner ciphertext body.
			if !bytes.Equal(inner.Body(), wantInnerCiphertext) {
				t.Errorf("inner Body mismatch:\n  got  %x\n  want %x", inner.Body(), wantInnerCiphertext)
			}

			// Verify the inner MAC using fixture keys.
			senderIdentityKey := mustDecodeIdentityKey(t, v.Inputs.SenderIdentityPublic)
			receiverIdentityKey := mustDecodeIdentityKey(t, v.Inputs.ReceiverIdentityPublic)
			if err := inner.VerifyMac(v.Inputs.MessageVersion, senderIdentityKey, receiverIdentityKey, macKey); err != nil {
				t.Errorf("inner VerifyMac: %v", err)
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
