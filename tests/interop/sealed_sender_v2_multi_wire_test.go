// Sealed Sender v2 multi-recipient parity: MessageForRecipient on the parsed Rust message must equal each Rust received-format view.

package interop

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/sealed"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type sealedSenderV2MultiWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			AliceDeviceID        int    `json:"alice_device_id"`
			AliceE164            string `json:"alice_e164"`
			AliceIdentityPrivate string `json:"alice_identity_private"`
			AliceIdentityPublic  string `json:"alice_identity_public"`
			AliceUUID            string `json:"alice_uuid"`
			BobDeviceID          int    `json:"bob_device_id"`
			BobIdentityPublic    string `json:"bob_identity_public"`
			BobUUID              string `json:"bob_uuid"`
			CarolDeviceID        int    `json:"carol_device_id"`
			CarolIdentityPublic  string `json:"carol_identity_public"`
			CarolUUID            string `json:"carol_uuid"`
			CertExpiryMs         int64  `json:"cert_expiry_ms"`
			DaveDeviceID         int    `json:"dave_device_id"`
			DaveIdentityPublic   string `json:"dave_identity_public"`
			DaveUUID             string `json:"dave_uuid"`
			Plaintext            string `json:"plaintext"`
			SenderCertSerialized string `json:"sender_cert_serialized"`
			TrustRootPublicKey   string `json:"trust_root_public_key"`
		} `json:"inputs"`
		Expected struct {
			BobReceivedMessage   string `json:"bob_received_message"`
			CarolReceivedMessage string `json:"carol_received_message"`
			DaveReceivedMessage  string `json:"dave_received_message"`
			SentMessage          string `json:"sent_message"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestSealedSenderV2MultiWire parses the Rust-emitted sent message and asserts
// that Go's MessageForRecipient produces byte-identical per-recipient views.
func TestSealedSenderV2MultiWire(t *testing.T) {
	raw := loader.MustRead("wire/sealed_sender_v2_multi.json")

	var fx sealedSenderV2MultiWireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			sentBytes := mustHex(t, v.Expected.SentMessage)
			wantBob := mustHex(t, v.Expected.BobReceivedMessage)
			wantCarol := mustHex(t, v.Expected.CarolReceivedMessage)
			wantDave := mustHex(t, v.Expected.DaveReceivedMessage)

			// Version byte must be 0x23 (v2 ServiceId format for multi-recipient).
			if len(sentBytes) < 1 {
				t.Fatal("sent message is empty")
			}
			if sentBytes[0] != sealed.SealedSenderV2VersionServiceId {
				t.Errorf("sent_message version: got 0x%02x, want 0x%02x (v2 ServiceId)",
					sentBytes[0], sealed.SealedSenderV2VersionServiceId)
			}

			// Parse the Rust-emitted sent message.
			parsed, err := sealed.ParseSealedSenderV2SentMessage(sentBytes)
			if err != nil {
				t.Fatalf("ParseSealedSenderV2SentMessage: %v\n  sent: %x", err, sentBytes)
			}

			// Build ServiceId objects for Bob, Carol, Dave.
			bobSID, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, v.Inputs.BobUUID)
			if err != nil {
				t.Fatalf("ServiceIdFromString(bob): %v", err)
			}
			carolSID, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, v.Inputs.CarolUUID)
			if err != nil {
				t.Fatalf("ServiceIdFromString(carol): %v", err)
			}
			daveSID, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, v.Inputs.DaveUUID)
			if err != nil {
				t.Fatalf("ServiceIdFromString(dave): %v", err)
			}

			// Each recipient must be present in the parsed message.
			recipients := []struct {
				name string
				sid  protocol.ServiceId
				want []byte
			}{
				{"bob", bobSID, wantBob},
				{"carol", carolSID, wantCarol},
				{"dave", daveSID, wantDave},
			}

			for _, r := range recipients {
				r := r
				t.Run(r.name, func(t *testing.T) {
					// MessageForRecipient must equal the Rust received-format view.
					got, err := parsed.MessageForRecipient(r.sid)
					if err != nil {
						t.Fatalf("MessageForRecipient(%s): %v", r.name, err)
					}
					if !bytes.Equal(got, r.want) {
						t.Errorf("MessageForRecipient(%s) mismatch:\n  got  %x\n  want %x",
							r.name, got, r.want)
					}
				})
			}

			// Also verify the received message version bytes are 0x22 (UUID format).
			// The received-format always uses 0x22 regardless of the sent version.
			for _, r := range recipients {
				view := mustHex(t, map[string]string{
					"bob":   v.Expected.BobReceivedMessage,
					"carol": v.Expected.CarolReceivedMessage,
					"dave":  v.Expected.DaveReceivedMessage,
				}[r.name])
				if len(view) < 1 || view[0] != sealed.SealedSenderV2VersionUUID {
					t.Errorf("%s received version: got 0x%02x, want 0x%02x",
						r.name, view[0], sealed.SealedSenderV2VersionUUID)
				}
			}

			t.Logf("v2 multi wire: bytes-equal MessageForRecipient passed (%d recipients)",
				len(parsed.Recipients))
		})
	}
}
