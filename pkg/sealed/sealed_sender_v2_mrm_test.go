//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 11 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) requires it for the Sealed Sender
// ephemeral keys, so the fips140only build tag drops this file from the FIPS
// gate. `make test` and `make coverage` still run it.

package sealed

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// buildV2Ciphertext is a test-only helper that builds a real Sealed Sender v2
// multi-recipient ciphertext for a single recipient. It is shared by the MRM
// helper tests in this file.
func buildV2Ciphertext(t *testing.T, plaintext string) ([]byte, *v2TestIdentityStore, *v2TestIdentityStore, *protocol.SignalAddress, protocol.ServiceId) {
	t.Helper()
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		2, senderCert, []byte(plaintext), ContentHintDefault, nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent: %v", err)
	}

	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil,
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt: %v", err)
	}

	bobServiceID, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	if err != nil {
		t.Fatalf("ServiceIdFromString: %v", err)
	}

	return ciphertext, aliceStore, bobStore, bobAddress, bobServiceID
}

func TestParseSealedSenderV2SentMessage_Empty(t *testing.T) {
	if _, err := ParseSealedSenderV2SentMessage(nil); err == nil {
		t.Error("expected error for nil input")
	}
	if _, err := ParseSealedSenderV2SentMessage([]byte{}); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseSealedSenderV2SentMessage_UnknownVersion(t *testing.T) {
	if _, err := ParseSealedSenderV2SentMessage([]byte{0x99, 0x00}); err == nil {
		t.Error("expected error for unknown version byte")
	}
}

func TestParseSealedSenderV2SentMessage_RecordsBufferAndVersion(t *testing.T) {
	ciphertext, _, _, _, _ := buildV2Ciphertext(t, "mrm test 1")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	if parsed.Version() != ciphertext[0] {
		t.Errorf("Version() = 0x%02x, want 0x%02x", parsed.Version(), ciphertext[0])
	}
	if got := parsed.FullMessage(); &got[0] != &ciphertext[0] || len(got) != len(ciphertext) {
		t.Error("FullMessage() should reference the input buffer")
	}
}

func TestParseSealedSenderV2SentMessage_RecipientOrderPopulated(t *testing.T) {
	ciphertext, _, _, _, bobServiceID := buildV2Ciphertext(t, "mrm test 2")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	if len(parsed.RecipientOrder) != 1 {
		t.Fatalf("RecipientOrder len = %d, want 1", len(parsed.RecipientOrder))
	}
	if parsed.RecipientOrder[0] != bobServiceID.String() {
		t.Errorf("RecipientOrder[0] = %q, want %q", parsed.RecipientOrder[0], bobServiceID.String())
	}
}

func TestOffsetOfSharedBytes_PointsAtEphemeralPublic(t *testing.T) {
	ciphertext, _, _, _, _ := buildV2Ciphertext(t, "mrm test 3")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	off, err := parsed.OffsetOfSharedBytes()
	if err != nil {
		t.Fatalf("OffsetOfSharedBytes: %v", err)
	}
	if off <= 0 || off >= len(ciphertext) {
		t.Fatalf("OffsetOfSharedBytes = %d, want 0 < x < %d", off, len(ciphertext))
	}
	// The shared region begins with the 32-byte ephemeral public key. Verify
	// those bytes match the parsed EphemeralPublic field.
	if got := ciphertext[off : off+32]; string(got) != string(parsed.EphemeralPublic) {
		t.Error("bytes at OffsetOfSharedBytes don't match EphemeralPublic")
	}
	// And the rest of the buffer is the encrypted payload.
	if got := ciphertext[off+32:]; string(got) != string(parsed.EncryptedPayload) {
		t.Error("bytes after EphemeralPublic don't match EncryptedPayload")
	}
}

func TestRangeForRecipient_BobMatchesEncryptedMAndAuthTag(t *testing.T) {
	ciphertext, _, _, _, bobServiceID := buildV2Ciphertext(t, "mrm test 4")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	start, end, err := parsed.RangeForRecipient(bobServiceID)
	if err != nil {
		t.Fatalf("RangeForRecipient: %v", err)
	}
	if end-start != v2EncryptedMKeySize+v2AuthTagSize {
		t.Errorf("range length = %d, want %d", end-start, v2EncryptedMKeySize+v2AuthTagSize)
	}
	bob := parsed.Recipients[bobServiceID.String()]
	if bob == nil {
		t.Fatal("bob recipient missing")
	}
	want := append(append([]byte(nil), bob.EncryptedMKey...), bob.AuthTag...)
	if got := ciphertext[start:end]; string(got) != string(want) {
		t.Error("range bytes don't match EncryptedMKey ‖ AuthTag")
	}
}

func TestRangeForRecipient_NotFound(t *testing.T) {
	ciphertext, _, _, _, _ := buildV2Ciphertext(t, "mrm test 5")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	stranger := protocol.NewACI([16]byte{9, 9, 9, 9})
	if _, _, err := parsed.RangeForRecipient(stranger); !errors.Is(err, ErrRecipientNotInMessage) {
		t.Errorf("expected ErrRecipientNotInMessage, got %v", err)
	}
}

func TestMessageForRecipient_Instance_DecryptsAsBob(t *testing.T) {
	ciphertext, _, bobStore, _, bobServiceID := buildV2Ciphertext(t, "mrm round trip")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}

	bobMsg, err := parsed.MessageForRecipient(bobServiceID)
	if err != nil {
		t.Fatalf("MessageForRecipient: %v", err)
	}
	if bobMsg[0] != SealedSenderV2VersionUUID {
		t.Errorf("recipient-view version = 0x%02x, want 0x%02x", bobMsg[0], SealedSenderV2VersionUUID)
	}

	// MessageForRecipient produces the ReceivedMessage format (the
	// per-client wire format), not the SentMessage / multi-recipient format,
	// so decrypt with SealedSenderV2DecryptReceivedToUSMC.
	usmc, err := SealedSenderV2DecryptReceivedToUSMC(bobMsg, bobStore)
	if err != nil {
		t.Fatalf("recipient message did not decrypt: %v", err)
	}
	if string(usmc.Contents()) != "mrm round trip" {
		t.Errorf("decrypted contents = %q, want %q", string(usmc.Contents()), "mrm round trip")
	}
}

func TestMessageForRecipient_Instance_NotFound(t *testing.T) {
	ciphertext, _, _, _, _ := buildV2Ciphertext(t, "mrm test 7")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	stranger := protocol.NewACI([16]byte{0xAA, 0xBB})
	if _, err := parsed.MessageForRecipient(stranger); !errors.Is(err, ErrRecipientNotInMessage) {
		t.Errorf("expected ErrRecipientNotInMessage, got %v", err)
	}
}

func TestSerializedRecipientView_LengthAndVersion(t *testing.T) {
	ciphertext, _, _, _, bobServiceID := buildV2Ciphertext(t, "mrm view header")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	view, err := parsed.SerializedRecipientView(bobServiceID)
	if err != nil {
		t.Fatalf("SerializedRecipientView: %v", err)
	}
	if len(view) != serializedRecipientViewSize {
		t.Errorf("view length = %d, want %d", len(view), serializedRecipientViewSize)
	}
	if view[0] != serializedRecipientViewVersion {
		t.Errorf("view version = 0x%02x, want 0x%02x", view[0], serializedRecipientViewVersion)
	}
}

func TestSerializedRecipientView_NotFound(t *testing.T) {
	ciphertext, _, _, _, _ := buildV2Ciphertext(t, "mrm test 8")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	stranger := protocol.NewACI([16]byte{0xAA, 0xBB})
	if _, err := parsed.SerializedRecipientView(stranger); !errors.Is(err, ErrRecipientNotInMessage) {
		t.Errorf("expected ErrRecipientNotInMessage, got %v", err)
	}
}

func TestMessageForRecipient_Static_RoundTripFromView(t *testing.T) {
	ciphertext, _, bobStore, _, bobServiceID := buildV2Ciphertext(t, "mrm static round trip")
	parsed, err := ParseSealedSenderV2SentMessage(ciphertext)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}
	view, err := parsed.SerializedRecipientView(bobServiceID)
	if err != nil {
		t.Fatalf("SerializedRecipientView: %v", err)
	}

	// Reconstruct the recipient's ReceivedMessage from full data + view
	// header, simulating the cache-rehydration code path.
	bobMsg, err := MessageForRecipient(ciphertext, view)
	if err != nil {
		t.Fatalf("MessageForRecipient(static): %v", err)
	}

	// Must match the instance-method output byte for byte.
	wantMsg, err := parsed.MessageForRecipient(bobServiceID)
	if err != nil {
		t.Fatalf("MessageForRecipient(instance): %v", err)
	}
	if string(bobMsg) != string(wantMsg) {
		t.Error("static MessageForRecipient does not match instance method output")
	}

	// And decrypts cleanly.
	usmc, err := SealedSenderV2DecryptReceivedToUSMC(bobMsg, bobStore)
	if err != nil {
		t.Fatalf("reconstructed message did not decrypt: %v", err)
	}
	if string(usmc.Contents()) != "mrm static round trip" {
		t.Errorf("decrypted contents = %q, want %q", string(usmc.Contents()), "mrm static round trip")
	}
}

func TestMessageForRecipient_Static_RejectsBadView(t *testing.T) {
	cases := []struct {
		name string
		view []byte
	}{
		{"too short", make([]byte, 12)},
		{"too long", make([]byte, 14)},
		{"unknown version", []byte{0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"shared offset out of range", func() []byte {
			b := make([]byte, 13)
			b[0] = serializedRecipientViewVersion
			// offsetOfSharedData = 0xFFFFFFFF
			for i := 1; i <= 4; i++ {
				b[i] = 0xFF
			}
			return b
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MessageForRecipient([]byte("anything"), tc.view); !errors.Is(err, ErrInvalidRecipientView) {
				t.Errorf("expected ErrInvalidRecipientView, got %v", err)
			}
		})
	}
}

func TestByteRangeHelpers_RequireParseFromBytes(t *testing.T) {
	// A struct constructed via v2ParseMessage (without the public Parse entry)
	// has no fullMessage reference; the helpers must surface that.
	m := &SealedSenderV2SentMessage{}
	if _, err := m.OffsetOfSharedBytes(); !errors.Is(err, ErrMessageNotParsedFromBytes) {
		t.Errorf("OffsetOfSharedBytes: expected ErrMessageNotParsedFromBytes, got %v", err)
	}
	if _, _, err := m.RangeForRecipient(protocol.NewACI([16]byte{1})); !errors.Is(err, ErrMessageNotParsedFromBytes) {
		t.Errorf("RangeForRecipient: expected ErrMessageNotParsedFromBytes, got %v", err)
	}
	if _, err := m.MessageForRecipient(protocol.NewACI([16]byte{1})); !errors.Is(err, ErrMessageNotParsedFromBytes) {
		t.Errorf("MessageForRecipient: expected ErrMessageNotParsedFromBytes, got %v", err)
	}
	if _, err := m.SerializedRecipientView(protocol.NewACI([16]byte{1})); !errors.Is(err, ErrMessageNotParsedFromBytes) {
		t.Errorf("SerializedRecipientView: expected ErrMessageNotParsedFromBytes, got %v", err)
	}
}

// TestParseSealedSenderV2SentMessage_ExcludedRecipientInMap verifies that
// excluded recipients (device_id == 0 wire entry) are inserted into the
// Recipients map with empty DeviceIDs and zero KeyMaterialLength, rather
// than being silently dropped. This matches Rust's IndexMap insert for
// devices:[] and c_and_at:[] entries.
func TestParseSealedSenderV2SentMessage_ExcludedRecipientInMap(t *testing.T) {
	aliceStore, _, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)
	senderCert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}
	usmc, err := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("hello"), ContentHintDefault, nil)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent: %v", err)
	}

	bobSID, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())

	// Encrypt with Bob as BOTH a destination AND an excluded recipient so the
	// wire message has one active entry + one excluded entry.
	ciphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		[]protocol.ServiceId{bobSID},
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt: %v", err)
	}

	// Build a second ciphertext where Bob is excluded only (no active destinations)
	// by passing an empty destinations list.
	excludedOnlyCT, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{},
		[]*record.Session{},
		[]protocol.ServiceId{bobSID},
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt (excluded only): %v", err)
	}

	parsed, err := ParseSealedSenderV2SentMessage(excludedOnlyCT)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}

	// Bob must be present in the Recipients map even though he is excluded.
	recip, ok := parsed.Recipients[bobSID.String()]
	if !ok {
		t.Fatal("excluded recipient must be present in Recipients map")
	}
	if len(recip.DeviceIDs) != 0 {
		t.Errorf("excluded recipient DeviceIDs must be empty, got %v", recip.DeviceIDs)
	}
	if recip.KeyMaterialLength != 0 {
		t.Errorf("excluded recipient KeyMaterialLength must be 0, got %d", recip.KeyMaterialLength)
	}
	// Bob must also appear in RecipientOrder.
	found := false
	for _, key := range parsed.RecipientOrder {
		if key == bobSID.String() {
			found = true
			break
		}
	}
	if !found {
		t.Error("excluded recipient must appear in RecipientOrder")
	}

	// RangeForRecipient returns (0,0) for excluded recipients (no key material).
	start, end, err := parsed.RangeForRecipient(bobSID)
	if err != nil {
		t.Fatalf("RangeForRecipient: %v", err)
	}
	if start != 0 || end != 0 {
		t.Errorf("RangeForRecipient for excluded recipient: got (%d,%d), want (0,0)", start, end)
	}

	// Suppress "ciphertext declared and not used" warning.
	_ = ciphertext
}

// TestParseSealedSenderV2SentMessage_NoRecipientCountCap verifies that
// v2ParseMessage does not reject messages based on recipient count alone.
// Rust caps only its IndexMap preallocation at 6000 but parses any count.
// We craft a minimal wire message with a large varint count but only one
// real recipient so the parse succeeds without truncation errors.
func TestParseSealedSenderV2SentMessage_NoRecipientCountCap(t *testing.T) {
	// Build a valid v2 wire body with varint count = 10001 but only 1
	// actual recipient block + ephemeral public key + ciphertext bytes.
	// The parser must not return "recipient count too large" for 10001 entries.
	// Instead it will fail with "truncated" after reading the first recipient
	// because there are no more bytes — which proves the count cap is gone.
	var body []byte

	// Recipient count varint = 10001.
	var countBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(countBuf[:], 10001)
	body = append(body, countBuf[:n]...)

	// One excluded recipient: 17-byte service ID + device_id=0.
	body = append(body, make([]byte, v2ServiceIdSize)...) // zero service ID
	body = append(body, 0x00)                             // device_id=0 → excluded

	// The remaining 10000 expected entries are missing, so the parse will
	// return a "truncated" error — NOT "recipient count too large".
	full := append([]byte{byte(SealedSenderV2VersionServiceId)}, body...)
	_, err := ParseSealedSenderV2SentMessage(full)
	if err == nil {
		t.Fatal("expected parse error (truncated), got nil")
	}
	errStr := err.Error()
	if errStr == "sealed: recipient count too large: 10001" {
		t.Error("parser must not reject messages based on recipient count; got cap error")
	}
}
