package protocol

import (
	"bytes"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// ServiceIdFromServiceIdString
// ---------------------------------------------------------------------------

// TestServiceIdFromServiceIdString_ACI verifies that a bare hyphenated UUID
// parses to an ACI and round-trips through String() without an "ACI:" prefix.
// Rust rejects the "ACI:" prefix form; String() for ACI returns a bare UUID.
func TestServiceIdFromServiceIdString_ACI(t *testing.T) {
	// Rust canonical form: bare UUID for ACI (no "ACI:" prefix).
	const bare = "550e8400-e29b-41d4-a716-446655440000"
	sid, err := ServiceIdFromServiceIdString(bare)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid.Kind() != ServiceIdKindACI {
		t.Fatalf("expected ACI kind, got %v", sid.Kind())
	}
	// String() must return the bare UUID (no "ACI:" prefix) to match Rust.
	if sid.String() != bare {
		t.Fatalf("String() mismatch: got %q want %q", sid.String(), bare)
	}
}

// TestServiceIdFromServiceIdString_ACIPrefix_Accepted verifies that the legacy
// "ACI:<uuid>" form is accepted (Postel's law: lenient input). String() still
// emits only the bare UUID, never the "ACI:" prefix.
func TestServiceIdFromServiceIdString_ACIPrefix_Accepted(t *testing.T) {
	const aciPrefixed = "ACI:550e8400-e29b-41d4-a716-446655440000"
	const bareUUID = "550e8400-e29b-41d4-a716-446655440000"
	sid, err := ServiceIdFromServiceIdString(aciPrefixed)
	if err != nil {
		t.Fatalf("expected success for legacy ACI:-prefixed input, got error: %v", err)
	}
	if sid.Kind() != ServiceIdKindACI {
		t.Fatalf("expected ACI kind, got %v", sid.Kind())
	}
	// String() must emit the bare UUID, never "ACI:".
	if sid.String() != bareUUID {
		t.Fatalf("String() must emit bare UUID, got %q", sid.String())
	}
}

func TestServiceIdFromServiceIdString_PNI(t *testing.T) {
	const raw = "PNI:550e8400-e29b-41d4-a716-446655440001"
	sid, err := ServiceIdFromServiceIdString(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid.Kind() != ServiceIdKindPNI {
		t.Fatalf("expected PNI kind, got %v", sid.Kind())
	}
	if sid.String() != raw {
		t.Fatalf("String() mismatch: got %q want %q", sid.String(), raw)
	}
}

func TestServiceIdFromServiceIdString_BareUUID_DefaultsToACI(t *testing.T) {
	const bare = "550e8400-e29b-41d4-a716-446655440000"
	sid, err := ServiceIdFromServiceIdString(bare)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid.Kind() != ServiceIdKindACI {
		t.Fatalf("bare UUID should default to ACI, got %v", sid.Kind())
	}
}

func TestServiceIdFromServiceIdString_InvalidUUID(t *testing.T) {
	cases := []string{
		"",
		"ACI:", // "ACI:" with no UUID → rejected
		"PNI:",
		"ACI:not-a-uuid", // "ACI:" prefix with malformed UUID → rejected
		"bogus",
		"ACI:550e8400-e29b-41d4", // "ACI:" prefix with truncated UUID → rejected
		"aci:550e8400-e29b-41d4-a716-446655440000", // lowercase prefix → rejected (case-sensitive)
		"550e8400e29b41d4a716446655440000",         // 32-char unhyphenated form is rejected
	}
	for _, c := range cases {
		_, err := ServiceIdFromServiceIdString(c)
		if err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
		var parseErr *ServiceIdParseError
		if !errors.As(err, &parseErr) {
			t.Errorf("expected *ServiceIdParseError for %q, got %T", c, err)
		}
	}
}

// ---------------------------------------------------------------------------
// SerializeAddresses
// ---------------------------------------------------------------------------

func TestSerializeAddresses_ACIAndACI(t *testing.T) {
	// ACI addresses use bare UUID (no "ACI:" prefix) per Rust canonical format.
	sender := NewSignalAddress("550e8400-e29b-41d4-a716-446655440000", 1)
	recipient := NewSignalAddress("550e8400-e29b-41d4-a716-446655440001", 2)

	buf := SerializeAddresses(sender, recipient)
	if buf == nil {
		t.Fatal("expected non-nil bytes for valid ACI+ACI addresses")
	}
	if len(buf) != 36 {
		t.Fatalf("expected 36 bytes, got %d", len(buf))
	}

	// Verify device ID byte positions.
	if buf[17] != byte(sender.DeviceID()) {
		t.Fatalf("sender device ID byte mismatch: got %d want %d", buf[17], sender.DeviceID())
	}
	if buf[35] != byte(recipient.DeviceID()) {
		t.Fatalf("recipient device ID byte mismatch: got %d want %d", buf[35], recipient.DeviceID())
	}

	// Verify kind bytes at positions 0 and 18 (ACI = 0x00).
	if buf[0] != byte(ServiceIdKindACI) {
		t.Fatalf("sender kind byte: expected 0x00, got 0x%02x", buf[0])
	}
	if buf[18] != byte(ServiceIdKindACI) {
		t.Fatalf("recipient kind byte: expected 0x00, got 0x%02x", buf[18])
	}
}

func TestSerializeAddresses_PNIAndACI(t *testing.T) {
	// ACI addresses use bare UUID; PNI uses "PNI:" prefix.
	sender := NewSignalAddress("PNI:550e8400-e29b-41d4-a716-446655440002", 3)
	recipient := NewSignalAddress("550e8400-e29b-41d4-a716-446655440003", 4)

	buf := SerializeAddresses(sender, recipient)
	if buf == nil {
		t.Fatal("expected non-nil bytes for valid PNI+ACI addresses")
	}
	if len(buf) != 36 {
		t.Fatalf("expected 36 bytes, got %d", len(buf))
	}
	// Sender is PNI (0x01) at position 0.
	if buf[0] != byte(ServiceIdKindPNI) {
		t.Fatalf("sender kind byte: expected 0x01 (PNI), got 0x%02x", buf[0])
	}
	// Recipient is ACI (0x00) at position 18.
	if buf[18] != byte(ServiceIdKindACI) {
		t.Fatalf("recipient kind byte: expected 0x00 (ACI), got 0x%02x", buf[18])
	}
}

func TestSerializeAddresses_MalformedSenderName(t *testing.T) {
	sender := NewSignalAddress("not-a-service-id", 1)
	recipient := NewSignalAddress("ACI:550e8400-e29b-41d4-a716-446655440001", 2)
	if buf := SerializeAddresses(sender, recipient); buf != nil {
		t.Fatalf("expected nil for malformed sender name, got %d bytes", len(buf))
	}
}

func TestSerializeAddresses_MalformedRecipientName(t *testing.T) {
	sender := NewSignalAddress("ACI:550e8400-e29b-41d4-a716-446655440000", 1)
	recipient := NewSignalAddress("also-not-a-service-id", 2)
	if buf := SerializeAddresses(sender, recipient); buf != nil {
		t.Fatalf("expected nil for malformed recipient name, got %d bytes", len(buf))
	}
}

func TestSerializeAddresses_Deterministic(t *testing.T) {
	sender := NewSignalAddress("ACI:550e8400-e29b-41d4-a716-446655440000", 1)
	recipient := NewSignalAddress("ACI:550e8400-e29b-41d4-a716-446655440001", 2)

	a := SerializeAddresses(sender, recipient)
	b := SerializeAddresses(sender, recipient)
	if !bytes.Equal(a, b) {
		t.Fatal("SerializeAddresses is not deterministic")
	}
}

// ---------------------------------------------------------------------------
// SignalMessage addresses field roundtrip and VerifyMacWithAddresses
// ---------------------------------------------------------------------------

const (
	testSenderUUID    = "550e8400-e29b-41d4-a716-446655440000"
	testRecipientUUID = "550e8400-e29b-41d4-a716-446655440001"
)

// newSignalMessageWithAddresses creates a test SignalMessage with addresses bound.
func newSignalMessageWithAddresses(t *testing.T, sender, recipient *SignalAddress) (*SignalMessage, []byte) {
	t.Helper()
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	for i := range macKey {
		macKey[i] = byte(i + 1)
	}

	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("ciphertext"),
		senderIdentity, receiverIdentity, serializer,
		nil, // pqRatchetMsg
		sender, recipient,
	)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}
	return msg, macKey
}

func TestSignalMessageAddressesRoundtrip(t *testing.T) {
	// ACI canonical form: bare UUID (no "ACI:" prefix).
	sender := NewSignalAddress(testSenderUUID, 1)
	recipient := NewSignalAddress(testRecipientUUID, 2)

	msg, _ := newSignalMessageWithAddresses(t, sender, recipient)

	if msg.Addresses() == nil {
		t.Fatal("Addresses() should be non-nil when addresses were supplied")
	}
	if len(msg.Addresses()) != 36 {
		t.Fatalf("Addresses() length: expected 36, got %d", len(msg.Addresses()))
	}

	// Serialize then deserialize via the serializer.
	serializer := &jsonSignalMessageSerializer{}
	raw, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	msg2, err := NewSignalMessageFromBytes(raw, serializer)
	if err != nil {
		t.Fatalf("NewSignalMessageFromBytes: %v", err)
	}

	if !bytes.Equal(msg.Addresses(), msg2.Addresses()) {
		t.Fatal("Addresses field not preserved after serialize/deserialize roundtrip")
	}
}

func TestSignalMessageNoAddresses_BackwardCompat(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderIdentity := newTestIdentityKey(t)
	receiverIdentity := newTestIdentityKey(t)

	macKey := make([]byte, 32)
	// Message without addresses (old-style).
	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, macKey,
		ratchetKey.PublicKey(), []byte("ciphertext"),
		senderIdentity, receiverIdentity, serializer,
		nil,      // pqRatchetMsg
		nil, nil, // no addresses
	)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}

	if msg.Addresses() != nil {
		t.Fatal("Addresses() should be nil when no addresses were supplied")
	}

	// VerifyMacWithAddresses must accept (nil addresses = backward compat).
	// ACI canonical form: bare UUID (no "ACI:" prefix).
	sender := NewSignalAddress(testSenderUUID, 1)
	recipient := NewSignalAddress(testRecipientUUID, 2)
	if err := msg.VerifyMacWithAddresses(
		CurrentVersion, senderIdentity, receiverIdentity, macKey, sender, recipient,
	); err != nil {
		t.Fatalf("VerifyMacWithAddresses should accept message without addresses: %v", err)
	}
}

func TestVerifyMacWithAddresses_Match(t *testing.T) {
	sender := NewSignalAddress(testSenderUUID, 1)
	recipient := NewSignalAddress(testRecipientUUID, 2)

	msg, macKey := newSignalMessageWithAddresses(t, sender, recipient)

	senderIdentity := msg.structure.RatchetKey // not used for identity check here
	_ = senderIdentity

	// Re-create identity keys from what was used during construction.
	// We need the actual keys used for MAC. Use a fresh message with known keys.
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	sid := newTestIdentityKey(t)
	rid := newTestIdentityKey(t)

	mk := make([]byte, 32)
	for i := range mk {
		mk[i] = byte(i + 5)
	}

	msg2, err := NewSignalMessage(
		CurrentVersion, 1, 0, mk,
		ratchetKey.PublicKey(), []byte("body"),
		sid, rid, serializer,
		nil, // pqRatchetMsg
		sender, recipient,
	)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}

	if err := msg2.VerifyMacWithAddresses(CurrentVersion, sid, rid, mk, sender, recipient); err != nil {
		t.Fatalf("VerifyMacWithAddresses should succeed on match: %v", err)
	}
	_ = macKey
}

func TestVerifyMacWithAddresses_AddressMismatch(t *testing.T) {
	sender := NewSignalAddress(testSenderUUID, 1)
	recipient := NewSignalAddress(testRecipientUUID, 2)
	wrongRecipient := NewSignalAddress("550e8400-e29b-41d4-a716-446655440099", 2)

	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	sid := newTestIdentityKey(t)
	rid := newTestIdentityKey(t)

	mk := make([]byte, 32)
	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, mk,
		ratchetKey.PublicKey(), []byte("body"),
		sid, rid, serializer,
		nil, // pqRatchetMsg
		sender, recipient,
	)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}

	// Wrong recipient → mismatch.
	err = msg.VerifyMacWithAddresses(CurrentVersion, sid, rid, mk, sender, wrongRecipient)
	if err == nil {
		t.Fatal("expected error for address mismatch")
	}
	if !errors.Is(err, ErrAddressMismatch) {
		t.Fatalf("expected ErrAddressMismatch, got %T: %v", err, err)
	}
}

func TestVerifyMacWithAddresses_BadMac(t *testing.T) {
	sender := NewSignalAddress(testSenderUUID, 1)
	recipient := NewSignalAddress(testRecipientUUID, 2)

	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	sid := newTestIdentityKey(t)
	rid := newTestIdentityKey(t)

	mk := make([]byte, 32)
	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, mk,
		ratchetKey.PublicKey(), []byte("body"),
		sid, rid, serializer,
		nil, // pqRatchetMsg
		sender, recipient,
	)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}

	wrongMk := make([]byte, 32)
	wrongMk[0] = 0xFF

	err = msg.VerifyMacWithAddresses(CurrentVersion, sid, rid, wrongMk, sender, recipient)
	if err == nil {
		t.Fatal("expected error for bad MAC")
	}
	if !errors.Is(err, ErrBadMac) {
		t.Fatalf("expected ErrBadMac, got %T: %v", err, err)
	}
}

func TestVerifyMacWithAddresses_LocalAddressesNotValidServiceId(t *testing.T) {
	sender := NewSignalAddress(testSenderUUID, 1)
	recipient := NewSignalAddress(testRecipientUUID, 2)

	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	sid := newTestIdentityKey(t)
	rid := newTestIdentityKey(t)

	mk := make([]byte, 32)
	msg, err := NewSignalMessage(
		CurrentVersion, 1, 0, mk,
		ratchetKey.PublicKey(), []byte("body"),
		sid, rid, serializer,
		nil, // pqRatchetMsg
		sender, recipient,
	)
	if err != nil {
		t.Fatalf("NewSignalMessage: %v", err)
	}

	// Supply a locally-invalid address name → SerializeAddresses returns nil → mismatch.
	invalidSender := NewSignalAddress("not-a-service-id", 1)
	err = msg.VerifyMacWithAddresses(CurrentVersion, sid, rid, mk, invalidSender, recipient)
	if err == nil {
		t.Fatal("expected error when local sender is not a valid ServiceId")
	}
	if !errors.Is(err, ErrAddressMismatch) {
		t.Fatalf("expected ErrAddressMismatch, got %T: %v", err, err)
	}
}
