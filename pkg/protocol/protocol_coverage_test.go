package protocol

import (
	"testing"
)

// TestSenderKeyDistributionMessage_DistributionID verifies DistributionID() accessor.
func TestSenderKeyDistributionMessage_DistributionID(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}
	signingKey := newTestKeyPair(t)

	var distID [16]byte
	for i := range distID {
		distID[i] = byte(i + 1)
	}

	structure := &SenderKeyDistributionMessageStructure{
		ID:             42,
		Iteration:      7,
		ChainKey:       validChainKey(),
		SigningKey:     signingKey.PublicKey().Serialize(),
		Version:        SenderKeyCurrentVersion,
		DistributionID: distID,
	}

	msg, err := NewSenderKeyDistributionMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := msg.DistributionID()
	if got != distID {
		t.Errorf("DistributionID() = %v, want %v", got, distID)
	}
}

// TestSenderKeyMessage_DistributionID verifies DistributionID() accessor.
func TestSenderKeyMessage_DistributionID(t *testing.T) {
	serializer := &jsonSenderKeyMessageSerializer{}

	var distID [16]byte
	for i := range distID {
		distID[i] = byte(i + 100)
	}

	structure := &SenderKeyMessageStructure{
		ID:             5,
		Iteration:      3,
		CipherText:     []byte("cipher"),
		Version:        SenderKeyCurrentVersion,
		Signature:      []byte("sig"),
		DistributionID: distID,
	}

	msg, err := NewSenderKeyMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := msg.DistributionID()
	if got != distID {
		t.Errorf("DistributionID() = %v, want %v", got, distID)
	}
}

// TestSignalMessage_PqRatchetKey_WhenNil verifies PqRatchetKey returns nil when absent.
func TestSignalMessage_PqRatchetKey_WhenNil(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)

	structure := &SignalMessageStructure{
		Version:    CurrentVersion,
		Counter:    1,
		RatchetKey: ratchetKey.PublicKey().Serialize(),
		CipherText: []byte("test ct"),
		// PqRatchetKey intentionally absent.
	}

	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg.PqRatchetKey() != nil {
		t.Error("PqRatchetKey() should return nil when not set")
	}
}

// TestSignalMessage_PqRatchetKey_WhenPresent verifies PqRatchetKey returns the bytes when set.
func TestSignalMessage_PqRatchetKey_WhenPresent(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	pqKey := []byte{0xAA, 0xBB, 0xCC}

	structure := &SignalMessageStructure{
		Version:      CurrentVersion,
		Counter:      1,
		RatchetKey:   ratchetKey.PublicKey().Serialize(),
		CipherText:   []byte("test ct"),
		PqRatchetKey: pqKey,
	}

	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := msg.PqRatchetKey()
	if len(got) != 3 || got[0] != 0xAA {
		t.Errorf("PqRatchetKey() = %v, want %v", got, pqKey)
	}
}

// TestSignalMessage_VerifyMac_InvalidMacKeyLength verifies the error path for short MAC keys.
func TestSignalMessage_VerifyMac_InvalidMacKeyLength(t *testing.T) {
	serializer := &jsonSignalMessageSerializer{}
	ratchetKey := newTestKeyPair(t)
	senderKey := newTestIdentityKey(t)
	receiverKey := newTestIdentityKey(t)

	structure := &SignalMessageStructure{
		Version:    CurrentVersion,
		Counter:    1,
		RatchetKey: ratchetKey.PublicKey().Serialize(),
		CipherText: []byte("test ct"),
		Mac:        []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	msg, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A MAC key shorter than 32 bytes should trigger ErrInvalidMacKeyLength.
	shortKey := make([]byte, 16) // less than 32
	err = msg.VerifyMac(CurrentVersion, senderKey, receiverKey, shortKey)
	if err == nil {
		t.Fatal("expected error for short MAC key")
	}
}

// TestDecryptionErrorMessage_NewWithNilRatchetKey verifies nil ratchet key path.
func TestDecryptionErrorMessage_NewWithNilRatchetKey(t *testing.T) {
	msg, err := NewDecryptionErrorMessage(99999, 5, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.RatchetKey() != nil {
		t.Error("RatchetKey() should be nil when not provided")
	}
	if msg.Timestamp() != 99999 {
		t.Errorf("Timestamp() = %d, want 99999", msg.Timestamp())
	}
	if msg.DeviceID() != 5 {
		t.Errorf("DeviceID() = %d, want 5", msg.DeviceID())
	}
}

// TestSenderKeyMessageWithVersion_DistributionID verifies NewSenderKeyMessageWithVersion
// sets the distribution ID correctly.
func TestSenderKeyMessageWithVersion_DistributionID(t *testing.T) {
	serializer := &jsonSenderKeyMessageSerializer{}
	signingKey := newTestKeyPair(t)

	var distID [16]byte
	for i := range distID {
		distID[i] = byte(i + 50)
	}

	msg, err := NewSenderKeyMessageWithVersion(
		SenderKeyCurrentVersion,
		distID,
		1,                    // keyID
		5,                    // iteration
		[]byte("ciphertext"), // ciphertext
		signingKey.PrivateKey(),
		serializer,
	)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageWithVersion failed: %v", err)
	}

	got := msg.DistributionID()
	if got != distID {
		t.Errorf("DistributionID() = %v, want %v", got, distID)
	}
}
