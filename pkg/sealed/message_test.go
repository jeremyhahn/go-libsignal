//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 5 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) requires it for the Sealed Sender
// ephemeral keys, so the fips140only build tag drops this file from the FIPS
// gate. `make test` and `make coverage` still run it.

package sealed

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/proto/sealedpb"
	"google.golang.org/protobuf/proto"
)

func TestNewUnidentifiedSenderMessageContent(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	usmc, err := NewUnidentifiedSenderMessageContent(
		2, // MESSAGE type
		cert,
		[]byte("encrypted content"),
		ContentHintDefault,
		nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent() error: %v", err)
	}

	if usmc.Type() != 2 {
		t.Errorf("Type() = %d, want 2", usmc.Type())
	}
	if usmc.Sender() == nil {
		t.Fatal("Sender() should not be nil")
	}
	if !bytes.Equal(usmc.Contents(), []byte("encrypted content")) {
		t.Error("Contents() does not match")
	}
	if usmc.ContentHint() != ContentHintDefault {
		t.Errorf("ContentHint() = %d, want %d", usmc.ContentHint(), ContentHintDefault)
	}
	if len(usmc.GroupID()) != 0 {
		t.Error("GroupID() should be empty when nil")
	}
	if len(usmc.Serialize()) == 0 {
		t.Fatal("Serialize() should not be empty")
	}
}

func TestNewUnidentifiedSenderMessageContentWithGroupID(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	groupID := []byte("test-group-id")
	usmc, err := NewUnidentifiedSenderMessageContent(
		7, // SENDERKEY_MESSAGE
		cert,
		[]byte("payload"),
		ContentHintResendable,
		groupID,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent() error: %v", err)
	}

	if usmc.ContentHint() != ContentHintResendable {
		t.Errorf("ContentHint() = %d, want %d", usmc.ContentHint(), ContentHintResendable)
	}
	if !bytes.Equal(usmc.GroupID(), groupID) {
		t.Error("GroupID() does not match")
	}
}

func TestNewUnidentifiedSenderMessageContentNilSender(t *testing.T) {
	_, err := NewUnidentifiedSenderMessageContent(
		2,
		nil,
		[]byte("payload"),
		ContentHintDefault,
		nil,
	)
	if err == nil {
		t.Error("NewUnidentifiedSenderMessageContent with nil sender should return error")
	}
}

func TestDeserializeUnidentifiedSenderMessageContent(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	original, err := NewUnidentifiedSenderMessageContent(
		2,
		cert,
		[]byte("test payload"),
		ContentHintImplicit,
		[]byte("group-abc"),
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent() error: %v", err)
	}

	restored, err := DeserializeUnidentifiedSenderMessageContent(original.Serialize())
	if err != nil {
		t.Fatalf("DeserializeUnidentifiedSenderMessageContent() error: %v", err)
	}

	if restored.Type() != original.Type() {
		t.Errorf("Restored Type() = %d, want %d", restored.Type(), original.Type())
	}
	if !bytes.Equal(restored.Contents(), original.Contents()) {
		t.Error("Restored Contents() does not match")
	}
	if restored.ContentHint() != original.ContentHint() {
		t.Errorf("Restored ContentHint() = %d, want %d", restored.ContentHint(), original.ContentHint())
	}
	if !bytes.Equal(restored.GroupID(), original.GroupID()) {
		t.Error("Restored GroupID() does not match")
	}
	if restored.Sender() == nil {
		t.Fatal("Restored Sender() should not be nil")
	}
	if restored.Sender().SenderUUID() != original.Sender().SenderUUID() {
		t.Errorf("Restored SenderUUID() = %q, want %q", restored.Sender().SenderUUID(), original.Sender().SenderUUID())
	}
}

func TestDeserializeUnidentifiedSenderMessageContentMissingSender(t *testing.T) {
	// Cover the "USMC missing sender certificate" error path at line 75.
	pbMsg := &sealedpb.UnidentifiedSenderMessage_Message{
		Type:    sealedpb.UnidentifiedSenderMessage_Message_MESSAGE.Enum(),
		Content: []byte("test"),
		// SenderCertificate is nil
	}
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		t.Fatalf("proto.Marshal error: %v", err)
	}
	_, err = DeserializeUnidentifiedSenderMessageContent(data)
	if err == nil {
		t.Error("Should error when sender certificate is missing")
	}
}

func TestDeserializeUnidentifiedSenderMessageContentCorruptSender(t *testing.T) {
	// Cover the DeserializeSenderCertificate error path at line 79.
	pbMsg := &sealedpb.UnidentifiedSenderMessage_Message{
		Type:              sealedpb.UnidentifiedSenderMessage_Message_MESSAGE.Enum(),
		Content:           []byte("test"),
		SenderCertificate: []byte{0xFF, 0xFF, 0xFF}, // invalid protobuf
	}
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		t.Fatalf("proto.Marshal error: %v", err)
	}
	_, err = DeserializeUnidentifiedSenderMessageContent(data)
	if err == nil {
		t.Error("Should error when sender certificate bytes are corrupt")
	}
}

func TestDeserializeUnidentifiedSenderMessageContentInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty bytes", []byte{}},
		{"invalid protobuf", []byte{0xFF, 0xFF, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeUnidentifiedSenderMessageContent(tt.input)
			if err == nil {
				t.Error("DeserializeUnidentifiedSenderMessageContent with invalid input should return error")
			}
		})
	}
}

// TestDeserializeUnidentifiedSenderMessageContent_MissingContent verifies
// Finding 4: a USMC protobuf message that omits the `content` field is rejected
// with a *CertificateError rather than silently accepted with nil content.
//
// The Rust reference (libsignal-protocol/src/sealed_sender.rs UnidentifiedSenderMessageContent
// decode) validates that the content field is non-empty; the Go implementation
// must enforce the same constraint.
//
// Before the fix, a USMC with no content field was accepted and usmc.Contents()
// returned nil, which callers passed to the session cipher without validation.
func TestDeserializeUnidentifiedSenderMessageContent_MissingContent(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	// Build a well-formed USMC protobuf that omits the content field.
	pbMsg := &sealedpb.UnidentifiedSenderMessage_Message{
		Type:              sealedpb.UnidentifiedSenderMessage_Message_MESSAGE.Enum(),
		SenderCertificate: cert.Serialize(),
		// Content intentionally absent.
	}
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	_, err = DeserializeUnidentifiedSenderMessageContent(data)
	if err == nil {
		t.Fatal("expected error for USMC with missing content field, got nil")
	}
	certErr, ok := err.(*CertificateError)
	if !ok {
		t.Fatalf("expected *CertificateError, got %T: %v", err, err)
	}
	if certErr.Detail == "" {
		t.Error("expected non-empty Detail in CertificateError")
	}
}

// TestDeserializeUnidentifiedSenderMessageContent_ContentPresent verifies the
// positive case for Finding 4: a USMC with the content field present is accepted.
func TestDeserializeUnidentifiedSenderMessageContent_ContentPresent(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	pbMsg := &sealedpb.UnidentifiedSenderMessage_Message{
		Type:              sealedpb.UnidentifiedSenderMessage_Message_MESSAGE.Enum(),
		SenderCertificate: cert.Serialize(),
		Content:           []byte("payload"),
	}
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	usmc, err := DeserializeUnidentifiedSenderMessageContent(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(usmc.Contents()) != "payload" {
		t.Errorf("Contents() = %q, want %q", usmc.Contents(), "payload")
	}
}
