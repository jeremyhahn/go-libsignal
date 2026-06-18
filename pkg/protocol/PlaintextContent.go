package protocol

import (
	"github.com/jeremyhahn/go-libsignal/pkg/proto/servicepb"
	"google.golang.org/protobuf/proto"
)

// plaintextContextIdentifierByte tags a serialized PlaintextContent. Mirrors
// PlaintextContent::PLAINTEXT_CONTEXT_IDENTIFIER_BYTE in
// rust/protocol/src/protocol.rs (RUST_REV 98915c4). Pinned at 0xC0 so callers
// cannot pass an arbitrary Content proto off as PlaintextContent.
const plaintextContextIdentifierByte byte = 0xC0

// PlaintextContent is a message type for unencrypted content (type 8).
// Used for DecryptionErrorMessages and other protocol-level messages
// that do not need encryption.
type PlaintextContent struct {
	serialized []byte
}

// NewPlaintextContent wraps body in the canonical PlaintextContent envelope:
// [0xC0 identifier] || body || [0x80 padding-boundary].
func NewPlaintextContent(body []byte) *PlaintextContent {
	serialized := make([]byte, 0, 2+len(body))
	serialized = append(serialized, plaintextContextIdentifierByte)
	serialized = append(serialized, body...)
	serialized = append(serialized, plaintextPaddingByte)
	return &PlaintextContent{
		serialized: serialized,
	}
}

// NewPlaintextContentFromBytes parses a previously serialized PlaintextContent.
// The bytes must begin with the 0xC0 identifier byte; otherwise an
// UnrecognizedMessageVersionError is returned, matching Rust's TryFrom.
func NewPlaintextContentFromBytes(serialized []byte) (*PlaintextContent, error) {
	if len(serialized) < 1 {
		return nil, &ContentTooShortError{MessageType: "plaintext content"}
	}
	if serialized[0] != plaintextContextIdentifierByte {
		return nil, newUnrecognizedVersionError("plaintext content", int(serialized[0]))
	}
	return &PlaintextContent{
		serialized: append([]byte(nil), serialized...),
	}, nil
}

// Body returns the bytes after the identifier byte, including the trailing
// 0x80 padding-boundary. Mirrors Rust's PlaintextContent::body which is fed
// directly into extract_decryption_error_message_from_serialized_content.
func (p *PlaintextContent) Body() []byte {
	if len(p.serialized) < 1 {
		return nil
	}
	return p.serialized[1:]
}

// Serialize returns the full serialized form including the version byte.
func (p *PlaintextContent) Serialize() ([]byte, error) {
	return p.serialized, nil
}

// Type returns the PLAINTEXT_TYPE constant (8).
func (p *PlaintextContent) Type() uint32 {
	return PLAINTEXT_TYPE
}

// PlaintextContentFromDEM wraps a DecryptionErrorMessage in a PlaintextContent
// envelope. The resulting bytes are:
//
//	[0xC0 identifier] || proto.Marshal(Content{decryption_error_message: dem.Serialize()}) || [0x80 padding]
//
// Mirrors Rust's From<DecryptionErrorMessage> for PlaintextContent at
// rust/protocol/src/protocol.rs:837-851.
func PlaintextContentFromDEM(dem *DecryptionErrorMessage) (*PlaintextContent, error) {
	demBytes, err := dem.Serialize()
	if err != nil {
		return nil, err
	}
	contentProto := &servicepb.Content{
		DecryptionErrorMessage: demBytes,
	}
	encoded, err := proto.Marshal(contentProto)
	if err != nil {
		return nil, err
	}
	serialized := make([]byte, 0, 1+len(encoded)+1)
	serialized = append(serialized, plaintextContextIdentifierByte)
	serialized = append(serialized, encoded...)
	serialized = append(serialized, plaintextPaddingByte)
	return &PlaintextContent{serialized: serialized}, nil
}
