package protocol

// PlaintextContent is a message type for unencrypted content (type 8).
// Used for DecryptionErrorMessages and other protocol-level messages
// that do not need encryption.
type PlaintextContent struct {
	serialized []byte
}

// NewPlaintextContent creates a PlaintextContent wrapping the given body.
// The serialized form is a version byte followed by the body.
func NewPlaintextContent(body []byte) *PlaintextContent {
	serialized := make([]byte, 0, 1+len(body))
	// Version byte: current version shifted into the high nibble,
	// with the current version in the low nibble.
	versionByte := byte((CurrentVersion << 4) | CurrentVersion)
	serialized = append(serialized, versionByte)
	serialized = append(serialized, body...)
	return &PlaintextContent{
		serialized: serialized,
	}
}

// NewPlaintextContentFromBytes parses a previously serialized PlaintextContent.
func NewPlaintextContentFromBytes(serialized []byte) (*PlaintextContent, error) {
	if len(serialized) < 1 {
		return nil, &ContentTooShortError{MessageType: "plaintext content"}
	}
	return &PlaintextContent{
		serialized: append([]byte(nil), serialized...),
	}, nil
}

// Body returns the message body (the serialized bytes after the version byte).
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
