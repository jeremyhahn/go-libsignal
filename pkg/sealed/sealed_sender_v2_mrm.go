package sealed

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// serializedRecipientViewVersion (0x01) heads a SerializedRecipientView, as in Java.
const serializedRecipientViewVersion byte = 0x01

// serializedRecipientViewSize is the fixed size in bytes of a
// SerializedRecipientView: version(1) + offsetOfSharedData(4) +
// offsetOfRecipientKeyMaterial(4) + lengthOfRecipientKeyMaterial(4).
const serializedRecipientViewSize = 1 + 4 + 4 + 4

// ErrRecipientNotInMessage is returned by RangeForRecipient and
// SerializedRecipientView when the supplied service ID is not among the
// message's recipients.
var ErrRecipientNotInMessage = errors.New("sealed: recipient not in message")

// ErrMessageNotParsedFromBytes is returned by byte-range helpers when called
// on a SealedSenderV2SentMessage that was constructed without retaining its
// original wire-format bytes (i.e. not via ParseSealedSenderV2SentMessage).
var ErrMessageNotParsedFromBytes = errors.New("sealed: message has no full-buffer reference; parse via ParseSealedSenderV2SentMessage")

// ParseSealedSenderV2SentMessage parses a full v2 sent message, keeping the buffer for SerializedRecipientView, RangeForRecipient and OffsetOfSharedBytes.
func ParseSealedSenderV2SentMessage(data []byte) (*SealedSenderV2SentMessage, error) {
	if len(data) == 0 {
		return nil, &V2ParseError{Detail: "message was empty"}
	}
	version := data[0]
	if version != SealedSenderV2VersionUUID && version != SealedSenderV2VersionServiceId {
		return nil, &V2ParseError{Detail: fmt.Sprintf("unknown sealed sender version: 0x%02x", version)}
	}

	parsed, err := v2ParseMessage(data[1:], version)
	if err != nil {
		return nil, err
	}

	// v2ParseMessage records offsets relative to its `data` argument
	// (which is data[1:] here). Bump every offset by 1 so the values are
	// relative to the full wire-format buffer that callers will index with.
	for _, recip := range parsed.Recipients {
		if recip.KeyMaterialLength > 0 {
			recip.KeyMaterialOffset++
		}
	}
	parsed.sharedBytesOffset++
	parsed.fullMessage = data
	parsed.version = version
	return parsed, nil
}

// Version returns the wire version (0x22 or 0x23), or zero if not parsed from bytes.
func (m *SealedSenderV2SentMessage) Version() byte {
	return m.version
}

// FullMessage returns the original wire-format bytes from which this message
// was parsed. Returns nil if the message was not constructed via
// ParseSealedSenderV2SentMessage. The returned slice MUST NOT be modified.
func (m *SealedSenderV2SentMessage) FullMessage() []byte {
	return m.fullMessage
}

// OffsetOfSharedBytes returns the offset of the shared ephemeral key and payload, or ErrMessageNotParsedFromBytes.
func (m *SealedSenderV2SentMessage) OffsetOfSharedBytes() (int, error) {
	if m.fullMessage == nil {
		return 0, ErrMessageNotParsedFromBytes
	}
	return m.sharedBytesOffset, nil
}

// RangeForRecipient returns the [start, end) range of the recipient's C_i || AT_i, (0, 0) if excluded; errors are ErrRecipientNotInMessage and ErrMessageNotParsedFromBytes.
func (m *SealedSenderV2SentMessage) RangeForRecipient(serviceID protocol.ServiceId) (start, end int, err error) {
	if m.fullMessage == nil {
		return 0, 0, ErrMessageNotParsedFromBytes
	}
	recip, ok := m.Recipients[serviceID.String()]
	if !ok {
		return 0, 0, ErrRecipientNotInMessage
	}
	if recip.KeyMaterialLength == 0 {
		return 0, 0, nil
	}
	return recip.KeyMaterialOffset, recip.KeyMaterialOffset + recip.KeyMaterialLength, nil
}

// MessageForRecipient returns the recipient's received message: version 0x22, C_i || AT_i, then the shared bytes (Java messageForRecipient); errors as RangeForRecipient.
func (m *SealedSenderV2SentMessage) MessageForRecipient(serviceID protocol.ServiceId) ([]byte, error) {
	if m.fullMessage == nil {
		return nil, ErrMessageNotParsedFromBytes
	}
	recip, ok := m.Recipients[serviceID.String()]
	if !ok {
		return nil, ErrRecipientNotInMessage
	}

	sharedLen := len(m.fullMessage) - m.sharedBytesOffset
	if sharedLen < 0 {
		return nil, &V2ParseError{Detail: "invalid shared-bytes offset"}
	}

	out := make([]byte, 0, 1+recip.KeyMaterialLength+sharedLen)
	out = append(out, SealedSenderV2VersionUUID)
	if recip.KeyMaterialLength > 0 {
		out = append(out, m.fullMessage[recip.KeyMaterialOffset:recip.KeyMaterialOffset+recip.KeyMaterialLength]...)
	}
	out = append(out, m.fullMessage[m.sharedBytesOffset:]...)
	return out, nil
}

// SerializedRecipientView returns the 13-byte view: version, shared-data offset, key-material offset and length (uint32 BE each), as in Java; errors as RangeForRecipient.
func (m *SealedSenderV2SentMessage) SerializedRecipientView(serviceID protocol.ServiceId) ([]byte, error) {
	if m.fullMessage == nil {
		return nil, ErrMessageNotParsedFromBytes
	}
	recip, ok := m.Recipients[serviceID.String()]
	if !ok {
		return nil, ErrRecipientNotInMessage
	}

	out := make([]byte, serializedRecipientViewSize)
	out[0] = serializedRecipientViewVersion
	binary.BigEndian.PutUint32(out[1:5], uint32(m.sharedBytesOffset))
	binary.BigEndian.PutUint32(out[5:9], uint32(recip.KeyMaterialOffset))
	binary.BigEndian.PutUint32(out[9:13], uint32(recip.KeyMaterialLength))
	return out, nil
}

// ErrInvalidRecipientView is returned by MessageForRecipient when the
// view byte slice is malformed (wrong length, unsupported version, or
// offsets outside the supplied data buffer).
var ErrInvalidRecipientView = errors.New("sealed: invalid serialized recipient view")

// MessageForRecipient rebuilds a recipient's received message from the full message and a stored view; returns ErrInvalidRecipientView for a bad view.
func MessageForRecipient(fullMessageData, serializedRecipientView []byte) ([]byte, error) {
	if len(serializedRecipientView) != serializedRecipientViewSize {
		return nil, &RecipientViewError{Detail: fmt.Sprintf(
			"length %d, want %d", len(serializedRecipientView), serializedRecipientViewSize)}
	}
	if version := serializedRecipientView[0]; version != serializedRecipientViewVersion {
		return nil, &RecipientViewError{Detail: fmt.Sprintf(
			"unsupported view version 0x%02x", version)}
	}

	offsetOfSharedData := int(binary.BigEndian.Uint32(serializedRecipientView[1:5]))
	offsetOfRecipientKeyMaterial := int(binary.BigEndian.Uint32(serializedRecipientView[5:9]))
	lengthOfRecipientKeyMaterial := int(binary.BigEndian.Uint32(serializedRecipientView[9:13]))

	if offsetOfSharedData < 0 || offsetOfSharedData > len(fullMessageData) {
		return nil, &RecipientViewError{Detail: fmt.Sprintf(
			"shared-data offset %d out of range [0,%d]", offsetOfSharedData, len(fullMessageData))}
	}
	if lengthOfRecipientKeyMaterial < 0 {
		return nil, &RecipientViewError{Detail: fmt.Sprintf(
			"negative recipient-key-material length %d", lengthOfRecipientKeyMaterial)}
	}
	if lengthOfRecipientKeyMaterial > 0 {
		end := offsetOfRecipientKeyMaterial + lengthOfRecipientKeyMaterial
		if offsetOfRecipientKeyMaterial < 0 || end > len(fullMessageData) {
			return nil, &RecipientViewError{Detail: fmt.Sprintf(
				"recipient key-material range [%d,%d) out of full-data length %d",
				offsetOfRecipientKeyMaterial, end, len(fullMessageData))}
		}
	}

	sharedLen := len(fullMessageData) - offsetOfSharedData
	out := make([]byte, 0, 1+lengthOfRecipientKeyMaterial+sharedLen)
	out = append(out, SealedSenderV2VersionUUID)
	if lengthOfRecipientKeyMaterial > 0 {
		out = append(out, fullMessageData[offsetOfRecipientKeyMaterial:offsetOfRecipientKeyMaterial+lengthOfRecipientKeyMaterial]...)
	}
	out = append(out, fullMessageData[offsetOfSharedData:]...)
	return out, nil
}
