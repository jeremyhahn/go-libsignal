package protocol

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/servicepb"
	"google.golang.org/protobuf/proto"
)

// DecryptionErrorMessageForOriginal creates a DecryptionErrorMessage from the
// serialized bytes and type of the original message that failed to decrypt.
// It extracts the ratchet key from Whisper and PreKey messages so the sender
// can advance the ratchet and re-encrypt the message.
//
// originalMsgType must be one of WHISPER_TYPE, PREKEY_TYPE, or SENDERKEY_TYPE.
// Passing PLAINTEXT_TYPE is an error (returns ErrInvalidArgumentPlaintext) because
// plaintext content is not encrypted and carries no ratchet key.
//
// Mirrors Rust libsignal_protocol DecryptionErrorMessage::for_original at
// rust/protocol/src/protocol.rs:881-917.
func DecryptionErrorMessageForOriginal(
	originalBytes []byte,
	originalMsgType uint32,
	originalTimestamp uint64,
	originalSenderDeviceID uint32,
	msgSerializer SignalMessageSerializer,
	preKeyMsgSerializer PreKeySignalMessageSerializer,
) (*DecryptionErrorMessage, error) {
	var ratchetKey ecc.ECPublicKeyable

	switch originalMsgType {
	case WHISPER_TYPE:
		sm, err := NewSignalMessageFromBytes(originalBytes, msgSerializer)
		if err != nil {
			return nil, err
		}
		ratchetKey = sm.SenderRatchetKey()
	case PREKEY_TYPE:
		pkm, err := NewPreKeySignalMessageFromBytes(originalBytes, preKeyMsgSerializer, msgSerializer)
		if err != nil {
			return nil, err
		}
		ratchetKey = pkm.WhisperMessage().SenderRatchetKey()
	case SENDERKEY_TYPE:
		// SenderKey messages carry no ratchet key; ratchetKey stays nil.
	case PLAINTEXT_TYPE:
		return nil, newInvalidArgumentPlaintextError()
	default:
		return nil, newIncompleteMessageError("DecryptionErrorMessage", "unknown original message type")
	}

	return NewDecryptionErrorMessage(originalTimestamp, originalSenderDeviceID, ratchetKey)
}

// plaintextPaddingByte is the boundary byte appended to PlaintextContent serializations.
// It matches PlaintextContent::PADDING_BOUNDARY_BYTE in the Rust reference (0x80).
const plaintextPaddingByte byte = 0x80

// DecryptionErrorMessage is sent when a message fails to decrypt,
// allowing the sender to potentially resend.
type DecryptionErrorMessage struct {
	ratchetKey ecc.ECPublicKeyable // optional
	timestamp  uint64
	deviceID   uint32
	serialized []byte
}

// NewDecryptionErrorMessage creates a new DecryptionErrorMessage with the given
// parameters. The ratchetKey may be nil if not applicable.
func NewDecryptionErrorMessage(timestamp uint64, deviceID uint32, ratchetKey ecc.ECPublicKeyable) (*DecryptionErrorMessage, error) {
	msg := &DecryptionErrorMessage{
		ratchetKey: ratchetKey,
		timestamp:  timestamp,
		deviceID:   deviceID,
	}

	serialized, err := msg.serialize()
	if err != nil {
		return nil, err
	}
	msg.serialized = serialized

	return msg, nil
}

// DeserializeDecryptionErrorMessage parses a serialized DecryptionErrorMessage
// from protobuf bytes.
func DeserializeDecryptionErrorMessage(data []byte) (*DecryptionErrorMessage, error) {
	if len(data) == 0 {
		return nil, &EmptyMessageError{MessageType: "decryption error message"}
	}

	pbMsg := &servicepb.DecryptionErrorMessage{}
	if err := proto.Unmarshal(data, pbMsg); err != nil {
		return nil, err
	}

	msg := &DecryptionErrorMessage{
		timestamp:  pbMsg.GetTimestamp(),
		deviceID:   pbMsg.GetDeviceId(),
		serialized: append([]byte(nil), data...),
	}

	if rk := pbMsg.GetRatchetKey(); len(rk) > 0 {
		pubKey, err := ecc.DecodePoint(rk, 0)
		if err != nil {
			return nil, err
		}
		msg.ratchetKey = pubKey
	}

	return msg, nil
}

// RatchetKey returns the optional ratchet key, or nil if not set.
func (d *DecryptionErrorMessage) RatchetKey() ecc.ECPublicKeyable {
	return d.ratchetKey
}

// Timestamp returns the timestamp of the original message that failed to decrypt.
func (d *DecryptionErrorMessage) Timestamp() uint64 {
	return d.timestamp
}

// DeviceID returns the device ID that failed to decrypt.
func (d *DecryptionErrorMessage) DeviceID() uint32 {
	return d.deviceID
}

// Serialize returns the protobuf-encoded bytes.
func (d *DecryptionErrorMessage) Serialize() ([]byte, error) {
	if d.serialized != nil {
		return d.serialized, nil
	}
	return d.serialize()
}

func (d *DecryptionErrorMessage) serialize() ([]byte, error) {
	pbMsg := &servicepb.DecryptionErrorMessage{
		Timestamp: &d.timestamp,
		DeviceId:  &d.deviceID,
	}

	if d.ratchetKey != nil {
		rk := d.ratchetKey.Serialize()
		pbMsg.RatchetKey = rk
	}

	return proto.Marshal(pbMsg)
}

// ExtractDecryptionErrorMessageFromSerializedContent parses a serialized Content
// proto body (with PlaintextContent padding byte appended) and returns the embedded
// DecryptionErrorMessage. This mirrors the Rust function of the same name in
// protocol/src/protocol.rs and is intended for use in testing and diagnostic tooling.
//
// Errors:
//   - ErrInvalidContentProto        — body is not a valid Content protobuf
//   - ErrMissingDecryptionErrorMessage — Content has no decryption_error_message field
//   - ErrDecryptionErrorMessageDeserialize — nested bytes could not be deserialized
func ExtractDecryptionErrorMessageFromSerializedContent(body []byte) (*DecryptionErrorMessage, error) {
	if len(body) == 0 || body[len(body)-1] != plaintextPaddingByte {
		return nil, newInvalidContentProtoError()
	}

	// Strip the trailing padding byte before proto-decoding.
	contentBytes := body[:len(body)-1]

	content := &servicepb.Content{}
	if err := proto.Unmarshal(contentBytes, content); err != nil {
		return nil, newInvalidContentProtoError()
	}

	dem := content.GetDecryptionErrorMessage()
	if len(dem) == 0 {
		return nil, newMissingDecryptionErrorMessageError()
	}

	msg, err := DeserializeDecryptionErrorMessage(dem)
	if err != nil {
		return nil, newDecryptionErrorMessageDeserializeError(err.Error())
	}

	return msg, nil
}
