package protocol

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/servicepb"
	"google.golang.org/protobuf/proto"
)

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
