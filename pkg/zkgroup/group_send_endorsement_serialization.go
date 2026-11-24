package zkgroup

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// SerializeGroupSendEndorsementsResponse encodes r as Rust bincode: reserved byte, points, proof, u64 LE expiration.
func SerializeGroupSendEndorsementsResponse(r *GroupSendEndorsementsResponse) []byte {
	inner := zkcredential.SerializeEndorsementResponse(r.Endorsements)
	out := make([]byte, 0, 1+len(inner)+8)

	out = append(out, 0x00) // reserved byte

	out = append(out, inner...)

	var u64Buf [8]byte
	binary.LittleEndian.PutUint64(u64Buf[:], r.Expiration.EpochSeconds())
	out = append(out, u64Buf[:]...)

	return out
}

// DeserializeGroupSendEndorsementsResponse decodes Rust bincode, returning [ErrUnexpectedReservedByte] or [ZkGroupDeserializationFailure].
func DeserializeGroupSendEndorsementsResponse(data []byte) (*GroupSendEndorsementsResponse, error) {
	const typeName = "GroupSendEndorsementsResponse"

	if len(data) < 1 {
		return nil, &ZkGroupDeserializationFailure{TypeName: typeName}
	}
	if data[0] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[0]}
	}
	off := 1

	endorsements, tail, err := zkcredential.ReadEndorsementResponse(data[off:])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: typeName}
	}

	// tail is the unconsumed remainder after the EndorsementResponse payload.
	// Remaining must be exactly 8 bytes for the expiration timestamp.
	if len(tail) != 8 {
		return nil, &ZkGroupDeserializationFailure{TypeName: typeName}
	}
	expiration := NewTimestamp(binary.LittleEndian.Uint64(tail))

	return &GroupSendEndorsementsResponse{
		Endorsements: endorsements,
		Expiration:   expiration,
	}, nil
}
