package zkgroup

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// SerializeGroupSendEndorsementsResponse encodes a
// [GroupSendEndorsementsResponse] to the Rust bincode wire format, producing
// byte-for-byte identical output to zkgroup::serialize on the same value.
//
// Wire layout (matches Rust GroupSendEndorsementsResponse at
// rust/zkgroup/src/api/groups/group_send_endorsement.rs, serialized by bincode
// with with_fixint_encoding + with_little_endian + reject_trailing_bytes):
//
//	[0x00]       reserved byte (ReservedByte)
//	[8 LE u64]   len(R)               — number of compressed ristretto255 points
//	[32*len(R)]  R bytes              — each compressed point is 32 bytes
//	[8 LE u64]   len(proof)           — proof byte count
//	[len(proof)] proof bytes
//	[8 LE u64]   expiration           — Timestamp (u64 epoch seconds)
//
// Rust source: rust/zkgroup/src/api/groups/group_send_endorsement.rs
// (GroupSendEndorsementsResponse struct fields: reserved, endorsements, expiration)
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

// DeserializeGroupSendEndorsementsResponse decodes a
// [GroupSendEndorsementsResponse] from the Rust bincode wire format produced
// by [SerializeGroupSendEndorsementsResponse].
//
// Returns [ErrUnexpectedReservedByte] if the first byte is not 0x00,
// or [ZkGroupDeserializationFailure] for structural errors.
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
