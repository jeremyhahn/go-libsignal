package zkcredential

import "encoding/binary"

// SerializeEndorsementResponse encodes an [EndorsementResponse] to the Rust
// bincode wire format, producing byte-for-byte identical output to
// zkgroup::serialize on the same value.
//
// Wire layout (matches Rust zkcredential::endorsements::EndorsementResponse at
// rust/zkcredential/src/endorsements.rs, serialized by bincode with
// with_fixint_encoding + with_little_endian + reject_trailing_bytes):
//
//	[8 LE u64]   len(R)               — number of compressed ristretto255 points
//	[32*len(R)]  R bytes              — each compressed point is 32 bytes
//	[8 LE u64]   len(proof)           — proof byte count
//	[len(proof)] proof bytes
//
// There is no reserved/version byte; that is added by the outer
// GroupSendEndorsementsResponse wrapper.
func SerializeEndorsementResponse(r *EndorsementResponse) []byte {
	nR := len(r.R)
	nProof := len(r.Proof)
	out := make([]byte, 0, 8+nR*32+8+nProof)

	var u64Buf [8]byte

	binary.LittleEndian.PutUint64(u64Buf[:], uint64(nR))
	out = append(out, u64Buf[:]...)

	for _, point := range r.R {
		out = append(out, point...)
	}

	binary.LittleEndian.PutUint64(u64Buf[:], uint64(nProof))
	out = append(out, u64Buf[:]...)

	out = append(out, r.Proof...)

	return out
}

// DeserializeEndorsementResponse decodes an [EndorsementResponse] from the
// Rust bincode wire format produced by [SerializeEndorsementResponse].
//
// Returns [ErrEndorsementResponseTruncated] if the data is too short,
// [ErrEndorsementResponsePointLength] if a point has an unexpected length,
// or [ErrEndorsementResponseTrailingBytes] if there are leftover bytes.
func DeserializeEndorsementResponse(data []byte) (*EndorsementResponse, error) {
	n, rest, err := ReadEndorsementResponse(data)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, &ErrEndorsementResponseTrailingBytes{Count: len(rest)}
	}
	return n, nil
}

// ReadEndorsementResponse reads an EndorsementResponse from the beginning of
// data and returns the parsed value plus any unconsumed tail bytes.
//
// This is the low-level parser used by [DeserializeEndorsementResponse] and
// by callers (such as zkgroup) that embed EndorsementResponse in a larger
// bincode struct and need to continue parsing after the response bytes.
func ReadEndorsementResponse(data []byte) (*EndorsementResponse, []byte, error) {
	off := 0

	// Read len(R).
	if len(data) < off+8 {
		return nil, nil, &ErrEndorsementResponseTruncated{Need: off + 8, Got: len(data)}
	}
	// ReadBincodeU64Len guards against u64 >= 2^63 (negative after int cast)
	// and against claims that exceed remaining data, matching Rust's
	// reject_trailing_bytes behavior (rust/zkgroup/src/common/serialization.rs).
	// This eliminates the narrowing-cast overflow in the diagnostic Need value
	// that existed when the rejected attacker u64 was cast directly to int.
	nR, err := ReadBincodeU64Len(data, off, 32, "R")
	if err != nil {
		return nil, nil, &ErrEndorsementResponseTruncated{Need: off + 8, Got: len(data)}
	}
	off += 8

	// Read R points (each 32 bytes).
	if len(data) < off+nR*32 {
		return nil, nil, &ErrEndorsementResponseTruncated{Need: off + nR*32, Got: len(data)}
	}
	R := make([][]byte, nR)
	for i := range R {
		point := make([]byte, 32)
		copy(point, data[off:off+32])
		R[i] = point
		off += 32
	}

	// Read len(proof).
	if len(data) < off+8 {
		return nil, nil, &ErrEndorsementResponseTruncated{Need: off + 8, Got: len(data)}
	}
	// ReadBincodeU64Len bounds the proof length against remaining data,
	// preventing a narrowing-cast overflow in the diagnostic Need field.
	nProof, err := ReadBincodeU64Len(data, off, 1, "proof")
	if err != nil {
		return nil, nil, &ErrEndorsementResponseTruncated{Need: off + 8, Got: len(data)}
	}
	off += 8

	// Read proof bytes.
	if len(data) < off+nProof {
		return nil, nil, &ErrEndorsementResponseTruncated{Need: off + nProof, Got: len(data)}
	}
	proof := make([]byte, nProof)
	copy(proof, data[off:off+nProof])
	off += nProof

	return &EndorsementResponse{R: R, Proof: proof}, data[off:], nil
}
