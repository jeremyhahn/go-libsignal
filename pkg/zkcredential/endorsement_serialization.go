package zkcredential

import "encoding/binary"

// SerializeEndorsementResponse encodes an [EndorsementResponse] as Rust bincode: u64 LE point count, 32-byte points, u64 LE proof length, proof.
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

// DeserializeEndorsementResponse decodes an [EndorsementResponse] from Rust bincode, rejecting truncated data, bad point lengths and trailing bytes.
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

// ReadEndorsementResponse parses an EndorsementResponse from the start of data and returns the remaining bytes.
func ReadEndorsementResponse(data []byte) (*EndorsementResponse, []byte, error) {
	off := 0

	// Read len(R).
	if len(data) < off+8 {
		return nil, nil, &ErrEndorsementResponseTruncated{Need: off + 8, Got: len(data)}
	}
	// ReadBincodeU64Len rejects lengths of 2^63 or more and lengths beyond the data.
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
