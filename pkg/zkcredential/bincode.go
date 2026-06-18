package zkcredential

import (
	"encoding/binary"
	"math"
)

// ReadBincodeU64Len reads a u64-LE length prefix from data[off:off+8] and
// returns it as a safe int, enforcing two invariants that match Rust's bincode
// behavior (with_fixint_encoding + with_little_endian + reject_trailing_bytes):
//
//  1. The raw u64 must be <= math.MaxInt so the int cast never goes negative
//     on any supported platform.
//  2. The raw u64 multiplied by elemSize must not exceed the remaining bytes
//     in data after the length field, preventing any allocation from exceeding
//     the actual available input.
//
// Together these prevent integer-overflow / unbounded-alloc attacks where an
// attacker supplies a wire u64 >= 2^63 that wraps to negative when cast to int,
// defeating subsequent bounds checks and causing make/copy to panic.
//
// Matches: rust/zkgroup/src/common/serialization.rs zkgroup_bincode_options()
// which uses:
//
//	bincode::DefaultOptions::new()
//	    .with_fixint_encoding()
//	    .with_little_endian()
//	    .reject_trailing_bytes()
//
// Parameters:
//
//	data      — the full byte slice being decoded
//	off       — byte offset of the 8-byte LE u64 length field
//	            (caller must ensure len(data) >= off+8 before calling)
//	elemSize  — size in bytes of each element counted by this length prefix
//	            (use 1 for raw byte slices, 32 for compressed Ristretto255 points)
//	fieldName — human-readable field name used in error messages
//
// Returns (length int, err) where length is safe to use directly with
// make, copy, and slice-index arithmetic.
func ReadBincodeU64Len(data []byte, off int, elemSize int, fieldName string) (int, error) {
	// Precondition guard: panic-free even when called from external code.
	// off < 0 or off+8 > len(data) would index out of bounds; return a typed
	// error rather than panicking, matching the security-library invariant that
	// exported functions must never panic on invalid caller input.
	if off < 0 || off > len(data)-8 {
		return 0, &ErrInvalidEncoding{
			Field: fieldName,
			Err:   &ErrLengthOverflow{Field: fieldName, Value: 0},
		}
	}
	raw := binary.LittleEndian.Uint64(data[off : off+8])

	// Guard 1: must fit in a signed int (prevents negative make/copy arguments).
	if raw > math.MaxInt {
		return 0, &ErrInvalidEncoding{
			Field: fieldName,
			Err:   &ErrLengthOverflow{Field: fieldName, Value: raw},
		}
	}

	// Guard 2: bytes remaining after the 8-byte length field divided by
	// elemSize gives the maximum safe count. Using integer division avoids
	// overflow in the comparison itself.
	remaining := uint64(len(data) - off - 8)
	var maxCount uint64
	if elemSize <= 1 {
		maxCount = remaining
	} else {
		maxCount = remaining / uint64(elemSize)
	}
	if raw > maxCount {
		return 0, &ErrInvalidEncoding{
			Field: fieldName,
			Err:   &ErrLengthExceedsInput{Field: fieldName, Value: raw, Remaining: remaining},
		}
	}

	return int(raw), nil
}

// readBincodeU64Len is the unexported shim for use within this package.
// It delegates to ReadBincodeU64Len.
func readBincodeU64Len(data []byte, off int, elemSize int, fieldName string) (int, error) {
	return ReadBincodeU64Len(data, off, elemSize, fieldName)
}
