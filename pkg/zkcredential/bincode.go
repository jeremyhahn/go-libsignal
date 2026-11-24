package zkcredential

import (
	"encoding/binary"
	"math"
)

// ReadBincodeU64Len reads the u64-LE length prefix at data[off:off+8] and returns it as an int, rejecting values above math.MaxInt or whose length*elemSize exceeds the remaining input, as zkgroup's bincode options (fixint, little-endian, reject trailing bytes) require. fieldName names the field in errors; the result is safe for make, copy and slicing.
func ReadBincodeU64Len(data []byte, off int, elemSize int, fieldName string) (int, error) {
	// An out-of-range off is an error, not a panic.
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
