package bytehelper

import "math"

// SliceToArray will convert byte slice to a 32 byte array
func SliceToArray(bytes []byte) [32]byte {
	var byteArray [32]byte
	copy(byteArray[:], bytes)
	return byteArray
}

// SliceToArray64 will convert byte slice to a 64 byte array
func SliceToArray64(bytes []byte) [64]byte {
	var byteArray [64]byte
	copy(byteArray[:], bytes)
	return byteArray
}

// ArrayToSlice will convert a 32 byte array to byte slice
func ArrayToSlice(bytes [32]byte) []byte {
	return bytes[:]
}

// ArrayToSlice64 will convert a 64 byte array to byte slice
func ArrayToSlice64(bytes [64]byte) []byte {
	return bytes[:]
}

// Split will take the given byte array and split it into half,
// with the first half being "firstLength" in size and the second
// half "secondLength" in size.
func Split(input []byte, firstLength, secondLength int) ([][]byte, error) {
	if input == nil {
		return nil, &ErrNilInput{}
	}
	if firstLength < 0 || secondLength < 0 {
		return nil, &ErrNegativeLength{Lengths: []int{firstLength, secondLength}}
	}
	// Guard against int overflow before summing the lengths.
	if secondLength > math.MaxInt-firstLength {
		return nil, &ErrInputTooSmall{Required: math.MaxInt, Got: len(input)}
	}
	required := firstLength + secondLength
	if len(input) < required {
		return nil, &ErrInputTooSmall{Required: required, Got: len(input)}
	}

	parts := make([][]byte, 2)

	parts[0] = make([]byte, firstLength)
	copy(parts[0], input[:firstLength])

	parts[1] = make([]byte, secondLength)
	copy(parts[1], input[firstLength:])

	return parts, nil
}

// SplitThree will take the given byte array and split it into thirds,
// with the first third being "firstLength" in size, the second third
// being "secondLength" in size, and the last third being "thirdLength"
// in size.
func SplitThree(input []byte, firstLength, secondLength, thirdLength int) ([][]byte, error) {
	if input == nil {
		return nil, &ErrNilInput{}
	}
	if firstLength < 0 || secondLength < 0 || thirdLength < 0 {
		return nil, &ErrNegativeLength{Lengths: []int{firstLength, secondLength, thirdLength}}
	}
	// Guard against int overflow before summing the lengths step by step.
	if secondLength > math.MaxInt-firstLength {
		return nil, &ErrInputTooSmall{Required: math.MaxInt, Got: len(input)}
	}
	partial := firstLength + secondLength
	if thirdLength > math.MaxInt-partial {
		return nil, &ErrInputTooSmall{Required: math.MaxInt, Got: len(input)}
	}
	required := partial + thirdLength
	if len(input) < required {
		return nil, &ErrInputTooSmall{Required: required, Got: len(input)}
	}

	parts := make([][]byte, 3)

	parts[0] = make([]byte, firstLength)
	copy(parts[0], input[:firstLength])

	parts[1] = make([]byte, secondLength)
	copy(parts[1], input[firstLength:][:secondLength])

	parts[2] = make([]byte, thirdLength)
	copy(parts[2], input[firstLength+secondLength:])

	return parts, nil
}

// Trim returns a copy of input truncated to length bytes. If length is
// negative it is clamped to 0; if length exceeds len(input) it is clamped
// to len(input). Trim never panics on out-of-range arguments.
func Trim(input []byte, length int) []byte {
	if length < 0 {
		length = 0
	}
	if length > len(input) {
		length = len(input)
	}
	result := make([]byte, length)
	copy(result, input[:length])

	return result
}

// Bytes5ToInt64 converts five consecutive bytes starting at offset to an int64.
// Returns 0 if offset is negative or offset+5 exceeds len(bytes).
func Bytes5ToInt64(bytes []byte, offset int) int64 {
	if offset < 0 || offset+5 > len(bytes) {
		return 0
	}

	value := (int64(bytes[offset]&0xff) << 32) |
		(int64(bytes[offset+1]&0xff) << 24) |
		(int64(bytes[offset+2]&0xff) << 16) |
		(int64(bytes[offset+3]&0xff) << 8) |
		int64(bytes[offset+4]&0xff)

	return value
}

// CopySlice returns a copy of the given bytes.
func CopySlice(bytes []byte) []byte {
	cp := make([]byte, len(bytes))
	copy(cp, bytes)

	return cp
}
