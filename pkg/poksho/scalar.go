package poksho

import (
	"math/big"
)

// ed25519Order is the order of the Ed25519 base point group:
// L = 2^252 + 27742317777372353535851937790883648493
var ed25519Order *big.Int

func init() {
	ed25519Order = new(big.Int)
	ed25519Order.SetString(
		"7237005577332262213973186563042994240857116359379907606001950938285454250989",
		10,
	)
}

// ScalarFromSliceWide converts a 64-byte wide value to a canonical scalar
// by reducing modulo the Ed25519 group order L.
//
// Deprecated: Rust marks the equivalent scalar_from_slice_wide as deprecated
// ("use Scalar::from_bytes_mod_order_wide directly instead"). Prefer the
// ristretto255 package's scalar API when possible.
//
// The input must be exactly 64 bytes. The 512-bit value is interpreted as
// a little-endian integer and reduced modulo L to produce a 256-bit scalar.
func ScalarFromSliceWide(input []byte) ([32]byte, error) {
	var result [32]byte

	if len(input) != 64 {
		return result, &ScalarSizeError{Expected: 64, Actual: len(input)}
	}

	// Interpret the input as a little-endian 512-bit integer.
	// big.Int uses big-endian, so we need to reverse the bytes.
	reversed := make([]byte, 64)
	for i, b := range input {
		reversed[63-i] = b
	}

	n := new(big.Int).SetBytes(reversed)
	n.Mod(n, ed25519Order)

	// Convert back to little-endian 32-byte output.
	nBytes := n.Bytes() // big-endian
	for i, b := range nBytes {
		result[len(nBytes)-1-i] = b
	}

	return result, nil
}

// ScalarFromSliceCanonical converts a 32-byte value to a scalar, verifying
// it is already in canonical form (strictly less than the group order L).
//
// Deprecated: Rust marks the equivalent scalar_from_slice_canonical as
// deprecated ("use Scalar::from_bytes_mod_order_wide directly instead").
// Prefer the ristretto255 package's scalar API when possible.
//
// Returns an error if the input is not exactly 32 bytes or if its value
// is greater than or equal to L.
func ScalarFromSliceCanonical(input []byte) ([32]byte, error) {
	var result [32]byte

	if len(input) != 32 {
		return result, &ScalarSizeError{Expected: 32, Actual: len(input)}
	}

	// Interpret as little-endian and check < L.
	reversed := make([]byte, 32)
	for i, b := range input {
		reversed[31-i] = b
	}

	n := new(big.Int).SetBytes(reversed)
	if n.Cmp(ed25519Order) >= 0 {
		return result, &ScalarNotCanonicalError{}
	}

	copy(result[:], input)
	return result, nil
}
