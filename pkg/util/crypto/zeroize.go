package crypto

import "runtime"

// Zeroize overwrites a byte slice with zeros to prevent sensitive data from lingering in memory.
// runtime.KeepAlive prevents the compiler from eliminating the stores as dead writes.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroizeArray32 overwrites a 32-byte array with zeros.
func ZeroizeArray32(b *[32]byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroizeArray64 overwrites a 64-byte array with zeros.
func ZeroizeArray64(b *[64]byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
