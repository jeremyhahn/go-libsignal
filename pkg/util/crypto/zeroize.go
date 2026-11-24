package crypto

import "runtime"

// Zeroize overwrites b with zeros; the stores are kept because b escapes, and runtime.KeepAlive keeps b reachable until they finish.
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
