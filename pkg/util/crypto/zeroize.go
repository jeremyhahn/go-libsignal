package crypto

import "runtime"

// Zeroize overwrites a byte slice with zeros to prevent sensitive data from
// lingering in memory. The writes survive compiler optimization because the
// backing array pointed to by b escapes to the caller: the compiler cannot
// prove the stores are unobservable and is required to preserve them.
// runtime.KeepAlive extends GC reachability of b's backing array to this
// point, ensuring the garbage collector does not collect it before the stores
// complete; it does not itself prevent dead-store elimination.
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
