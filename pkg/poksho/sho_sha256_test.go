package poksho

// ShoSha256 dedicated test file.
//
// Known-answer vectors (KATs) for ShoSha256 are in sho_test.go alongside
// the ShoHmacSha256 KATs so the two variants can be compared side-by-side.
//
// Rust source for the KATs: libsignal/rust/poksho/src/shosha256.rs @98915c44
//
// Design differences from ShoHmacSha256 (both implemented in sho.go):
//
//   Digest:        raw SHA-256, not HMAC-SHA-256.
//   Absorb init:   SHA-256(zeros[64] || cv || input...)
//   Ratchet:       cv = SHA-256(SHA-256(accumulated))     (double hash)
//   Squeeze block: SHA-256(zeros[63] || 0x01 || cv || i_be64)
//   State update:  SHA-256(zeros[63] || 0x02 || cv || outlen_be64)
//
// The HMAC variant keys the hasher with cv; the SHA-256 variant prepends a
// zero-padded block as a poor-man's domain separator.  Both produce 32-byte
// chaining values and 32-byte blocks, but the outputs are NOT interchangeable.
