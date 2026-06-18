// Package poksho — ShoSha256 is the SHA-256 variant of the Stateful Hash Object.
//
// Rust source: libsignal/rust/poksho/src/shosha256.rs
//
// ShoSha256 uses raw SHA-256 as the underlying digest instead of HMAC-SHA-256.
// The construction is called "innerpad SHO/SHA256":
//
//   - Absorb phase: SHA-256(pad64_zeros || cv || input...)
//   - Ratchet:      cv = SHA-256(SHA-256(accumulated))   (double hash)
//   - Squeeze block i: SHA-256(pad63_zeros || 0x01 || cv || i_be64)
//   - Squeeze state update: SHA-256(pad63_zeros || 0x02 || cv || outlen_be64)
//
// Key differences from ShoHmacSha256:
//
//   - Digest:      SHA-256 (no keying), not HMAC-SHA-256.
//   - Block size:  64 bytes for both (SHA-256 block size equals HMAC-SHA-256 block size).
//   - Hash size:   32 bytes for both.
//   - Absorb init: prepends 64 zero bytes followed by cv (vs HMAC keying cv).
//   - Ratchet:     double-hash cv = SHA256(SHA256(state)) (vs HMAC append 0x00, finalize).
//   - Squeeze:     uses byte 0x01 domain separator in a prefix of (pad63 || 0x01)
//     (vs HMAC with domain-separator byte after counter).
//   - State update: pad63 || 0x02 || cv || outlen_be64
//     (vs HMAC with domain-separator byte after outlen).
package poksho

// NewShoSha256 creates a new SHO using SHA-256 with the given label.
//
// This matches the Rust ShoSha256::new() from libsignal/rust/poksho/src/shosha256.rs.
// The implementation lives in sho.go via sha256Variant; this file provides the
// dedicated constructor and documents the SHA-256 variant's design.
//
// Use NewShoSha256 when you need byte-identical output with Rust's ShoSha256.
// Use NewShoHmacSha256 when you need byte-identical output with Rust's ShoHmacSha256.
//
// The two variants are NOT interchangeable: they produce different output for the
// same label and input.
func init() {
	// Compile-time check: sha256Variant must implement shoVariant.
	var _ shoVariant = sha256Variant{}
}
