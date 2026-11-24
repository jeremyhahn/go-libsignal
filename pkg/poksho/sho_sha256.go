// ShoSha256 is the SHA-256 SHO variant (rust/poksho/src/shosha256.rs): zero-padded prefixes instead of HMAC keying, and a double-hash ratchet.
package poksho

// NewShoSha256 creates a SHA-256 SHO with label, byte-identical to Rust ShoSha256; its output differs from NewShoHmacSha256.
func init() {
	// Compile-time check: sha256Variant must implement shoVariant.
	var _ shoVariant = sha256Variant{}
}
