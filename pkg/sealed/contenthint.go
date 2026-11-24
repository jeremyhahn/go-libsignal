// Package sealed implements the Signal Sealed Sender (v1) protocol,
// which allows sending messages without revealing the sender's identity
// to the server.
package sealed

// ContentHint indicates how the recipient should handle errors when
// processing the sealed sender message content.
//
// Mirrors Rust libsignal's ContentHint at
// rust/protocol/src/sealed_sender.rs. The Unknown variant carries any
// raw u32 value that does not map to a known proto enum, preserving
// forward-compatibility: callers can inspect the raw value and gate
// behaviour on it without discarding the hint.
type ContentHint uint32

const (
	// ContentHintDefault indicates the sender will not resend; an error
	// should be shown immediately.
	ContentHintDefault ContentHint = 0

	// ContentHintResendable indicates the sender will try to resend;
	// delay any error UI if possible.
	ContentHintResendable ContentHint = 1

	// ContentHintImplicit indicates no error UI should be shown at all;
	// this is something sent implicitly like a typing message or a receipt.
	ContentHintImplicit ContentHint = 2
)

// ContentHintFromRaw converts a raw uint32 wire value to a ContentHint.
// Known values map to their named constants; any other value is returned
// as-is (matching Rust's ContentHint::Unknown(u32) forward-compat branch).
//
// Mirrors Rust libsignal's From<u32> for ContentHint at
// rust/protocol/src/sealed_sender.rs.
func ContentHintFromRaw(raw uint32) ContentHint {
	return ContentHint(raw)
}

// IsKnown reports whether the hint is one of the three named values.
// Returns false for forward-compat unknown values (equivalent to Rust's
// ContentHint::Unknown variant).
func (c ContentHint) IsKnown() bool {
	switch c {
	case ContentHintDefault, ContentHintResendable, ContentHintImplicit:
		return true
	default:
		return false
	}
}

// Raw returns the underlying uint32 wire value of the hint.
func (c ContentHint) Raw() uint32 {
	return uint32(c)
}
