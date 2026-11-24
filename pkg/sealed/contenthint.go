// Package sealed implements the Signal Sealed Sender (v1) protocol,
// which allows sending messages without revealing the sender's identity
// to the server.
package sealed

// ContentHint tells the recipient how to handle content errors; unknown raw values are kept (Rust ContentHint).
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

// ContentHintFromRaw converts a wire value to a ContentHint, keeping unknown values (Rust From<u32>).
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
