// Package sealed implements the Signal Sealed Sender (v1) protocol,
// which allows sending messages without revealing the sender's identity
// to the server.
package sealed

// ContentHint indicates how the recipient should handle errors when
// processing the sealed sender message content.
type ContentHint int

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
