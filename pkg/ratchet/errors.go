package ratchet

// ErrMissingKyberPreKeyError is the typed error for a missing Kyber pre-key.
type ErrMissingKyberPreKeyError struct{}

func (e *ErrMissingKyberPreKeyError) Error() string {
	return "ratchet: missing Kyber pre-key for PQXDH session"
}

// ErrMissingKyberCiphertextError is the typed error for a missing Kyber ciphertext.
type ErrMissingKyberCiphertextError struct{}

func (e *ErrMissingKyberCiphertextError) Error() string {
	return "ratchet: missing Kyber ciphertext for PQXDH session"
}

// ErrNonCanonicalBaseKeyError is the typed error for a non-canonical base key.
type ErrNonCanonicalBaseKeyError struct{}

func (e *ErrNonCanonicalBaseKeyError) Error() string {
	return "ratchet: incoming base key is not canonical"
}

// ErrNilBaseKeyError is the typed error for a nil TheirBaseKey.
type ErrNilBaseKeyError struct{}

func (e *ErrNilBaseKeyError) Error() string {
	return "ratchet: TheirBaseKey must not be nil"
}

// Sentinel errors for backward-compatible errors.Is matching.
var (
	// ErrMissingKyberPreKey is returned when a v4 PQXDH session initialization is
	// attempted but the required Kyber pre-key parameters are missing.
	ErrMissingKyberPreKey error = &ErrMissingKyberPreKeyError{}

	// ErrMissingKyberCiphertext is returned when the receiver path is missing
	// the Kyber ciphertext required for PQXDH decapsulation.
	ErrMissingKyberCiphertext error = &ErrMissingKyberCiphertextError{}

	// ErrNonCanonicalBaseKey is returned when the receiver detects that the
	// sender's base key is not in canonical form (not torsion-free or not
	// in the reduced scalar range). This matches the Rust check in
	// initialize_bob_session.
	ErrNonCanonicalBaseKey error = &ErrNonCanonicalBaseKeyError{}

	// ErrNilBaseKey is returned when TheirBaseKey is nil in ReceiverParameters,
	// which would cause a nil-pointer dereference in CalculateReceiverSession.
	ErrNilBaseKey error = &ErrNilBaseKeyError{}
)
