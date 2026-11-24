package session

import "fmt"

// Error represents a session cipher error.
type Error struct {
	kind    errorKind
	address string
	index   uint32
	counter uint32
}

type errorKind int

const (
	errNoSession errorKind = iota + 1
	errNoValidSessions
	errUninitializedSession
	errWrongMessageVersion
	errOldCounter
	errTooFarIntoFuture
	errMaxSkippedKeysExceeded
	errDuplicateMessage
	errUntrustedIdentity
	errMissingPQPreKeyID
	errMissingPQCiphertext
	errX3DHNoLongerSupported
	errStaleSession
	errNoSignedPreKey
	errInvalidSignature
	errInvalidKyberSignature
	errMissingKyberSignature
	errNilOneTimePreKey
	errMissingKyberPreKey
)

// ErrNoSession indicates no session exists for the given address.
var ErrNoSession = &Error{kind: errNoSession}

// ErrNoValidSessions indicates no valid session state could decrypt the message.
var ErrNoValidSessions = &Error{kind: errNoValidSessions}

// ErrUninitializedSession indicates the session state has no sender chain.
var ErrUninitializedSession = &Error{kind: errUninitializedSession}

// ErrWrongMessageVersion indicates a message version mismatch with the session.
var ErrWrongMessageVersion = &Error{kind: errWrongMessageVersion}

// ErrOldCounter indicates a message was received with an already-consumed counter.
var ErrOldCounter = &Error{kind: errOldCounter}

// ErrTooFarIntoFuture indicates a message counter is too far ahead of the chain index.
var ErrTooFarIntoFuture = &Error{kind: errTooFarIntoFuture}

// ErrMaxSkippedKeysExceeded is retained for API compatibility. The session cipher
// no longer returns this error; per-chain FIFO eviction is used instead (matching
// the Rust reference), so no error is returned when the per-chain limit is reached.
var ErrMaxSkippedKeysExceeded = &Error{kind: errMaxSkippedKeysExceeded}

// ErrDuplicateMessage indicates a message with an already-consumed counter was received.
var ErrDuplicateMessage = &Error{kind: errDuplicateMessage}

// ErrUntrustedIdentity indicates the remote identity key is not trusted.
var ErrUntrustedIdentity = &Error{kind: errUntrustedIdentity}

// ErrMissingPQPreKeyID indicates a v4+ PreKey message is missing the required
// Kyber pre-key ID. Mirrors Rust's InvalidMessage(PreKey, "missing pq pre-key ID")
// from process_prekey_impl in rust/protocol/src/session.rs.
var ErrMissingPQPreKeyID = &Error{kind: errMissingPQPreKeyID}

// ErrMissingPQCiphertext indicates a v4+ PreKey message is missing the required
// Kyber ciphertext. Mirrors Rust's InvalidMessage(PreKey, "missing pq ciphertext")
// from process_prekey_impl in rust/protocol/src/session.rs.
var ErrMissingPQCiphertext = &Error{kind: errMissingPQCiphertext}

// ErrX3DHNoLongerSupported indicates an X3DH (pre-Kyber version) PreKey message
// was received, which is no longer supported.
var ErrX3DHNoLongerSupported = &Error{kind: errX3DHNoLongerSupported}

// ErrStaleSession indicates the session has an unacknowledged pre-key message
// that has exceeded the maximum allowed age.
var ErrStaleSession = &Error{kind: errStaleSession}

// ErrNoSignedPreKey indicates the pre-key bundle is missing a signed pre-key.
var ErrNoSignedPreKey = &Error{kind: errNoSignedPreKey}

// ErrInvalidSignature indicates the signature on the device's signed pre-key is invalid.
var ErrInvalidSignature = &Error{kind: errInvalidSignature}

// ErrInvalidKyberSignature indicates the signature on the Kyber pre-key is invalid.
var ErrInvalidKyberSignature = &Error{kind: errInvalidKyberSignature}

// ErrMissingKyberSignature indicates a Kyber pre-key is present but its signature is missing.
var ErrMissingKyberSignature = &Error{kind: errMissingKyberSignature}

// ErrNilOneTimePreKey indicates the pre-key store returned a nil one-time pre-key,
// suggesting the key was already processed.
var ErrNilOneTimePreKey = &Error{kind: errNilOneTimePreKey}

// ErrMissingKyberPreKey indicates a pre-key bundle is missing the required
// Kyber pre-key for PQXDH session establishment.
var ErrMissingKyberPreKey = &Error{kind: errMissingKyberPreKey}

func (e *Error) Error() string {
	switch e.kind {
	case errNoSession:
		if e.address != "" {
			return fmt.Sprintf("session: no session for %s", e.address)
		}
		return "session: no session for address"
	case errNoValidSessions:
		return "session: no valid sessions"
	case errUninitializedSession:
		return "session: uninitialized session"
	case errWrongMessageVersion:
		return "session: wrong message version"
	case errOldCounter:
		return fmt.Sprintf("session: received message with old counter: chain index %d, message counter %d", e.index, e.counter)
	case errTooFarIntoFuture:
		return "session: too many messages into the future"
	case errMaxSkippedKeysExceeded:
		return "session: max skipped message keys exceeded"
	case errDuplicateMessage:
		return fmt.Sprintf("session: duplicate message (chain index %d, counter %d)", e.index, e.counter)
	case errUntrustedIdentity:
		if e.address != "" {
			return fmt.Sprintf("session: untrusted identity for %s", e.address)
		}
		return "session: untrusted identity"
	case errMissingPQPreKeyID:
		return "session: missing pq pre-key ID"
	case errMissingPQCiphertext:
		return "session: missing pq ciphertext"
	case errX3DHNoLongerSupported:
		return "session: X3DH no longer supported"
	case errStaleSession:
		return "session: stale unacknowledged session"
	case errNoSignedPreKey:
		return "session: no signed pre-key in bundle"
	case errInvalidSignature:
		return "session: invalid signature on device key"
	case errInvalidKyberSignature:
		return "session: invalid signature on Kyber pre-key"
	case errMissingKyberSignature:
		return "session: Kyber pre-key present but signature is missing"
	case errNilOneTimePreKey:
		return "session: pre-key store returned nil one-time pre-key (already processed?)"
	case errMissingKyberPreKey:
		return "session: missing Kyber pre-key in bundle (PQXDH required)"
	default:
		return "session: unknown error"
	}
}

// Is implements errors.Is matching. Sentinel errors match by kind.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.kind == t.kind
}

// newNoSessionError creates an error for a missing session at the given address.
func newNoSessionError(address string) *Error {
	return &Error{kind: errNoSession, address: address}
}

// newOldCounterError creates an error for a message with an already-consumed counter.
func newOldCounterError(index, counter uint32) *Error {
	return &Error{kind: errOldCounter, index: index, counter: counter}
}

// newDuplicateMessageError creates an error for a message with an already-consumed counter
// where the message key has already been removed (used).
func newDuplicateMessageError(index, counter uint32) *Error {
	return &Error{kind: errDuplicateMessage, index: index, counter: counter}
}

// newUntrustedIdentityError creates an error for an untrusted identity at the given address.
func newUntrustedIdentityError(address string) *Error {
	return &Error{kind: errUntrustedIdentity, address: address}
}
