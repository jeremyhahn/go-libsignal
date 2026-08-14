// Package sessionmanagement provides the high-level encrypt/decrypt
// facade for the Signal Protocol session, mirroring the Rust libsignal
// module rust/protocol/src/session_management.rs.
//
// Rust exposes four public functions on the protocol crate's top-level
// re-exports: message_encrypt, message_decrypt, message_decrypt_signal,
// message_decrypt_prekey. Each one composes lower-level session and
// session-cipher operations into a single call that is the canonical
// entry point client code is expected to use.
//
// The Go counterparts in this package have the same names (camel-cased
// per Go conventions) and the same compositional semantics. They wrap
// pkg/session.Builder and pkg/session.Cipher, taking the four storage
// interfaces explicitly so the facade is testable without a top-level
// SignalProtocol store.
//
// Layering: this package depends on pkg/session, pkg/protocol,
// pkg/state/store, and pkg/serialize. Nothing in pkg/protocol or
// pkg/session depends on it, so it can be added without a cycle.
//
// Address binding: address binding is automatically enabled when BOTH the
// local and remote addresses are canonical ServiceIds (bare UUID → ACI,
// "PNI:<uuid>", or legacy "ACI:<uuid>"). When either endpoint is nil or
// carries a non-canonical name (phone number, username, etc.) the legacy
// unbound path is used automatically — the cipher is constructed with nil
// for both addresses. This preserves backward compatibility for callers
// that use phone numbers or other opaque names as SignalAddress.Name().
package sessionmanagement

import (
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
)

// effectiveLocalAddress returns local when both addresses are canonical
// ServiceIds (enabling address-binding in the SignalMessage proto field 6),
// and nil otherwise (falling back to the legacy unbound path). The remote
// address is always passed directly to the cipher for session-store lookup;
// only the local address governs whether binding is active.
//
// This is the single choke-point for the back-compat decision documented in
// the package doc comment.
func effectiveLocalAddress(local, remote *protocol.SignalAddress) *protocol.SignalAddress {
	if protocol.IsCanonicalServiceIdAddress(local) && protocol.IsCanonicalServiceIdAddress(remote) {
		return local
	}
	return nil
}

// InvalidCiphertextTypeError is returned by MessageDecrypt when the caller
// passes a CiphertextMessage that is neither a SignalMessage nor a
// PreKeySignalMessage. Mirrors Rust's
// SignalProtocolError::InvalidArgument("message_decrypt cannot be used to
// decrypt {kind} messages") at session_management.rs:181.
type InvalidCiphertextTypeError struct {
	// Kind is the message-type label that was rejected. Empty when the
	// caller passed nil.
	Kind string
}

func (e *InvalidCiphertextTypeError) Error() string {
	if e.Kind == "" {
		return "sessionmanagement: nil ciphertext message"
	}
	return "sessionmanagement: cannot decrypt message of kind " + e.Kind
}

// MessageEncrypt encrypts plaintext for remoteAddress using the session
// stored under remoteAddress in sessionStore. If the session is unack'd
// (locally initiated, no inbound response yet), the result is wrapped as
// a PreKeySignalMessage; otherwise it is returned as a SignalMessage.
//
// Mirrors Rust session_management::message_encrypt at
// rust/protocol/src/session_management.rs:43.
//
// localAddress is the caller's own SignalAddress. Address binding is enabled
// automatically when both endpoints are canonical ServiceIds; otherwise the
// legacy unbound path is used (see package doc comment).
func MessageEncrypt(
	plaintext []byte,
	remoteAddress *protocol.SignalAddress,
	localAddress *protocol.SignalAddress,
	sessionStore store.Session,
	identityStore store.IdentityKey,
	serializer *serialize.Serializer,
) (protocol.CiphertextMessage, error) {
	cipher := session.NewCipherFromSessionWithLocalAddress(
		nil, // sessionRecord — Cipher loads from sessionStore on demand
		effectiveLocalAddress(localAddress, remoteAddress),
		remoteAddress,
		sessionStore,
		nil, // preKeyStore not needed for encrypt
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	cipher.SetIdentityStore(identityStore)
	return cipher.Encrypt(plaintext)
}

// MessageDecrypt routes the ciphertext to MessageDecryptSignal or
// MessageDecryptPreKey based on its concrete type.
//
// Mirrors Rust session_management::message_decrypt at
// rust/protocol/src/session_management.rs:152.
func MessageDecrypt(
	ciphertext protocol.CiphertextMessage,
	remoteAddress *protocol.SignalAddress,
	localAddress *protocol.SignalAddress,
	sessionStore store.Session,
	identityStore store.IdentityKey,
	preKeyStore store.PreKey,
	signedPreKeyStore store.SignedPreKey,
	kyberPreKeyStore store.KyberPreKey,
	serializer *serialize.Serializer,
) ([]byte, error) {
	switch m := ciphertext.(type) {
	case nil:
		return nil, &InvalidCiphertextTypeError{}
	case *protocol.SignalMessage:
		return MessageDecryptSignal(m, remoteAddress, localAddress, sessionStore, identityStore, serializer)
	case *protocol.PreKeySignalMessage:
		return MessageDecryptPreKey(
			m,
			remoteAddress,
			localAddress,
			sessionStore,
			identityStore,
			preKeyStore,
			signedPreKeyStore,
			kyberPreKeyStore,
			serializer,
		)
	default:
		return nil, &InvalidCiphertextTypeError{Kind: messageKind(ciphertext)}
	}
}

// MessageDecryptSignal decrypts an inbound SignalMessage from remoteAddress,
// looks up the matching session in sessionStore, runs the ratchet, and persists
// state.
//
// localAddress is the caller's own SignalAddress. Address binding is enabled
// automatically when both endpoints are canonical ServiceIds; otherwise the
// legacy unbound path is used (see package doc comment).
//
// Mirrors Rust session_management::message_decrypt_signal at
// rust/protocol/src/session_management.rs:282 and the address-binding check at
// rust/protocol/src/session_management.rs:242.
func MessageDecryptSignal(
	ciphertext *protocol.SignalMessage,
	remoteAddress *protocol.SignalAddress,
	localAddress *protocol.SignalAddress,
	sessionStore store.Session,
	identityStore store.IdentityKey,
	serializer *serialize.Serializer,
) ([]byte, error) {
	cipher := session.NewCipherFromSessionWithLocalAddress(
		nil,
		effectiveLocalAddress(localAddress, remoteAddress),
		remoteAddress,
		sessionStore,
		nil,
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	cipher.SetIdentityStore(identityStore)
	return cipher.Decrypt(ciphertext)
}

// MessageDecryptPreKey processes the inbound pre-key material to
// establish (or fast-forward) a session, then decrypts the inner
// SignalMessage. On success, it commits deferred side effects:
// MarkKyberPreKeyUsed (if a Kyber pre-key was consumed), pre-key removal
// (if a one-time pre-key was consumed), and session-record store.
//
// Mirrors Rust session_management::message_decrypt_prekey at
// rust/protocol/src/session_management.rs:193.
//
// Address binding is enabled automatically when both endpoints are canonical
// ServiceIds; otherwise the legacy unbound path is used (see package doc
// comment). Mirrors the address-binding check at
// rust/protocol/src/session_management.rs:242.
func MessageDecryptPreKey(
	ciphertext *protocol.PreKeySignalMessage,
	remoteAddress *protocol.SignalAddress,
	localAddress *protocol.SignalAddress,
	sessionStore store.Session,
	identityStore store.IdentityKey,
	preKeyStore store.PreKey,
	signedPreKeyStore store.SignedPreKey,
	kyberPreKeyStore store.KyberPreKey,
	serializer *serialize.Serializer,
) ([]byte, error) {
	builder := session.NewBuilderWithKyber(
		sessionStore,
		preKeyStore,
		signedPreKeyStore,
		identityStore,
		kyberPreKeyStore,
		remoteAddress,
		serializer,
	)

	cipher := session.NewCipherFromSessionWithLocalAddress(
		nil,
		effectiveLocalAddress(localAddress, remoteAddress),
		remoteAddress,
		sessionStore,
		preKeyStore,
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	cipher.SetIdentityStore(identityStore)

	// DecryptPreKeyMessage calls deferred.Complete() internally and returns
	// a non-nil deferred only on success. Calling Complete() a second time
	// here was a double-commit bug: on a non-idempotent store (e.g., one
	// that errors on the second RemovePreKey or MarkKyberPreKeyUsed call)
	// a valid first-message decrypt would return a spurious error.
	// Mirrors sealed/sealed_sender.go which discards the returned deferred
	// for the same reason.
	//
	// Rust reference: session_cipher.rs message_decrypt_prekey only calls
	// the side-effect functions once.
	plaintext, _, err := cipher.DecryptPreKeyMessage(builder, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// messageKind returns a human-readable label for a CiphertextMessage,
// used in error reporting from MessageDecrypt.
func messageKind(m protocol.CiphertextMessage) string {
	if m == nil {
		return ""
	}
	switch m.(type) {
	case *protocol.SenderKeyMessage:
		return "SenderKeyMessage"
	case *protocol.SenderKeyDistributionMessage:
		return "SenderKeyDistributionMessage"
	case *protocol.PlaintextContent:
		return "PlaintextContent"
	default:
		return "unknown"
	}
}
