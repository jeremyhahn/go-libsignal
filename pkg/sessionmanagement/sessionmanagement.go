// Package sessionmanagement provides MessageEncrypt and the MessageDecrypt functions over pkg/session, as Rust session_management.rs does; address binding is on when both addresses are canonical ServiceIds, otherwise the unbound path is used.
package sessionmanagement

import (
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
)

// effectiveLocalAddress returns local when both addresses are canonical ServiceIds, enabling address binding, and nil otherwise.
func effectiveLocalAddress(local, remote *protocol.SignalAddress) *protocol.SignalAddress {
	if protocol.IsCanonicalServiceIdAddress(local) && protocol.IsCanonicalServiceIdAddress(remote) {
		return local
	}
	return nil
}

// InvalidCiphertextTypeError is returned by MessageDecrypt for a message that is neither a SignalMessage nor a PreKeySignalMessage.
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

// MessageEncrypt encrypts plaintext for remoteAddress, as a PreKeySignalMessage while the session is unacknowledged and a SignalMessage after.
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

// MessageDecrypt dispatches to MessageDecryptSignal or MessageDecryptPreKey by type.
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

// MessageDecryptSignal decrypts a SignalMessage from remoteAddress and persists the session.
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

// MessageDecryptPreKey establishes the session from the pre-key message, decrypts the inner message and then commits the pre-key and session changes.
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

	// DecryptPreKeyMessage already called Complete; calling it again would double-commit.
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
