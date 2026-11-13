package session

import (
	"errors"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/root"
	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

const maxFutureMessages = 25000

// Per-chain skipped message key limit (MAX_MESSAGE_KEYS = 2000) is
// enforced in state/record.SessionState.SetMessageKeys via FIFO eviction.

// maxUnacknowledgedSessionAge is the maximum age of an unacknowledged
// pre-key session before it is considered stale. Set to 30 days to
// match the Rust reference (MAX_UNACKNOWLEDGED_SESSION_AGE).
const maxUnacknowledgedSessionAge = 30 * 24 * time.Hour

// NewCipher constructs a session cipher using the legacy unbound path
// (no address binding). localAddress is set to nil, so SignalMessage
// field 6 is not populated.
//
// Deprecated: NewCipher omits the address-binding proto field (SignalMessage
// field 6) that Rust libsignal always includes when a local address is known.
// Use NewCipherWithLocalAddress with a non-nil localAddress to match Rust
// behavior and prevent address-substitution downgrade attacks.
func NewCipher(builder *Builder, remoteAddress *protocol.SignalAddress) *Cipher {
	return NewCipherWithLocalAddress(builder, nil, remoteAddress)
}

// NewCipherWithLocalAddress constructs a session cipher for encrypt/decrypt
// operations on a session. In order to use the session cipher, a session must
// have already been created and stored using session.Builder.
//
// localAddress is the caller's own SignalAddress. When both localAddress and
// remoteAddress are non-nil canonical ServiceIds, address binding is active
// and SignalMessage field 6 is populated. Pass nil for localAddress to use
// the legacy unbound path.
//
// Rust source: rust/protocol/src/session_cipher.rs SessionCipher::new.
func NewCipherWithLocalAddress(builder *Builder, localAddress, remoteAddress *protocol.SignalAddress) *Cipher {
	return &Cipher{
		sessionStore:            builder.sessionStore,
		preKeyMessageSerializer: builder.serializer.PreKeySignalMessage,
		signalMessageSerializer: builder.serializer.SignalMessage,
		preKeyStore:             builder.preKeyStore,
		identityStore:           builder.identityKeyStore,
		localAddress:            localAddress,
		remoteAddress:           remoteAddress,
	}
}

// NewCipherFromSession creates a cipher from an existing session record
// using the legacy unbound path (no address binding). localAddress is set
// to nil, so SignalMessage field 6 is not populated.
//
// Deprecated: NewCipherFromSession omits the address-binding proto field
// (SignalMessage field 6) that Rust libsignal always includes when a local
// address is known. Use NewCipherFromSessionWithLocalAddress with a non-nil
// localAddress to match Rust behavior and prevent address-substitution
// downgrade attacks.
func NewCipherFromSession(sess *record.Session, remoteAddress *protocol.SignalAddress,
	sessionStore store.Session, preKeyStore store.PreKey,
	preKeyMessageSerializer protocol.PreKeySignalMessageSerializer,
	signalMessageSerializer protocol.SignalMessageSerializer) *Cipher {
	return NewCipherFromSessionWithLocalAddress(sess, nil, remoteAddress,
		sessionStore, preKeyStore, preKeyMessageSerializer, signalMessageSerializer)
}

// NewCipherFromSessionWithLocalAddress creates a cipher from an existing session record.
//
// localAddress is the caller's own SignalAddress. When both localAddress and
// remoteAddress are non-nil canonical ServiceIds, address binding is active
// and SignalMessage field 6 is populated. Pass nil for localAddress to use
// the legacy unbound path.
//
// Rust source: rust/protocol/src/session_management.rs message_encrypt /
// message_decrypt_signal.
func NewCipherFromSessionWithLocalAddress(sess *record.Session, localAddress, remoteAddress *protocol.SignalAddress,
	sessionStore store.Session, preKeyStore store.PreKey,
	preKeyMessageSerializer protocol.PreKeySignalMessageSerializer,
	signalMessageSerializer protocol.SignalMessageSerializer) *Cipher {
	return &Cipher{
		sessionStore:            sessionStore,
		preKeyMessageSerializer: preKeyMessageSerializer,
		signalMessageSerializer: signalMessageSerializer,
		preKeyStore:             preKeyStore,
		localAddress:            localAddress,
		remoteAddress:           remoteAddress,
	}
}

// NewCipherWithIdentity creates a cipher with an identity key store for
// trust verification on encrypt and decrypt, using the legacy unbound path
// (no address binding). localAddress is set to nil.
//
// Deprecated: NewCipherWithIdentity omits the address-binding proto field
// (SignalMessage field 6) that Rust libsignal always includes when a local
// address is known. Use NewCipherWithIdentityAndLocalAddress with a non-nil
// localAddress to match Rust behavior and prevent address-substitution
// downgrade attacks.
func NewCipherWithIdentity(builder *Builder, remoteAddress *protocol.SignalAddress,
	identityStore store.IdentityKey) *Cipher {
	return NewCipherWithIdentityAndLocalAddress(builder, nil, remoteAddress, identityStore)
}

// NewCipherWithIdentityAndLocalAddress creates a cipher with an identity key
// store for trust verification on encrypt and decrypt.
//
// localAddress is the caller's own SignalAddress. When both localAddress and
// remoteAddress are non-nil canonical ServiceIds, address binding is active
// and SignalMessage field 6 is populated. Pass nil for localAddress to use
// the legacy unbound path.
//
// Rust source: rust/protocol/src/session_cipher.rs SessionCipher::new with
// identity-store composition at rust/protocol/src/session_management.rs.
func NewCipherWithIdentityAndLocalAddress(builder *Builder, localAddress, remoteAddress *protocol.SignalAddress,
	identityStore store.IdentityKey) *Cipher {
	return &Cipher{
		sessionStore:            builder.sessionStore,
		preKeyMessageSerializer: builder.serializer.PreKeySignalMessage,
		signalMessageSerializer: builder.serializer.SignalMessage,
		preKeyStore:             builder.preKeyStore,
		identityStore:           identityStore,
		localAddress:            localAddress,
		remoteAddress:           remoteAddress,
	}
}

// SetIdentityStore attaches an identity-key store to an existing Cipher.
// Provided so the high-level pkg/sessionmanagement facade can compose a
// Cipher around a Builder without needing a second constructor.
func (d *Cipher) SetIdentityStore(s store.IdentityKey) {
	d.identityStore = s
}

// Cipher is the main entry point for Signal Protocol encrypt/decrypt operations.
// Once a session has been established with session.Builder, this can be used for
// all encrypt/decrypt operations within that session.
//
// A Cipher instance is NOT safe for concurrent use by multiple goroutines.
// Callers must provide their own synchronization if encrypting or decrypting
// messages for the same address from multiple goroutines. Alternatively,
// the session store implementation can provide per-address locking.
// This matches the Rust reference which enforces single-threaded access
// via the borrow checker's &mut requirement.
type Cipher struct {
	sessionStore            store.Session
	preKeyMessageSerializer protocol.PreKeySignalMessageSerializer
	signalMessageSerializer protocol.SignalMessageSerializer
	preKeyStore             store.PreKey
	identityStore           store.IdentityKey
	localAddress            *protocol.SignalAddress
	remoteAddress           *protocol.SignalAddress
}

// Encrypt will take the given message in bytes and return an object that follows
// the CiphertextMessage interface.
func (d *Cipher) Encrypt(plaintext []byte) (protocol.CiphertextMessage, error) {
	sessionRecord, err := d.sessionStore.LoadSession(d.remoteAddress)
	if err != nil {
		return nil, err
	}
	sessionState := sessionRecord.SessionState()
	// SenderChainKey hands back a copy in its own guarded buffer. The ratchet
	// forward below consumes it; this releases it on the paths that return
	// before that happens.
	chainKey := sessionState.SenderChainKey()
	defer chainKey.(*chain.Key).Zeroize()

	// Derive message keys, incorporating SPQR ratchet if active.
	var (
		messageKeys *message.Keys
		pqrMsg      []byte
	)
	if pqrState := sessionState.PqRatchetState(); len(pqrState) > 0 {
		// PqRatchetState returns an owned copy; wipe it on return.
		defer crypto.Zeroize(pqrState)
		newState, msg, pqrKey, pqrErr := spqr.Send(pqrState)
		if pqrErr != nil {
			return nil, pqrErr
		}
		if setErr := sessionState.SetPqRatchetState(newState); setErr != nil {
			return nil, setErr
		}
		pqrMsg = msg
		messageKeys, err = chainKey.MessageKeysWithSalt(pqrKey)
	} else {
		messageKeys, err = chainKey.MessageKeys()
	}
	if err != nil {
		return nil, err
	}
	// Zeroize message keys after they have been used for encryption.
	// This is deferred so it runs even if subsequent steps return an error,
	// limiting the window during which the plaintext-equivalent key material
	// is live on the heap.
	defer messageKeys.Zeroize()

	senderEphemeral := sessionState.SenderRatchetKey()
	previousCounter := sessionState.PreviousCounter()
	sessionVersion := sessionState.Version()

	ciphertextBody, err := encrypt(messageKeys, plaintext)
	if err != nil {
		return nil, err
	}

	// MacKey returns an owned copy; wipe it once the message is built.
	macKey := messageKeys.MacKey()
	defer crypto.Zeroize(macKey)

	var ciphertextMessage protocol.CiphertextMessage
	ciphertextMessage, err = protocol.NewSignalMessage(
		sessionVersion,
		chainKey.Index(),
		previousCounter,
		macKey,
		senderEphemeral,
		ciphertextBody,
		sessionState.LocalIdentityKey(),
		sessionState.RemoteIdentityKey(),
		d.signalMessageSerializer,
		pqrMsg,
		d.localAddress,
		d.remoteAddress,
	)
	if err != nil {
		return nil, err
	}

	// If we haven't established a session with the recipient yet,
	// send our message as a PreKeySignalMessage.
	if sessionState.HasUnacknowledgedPreKeyMessage() {
		// M15: Check stale session age before encrypting with unacknowledged
		// pre-key. Matches Rust MAX_UNACKNOWLEDGED_SESSION_AGE check.
		if sessionState.UnacknowledgedTimestamp() > 0 {
			createdAt := time.Unix(int64(sessionState.UnacknowledgedTimestamp()), 0)
			if createdAt.Add(maxUnacknowledgedSessionAge).Before(time.Now()) {
				logger.Warning("Stale unacknowledged session for ", d.remoteAddress.String())
				return nil, &Error{kind: errStaleSession}
			}
		}

		items, err := sessionState.UnackPreKeyMessageItems()
		if err != nil {
			return nil, err
		}
		localRegistrationID := sessionState.LocalRegistrationID()

		ciphertextMessage, err = protocol.NewPreKeySignalMessageWithKyber(
			sessionVersion,
			localRegistrationID,
			items.PreKeyID(),
			items.SignedPreKeyID(),
			items.BaseKey(),
			sessionState.LocalIdentityKey(),
			ciphertextMessage.(*protocol.SignalMessage),
			d.preKeyMessageSerializer,
			d.signalMessageSerializer,
			items.KyberPreKeyID(),
			items.KyberCiphertext(),
		)
		if err != nil {
			return nil, err
		}
	}

	nextChainKey := chainKey.NextKey()
	// Old chain key material is automatically destroyed by NextKey() via go-enclave.
	sessionState.SetSenderChainKey(nextChainKey)

	// Identity trust check is performed after chain key advancement but before
	// StoreSession. If the check fails, the in-memory session with the advanced
	// chain key is discarded (never persisted). This matches the Rust reference
	// ordering (session_cipher.rs) and is safe because the store is not updated.
	if d.identityStore != nil {
		theirIdentityKey := sessionState.RemoteIdentityKey()
		trusted, trustErr := d.identityStore.IsTrustedIdentity(d.remoteAddress, theirIdentityKey, store.DirectionSending)
		if trustErr != nil {
			return nil, trustErr
		}
		if !trusted {
			logger.Warning("Identity key is not trusted for sending to ", d.remoteAddress.String())
			return nil, newUntrustedIdentityError(d.remoteAddress.String())
		}
		if _, err := d.identityStore.SaveIdentity(d.remoteAddress, theirIdentityKey); err != nil {
			return nil, err
		}
	}

	if err := d.sessionStore.StoreSession(d.remoteAddress, sessionRecord); err != nil {
		return nil, err
	}

	return ciphertextMessage, nil
}

// Decrypt decrypts the given message using an existing session that
// is stored in the session store. Message keys are zeroized after use;
// callers that need the keys should use DecryptAndGetKey instead and
// call Zeroize() on the returned keys when done.
func (d *Cipher) Decrypt(ciphertextMessage *protocol.SignalMessage) ([]byte, error) {
	plaintext, messageKeys, err := d.DecryptAndGetKey(ciphertextMessage)
	if messageKeys != nil {
		messageKeys.Zeroize()
	}
	return plaintext, err
}

// DecryptPreKeyMessage handles the full PreKeySignalMessage decryption flow
// with deferred side effects, matching the Rust reference implementation
// (session_cipher.rs message_decrypt_prekey). It:
//  1. Calls builder.Process() to establish the session (without storing)
//  2. Decrypts the inner SignalMessage using the new session record
//  3. Only on success: commits the deferred side effects (store session,
//     save identity, mark Kyber pre-key used, remove one-time pre-key)
//
// If decryption fails, pre-keys are preserved because the deferred
// operations are never committed.
func (d *Cipher) DecryptPreKeyMessage(builder *Builder, preKeyMessage *protocol.PreKeySignalMessage) ([]byte, *DeferredActions, error) {
	deferred, err := builder.Process(preKeyMessage)
	if err != nil {
		return nil, nil, err
	}

	plaintext, msgKeys, err := d.DecryptWithRecordPreKey(deferred.SessionRecord, preKeyMessage.WhisperMessage())
	if msgKeys != nil {
		msgKeys.Zeroize()
	}
	if err != nil {
		return nil, nil, err
	}

	if err := deferred.Complete(); err != nil {
		return nil, nil, err
	}

	return plaintext, deferred, nil
}

// DecryptAndGetKey decrypts the given message using an existing session that
// is stored in the session store and returns the message keys used for encryption.
// The caller is responsible for calling Zeroize() on the returned *message.Keys
// when it is no longer needed to clear key material from heap memory.
func (d *Cipher) DecryptAndGetKey(ciphertextMessage *protocol.SignalMessage) ([]byte, *message.Keys, error) {
	hasSession, err := d.sessionStore.ContainsSession(d.remoteAddress)
	if err != nil {
		return nil, nil, err
	}
	if !hasSession {
		return nil, nil, newNoSessionError(d.remoteAddress.String())
	}

	// Load the session record from our session store and decrypt the message.
	sessionRecord, err := d.sessionStore.LoadSession(d.remoteAddress)
	if err != nil {
		return nil, nil, err
	}
	plaintext, messageKeys, err := d.DecryptWithRecord(sessionRecord, ciphertextMessage)
	if err != nil {
		return nil, nil, err
	}

	// H3: Identity trust check after decryption (matches Rust message_decrypt_signal).
	if d.identityStore != nil {
		theirIdentityKey := sessionRecord.SessionState().RemoteIdentityKey()
		trusted, trustErr := d.identityStore.IsTrustedIdentity(d.remoteAddress, theirIdentityKey, store.DirectionReceiving)
		if trustErr != nil {
			return nil, nil, trustErr
		}
		if !trusted {
			logger.Warning("Identity key is not trusted for receiving from ", d.remoteAddress.String())
			return nil, nil, newUntrustedIdentityError(d.remoteAddress.String())
		}
		if _, err := d.identityStore.SaveIdentity(d.remoteAddress, theirIdentityKey); err != nil {
			return nil, nil, err
		}
	}

	// Store the session record in our session store.
	if err := d.sessionStore.StoreSession(d.remoteAddress, sessionRecord); err != nil {
		return nil, nil, err
	}

	return plaintext, messageKeys, nil
}

// DecryptWithKey will decrypt the given message using the given symmetric key. This
// can be used when decrypting messages at a later time if the message key was saved.
func (d *Cipher) DecryptWithKey(ciphertextMessage *protocol.SignalMessage, key *message.Keys) ([]byte, error) {
	plaintext, err := decrypt(key, ciphertextMessage.Body())
	if err != nil {
		logger.Error("Unable to get plain text from ciphertext: ", err)
		return nil, err
	}

	return plaintext, nil
}

// DecryptWithRecord decrypts the given message using the given session record.
// It implements the short-circuit logic from the Rust reference:
//   - DuplicateMessage errors are returned immediately (M1)
//   - PreKey messages do not fall back to previous sessions (M2)
func (d *Cipher) DecryptWithRecord(sessionRecord *record.Session, ciphertext *protocol.SignalMessage) ([]byte, *message.Keys, error) {
	return d.decryptWithRecordAndType(sessionRecord, ciphertext, protocol.WHISPER_TYPE)
}

// DecryptWithRecordPreKey decrypts the inner SignalMessage of a PreKeySignalMessage
// using the given session record. PreKey messages do not fall back to previous sessions.
func (d *Cipher) DecryptWithRecordPreKey(sessionRecord *record.Session, ciphertext *protocol.SignalMessage) ([]byte, *message.Keys, error) {
	return d.decryptWithRecordAndType(sessionRecord, ciphertext, protocol.PREKEY_TYPE)
}

// decryptWithRecordAndType is the internal implementation that handles both
// regular and PreKey message decryption with appropriate short-circuit behavior.
func (d *Cipher) decryptWithRecordAndType(sessionRecord *record.Session, ciphertext *protocol.SignalMessage, messageType uint32) ([]byte, *message.Keys, error) {
	previousStates := sessionRecord.PreviousSessionStates()
	sessionState := sessionRecord.SessionState()

	// Try and decrypt the message with the current session state.
	plaintext, messageKeys, err := d.DecryptWithState(sessionState, ciphertext)

	if err != nil {
		// M1: DuplicateMessage short-circuit. If a message key was already
		// consumed, return immediately instead of trying other sessions.
		if errors.Is(err, ErrDuplicateMessage) {
			return nil, nil, err
		}

		// M3: AddressMismatch short-circuit. An address-binding mismatch means
		// the message's embedded (sender, recipient) pair does not match the
		// expected local addresses. No previous session can resolve this — the
		// binding is a property of the message, not the session state. Surface
		// the typed error immediately so callers can distinguish a wrong-recipient
		// delivery from a genuine decryption failure.
		//
		// Mirrors Rust session_management.rs:242 and the address-binding
		// enforcement in triple_ratchet.rs TripleRatchet::decrypt.
		if errors.Is(err, protocol.ErrAddressMismatch) {
			return nil, nil, err
		}

		// M2: PreKey message short-circuit. A PreKey message creates a fresh
		// session, so previous sessions are irrelevant. Return immediately.
		if messageType == protocol.PREKEY_TYPE {
			logger.Error("PreKey message decryption failed with current session, not trying previous states")
			return nil, nil, &Error{kind: errNoValidSessions}
		}

		logger.Warning(err)
		for idx, state := range previousStates {
			// Try decrypting the message with previous states
			plaintext, messageKeys, err = d.DecryptWithState(state, ciphertext)
			if err != nil {
				// M1: DuplicateMessage short-circuit in previous states too.
				// SPQR duplicate errors are NOT short-circuited here because
				// a counter collision on a previous session is merely a
				// wrong-session mismatch, not a genuine replay.
				if errors.Is(err, ErrDuplicateMessage) {
					return nil, nil, err
				}
				// M3: Address mismatch short-circuit in previous states.
				if errors.Is(err, protocol.ErrAddressMismatch) {
					return nil, nil, err
				}
				continue
			}

			// DR-W5: Use PromoteOldSession to remove the old entry from
			// previousStates before promoting, preventing duplicates.
			sessionRecord.PromoteOldSession(idx, state)

			return plaintext, messageKeys, nil
		}

		return nil, nil, &Error{kind: errNoValidSessions}
	}

	// If decryption was successful, set the session state and return the plain text.
	sessionRecord.SetState(sessionState)

	return plaintext, messageKeys, nil
}

// DecryptWithState decrypts the given message with the given session state.
// Per Signal spec section 3.5, if decryption fails, all mutations to the
// session state are discarded. This is achieved by operating on a cloned
// copy of the state and only committing changes on success.
func (d *Cipher) DecryptWithState(sessionState *record.State, ciphertextMessage *protocol.SignalMessage) ([]byte, *message.Keys, error) {
	if !sessionState.HasSenderChain() {
		logger.Error("Unable to decrypt message with state: uninitialized session")
		return nil, nil, &Error{kind: errUninitializedSession}
	}

	if ciphertextMessage.MessageVersion() != sessionState.Version() {
		logger.Error("Unable to decrypt message with state: wrong message version")
		return nil, nil, &Error{kind: errWrongMessageVersion}
	}

	// Clone the session state so that mutations can be rolled back on failure.
	// Per Double Ratchet spec section 3.5: "If an exception is raised then
	// the message is discarded and changes to the state object are discarded."
	workingState, cloneErr := sessionState.Clone()
	if cloneErr != nil {
		logger.Error("Unable to clone session state: ", cloneErr)
		return nil, nil, cloneErr
	}

	// The clone holds its own guarded buffers, and a failed decrypt throws it
	// away. Release them rather than abandoning them: go-enclave reclaims
	// nothing on its own, so otherwise every message that fails MAC
	// verification would cost the process locked memory it never gets back.
	// The commit below moves those buffers into sessionState, which is why the
	// discard is disarmed on the success path.
	committed := false
	defer func() {
		if !committed {
			workingState.DiscardClone()
		}
	}()

	plaintext, messageKeys, err := d.decryptWithClonedState(workingState, ciphertextMessage)
	if err != nil {
		return nil, nil, err
	}

	// Decryption succeeded -- commit the working state back to the original.
	// Committing rather than copying releases the guarded material the commit
	// supersedes, so a long-lived session does not accumulate a locked buffer
	// per message it accepts.
	sessionState.CommitClone(workingState)
	committed = true

	return plaintext, messageKeys, nil
}

// decryptWithClonedState performs the actual decryption logic on a cloned
// session state. All mutations happen on this copy; if any step fails, the
// caller simply discards it.
//
// SPQR ordering note: Both Go and Rust advance SPQR state before MAC
// verification. The structural difference is that Go advances SPQR state
// during the skipped-key lookup path (early in this function), whereas Rust
// advances SPQR state after chain key creation (further down the normal path).
// The functional outcome is identical because both implementations operate on
// cloned/working state that is discarded on failure:
//
//  1. This method operates on a cloned session state (see DecryptWithState).
//     If MAC verification or decryption fails at any point, the clone is
//     discarded and the original session state remains unchanged -- no SPQR
//     state mutation is ever committed.
//
//  2. The clone-then-commit pattern provides the same rollback semantics as
//     the Rust borrow checker's &mut requirement, ensuring that a failed
//     decrypt attempt cannot corrupt the SPQR ratchet position regardless
//     of which code path triggered the failure.
//
//  3. Advancing SPQR before MAC verification is necessary because the PQR
//     salt is needed to derive the correct message keys for verification.
//     Without advancing first, we cannot compute the expected MAC.
func (d *Cipher) decryptWithClonedState(sessionState *record.State, ciphertextMessage *protocol.SignalMessage) ([]byte, *message.Keys, error) {
	messageVersion := ciphertextMessage.MessageVersion()
	theirEphemeral := ciphertextMessage.SenderRatchetKey()
	counter := ciphertextMessage.Counter()

	// TrySkippedMessageKeys: check for stored skipped message keys before
	// performing a potentially expensive DH ratchet step.
	if sessionState.HasReceiverChain(theirEphemeral) && sessionState.HasMessageKeys(theirEphemeral, counter) {
		skippedKeys := sessionState.RemoveMessageKeys(theirEphemeral, counter)

		// The keys are no longer part of the clone, so discarding the clone no
		// longer covers them. Release them on every exit that does not hand
		// them to the caller — a message that matches a stored skipped key but
		// fails authentication is attacker-supplied.
		keysHandedOver := false
		defer func() {
			if !keysHandedOver && skippedKeys != nil {
				skippedKeys.Zeroize()
			}
		}()

		// Note: PQR state is advanced before MAC verification, which differs from
		// Rust's ordering. This is safe because decryptWithClonedState operates on
		// a cloned session state; if MAC verification fails, the clone is discarded
		// and the original state remains unchanged.
		//
		// SPQR: If the stored key has seed material and the message carries PQR
		// data, re-derive the message keys with the PQR salt from the SPQR ratchet.
		if seed := skippedKeys.SeedMaterial(); len(seed) > 0 {
			// SeedMaterial returns an owned copy; wipe it on return.
			defer crypto.Zeroize(seed)
			if pqrData := ciphertextMessage.PqRatchetKey(); len(pqrData) > 0 {
				if pqrState := sessionState.PqRatchetState(); len(pqrState) > 0 {
					// PqRatchetState returns an owned copy; wipe it on return.
					defer crypto.Zeroize(pqrState)
					newState, pqrKey, pqrErr := spqr.Recv(pqrState, pqrData)
					if pqrErr != nil {
						return nil, nil, pqrErr
					}
					if setErr := sessionState.SetPqRatchetState(newState); setErr != nil {
						return nil, nil, setErr
					}
					seedCopy := make([]byte, len(seed))
					copy(seedCopy, seed)
					reDerived, reErr := chain.DeriveMessageKeysFromSeed(
						kdf.DeriveSecrets, seedCopy, pqrKey, skippedKeys.Index(),
					)
					if reErr != nil {
						return nil, nil, reErr
					}
					// The stored keys have been superseded by the re-derived
					// ones; the seed was copied out above.
					skippedKeys.Zeroize()
					skippedKeys = reDerived
				}
			}
		}

		// F15: Use VerifyMacWithAddresses when both local and remote addresses are
		// known, enforcing address binding on pre-key decrypt. Mirrors Rust
		// rust/protocol/src/session_management.rs:242 and
		// rust/protocol/src/triple_ratchet.rs TripleRatchet::decrypt.
		// MacKey returns an owned copy; wipe it when decrypt returns.
		skippedMacKey := skippedKeys.MacKey()
		defer crypto.Zeroize(skippedMacKey)
		if d.localAddress != nil && d.remoteAddress != nil {
			err := ciphertextMessage.VerifyMacWithAddresses(messageVersion,
				sessionState.RemoteIdentityKey(), sessionState.LocalIdentityKey(),
				skippedMacKey, d.remoteAddress, d.localAddress)
			if err != nil {
				logger.Error("Unable to verify ciphertext mac (with addresses) for skipped key: ", err)
				return nil, nil, err
			}
		} else {
			err := ciphertextMessage.VerifyMac(messageVersion, sessionState.RemoteIdentityKey(), sessionState.LocalIdentityKey(), skippedMacKey)
			if err != nil {
				logger.Error("Unable to verify ciphertext mac for skipped key: ", err)
				return nil, nil, err
			}
		}

		plaintext, err := d.DecryptWithKey(ciphertextMessage, skippedKeys)
		if err != nil {
			return nil, nil, err
		}

		sessionState.ClearUnackPreKeyMessage()
		keysHandedOver = true
		return plaintext, skippedKeys, nil
	}

	chainKey, chainCreateErr := getOrCreateChainKey(sessionState, theirEphemeral)
	if chainCreateErr != nil {
		logger.Error("Unable to get or create chain key: ", chainCreateErr)
		return nil, nil, chainCreateErr
	}
	// The chain key is this call's own copy. Ratcheting it forward destroys its
	// buffer, so this is a no-op on the paths that get that far and a release
	// on the ones that return first — a duplicate message, for instance.
	defer chainKey.Zeroize()

	// SPQR: Derive the PQR salt for message key derivation if both the message
	// carries PQR data and the session has active SPQR state.
	var pqrSalt []byte
	if pqrData := ciphertextMessage.PqRatchetKey(); len(pqrData) > 0 {
		if pqrState := sessionState.PqRatchetState(); len(pqrState) > 0 {
			// PqRatchetState returns an owned copy; wipe it on return.
			defer crypto.Zeroize(pqrState)
			newState, pqrKey, pqrErr := spqr.Recv(pqrState, pqrData)
			if pqrErr != nil {
				// SPQR duplicate errors can mean either a genuine replay (same
				// session) or a wrong-session mismatch (different session reusing
				// a similar SPQR counter). Check the Double Ratchet's own state:
				// if the chain has already advanced past this counter and the
				// message key was consumed, this is a genuine replay.
				if isSpqrDuplicateErr(pqrErr) && chainKey.Index() > counter &&
					!sessionState.HasMessageKeys(theirEphemeral, counter) {
					return nil, nil, newDuplicateMessageError(chainKey.Index(), counter)
				}
				return nil, nil, pqrErr
			}
			if setErr := sessionState.SetPqRatchetState(newState); setErr != nil {
				return nil, nil, setErr
			}
			pqrSalt = pqrKey
		}
	}

	messageKeys, keysCreateErr := getOrCreateMessageKeys(sessionState, theirEphemeral, chainKey, counter, pqrSalt)
	if keysCreateErr != nil {
		logger.Error("Unable to get or create message keys: ", keysCreateErr)
		return nil, nil, keysCreateErr
	}
	// These keys are derived here and belong to nothing else. Release them on
	// every exit that does not hand them to the caller — authentication has
	// not happened yet, so the exits below are exactly the ones an attacker
	// can drive.
	messageKeysHandedOver := false
	defer func() {
		if !messageKeysHandedOver && messageKeys != nil {
			messageKeys.Zeroize()
		}
	}()

	// F15: Use VerifyMacWithAddresses when both local and remote addresses are
	// known, enforcing address binding. Mirrors Rust
	// rust/protocol/src/session_management.rs:242.
	// MacKey returns an owned copy; wipe it when decrypt returns.
	macKey := messageKeys.MacKey()
	defer crypto.Zeroize(macKey)
	if d.localAddress != nil && d.remoteAddress != nil {
		err := ciphertextMessage.VerifyMacWithAddresses(messageVersion,
			sessionState.RemoteIdentityKey(), sessionState.LocalIdentityKey(),
			macKey, d.remoteAddress, d.localAddress)
		if err != nil {
			logger.Error("Unable to verify ciphertext mac (with addresses): ", err)
			return nil, nil, err
		}
	} else {
		err := ciphertextMessage.VerifyMac(messageVersion, sessionState.RemoteIdentityKey(), sessionState.LocalIdentityKey(), macKey)
		if err != nil {
			logger.Error("Unable to verify ciphertext mac: ", err)
			return nil, nil, err
		}
	}

	plaintext, err := d.DecryptWithKey(ciphertextMessage, messageKeys)
	if err != nil {
		return nil, nil, err
	}

	sessionState.ClearUnackPreKeyMessage()

	messageKeysHandedOver = true
	return plaintext, messageKeys, nil
}

func getOrCreateMessageKeys(sessionState *record.State, theirEphemeral ecc.ECPublicKeyable,
	chainKey *chain.Key, counter uint32, pqrSalt []byte) (*message.Keys, error) {

	if chainKey.Index() > counter {
		if sessionState.HasMessageKeys(theirEphemeral, counter) {
			storedKeys := sessionState.RemoveMessageKeys(theirEphemeral, counter)
			// SPQR: Re-derive with PQR salt if the stored key has seed material.
			if seed := storedKeys.SeedMaterial(); len(seed) > 0 && len(pqrSalt) > 0 {
				// SeedMaterial returns an owned copy; wipe it on return.
				defer crypto.Zeroize(seed)
				seedCopy := make([]byte, len(seed))
				copy(seedCopy, seed)
				// The stored keys leave the clone here and are superseded by
				// the re-derived ones, so nothing else will release them.
				defer storedKeys.Zeroize()
				return chain.DeriveMessageKeysFromSeed(kdf.DeriveSecrets, seedCopy, pqrSalt, storedKeys.Index())
			}
			return storedKeys, nil
		}
		// The message key has already been consumed (removed). This is a
		// duplicate message, matching Rust's DuplicatedMessage error.
		return nil, newDuplicateMessageError(chainKey.Index(), counter)
	}

	// DR-W2: Rust exempts self-sessions from the MAX_FORWARD_JUMPS check.
	// Self-sessions (linked device sync) can have large counter gaps due to
	// multi-device message ordering, matching Rust's session_with_self check.
	if counter-chainKey.Index() > maxFutureMessages {
		if sessionState.SessionWithSelf() {
			logger.Info("Self-session: jumping ahead ",
				counter-chainKey.Index(), " messages (index: ",
				chainKey.Index(), ", counter: ", counter, ")")
		} else {
			return nil, &Error{kind: errTooFarIntoFuture}
		}
	}

	// Per-chain FIFO eviction: when the chain accumulates more than 2000
	// entries, SetMessageKeys evicts the oldest key automatically, matching
	// Rust's per-chain eviction. The state layer enforces the bound.

	hasSPQR := len(pqrSalt) > 0

	// Walking the chain forward replaces chainKey with each derived key, and
	// only the one that reaches SetReceiverChainKey below finds an owner.
	// Release whatever the walk ends on if it does not get there; the caller's
	// own release covers the key it passed in, and both are idempotent.
	walked := chainKey
	defer func() {
		if walked != nil {
			walked.Zeroize()
		}
	}()

	for chainKey.Index() < counter {
		var msgKeys *message.Keys
		var err error
		if hasSPQR {
			// Store seed material so skipped keys can be re-derived with PQR salt later.
			msgKeys, err = chainKey.MessageKeysWithSeed()
		} else {
			msgKeys, err = chainKey.MessageKeys()
		}
		if err != nil {
			return nil, err
		}
		if err := sessionState.SetMessageKeys(theirEphemeral, msgKeys); err != nil {
			return nil, err
		}
		// NextKey zeroizes the old chain key internally.
		chainKey = chainKey.NextKey()
		walked = chainKey
	}

	// Get message keys before advancing, since NextKey destroys the current key's
	// guarded memory. Use PQR salt if provided for SPQR-enhanced derivation.
	msgKeys, err := chainKey.MessageKeysWithSalt(pqrSalt)
	if err != nil {
		return nil, err
	}
	nextKey := chainKey.NextKey()
	walked = nextKey
	if err := sessionState.SetReceiverChainKey(theirEphemeral, nextKey); err != nil {
		return nil, err
	}
	walked = nil
	return msgKeys, nil
}

// getOrCreateChainKey will either return the existing chain key or
// create a new one with the given session state and ephemeral key.
//
// The returned key is the caller's own guarded copy in both cases, never the
// one the state holds. Ratcheting it forward with NextKey consumes it; a
// caller that returns without doing so must release it.
func getOrCreateChainKey(sessionState *record.State, theirEphemeral ecc.ECPublicKeyable) (*chain.Key, error) {

	// If our session state already has a receiver chain, use their
	// ephemeral key in the existing chain.
	if sessionState.HasReceiverChain(theirEphemeral) {
		return sessionState.ReceiverChainKey(theirEphemeral), nil
	}

	// If we don't have a chain key, create one with ephemeral keys.
	rootKey := sessionState.RootKey()
	ourEphemeral := sessionState.SenderRatchetKeyPair()
	receiverChain, rErr := rootKey.CreateChain(theirEphemeral, ourEphemeral)
	if rErr != nil {
		return nil, rErr
	}

	// Generate a new ephemeral key pair.
	ourNewEphemeral, gErr := ecc.GenerateKeyPair()
	if gErr != nil {
		return nil, gErr
	}

	// Create a new chain using our new ephemeral key. The intermediate root key
	// is consumed here and never stored, so release its guarded buffer.
	senderChain, cErr := receiverChain.RootKey.CreateChain(theirEphemeral, ourNewEphemeral)
	if intermediateRootKey, ok := receiverChain.RootKey.(*root.Key); ok {
		intermediateRootKey.Zeroize()
	}
	if cErr != nil {
		return nil, cErr
	}

	// Set our session state parameters.
	if err := sessionState.SetRootKey(senderChain.RootKey); err != nil {
		return nil, err
	}
	sessionState.AddReceiverChain(theirEphemeral, receiverChain.ChainKey)

	// H1: Previous counter uses max(current_index - 1, 0) to match Rust.
	// SenderChainKey hands back a copy in its own guarded buffer, so release it
	// once its index has been read.
	senderChainKey := sessionState.SenderChainKey()
	previousCounter := senderChainKey.Index()
	senderChainKey.(*chain.Key).Zeroize()
	if previousCounter > 0 {
		previousCounter--
	}
	sessionState.SetPreviousCounter(previousCounter)
	sessionState.SetSenderChain(ourNewEphemeral, senderChain.ChainKey)

	// Hand back a copy rather than the chain's own key, so the caller owns what
	// it is given here exactly as it does on the existing-chain path above.
	return sessionState.ReceiverChainKey(theirEphemeral), nil
}

// decrypt will use the given message keys and ciphertext and return
// the plaintext bytes.
func decrypt(keys *message.Keys, body []byte) ([]byte, error) {
	// The accessors return owned copies; wipe them after use.
	iv, cipherKey := keys.Iv(), keys.CipherKey()
	defer crypto.Zeroize(iv)
	defer crypto.Zeroize(cipherKey)
	return cipher.Decrypt(iv, cipherKey, bytehelper.CopySlice(body))
}

// encrypt will use the given cipher, message keys, and plaintext bytes
// and return ciphertext bytes.
func encrypt(messageKeys *message.Keys, plaintext []byte) ([]byte, error) {
	// The accessors return owned copies; wipe them after use.
	iv, cipherKey := messageKeys.Iv(), messageKeys.CipherKey()
	defer crypto.Zeroize(iv)
	defer crypto.Zeroize(cipherKey)
	return cipher.Encrypt(iv, cipherKey, plaintext)
}

// isSpqrDuplicateErr returns true if the error indicates a duplicate/already-consumed
// PQR key, which corresponds to a replayed or duplicate message.
func isSpqrDuplicateErr(err error) bool {
	switch err.(type) {
	case *spqr.ErrKeyAlreadyRequested, *spqr.ErrKeyTrimmed:
		return true
	default:
		return false
	}
}
