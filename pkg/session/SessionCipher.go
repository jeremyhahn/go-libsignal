package session

import (
	"errors"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
)

const maxFutureMessages = 25000

// Per-chain skipped message key limit (MAX_MESSAGE_KEYS = 2000) is
// enforced in state/record.SessionState.SetMessageKeys via FIFO eviction.

// maxUnacknowledgedSessionAge is the maximum age of an unacknowledged
// pre-key session before it is considered stale. Set to 30 days to
// match the Rust reference (MAX_UNACKNOWLEDGED_SESSION_AGE).
const maxUnacknowledgedSessionAge = 30 * 24 * time.Hour

// NewCipher constructs a session cipher for encrypt/decrypt operations on a
// session. In order to use the session cipher, a session must have already
// been created and stored using session.Builder.
func NewCipher(builder *Builder, remoteAddress *protocol.SignalAddress) *Cipher {
	cipher := &Cipher{
		sessionStore:            builder.sessionStore,
		preKeyMessageSerializer: builder.serializer.PreKeySignalMessage,
		signalMessageSerializer: builder.serializer.SignalMessage,
		preKeyStore:             builder.preKeyStore,
		identityStore:           builder.identityKeyStore,
		remoteAddress:           remoteAddress,
	}

	return cipher
}

// NewCipherFromSession creates a cipher from an existing session record.
func NewCipherFromSession(session *record.Session, remoteAddress *protocol.SignalAddress,
	sessionStore store.Session, preKeyStore store.PreKey,
	preKeyMessageSerializer protocol.PreKeySignalMessageSerializer,
	signalMessageSerializer protocol.SignalMessageSerializer) *Cipher {
	cipher := &Cipher{
		sessionStore:            sessionStore,
		preKeyMessageSerializer: preKeyMessageSerializer,
		signalMessageSerializer: signalMessageSerializer,
		preKeyStore:             preKeyStore,
		remoteAddress:           remoteAddress,
	}

	return cipher
}

// NewCipherWithIdentity creates a cipher with an identity key store for
// trust verification on encrypt and decrypt. This is the recommended
// constructor as it enables identity trust checks matching the Rust reference.
func NewCipherWithIdentity(builder *Builder, remoteAddress *protocol.SignalAddress,
	identityStore store.IdentityKey) *Cipher {
	cipher := &Cipher{
		sessionStore:            builder.sessionStore,
		preKeyMessageSerializer: builder.serializer.PreKeySignalMessage,
		signalMessageSerializer: builder.serializer.SignalMessage,
		preKeyStore:             builder.preKeyStore,
		identityStore:           identityStore,
		remoteAddress:           remoteAddress,
	}

	return cipher
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
	remoteAddress           *protocol.SignalAddress
}

// Encrypt will take the given message in bytes and return an object that follows
// the CiphertextMessage interface.
func (d *Cipher) Encrypt(plaintext []byte) (protocol.CiphertextMessage, error) {
	sessionRecord := d.sessionStore.LoadSession(d.remoteAddress)
	sessionState := sessionRecord.SessionState()
	chainKey := sessionState.SenderChainKey()

	// Derive message keys, incorporating SPQR ratchet if active.
	var (
		messageKeys *message.Keys
		pqrMsg      []byte
		err         error
	)
	if pqrState := sessionState.PqRatchetState(); len(pqrState) > 0 {
		newState, msg, pqrKey, pqrErr := spqr.Send(pqrState)
		if pqrErr != nil {
			return nil, pqrErr
		}
		sessionState.SetPqRatchetState(newState)
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

	var ciphertextMessage protocol.CiphertextMessage
	ciphertextMessage, err = protocol.NewSignalMessage(
		sessionVersion,
		chainKey.Index(),
		previousCounter,
		messageKeys.MacKey(),
		senderEphemeral,
		ciphertextBody,
		sessionState.LocalIdentityKey(),
		sessionState.RemoteIdentityKey(),
		d.signalMessageSerializer,
		pqrMsg,
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
	// Old chain key material is automatically destroyed by NextKey() via memguard.
	sessionState.SetSenderChainKey(nextChainKey)

	// Identity trust check is performed after chain key advancement but before
	// StoreSession. If the check fails, the in-memory session with the advanced
	// chain key is discarded (never persisted). This matches the Rust reference
	// ordering (session_cipher.rs) and is safe because the store is not updated.
	if d.identityStore != nil {
		theirIdentityKey := sessionState.RemoteIdentityKey()
		if !d.identityStore.IsTrustedIdentity(d.remoteAddress, theirIdentityKey, store.DirectionSending) {
			logger.Warning("Identity key is not trusted for sending to ", d.remoteAddress.String())
			return nil, newUntrustedIdentityError(d.remoteAddress.String())
		}
		d.identityStore.SaveIdentity(d.remoteAddress, theirIdentityKey)
	}

	d.sessionStore.StoreSession(d.remoteAddress, sessionRecord)

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
	if !d.sessionStore.ContainsSession(d.remoteAddress) {
		return nil, nil, newNoSessionError(d.remoteAddress.String())
	}

	// Load the session record from our session store and decrypt the message.
	sessionRecord := d.sessionStore.LoadSession(d.remoteAddress)
	plaintext, messageKeys, err := d.DecryptWithRecord(sessionRecord, ciphertextMessage)
	if err != nil {
		return nil, nil, err
	}

	// H3: Identity trust check after decryption (matches Rust message_decrypt_signal).
	if d.identityStore != nil {
		theirIdentityKey := sessionRecord.SessionState().RemoteIdentityKey()
		if !d.identityStore.IsTrustedIdentity(d.remoteAddress, theirIdentityKey, store.DirectionReceiving) {
			logger.Warning("Identity key is not trusted for receiving from ", d.remoteAddress.String())
			return nil, nil, newUntrustedIdentityError(d.remoteAddress.String())
		}
		d.identityStore.SaveIdentity(d.remoteAddress, theirIdentityKey)
	}

	// Store the session record in our session store.
	d.sessionStore.StoreSession(d.remoteAddress, sessionRecord)

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

	plaintext, messageKeys, err := d.decryptWithClonedState(workingState, ciphertextMessage)
	if err != nil {
		return nil, nil, err
	}

	// Decryption succeeded -- commit the working state back to the original.
	sessionState.CopyFrom(workingState)

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

		// Note: PQR state is advanced before MAC verification, which differs from
		// Rust's ordering. This is safe because decryptWithClonedState operates on
		// a cloned session state; if MAC verification fails, the clone is discarded
		// and the original state remains unchanged.
		//
		// SPQR: If the stored key has seed material and the message carries PQR
		// data, re-derive the message keys with the PQR salt from the SPQR ratchet.
		if seed := skippedKeys.SeedMaterial(); len(seed) > 0 {
			if pqrData := ciphertextMessage.PqRatchetKey(); len(pqrData) > 0 {
				if pqrState := sessionState.PqRatchetState(); len(pqrState) > 0 {
					newState, pqrKey, pqrErr := spqr.Recv(pqrState, pqrData)
					if pqrErr != nil {
						return nil, nil, pqrErr
					}
					sessionState.SetPqRatchetState(newState)
					seedCopy := make([]byte, len(seed))
					copy(seedCopy, seed)
					reDerived, reErr := chain.DeriveMessageKeysFromSeed(
						kdf.DeriveSecrets, seedCopy, pqrKey, skippedKeys.Index(),
					)
					if reErr != nil {
						return nil, nil, reErr
					}
					skippedKeys = reDerived
				}
			}
		}

		err := ciphertextMessage.VerifyMac(messageVersion, sessionState.RemoteIdentityKey(), sessionState.LocalIdentityKey(), skippedKeys.MacKey())
		if err != nil {
			logger.Error("Unable to verify ciphertext mac for skipped key: ", err)
			return nil, nil, err
		}

		plaintext, err := d.DecryptWithKey(ciphertextMessage, skippedKeys)
		if err != nil {
			return nil, nil, err
		}

		sessionState.ClearUnackPreKeyMessage()
		return plaintext, skippedKeys, nil
	}

	chainKey, chainCreateErr := getOrCreateChainKey(sessionState, theirEphemeral)
	if chainCreateErr != nil {
		logger.Error("Unable to get or create chain key: ", chainCreateErr)
		return nil, nil, chainCreateErr
	}

	// SPQR: Derive the PQR salt for message key derivation if both the message
	// carries PQR data and the session has active SPQR state.
	var pqrSalt []byte
	if pqrData := ciphertextMessage.PqRatchetKey(); len(pqrData) > 0 {
		if pqrState := sessionState.PqRatchetState(); len(pqrState) > 0 {
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
			sessionState.SetPqRatchetState(newState)
			pqrSalt = pqrKey
		}
	}

	messageKeys, keysCreateErr := getOrCreateMessageKeys(sessionState, theirEphemeral, chainKey, counter, pqrSalt)
	if keysCreateErr != nil {
		logger.Error("Unable to get or create message keys: ", keysCreateErr)
		return nil, nil, keysCreateErr
	}

	err := ciphertextMessage.VerifyMac(messageVersion, sessionState.RemoteIdentityKey(), sessionState.LocalIdentityKey(), messageKeys.MacKey())
	if err != nil {
		logger.Error("Unable to verify ciphertext mac: ", err)
		return nil, nil, err
	}

	plaintext, err := d.DecryptWithKey(ciphertextMessage, messageKeys)
	if err != nil {
		return nil, nil, err
	}

	sessionState.ClearUnackPreKeyMessage()

	return plaintext, messageKeys, nil
}

func getOrCreateMessageKeys(sessionState *record.State, theirEphemeral ecc.ECPublicKeyable,
	chainKey *chain.Key, counter uint32, pqrSalt []byte) (*message.Keys, error) {

	if chainKey.Index() > counter {
		if sessionState.HasMessageKeys(theirEphemeral, counter) {
			storedKeys := sessionState.RemoveMessageKeys(theirEphemeral, counter)
			// SPQR: Re-derive with PQR salt if the stored key has seed material.
			if seed := storedKeys.SeedMaterial(); len(seed) > 0 && len(pqrSalt) > 0 {
				seedCopy := make([]byte, len(seed))
				copy(seedCopy, seed)
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
	for chainKey.Index() < counter {
		var messageKeys *message.Keys
		var err error
		if hasSPQR {
			// Store seed material so skipped keys can be re-derived with PQR salt later.
			messageKeys, err = chainKey.MessageKeysWithSeed()
		} else {
			messageKeys, err = chainKey.MessageKeys()
		}
		if err != nil {
			return nil, err
		}
		if err := sessionState.SetMessageKeys(theirEphemeral, messageKeys); err != nil {
			return nil, err
		}
		// NextKey zeroizes the old chain key internally.
		chainKey = chainKey.NextKey()
	}

	// Get message keys before advancing, since NextKey destroys the current key's
	// guarded memory. Use PQR salt if provided for SPQR-enhanced derivation.
	msgKeys, err := chainKey.MessageKeysWithSalt(pqrSalt)
	if err != nil {
		return nil, err
	}
	nextKey := chainKey.NextKey()
	if err := sessionState.SetReceiverChainKey(theirEphemeral, nextKey); err != nil {
		return nil, err
	}
	return msgKeys, nil
}

// getOrCreateChainKey will either return the existing chain key or
// create a new one with the given session state and ephemeral key.
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

	// Create a new chain using our new ephemeral key.
	senderChain, cErr := receiverChain.RootKey.CreateChain(theirEphemeral, ourNewEphemeral)
	if cErr != nil {
		return nil, cErr
	}

	// Set our session state parameters.
	if err := sessionState.SetRootKey(senderChain.RootKey); err != nil {
		return nil, err
	}
	sessionState.AddReceiverChain(theirEphemeral, receiverChain.ChainKey)

	// H1: Previous counter uses max(current_index - 1, 0) to match Rust.
	previousCounter := sessionState.SenderChainKey().Index()
	if previousCounter > 0 {
		previousCounter--
	}
	sessionState.SetPreviousCounter(previousCounter)
	sessionState.SetSenderChain(ourNewEphemeral, senderChain.ChainKey)

	return receiverChain.ChainKey.(*chain.Key), nil
}

// decrypt will use the given message keys and ciphertext and return
// the plaintext bytes.
func decrypt(keys *message.Keys, body []byte) ([]byte, error) {
	return cipher.Decrypt(keys.Iv(), keys.CipherKey(), bytehelper.CopySlice(body))
}

// encrypt will use the given cipher, message keys, and plaintext bytes
// and return ciphertext bytes.
func encrypt(messageKeys *message.Keys, plaintext []byte) ([]byte, error) {
	return cipher.Encrypt(messageKeys.Iv(), messageKeys.CipherKey(), plaintext)
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
