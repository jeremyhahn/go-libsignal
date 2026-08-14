// Package session provides the methods necessary to build Signal Protocol
// sessions and encrypt/decrypt messages. Callers should use the
// ...WithLocalAddress constructor variants (NewCipherWithLocalAddress,
// NewCipherFromSessionWithLocalAddress, NewCipherWithIdentityAndLocalAddress)
// to enable address binding (SignalMessage field 6), which Rust libsignal
// always populates and which prevents address-substitution downgrade attacks.
// The legacy constructors without a local-address parameter leave field 6
// unpopulated and are deprecated.
package session

import (
	"bytes"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/ratchet"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// NewBuilder constructs a session builder.
func NewBuilder(sessionStore store.Session, preKeyStore store.PreKey,
	signedStore store.SignedPreKey, identityStore store.IdentityKey,
	remoteAddress *protocol.SignalAddress, serializer *serialize.Serializer) *Builder {

	builder := Builder{
		sessionStore:      sessionStore,
		preKeyStore:       preKeyStore,
		signedPreKeyStore: signedStore,
		identityKeyStore:  identityStore,
		remoteAddress:     remoteAddress,
		serializer:        serializer,
	}

	return &builder
}

// NewBuilderWithKyber constructs a session builder with Kyber pre-key store
// support for PQXDH post-quantum key exchange.
func NewBuilderWithKyber(sessionStore store.Session, preKeyStore store.PreKey,
	signedStore store.SignedPreKey, identityStore store.IdentityKey,
	kyberStore store.KyberPreKey,
	remoteAddress *protocol.SignalAddress, serializer *serialize.Serializer) *Builder {

	builder := Builder{
		sessionStore:      sessionStore,
		preKeyStore:       preKeyStore,
		signedPreKeyStore: signedStore,
		identityKeyStore:  identityStore,
		kyberPreKeyStore:  kyberStore,
		remoteAddress:     remoteAddress,
		serializer:        serializer,
	}

	return &builder
}

// NewBuilderFromSignal Store constructs a session builder using a
// SignalProtocol Store.
func NewBuilderFromSignal(signalStore store.SignalProtocol,
	remoteAddress *protocol.SignalAddress, serializer *serialize.Serializer) *Builder {

	builder := Builder{
		sessionStore:      signalStore,
		preKeyStore:       signalStore,
		signedPreKeyStore: signalStore,
		identityKeyStore:  signalStore,
		kyberPreKeyStore:  signalStore,
		remoteAddress:     remoteAddress,
		serializer:        serializer,
	}

	return &builder
}

// Builder is responsible for setting up encrypted sessions.
// Once a session has been established, SessionCipher can be
// used to encrypt/decrypt messages in that session.
//
// Sessions are built from one of three different vectors:
//   - PreKeyBundle retrieved from a server.
//   - PreKeySignalMessage received from a client.
//   - KeyExchangeMessage sent to or received from a client.
//
// Sessions are constructed per recipientId + deviceId tuple.
// Remote logical users are identified by their recipientId,
// and each logical recipientId can have multiple physical
// devices.
type Builder struct {
	sessionStore      store.Session
	preKeyStore       store.PreKey
	signedPreKeyStore store.SignedPreKey
	identityKeyStore  store.IdentityKey
	kyberPreKeyStore  store.KyberPreKey
	remoteAddress     *protocol.SignalAddress
	serializer        *serialize.Serializer
}

// DeferredActions holds session state changes that must only be committed
// after the inner SignalMessage is successfully decrypted. This matches
// the Rust reference (session_cipher.rs:207-260 message_decrypt_prekey)
// which defers save_identity, mark_kyber_pre_key_used, remove_pre_key,
// and store_session until after decrypt succeeds.
type DeferredActions struct {
	// SessionRecord is the newly established session record.
	SessionRecord *record.Session

	// UnsignedPreKeyID is the one-time pre-key ID to remove, or nil.
	UnsignedPreKeyID *optional.Uint32

	// KyberPreKeyID is the Kyber pre-key ID to mark as used, or nil.
	KyberPreKeyID *optional.Uint32

	// TheirIdentityKey is the remote identity key to save.
	TheirIdentityKey *identity.Key

	// signedPreKeyID and baseKey are needed for MarkKyberPreKeyUsed.
	signedPreKeyID uint32
	baseKey        ecc.ECPublicKeyable

	// builder holds internal references for executing deferred operations.
	builder *Builder
}

// Complete commits the deferred side effects after successful decryption.
// This stores the session, saves the identity key, marks the Kyber pre-key
// as used, and removes the one-time pre-key. The caller must invoke this
// only after the inner SignalMessage decryption succeeds.
func (d *DeferredActions) Complete() error {
	// Store the updated session record.
	if err := d.builder.sessionStore.StoreSession(d.builder.remoteAddress, d.SessionRecord); err != nil {
		return err
	}

	// Save the identity key to our identity store.
	if _, err := d.builder.identityKeyStore.SaveIdentity(d.builder.remoteAddress, d.TheirIdentityKey); err != nil {
		return err
	}

	// Mark Kyber pre-key as used if present.
	if d.KyberPreKeyID != nil && d.builder.kyberPreKeyStore != nil {
		if err := d.builder.kyberPreKeyStore.MarkKyberPreKeyUsed(
			d.KyberPreKeyID.Value, d.signedPreKeyID, d.baseKey,
		); err != nil {
			return err
		}
	}

	// Remove the one-time pre-key if present.
	if d.UnsignedPreKeyID != nil {
		logger.Debug("Removing preKey from our prekey store: ", d.UnsignedPreKeyID.Value)
		if err := d.builder.preKeyStore.RemovePreKey(d.UnsignedPreKeyID.Value); err != nil {
			return err
		}
	}

	return nil
}

// Process builds a new session from a session record and pre key signal
// message. It returns a DeferredActions struct whose Complete() method
// must be called after the inner SignalMessage is successfully decrypted.
// If decryption fails, the caller discards the DeferredActions, preserving
// pre-keys from being burned.
func (b *Builder) Process(message *protocol.PreKeySignalMessage) (*DeferredActions, error) {

	// Load or create session record for this session.
	loadedRecord, err := b.sessionStore.LoadSession(b.remoteAddress)
	if err != nil {
		return nil, err
	}

	// Operate on a deep copy. Session stores return their record by reference,
	// so processV3 (which adds the new session state) and the subsequent
	// DecryptWithRecordPreKey (which advances the ratchet) would otherwise
	// mutate the persisted session in place — corrupting it even when the inner
	// SignalMessage fails to decrypt and Complete() is never called. By cloning
	// here, a failed decryption leaves the stored session untouched and the
	// one-time pre-key unburned; Complete() persists this copy only on success.
	// Mirrors Rust's atomic process_prekey_signal_message (session.rs).
	sessionRecord, err := loadedRecord.Copy()
	if err != nil {
		return nil, err
	}

	// Check to see if the keys are trusted.
	theirIdentityKey := message.IdentityKey()
	trusted, err := b.identityKeyStore.IsTrustedIdentity(b.remoteAddress, theirIdentityKey, store.DirectionReceiving)
	if err != nil {
		return nil, err
	}
	if !trusted {
		return nil, &Error{kind: errUntrustedIdentity}
	}

	// Use version 3 of the signal/axolotl protocol.
	unsignedPreKeyID, kyberPreKeyID, err := b.processV3(sessionRecord, message)
	if err != nil {
		return nil, err
	}

	return &DeferredActions{
		SessionRecord:    sessionRecord,
		UnsignedPreKeyID: unsignedPreKeyID,
		KyberPreKeyID:    kyberPreKeyID,
		TheirIdentityKey: theirIdentityKey,
		signedPreKeyID:   message.SignedPreKeyID(),
		baseKey:          message.BaseKey(),
		builder:          b,
	}, nil
}

// processV3 builds a new session from a session record and pre key
// signal message. It returns the unsigned pre-key ID and Kyber pre-key
// ID without performing any store mutations. The caller is responsible
// for deferring those operations until after successful decryption.
func (b *Builder) processV3(sessionRecord *record.Session,
	message *protocol.PreKeySignalMessage) (unsignedPreKeyID *optional.Uint32, kyberPreKeyID *optional.Uint32, err error) {

	logger.Debug("Processing message with PreKeyID: ", message.PreKeyID())

	// Check to see if we've already set up a session for this V3 message.
	sessionExists := sessionRecord.HasSessionState(
		message.MessageVersion(),
		message.BaseKey().Serialize(),
	)
	if sessionExists {
		logger.Warning("We've already setup a session for this V3 message, letting bundled message fall through...")
		return nil, nil, nil
	}

	// H4: Enforce PQXDH requirement. X3DH (PreKyberVersion) is no longer
	// supported, matching Rust process_prekey_impl which rejects v3 messages
	// with "X3DH no longer supported".
	if message.MessageVersion() == protocol.PreKyberVersion {
		return nil, nil, &Error{kind: errX3DHNoLongerSupported}
	}

	// H4: For v4+ messages, the Kyber pre-key ID and ciphertext MUST be present.
	// Matches Rust process_prekey_impl which returns distinct errors:
	// "missing pq pre-key ID" and "missing pq ciphertext".
	if message.KyberPreKeyID() == nil {
		return nil, nil, &Error{kind: errMissingPQPreKeyID}
	}
	if message.KyberCiphertext() == nil {
		return nil, nil, &Error{kind: errMissingPQCiphertext}
	}

	// Load our signed prekey from our signed prekey store.
	ourSignedPreKeyRecord, err := b.signedPreKeyStore.LoadSignedPreKey(message.SignedPreKeyID())
	if err != nil {
		return nil, nil, err
	}
	if ourSignedPreKeyRecord == nil {
		return nil, nil, &Error{kind: errNoSignedPreKey}
	}
	ourSignedPreKey := ourSignedPreKeyRecord.KeyPair()

	// Build the parameters of the session.
	parameters := ratchet.NewEmptyReceiverParameters()
	parameters.SetTheirBaseKey(message.BaseKey())
	parameters.SetTheirIdentityKey(message.IdentityKey())
	parameters.SetOurIdentityKeyPair(b.identityKeyStore.GetIdentityKeyPair())
	parameters.SetOurSignedPreKey(ourSignedPreKey)
	parameters.SetOurRatchetKey(ourSignedPreKey)

	// Set our one time pre key with the one from our prekey store
	// if the message contains a valid pre key id
	if message.PreKeyID() != nil {
		oneTimePreKey, pkErr := b.preKeyStore.LoadPreKey(message.PreKeyID().Value)
		if pkErr != nil {
			return nil, nil, pkErr
		}
		if oneTimePreKey == nil {
			logger.Error("pre-key store returned nil one-time pre-key")
			return nil, nil, &Error{kind: errNilOneTimePreKey}
		}
		parameters.SetOurOneTimePreKey(oneTimePreKey.KeyPair())
	} else {
		parameters.SetOurOneTimePreKey(nil)
	}

	// PQXDH: If the message contains a Kyber pre-key ID and ciphertext,
	// load our Kyber pre-key pair and set the receiver parameters with
	// the secret key in memguard-protected memory.
	if message.KyberPreKeyID() != nil && message.KyberCiphertext() != nil && b.kyberPreKeyStore != nil {
		kyberPreKeyRecord, kyberErr := b.kyberPreKeyStore.LoadKyberPreKey(message.KyberPreKeyID().Value)
		if kyberErr != nil {
			return nil, nil, kyberErr
		}
		guardedKP, guardErr := kyberPreKeyRecord.GuardedKeyPair()
		if guardErr != nil {
			return nil, nil, guardErr
		}
		// Note: guardedKP.Destroy() is called explicitly after
		// CalculateReceiverSession below, not deferred, to make the
		// lifetime dependency on the ratchet calculation explicit.
		parameters.SetOurKyberPreKeyPair(guardedKP)

		ct, ctErr := kem.DeserializeCiphertext(message.KyberCiphertext())
		if ctErr != nil {
			return nil, nil, ctErr
		}
		parameters.SetTheirKyberCiphertext(ct)
	}

	// If this is a fresh record, archive our current state.
	if !sessionRecord.IsFresh() {
		sessionRecord.ArchiveCurrentState()
	}
	sessionRecord.MarkEstablished()

	///////// Initialize our session /////////
	sessionState := sessionRecord.SessionState()
	derivedKeys, sessionErr := ratchet.CalculateReceiverSession(parameters)

	// Destroy the guarded Kyber key pair now that CalculateReceiverSession
	// has consumed it via decapsulation. This is done explicitly rather than
	// via defer to make the lifetime dependency clear and avoid fragility
	// if code is reordered.
	if kp := parameters.OurKyberPreKeyPair(); kp != nil {
		kp.Destroy()
	}

	if sessionErr != nil {
		return nil, nil, sessionErr
	}
	// Set version to match the incoming message's version. The receiver
	// should use the same protocol version the sender negotiated.
	sessionState.SetVersion(message.MessageVersion())
	sessionState.SetRemoteIdentityKey(parameters.TheirIdentityKey())
	sessionState.SetLocalIdentityKey(parameters.OurIdentityKeyPair().PublicKey())
	sessionState.SetSenderChain(parameters.OurRatchetKey(), derivedKeys.ChainKey)
	if err := sessionState.SetRootKey(derivedKeys.RootKey); err != nil {
		return nil, nil, err
	}

	// SPQR: Initialize post-quantum ratchet state from the InitialPQRKey
	// derived during PQXDH. Bob is DirectionB2A (receiver side).
	// Self-sessions (where local and remote identity keys match) use
	// math.MaxUint32 as the max forward jump to match Rust's u32::MAX.
	if derivedKeys.InitialPQRKey != nil && !derivedKeys.InitialPQRKey.IsDestroyed() {
		pqrBytes := derivedKeys.InitialPQRKey.Bytes()
		selfSession := bytes.Equal(
			parameters.OurIdentityKeyPair().PublicKey().Serialize(),
			parameters.TheirIdentityKey().PublicKey().Serialize(),
		)
		pqrState, pqrErr := spqr.InitialState(pqrBytes, spqr.DirectionB2A, selfSession)
		derivedKeys.Zeroize()
		if pqrErr != nil {
			return nil, nil, pqrErr
		}
		sessionState.SetPqRatchetState(pqrState)
	}

	// Set the session's registration ids and base key
	sessionState.SetLocalRegistrationID(b.identityKeyStore.GetLocalRegistrationId())
	sessionState.SetRemoteRegistrationID(message.RegistrationID())
	sessionState.SetSenderBaseKey(message.BaseKey().Serialize())

	// Collect the Kyber pre-key ID for deferred marking after successful
	// decryption. The actual MarkKyberPreKeyUsed call is deferred to
	// DeferredActions.Complete() to prevent burning keys on decrypt failure.
	var retKyberPreKeyID *optional.Uint32
	if message.KyberPreKeyID() != nil && b.kyberPreKeyStore != nil {
		retKyberPreKeyID = optional.NewOptionalUint32(message.KyberPreKeyID().Value)
	}

	// Collect the unsigned pre-key ID for deferred removal after successful
	// decryption. The actual RemovePreKey call is deferred to
	// DeferredActions.Complete() to prevent burning keys on decrypt failure.
	// A nil PreKeyID or an empty optional indicates no one-time pre-key was used.
	var retUnsignedPreKeyID *optional.Uint32
	if message.PreKeyID() != nil && !message.PreKeyID().IsEmpty {
		retUnsignedPreKeyID = message.PreKeyID()
	}
	return retUnsignedPreKeyID, retKyberPreKeyID, nil
}

// ProcessBundle builds a new session from a PreKeyBundle retrieved
// from a server.
func (b *Builder) ProcessBundle(preKey *prekey.Bundle) error {
	// Check to see if the keys are trusted.
	trusted, err := b.identityKeyStore.IsTrustedIdentity(b.remoteAddress, preKey.IdentityKey(), store.DirectionSending)
	if err != nil {
		return err
	}
	if !trusted {
		return &Error{kind: errUntrustedIdentity}
	}

	// Check to see if the bundle has a signed pre key.
	if preKey.SignedPreKey() == nil {
		return &Error{kind: errNoSignedPreKey}
	}

	// Verify the signature of the pre key
	preKeyPublic := preKey.IdentityKey().PublicKey()
	preKeyBytes := preKey.SignedPreKey().Serialize()
	preKeySignature := preKey.SignedPreKeySignature()
	if !ecc.VerifySignature(preKeyPublic, preKeyBytes, preKeySignature) {
		return &Error{kind: errInvalidSignature}
	}

	// PQXDH: Verify the Kyber pre-key signature if present.
	// Per the PQXDH spec, if a Kyber pre-key is present, its signature MUST
	// be verified. A missing signature when the key is present is an error.
	if preKey.KyberPreKey() != nil {
		if preKey.KyberPreKeySignature() == nil {
			return &Error{kind: errMissingKyberSignature}
		}
		kyberPreKeyBytes := preKey.KyberPreKey().Serialize()
		kyberSig := preKey.KyberPreKeySignature()
		if len(kyberSig) != 64 {
			return &Error{kind: errInvalidKyberSignature}
		}
		var kyberSigArr [64]byte
		copy(kyberSigArr[:], kyberSig)
		if !ecc.VerifySignature(preKeyPublic, kyberPreKeyBytes, kyberSigArr) {
			return &Error{kind: errInvalidKyberSignature}
		}
	}

	// PQXDH is mandatory for all sessions (v4+). Reject bundles missing a
	// Kyber pre-key early, before reaching the ratchet layer.
	if preKey.KyberPreKey() == nil {
		return &Error{kind: errMissingKyberPreKey}
	}

	// Load our session and generate keys.
	sessionRecord, err := b.sessionStore.LoadSession(b.remoteAddress)
	if err != nil {
		return err
	}
	ourBaseKey, err := ecc.GenerateKeyPair()
	if err != nil {
		return err
	}
	theirSignedPreKey := preKey.SignedPreKey()
	theirOneTimePreKey := preKey.PreKey()
	theirOneTimePreKeyID := preKey.PreKeyID()

	// Build the parameters of the session
	parameters := ratchet.NewEmptySenderParameters()
	parameters.SetOurBaseKey(ourBaseKey)
	parameters.SetOurIdentityKey(b.identityKeyStore.GetIdentityKeyPair())
	parameters.SetTheirIdentityKey(preKey.IdentityKey())
	parameters.SetTheirSignedPreKey(theirSignedPreKey)
	parameters.SetTheirRatchetKey(theirSignedPreKey)
	parameters.SetTheirOneTimePreKey(theirOneTimePreKey)

	// PQXDH: Pass the Kyber pre-key to the ratchet parameters if present.
	if preKey.KyberPreKey() != nil {
		parameters.SetTheirKyberPreKey(preKey.KyberPreKey())
	}

	// If this is a fresh record, archive our current state.
	if !sessionRecord.IsFresh() {
		sessionRecord.ArchiveCurrentState()
	}
	sessionRecord.MarkEstablished()

	///////// Initialize our session /////////
	sessionState := sessionRecord.SessionState()
	derivedKeys, kyberCiphertext, sessionErr := ratchet.CalculateSenderSession(parameters)
	// Per the PQXDH spec: "After calculating SK, Alice deletes her
	// ephemeral private key." Zeroize regardless of error.
	ourBaseKey.ZeroizePrivateKey()
	if sessionErr != nil {
		return sessionErr
	}
	// Generate an ephemeral "ratchet" key that will be advertised to
	// the receiving user.
	sendingRatchetKey, keyErr := ecc.GenerateKeyPair()
	if keyErr != nil {
		return keyErr
	}
	sendingChain, chainErr := derivedKeys.RootKey.CreateChain(
		parameters.TheirRatchetKey(),
		sendingRatchetKey,
	)
	if chainErr != nil {
		return chainErr
	}

	// S-C3: CalculateSenderSession now enforces PQXDH, so kyberCiphertext is
	// always non-nil at this point. All sessions use CurrentVersion=4.
	sessionState.SetVersion(protocol.CurrentVersion)
	sessionState.SetRemoteIdentityKey(parameters.TheirIdentityKey())
	sessionState.SetLocalIdentityKey(parameters.OurIdentityKey().PublicKey())
	sessionState.AddReceiverChain(parameters.TheirRatchetKey(), derivedKeys.ChainKey.Current())
	sessionState.SetSenderChain(sendingRatchetKey, sendingChain.ChainKey)
	if err := sessionState.SetRootKey(sendingChain.RootKey); err != nil {
		return err
	}

	// SPQR: Initialize post-quantum ratchet state from the InitialPQRKey
	// derived during PQXDH. Alice is DirectionA2B (sender initiated session).
	// Self-sessions (where local and remote identity keys match) use
	// math.MaxUint32 as the max forward jump to match Rust's u32::MAX.
	if derivedKeys.InitialPQRKey != nil && !derivedKeys.InitialPQRKey.IsDestroyed() {
		pqrBytes := derivedKeys.InitialPQRKey.Bytes()
		selfSession := bytes.Equal(
			parameters.OurIdentityKey().PublicKey().Serialize(),
			parameters.TheirIdentityKey().PublicKey().Serialize(),
		)
		pqrState, pqrErr := spqr.InitialState(pqrBytes, spqr.DirectionA2B, selfSession)
		derivedKeys.Zeroize()
		if pqrErr != nil {
			return pqrErr
		}
		sessionState.SetPqRatchetState(pqrState)
	}

	// Update our session record with the unacknowledged prekey message,
	// including mandatory Kyber pre-key ID and ciphertext.
	sessionState.SetUnacknowledgedPreKeyMessageWithKyber(
		theirOneTimePreKeyID,
		preKey.SignedPreKeyID(),
		ourBaseKey.PublicKey(),
		preKey.KyberPreKeyID(),
		kyberCiphertext.Serialize(),
	)

	// Set the local registration ID based on the registration id in our identity key store.
	sessionState.SetLocalRegistrationID(
		b.identityKeyStore.GetLocalRegistrationId(),
	)

	// Set the remote registration ID based on the given prekey bundle registrationID.
	sessionState.SetRemoteRegistrationID(
		preKey.RegistrationID(),
	)

	// Set the sender base key in our session record state.
	sessionState.SetSenderBaseKey(
		ourBaseKey.PublicKey().Serialize(),
	)

	// Store the session in our session store and save the identity in our identity store.
	if err := b.sessionStore.StoreSession(b.remoteAddress, sessionRecord); err != nil {
		return err
	}
	if _, err := b.identityKeyStore.SaveIdentity(b.remoteAddress, preKey.IdentityKey()); err != nil {
		return err
	}

	return nil
}
