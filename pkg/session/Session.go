// Package session builds Signal sessions and encrypts and decrypts messages; use the WithLocalAddress constructors for address binding, as the others are deprecated.
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
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
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

// Builder sets up sessions per recipient and device from a PreKeyBundle, a PreKeySignalMessage or a KeyExchangeMessage.
type Builder struct {
	sessionStore      store.Session
	preKeyStore       store.PreKey
	signedPreKeyStore store.SignedPreKey
	identityKeyStore  store.IdentityKey
	kyberPreKeyStore  store.KyberPreKey
	remoteAddress     *protocol.SignalAddress
	serializer        *serialize.Serializer
}

// DeferredActions holds store changes committed only after the inner SignalMessage decrypts, as Rust message_decrypt_prekey defers them.
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

// Complete stores the session and identity, marks the Kyber pre-key used and removes the one-time pre-key; call it only after decryption succeeds.
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

// Process builds a session from a PreKeySignalMessage and returns DeferredActions; call Complete after decryption, or discard it to keep the pre-keys.
func (b *Builder) Process(message *protocol.PreKeySignalMessage) (*DeferredActions, error) {

	// Load or create session record for this session.
	loadedRecord, err := b.sessionStore.LoadSession(b.remoteAddress)
	if err != nil {
		return nil, err
	}

	// Work on a copy so a failed decryption leaves the stored session and pre-key untouched; Complete persists it.
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

// processV3 adds the new session state and returns the pre-key and Kyber pre-key IDs without touching the stores.
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

	// PQXDH is required; X3DH is no longer supported, as in Rust.
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
	// the secret key in locked memory.
	if message.KyberPreKeyID() != nil && message.KyberCiphertext() != nil && b.kyberPreKeyStore != nil {
		kyberPreKeyRecord, kyberErr := b.kyberPreKeyStore.LoadKyberPreKey(message.KyberPreKeyID().Value)
		if kyberErr != nil {
			return nil, nil, kyberErr
		}
		guardedKP, guardErr := kyberPreKeyRecord.GuardedKeyPair()
		if guardErr != nil {
			return nil, nil, guardErr
		}
		// The clone stays alive until this function returns, which covers
		// CalculateReceiverSession below, and is released on every exit
		// path — including a malformed ciphertext, which a peer controls.
		defer guardedKP.Destroy()
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

	if sessionErr != nil {
		return nil, nil, sessionErr
	}
	// Set version to match the incoming message's version. The receiver
	// should use the same protocol version the sender negotiated.
	sessionState.SetVersion(message.MessageVersion())
	sessionState.SetRemoteIdentityKey(parameters.TheirIdentityKey())
	sessionState.SetLocalIdentityKey(parameters.OurIdentityKeyPair().PublicKey())
	// The state destroys chains it supersedes, so give it a copy of the store-owned signed pre-key.
	ourRatchetKey, ratchetErr := cloneKeyPairForState(parameters.OurRatchetKey())
	if ratchetErr != nil {
		return nil, nil, ratchetErr
	}
	sessionState.SetSenderChain(ourRatchetKey, derivedKeys.ChainKey)
	if err := sessionState.SetRootKey(derivedKeys.RootKey); err != nil {
		return nil, nil, err
	}

	// Bob's SPQR state (DirectionB2A) starts from InitialPQRKey; self-sessions allow a MaxUint32 forward jump, as Rust does.
	if derivedKeys.InitialPQRKey != nil && !derivedKeys.InitialPQRKey.IsDestroyed() {
		// spqr keeps no reference to the key; it is copied out of the
		// read-only view and the copy is wiped once the state is built.
		var pqrBytes []byte
		_ = derivedKeys.InitialPQRKey.WithBytes(func(b []byte) error {
			pqrBytes = append([]byte(nil), b...)
			return nil
		})
		selfSession := bytes.Equal(
			parameters.OurIdentityKeyPair().PublicKey().Serialize(),
			parameters.TheirIdentityKey().PublicKey().Serialize(),
		)
		pqrState, pqrErr := spqr.InitialState(pqrBytes, spqr.DirectionB2A, selfSession)
		clear(pqrBytes)
		derivedKeys.Zeroize()
		if pqrErr != nil {
			return nil, nil, pqrErr
		}
		if setErr := sessionState.SetPqRatchetState(pqrState); setErr != nil {
			return nil, nil, setErr
		}
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

	// Record the one-time pre-key ID for removal in Complete; nil or empty means none was used.
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

	// Alice's SPQR state (DirectionA2B) starts from InitialPQRKey; self-sessions allow a MaxUint32 forward jump, as Rust does.
	if derivedKeys.InitialPQRKey != nil && !derivedKeys.InitialPQRKey.IsDestroyed() {
		// spqr keeps no reference to the key; it is copied out of the
		// read-only view and the copy is wiped once the state is built.
		var pqrBytes []byte
		_ = derivedKeys.InitialPQRKey.WithBytes(func(b []byte) error {
			pqrBytes = append([]byte(nil), b...)
			return nil
		})
		selfSession := bytes.Equal(
			parameters.OurIdentityKey().PublicKey().Serialize(),
			parameters.TheirIdentityKey().PublicKey().Serialize(),
		)
		pqrState, pqrErr := spqr.InitialState(pqrBytes, spqr.DirectionA2B, selfSession)
		clear(pqrBytes)
		derivedKeys.Zeroize()
		if pqrErr != nil {
			return pqrErr
		}
		if setErr := sessionState.SetPqRatchetState(pqrState); setErr != nil {
			return setErr
		}
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

// cloneKeyPairForState returns the key pair with an independent guarded copy of the private key, since the state destroys what it is given and the original may belong to the pre-key store.
func cloneKeyPairForState(keyPair *ecc.ECKeyPair) (*ecc.ECKeyPair, error) {
	privateKey := keyPair.PrivateKey()
	if guarded, ok := privateKey.(*ecc.GuardedECPrivateKey); ok {
		clonedPrivate, err := guarded.Clone()
		if err != nil {
			return nil, err
		}
		return ecc.NewECKeyPair(keyPair.PublicKey(), clonedPrivate), nil
	}
	if privateKey == nil {
		return keyPair, nil
	}
	material := privateKey.Serialize()
	defer crypto.ZeroizeArray32(&material)
	clonedPrivate, err := ecc.NewGuardedECPrivateKey(material)
	if err != nil {
		return nil, err
	}
	return ecc.NewECKeyPair(keyPair.PublicKey(), clonedPrivate), nil
}
