package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/root"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/session"
	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"github.com/jeremyhahn/go-libsignal/pkg/util/errorhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

const maxMessageKeys int = 2000
const maxReceiverChains int = 5

// StateSerializer is an interface for serializing and deserializing
// a Signal State into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type StateSerializer interface {
	Serialize(state *StateStructure) ([]byte, error)
	Deserialize(serialized []byte) (*StateStructure, error)
}

// NewStateFromBytes will return a Signal State from the given
// bytes using the given serializer.
func NewStateFromBytes(serialized []byte, serializer StateSerializer) (*State, error) {
	// Use the given serializer to decode the signal message.
	stateStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}
	// The structure decoded here is ours; release its guarded key material once
	// the state has taken its own copy.
	defer stateStructure.Zeroize()

	return NewStateFromStructure(stateStructure, serializer)
}

// NewState returns a new session state.
func NewState(serializer StateSerializer) *State {
	return &State{serializer: serializer}
}

// NewStateFromStructure will return a new session state with the
// given state structure. The state copies the guarded key material out of the
// structure; the caller keeps ownership of the structure and should Zeroize it
// when done.
func NewStateFromStructure(structure *StateStructure, serializer StateSerializer) (*State, error) {
	// Keep a list of errors, so they can be handled once.
	errors := errorhelper.NewMultiError()

	// Convert our ecc keys from bytes into object form.
	localIdentityPublic, err := ecc.DecodePoint(structure.LocalIdentityPublic, 0)
	errors.Add(err)
	remoteIdentityPublic, err := ecc.DecodePoint(structure.RemoteIdentityPublic, 0)
	errors.Add(err)
	senderBaseKey, err := ecc.DecodePoint(structure.SenderBaseKey, 0)
	errors.Add(err)
	pendingPreKey, err := NewPendingPreKeyFromStruct(structure.PendingPreKey)
	errors.Add(err)
	senderChain, err := NewChainFromStructure(structure.SenderChain)
	errors.Add(err)

	// Build our receiver chains from structure.
	receiverChains := make([]*Chain, len(structure.ReceiverChains))
	for i := range structure.ReceiverChains {
		receiverChains[i], err = NewChainFromStructure(structure.ReceiverChains[i])
		errors.Add(err)
	}

	// Deserialize the pending key exchange.
	pendingKeyExchange, pkeErr := NewPendingKeyExchangeFromStruct(structure.PendingKeyExchange)
	errors.Add(pkeErr)

	// The chains and the pending key exchange each moved key material into
	// guarded memory as they decoded, and errors are accumulated rather than
	// returned at the first failure, so by this point a record that is
	// malformed anywhere holds locked buffers for every part of it that was
	// well formed. Assemble the state as it is built and release it on any exit
	// that does not hand it to the caller.
	state := &State{
		pendingKeyExchange: pendingKeyExchange,
		receiverChains:     receiverChains,
		senderChain:        senderChain,
	}
	handedOver := false
	defer func() {
		if !handedOver {
			destroyState(state)
		}
	}()

	// Handle any errors. The first error will always be returned if there are multiple.
	if errors.HasErrors() {
		return nil, errors
	}

	// Clone the PQ ratchet state guarded-to-guarded, so the serialized SPQR
	// state — which carries live ratchet secrets — never lands on the Go heap.
	// The structure keeps its own copy; the caller Zeroizes it.
	if secretLen(&structure.PqRatchetState) > 0 {
		pqRatchetState, pqErr := structure.PqRatchetState.Clone()
		if pqErr != nil {
			return nil, pqErr
		}
		state.pqRatchetState = pqRatchetState
	}

	// Finish building our state object.
	state.localIdentityPublic = identity.NewKey(localIdentityPublic)
	state.localRegistrationID = structure.LocalRegistrationID
	state.needsRefresh = structure.NeedsRefresh
	state.pendingPreKey = pendingPreKey
	state.previousCounter = structure.PreviousCounter
	state.remoteIdentityPublic = identity.NewKey(remoteIdentityPublic)
	state.remoteRegistrationID = structure.RemoteRegistrationID
	state.rootKey = root.NewKey(kdf.DeriveSecrets, copySecret(&structure.RootKey))
	state.senderBaseKey = senderBaseKey
	state.serializer = serializer
	state.sessionVersion = structure.SessionVersion

	handedOver = true
	return state, nil
}

// StateStructure is the structure of a session state. Fields are public
// to be used for serialization and deserialization. The secret-bearing fields
// — the root key and the serialized PQ ratchet state — are held in guarded
// memory; see PendingKeyExchangeStructure for the rationale. SenderBaseKey is
// Alice's public base key and stays plain.
type StateStructure struct {
	LocalIdentityPublic  []byte
	LocalRegistrationID  uint32
	NeedsRefresh         bool
	PendingKeyExchange   *PendingKeyExchangeStructure
	PendingPreKey        *PendingPreKeyStructure
	PreviousCounter      uint32
	ReceiverChains       []*ChainStructure
	RemoteIdentityPublic []byte
	RemoteRegistrationID uint32
	RootKey              secret.Secret
	SenderBaseKey        []byte
	SenderChain          *ChainStructure
	SessionVersion       int
	PqRatchetState       secret.Secret
}

// Zeroize releases all sensitive key material in the structure: guarded
// material is destroyed and the remaining plain material is overwritten with
// zeros. Call this (via defer) after the structure has been serialized to
// prevent root key, chain key, private key, and PQ ratchet bytes from
// outliving the serialization.
func (s *StateStructure) Zeroize() {
	s.RootKey.Destroy()
	s.PqRatchetState.Destroy()
	if s.PendingKeyExchange != nil {
		s.PendingKeyExchange.Zeroize()
	}
	for _, rc := range s.ReceiverChains {
		if rc != nil {
			rc.Zeroize()
		}
	}
	if s.SenderChain != nil {
		s.SenderChain.Zeroize()
	}
}

// State is a session state that contains the structure for
// all sessions. Session states are contained inside session records.
// The session state is implemented as a struct rather than protobuffers
// to allow other serialization methods.
type State struct {
	localIdentityPublic  *identity.Key
	localRegistrationID  uint32
	needsRefresh         bool
	pendingKeyExchange   *PendingKeyExchange
	pendingPreKey        *PendingPreKey
	previousCounter      uint32
	receiverChains       []*Chain
	remoteIdentityPublic *identity.Key
	remoteRegistrationID uint32
	rootKey              *root.Key
	senderBaseKey        ecc.ECPublicKeyable
	senderChain          *Chain
	serializer           StateSerializer
	sessionVersion       int
	pqRatchetState       *secret.Secret
}

// SenderBaseKey returns the sender's base key in bytes.
func (s *State) SenderBaseKey() []byte {
	if s.senderBaseKey == nil {
		return nil
	}
	return s.senderBaseKey.Serialize()
}

// SetSenderBaseKey sets the sender's base key with the given serialized bytes.
// The input must be the 33-byte type-prefixed EC public key form ([0x05 || 32 key bytes])
// as returned by ECPublicKeyable.Serialize(). Using ecc.DecodePoint rather than
// bytehelper.SliceToArray + NewDjbECPublicKey prevents a truncation bug where
// SliceToArray kept the 0x05 type byte and dropped the last key byte, producing a
// 34-byte Serialize() output that never matched the expected 33-byte comparison
// in HasSessionState. If decoding fails the field is set to nil and the error logged.
func (s *State) SetSenderBaseKey(senderBaseKey []byte) {
	if len(senderBaseKey) == 0 {
		s.senderBaseKey = nil
		return
	}
	pub, err := ecc.DecodePoint(senderBaseKey, 0)
	if err != nil {
		logger.Error("SetSenderBaseKey: failed to decode public key: ", err)
		s.senderBaseKey = nil
		return
	}
	s.senderBaseKey = pub
}

// Version returns the session's version. A stored version of 0 indicates a
// pre-versioning session and is mapped to version 2, matching the Rust
// reference implementation behavior.
func (s *State) Version() int {
	if s.sessionVersion == 0 {
		return 2
	}
	return s.sessionVersion
}

// SetVersion sets the session state's version number.
func (s *State) SetVersion(version int) {
	s.sessionVersion = version
}

// RemoteIdentityKey returns the identity key of the remote user.
func (s *State) RemoteIdentityKey() *identity.Key {
	return s.remoteIdentityPublic
}

// SetRemoteIdentityKey sets this session's identity key for the remote
// user.
func (s *State) SetRemoteIdentityKey(identityKey *identity.Key) {
	s.remoteIdentityPublic = identityKey
}

// LocalIdentityKey returns the session's identity key for the local
// user.
func (s *State) LocalIdentityKey() *identity.Key {
	return s.localIdentityPublic
}

// SetLocalIdentityKey sets the session's identity key for the local
// user.
func (s *State) SetLocalIdentityKey(identityKey *identity.Key) {
	s.localIdentityPublic = identityKey
}

// SessionWithSelf returns true if this is a self-session, i.e., the local
// and remote identity keys are the same. This is used for linked device
// message sync where the sender and receiver are the same user. Matches
// Rust's session_with_self method.
func (s *State) SessionWithSelf() bool {
	if s.localIdentityPublic == nil || s.remoteIdentityPublic == nil {
		return false
	}
	localBytes := s.localIdentityPublic.Serialize()
	remoteBytes := s.remoteIdentityPublic.Serialize()
	if len(localBytes) == 0 || len(remoteBytes) == 0 {
		return false
	}
	if len(localBytes) != len(remoteBytes) {
		return false
	}
	for i := range localBytes {
		if localBytes[i] != remoteBytes[i] {
			return false
		}
	}
	return true
}

// PqRatchetState returns a heap copy of the serialized SPQR ratchet state,
// read inside a WithBytes borrow, or nil if not set. The state carries live
// ratchet secrets, so the caller should wipe the copy after use.
func (s *State) PqRatchetState() []byte {
	return copySecret(s.pqRatchetState)
}

// SetPqRatchetState moves the given serialized SPQR ratchet state into guarded
// memory, destroying whatever state it replaces. The caller's slice is zeroized
// as part of the move and must not be used afterwards. An empty state clears
// the field.
//
// Returns an error only if guarded memory cannot be allocated; the previous
// state is left in place in that case.
func (s *State) SetPqRatchetState(state []byte) error {
	guarded, err := secret.NewOptional(state)
	if err != nil {
		return err
	}
	s.pqRatchetState.Destroy()
	s.pqRatchetState = guarded
	return nil
}

// PreviousCounter returns the counter of the previous message.
func (s *State) PreviousCounter() uint32 {
	return s.previousCounter
}

// SetPreviousCounter sets the counter for the previous message.
func (s *State) SetPreviousCounter(previousCounter uint32) {
	s.previousCounter = previousCounter
}

// RootKey returns the root key for the session.
func (s *State) RootKey() session.RootKeyable {
	return s.rootKey
}

// SetRootKey sets the root key for the session.
// Returns RootKeyTypeError if rootKey is not a *root.Key.
func (s *State) SetRootKey(rootKey session.RootKeyable) error {
	rk, ok := rootKey.(*root.Key)
	if !ok {
		return &RootKeyTypeError{Got: rootKey}
	}
	// The root key being replaced is guarded and the state was its only owner,
	// so a ratchet step must destroy it rather than drop it.
	superseded := s.rootKey
	s.rootKey = rk
	if superseded != nil && superseded != rk {
		superseded.Zeroize()
	}
	return nil
}

// SenderRatchetKey returns the public ratchet key of the sender.
func (s *State) SenderRatchetKey() ecc.ECPublicKeyable {
	return s.senderChain.senderRatchetKeyPair.PublicKey()
}

// SenderRatchetKeyPair returns the public/private ratchet key pair
// of the sender.
func (s *State) SenderRatchetKeyPair() *ecc.ECKeyPair {
	return s.senderChain.senderRatchetKeyPair
}

// HasReceiverChain will check to see if the session state has
// the given ephemeral key.
func (s *State) HasReceiverChain(senderEphemeral ecc.ECPublicKeyable) bool {
	return s.receiverChain(senderEphemeral) != nil
}

// HasSenderChain will check to see if the session state has a
// sender chain.
func (s *State) HasSenderChain() bool {
	return s.senderChain != nil
}

// receiverChain will loop through the session state's receiver chains
// and compare the given ephemeral key. If it is found, then the chain
// and index will be returned as a pair.
func (s *State) receiverChain(senderEphemeral ecc.ECPublicKeyable) *ReceiverChainPair {
	receiverChains := s.receiverChains

	for i, receiverChain := range receiverChains {
		chainSenderRatchetKey, err := ecc.DecodePoint(receiverChain.senderRatchetKeyPair.PublicKey().Serialize(), 0)
		if err != nil {
			logger.Error("Error getting receiverchain: ", err)
			continue
		}

		// If the chainSenderRatchetKey equals our senderEphemeral key, return it.
		if chainSenderRatchetKey.PublicKey() == senderEphemeral.PublicKey() {
			return NewReceiverChainPair(receiverChain, i)
		}
	}

	return nil
}

// ReceiverChainKey will use the given ephemeral key to generate a new
// chain key.
func (s *State) ReceiverChainKey(senderEphemeral ecc.ECPublicKeyable) *chain.Key {
	receiverChainAndIndex := s.receiverChain(senderEphemeral)
	if receiverChainAndIndex == nil {
		return nil
	}
	receiverChain := receiverChainAndIndex.ReceiverChain
	if receiverChain == nil {
		return nil
	}

	// Copy bytes out of guarded memory before passing to constructor,
	// since NewKey moves data into new guarded memory and zeroizes the source.
	keyBytes := make([]byte, len(receiverChain.chainKey.Key()))
	copy(keyBytes, receiverChain.chainKey.Key())
	return chain.NewKey(
		kdf.DeriveSecrets,
		keyBytes,
		receiverChain.chainKey.Index(),
	)
}

// AddReceiverChain will add the given ratchet key and chain key to the session
// state.
func (s *State) AddReceiverChain(senderRatchetKey ecc.ECPublicKeyable, chainKey session.ChainKeyable) {
	// Create a keypair structure with our sender ratchet key.
	senderKey := ecc.NewECKeyPair(senderRatchetKey, nil)

	// Create a Chain state object that will hold our sender key, chain key, and
	// message keys.
	chain := NewChain(senderKey, chainKey.(*chain.Key), []*message.Keys{})

	// Add the Chain state to our list of receiver chain states.
	s.receiverChains = append(s.receiverChains, chain)

	// If our list of receiver chains is too big, delete the oldest entry. The
	// evicted chain's guarded material is destroyed rather than dropped: the
	// state was its only owner and go-enclave reclaims nothing on its own.
	if len(s.receiverChains) > maxReceiverChains {
		i := 0
		evicted := s.receiverChains[i]
		s.receiverChains = append(s.receiverChains[:i], s.receiverChains[i+1:]...)
		destroyChain(evicted)
	}
}

// SetSenderChain will set the given ratchet key pair and chain key for this session
// state.
//
// The state takes ownership of both: a later ratchet step, or a clone committed
// over this state, destroys the chain this one supersedes, and that includes
// the ratchet private key and the chain key. A caller that must keep using
// either — a signed pre-key still held by the pre-key store, say — must pass a
// copy.
func (s *State) SetSenderChain(senderRatchetKeyPair *ecc.ECKeyPair, chainKey session.ChainKeyable) {
	// Create a Chain state object that will hold our sender key, chain key, and
	// message keys.
	chain := NewChain(senderRatchetKeyPair, chainKey.(*chain.Key), []*message.Keys{})

	// A ratchet step replaces the whole sender chain. Destroy the one it
	// supersedes — its chain key and ratchet private key are guarded, and the
	// state was their only owner.
	superseded := s.senderChain

	// Set the sender chain.
	s.senderChain = chain

	if superseded != nil && superseded != chain {
		destroyChain(superseded)
	}
}

// SenderChainKey will return the chain key of the session state.
func (s *State) SenderChainKey() session.ChainKeyable {
	chainKey := s.senderChain.chainKey
	// Copy bytes out of guarded memory before passing to constructor.
	keyBytes := make([]byte, len(chainKey.Key()))
	copy(keyBytes, chainKey.Key())
	return chain.NewKey(kdf.DeriveSecrets, keyBytes, chainKey.Index())
}

// SetSenderChainKey will set the chain key in the chain state for this session to
// the given chain key.
func (s *State) SetSenderChainKey(nextChainKey session.ChainKeyable) {
	senderChain := s.senderChain
	senderChain.SetChainKey(nextChainKey.(*chain.Key))
}

// HasMessageKeys returns true if we have message keys associated with the given
// sender key and counter.
func (s *State) HasMessageKeys(senderEphemeral ecc.ECPublicKeyable, counter uint32) bool {
	// Get our chain state that has our chain key.
	chainAndIndex := s.receiverChain(senderEphemeral)

	// If there is no receiver chain for this ephemeral key, return false.
	if chainAndIndex == nil {
		return false
	}
	receiverChain := chainAndIndex.ReceiverChain

	// If the chain is empty, we don't have any message keys.
	if receiverChain == nil {
		return false
	}

	// Get our message keys from our receiver chain.
	messageKeyList := receiverChain.MessageKeys()

	// Loop through our message keys and compare its index with the
	// given counter.
	for _, messageKey := range messageKeyList {
		if messageKey.Index() == counter {
			return true
		}
	}

	return false
}

// RemoveMessageKeys removes the message key with the given sender key and
// counter. It will return the removed message key, or nil if no matching
// key was found.
func (s *State) RemoveMessageKeys(senderEphemeral ecc.ECPublicKeyable, counter uint32) *message.Keys {
	// Get our chain state that has our chain key.
	chainAndIndex := s.receiverChain(senderEphemeral)

	// If there is no receiver chain for this ephemeral key, return nil.
	if chainAndIndex == nil {
		return nil
	}
	chainKey := chainAndIndex.ReceiverChain

	// If the chain is empty, we don't have any message keys.
	if chainKey == nil {
		return nil
	}

	// Get our message keys from our receiver chain.
	messageKeyList := chainKey.MessageKeys()

	// Loop through our message keys and compare its index with the
	// given counter. When we find a match, remove it from our list.
	found := false
	rmIndex := 0
	for i, messageKey := range messageKeyList {
		if messageKey.Index() == counter {
			rmIndex = i
			found = true
			break
		}
	}

	// If no matching key was found, return nil.
	if !found {
		return nil
	}

	// Retrieve the message key.
	messageKey := chainKey.messageKeys[rmIndex]

	// Delete the message key from the given position.
	chainKey.messageKeys = append(chainKey.messageKeys[:rmIndex], chainKey.messageKeys[rmIndex+1:]...)

	// The caller gets an independent copy below, and the entry is no longer in
	// the chain, so the original's guarded material has no owner left. Destroy
	// it rather than dropping it — go-enclave reclaims nothing on its own, and a
	// peer can drive this path with any message that matches a stored key.
	defer messageKey.Zeroize()

	// Seed-only form: the key was stored with seed material only (cipher/mac/iv
	// are nil). The caller (decryptWithClonedState) will re-derive the actual
	// keys from seed using DeriveMessageKeysFromSeed once the PQR salt is known.
	// This matches Rust MessageKeyGenerator::Seed where keys are re-derived via
	// MessageKeyGenerator::keys_and_pqr at rust/protocol/src/ratchet/keys.rs:33-43.
	if seed := messageKey.SeedMaterial(); len(seed) > 0 {
		seedCopy := make([]byte, len(seed))
		copy(seedCopy, seed)
		result := message.NewSeedOnlyKeys(messageKey.Index(), seedCopy)
		return result
	}

	// Derived-keys form: copy bytes out of guarded memory before passing to
	// constructor so we do not hold a reference into the now-removed chain entry.
	cipherCopy := make([]byte, len(messageKey.CipherKey()))
	copy(cipherCopy, messageKey.CipherKey())
	macCopy := make([]byte, len(messageKey.MacKey()))
	copy(macCopy, messageKey.MacKey())
	ivCopy := make([]byte, len(messageKey.Iv()))
	copy(ivCopy, messageKey.Iv())
	return message.NewKeys(cipherCopy, macCopy, ivCopy, messageKey.Index())
}

// SetMessageKeys will update the chain associated with the given sender key with
// the given message keys.
func (s *State) SetMessageKeys(senderEphemeral ecc.ECPublicKeyable, messageKeys *message.Keys) error {
	chainAndIndex := s.receiverChain(senderEphemeral)
	if chainAndIndex == nil {
		return &ReceiverChainNotFoundError{Operation: "SetMessageKeys"}
	}
	chainState := chainAndIndex.ReceiverChain

	// Copy bytes out of guarded memory before passing to constructor.
	cipherCopy := make([]byte, len(messageKeys.CipherKey()))
	copy(cipherCopy, messageKeys.CipherKey())
	macCopy := make([]byte, len(messageKeys.MacKey()))
	copy(macCopy, messageKeys.MacKey())
	ivCopy := make([]byte, len(messageKeys.Iv()))
	copy(ivCopy, messageKeys.Iv())

	// Add the message keys to our chain state.
	newKeys := message.NewKeys(
		cipherCopy,
		macCopy,
		ivCopy,
		messageKeys.Index(),
	)
	// Propagate seed material for SPQR re-derivation of skipped keys.
	if seed := messageKeys.SeedMaterial(); len(seed) > 0 {
		seedCopy := make([]byte, len(seed))
		copy(seedCopy, seed)
		newKeys.SetSeedMaterial(seedCopy)
	}
	chainState.AddMessageKeys(newKeys)

	if len(chainState.MessageKeys()) > maxMessageKeys {
		chainState.PopFirstMessageKeys()
	}
	return nil
}

// TotalSkippedMessageKeys returns the total number of stored skipped message keys
// across all receiver chains. This is used to enforce the global MAX_SKIP limit
// specified by the Double Ratchet protocol to prevent DoS attacks.
func (s *State) TotalSkippedMessageKeys() int {
	total := 0
	for _, rc := range s.receiverChains {
		total += len(rc.MessageKeys())
	}
	return total
}

// SetReceiverChainKey sets the session's receiver chain key with the given chain key
// associated with the given senderEphemeral key.
func (s *State) SetReceiverChainKey(senderEphemeral ecc.ECPublicKeyable, chainKey session.ChainKeyable) error {
	chainAndIndex := s.receiverChain(senderEphemeral)
	if chainAndIndex == nil {
		return &ReceiverChainNotFoundError{Operation: "SetReceiverChainKey"}
	}
	chainState := chainAndIndex.ReceiverChain
	chainState.SetChainKey(chainKey.(*chain.Key))
	return nil
}

// SetPendingKeyExchange will set the session's pending key exchange state to the given
// sequence and key pairs.
func (s *State) SetPendingKeyExchange(sequence uint32, ourBaseKey, ourRatchetKey *ecc.ECKeyPair,
	ourIdentityKey *identity.KeyPair) {

	s.pendingKeyExchange = NewPendingKeyExchange(
		sequence,
		ourBaseKey,
		ourRatchetKey,
		ourIdentityKey,
	)
}

// PendingKeyExchangeSequence will return the session's pending key exchange sequence
// number.
func (s *State) PendingKeyExchangeSequence() uint32 {
	return s.pendingKeyExchange.sequence
}

// PendingKeyExchangeBaseKeyPair will return the session's pending key exchange base keypair.
func (s *State) PendingKeyExchangeBaseKeyPair() *ecc.ECKeyPair {
	return s.pendingKeyExchange.localBaseKeyPair
}

// PendingKeyExchangeRatchetKeyPair will return the session's pending key exchange ratchet
// keypair.
func (s *State) PendingKeyExchangeRatchetKeyPair() *ecc.ECKeyPair {
	return s.pendingKeyExchange.localRatchetKeyPair
}

// PendingKeyExchangeIdentityKeyPair will return the session's pending key exchange identity
// keypair.
func (s *State) PendingKeyExchangeIdentityKeyPair() *identity.KeyPair {
	return s.pendingKeyExchange.localIdentityKeyPair
}

// HasPendingKeyExchange will return true if there is a valid pending key exchange waiting.
func (s *State) HasPendingKeyExchange() bool {
	return s.pendingKeyExchange != nil
}

// SetUnacknowledgedPreKeyMessage will return unacknowledged pre key message with the
// given key ids and base key.
func (s *State) SetUnacknowledgedPreKeyMessage(preKeyID *optional.Uint32, signedPreKeyID uint32, baseKey ecc.ECPublicKeyable) {
	s.pendingPreKey = NewPendingPreKey(
		preKeyID,
		signedPreKeyID,
		baseKey,
	)
}

// SetUnacknowledgedPreKeyMessageWithKyber sets the unacknowledged pre key message with
// optional PQXDH Kyber pre-key ID and ciphertext.
func (s *State) SetUnacknowledgedPreKeyMessageWithKyber(preKeyID *optional.Uint32, signedPreKeyID uint32,
	baseKey ecc.ECPublicKeyable, kyberPreKeyID *optional.Uint32, kyberCiphertext []byte) {
	s.pendingPreKey = NewPendingPreKey(
		preKeyID,
		signedPreKeyID,
		baseKey,
	)
	s.pendingPreKey.kyberPreKeyID = kyberPreKeyID
	s.pendingPreKey.kyberCiphertext = kyberCiphertext
}

// HasUnacknowledgedPreKeyMessage will return true if this session has an unacknowledged
// pre key message.
func (s *State) HasUnacknowledgedPreKeyMessage() bool {
	return s.pendingPreKey != nil
}

// UnackPreKeyMessageItems will return the session's unacknowledged pre key messages.
func (s *State) UnackPreKeyMessageItems() (*UnackPreKeyMessageItems, error) {
	preKeyID := s.pendingPreKey.preKeyID
	signedPreKeyID := s.pendingPreKey.signedPreKeyID
	baseKey, err := ecc.DecodePoint(s.pendingPreKey.baseKey.Serialize(), 0)
	if err != nil {
		return nil, err
	}
	items := NewUnackPreKeyMessageItems(preKeyID, signedPreKeyID, baseKey)
	items.kyberPreKeyID = s.pendingPreKey.kyberPreKeyID
	items.kyberCiphertext = s.pendingPreKey.kyberCiphertext
	return items, nil
}

// ClearUnackPreKeyMessage will clear the session's pending pre key.
func (s *State) ClearUnackPreKeyMessage() {
	s.pendingPreKey = nil
}

// UnacknowledgedTimestamp returns the creation timestamp of the pending
// pre-key message in seconds since Unix epoch. Returns 0 if there is no
// pending pre-key message.
func (s *State) UnacknowledgedTimestamp() uint64 {
	if s.pendingPreKey == nil {
		return 0
	}
	return s.pendingPreKey.Timestamp()
}

// SetRemoteRegistrationID sets the remote user's registration id.
func (s *State) SetRemoteRegistrationID(registrationID uint32) {
	s.remoteRegistrationID = registrationID
}

// RemoteRegistrationID returns the remote user's registration id.
func (s *State) RemoteRegistrationID() uint32 {
	return s.remoteRegistrationID
}

// SetLocalRegistrationID sets the local user's registration id.
func (s *State) SetLocalRegistrationID(registrationID uint32) {
	s.localRegistrationID = registrationID
}

// LocalRegistrationID returns the local user's registration id.
func (s *State) LocalRegistrationID() uint32 {
	return s.localRegistrationID
}

// Serialize will return the state as bytes using the given serializer.
func (s *State) Serialize() ([]byte, error) {
	st, err := s.structure()
	if err != nil {
		return nil, err
	}
	defer st.Zeroize()
	return s.serializer.Serialize(st)
}

// Clone creates a deep copy of the session state by serializing and
// deserializing through the state's serializer. This is used to preserve
// state before speculative operations that may need to be rolled back.
func (s *State) Clone() (*State, error) {
	// An uninitialized state (sessionVersion 0) — the placeholder current state
	// of a fresh or freshly-archived session — carries no ratchet material and
	// cannot survive a Serialize/Deserialize round-trip. It has nothing to deep
	// copy, so return a new empty state bound to the same serializer.
	if s.sessionVersion == 0 {
		return NewState(s.serializer), nil
	}
	serialized, err := s.Serialize()
	if err != nil {
		return nil, err
	}
	return NewStateFromBytes(serialized, s.serializer)
}

// DiscardClone releases the guarded key material held by a state that Clone
// produced and that is being thrown away instead of committed.
//
// A clone is the one kind of live state a caller owns outright: Clone
// round-trips through the serializer, so every guarded buffer in the clone is
// its own and nothing else can reach it. It stops being that the moment it is
// committed — CopyFrom moves the clone's chains, root key and PQ ratchet state
// into the state committed into — so a caller that commits must not also
// discard. Discarding a clone that was never committed is what keeps a failed
// speculative operation, such as a decrypt that fails MAC verification, from
// stranding locked memory.
//
// This is deliberately not a general destruction model for session states.
// Ordinary live states share their guarded objects; their ownership is a
// separate question.
func (s *State) DiscardClone() {
	destroyState(s)
}

// CommitClone replaces this state with a working clone produced by Clone and
// releases the guarded material the commit supersedes.
//
// This is the counterpart to DiscardClone: a speculative operation clones the
// state, and the clone is either committed here or discarded there. Committing
// adopts the clone's chains, root key, pending key exchange and PQ ratchet
// state, which leaves this state's previous ones with no owner at all — and
// go-enclave reclaims nothing on its own, so leaving them behind costs a locked
// buffer per committed message for the life of the process. Only material the
// commit actually replaced is released, so handing back a clone that still
// shares an object with this state is safe.
//
// The clone belongs to this state afterwards and must not also be discarded.
// Callers must not hold guarded sub-objects of this state — a *message.Keys
// taken with RemoveMessageKeys, say — across a commit.
func (s *State) CommitClone(clone *State) {
	if clone == nil || clone == s {
		return
	}

	supersededSenderChain := s.senderChain
	supersededReceiverChains := s.receiverChains
	supersededPendingKeyExchange := s.pendingKeyExchange
	supersededRootKey := s.rootKey

	s.CopyFrom(clone)

	for _, supersededChain := range append([]*Chain{supersededSenderChain}, supersededReceiverChains...) {
		if supersededChain != nil && !s.ownsChain(supersededChain) {
			destroyChain(supersededChain)
		}
	}
	if supersededPendingKeyExchange != nil && supersededPendingKeyExchange != s.pendingKeyExchange {
		destroyPendingKeyExchange(supersededPendingKeyExchange)
	}
	if supersededRootKey != nil && supersededRootKey != s.rootKey {
		supersededRootKey.Zeroize()
	}
}

// ownsChain reports whether the given chain is one this state still holds,
// which is how CommitClone tells a replaced chain from one the caller kept.
func (s *State) ownsChain(candidate *Chain) bool {
	if s.senderChain == candidate {
		return true
	}
	for _, receiverChain := range s.receiverChains {
		if receiverChain == candidate {
			return true
		}
	}
	return false
}

// CopyFrom replaces all fields of this state with those from the source state.
// This is used to commit a successfully-modified clone back to the original.
// The clone's guarded objects become this state's; the caller must not discard
// the clone afterwards.
func (s *State) CopyFrom(source *State) {
	s.localIdentityPublic = source.localIdentityPublic
	s.localRegistrationID = source.localRegistrationID
	s.needsRefresh = source.needsRefresh
	s.pendingKeyExchange = source.pendingKeyExchange
	s.pendingPreKey = source.pendingPreKey
	s.previousCounter = source.previousCounter
	s.receiverChains = source.receiverChains
	s.remoteIdentityPublic = source.remoteIdentityPublic
	s.remoteRegistrationID = source.remoteRegistrationID
	s.rootKey = source.rootKey
	s.senderBaseKey = source.senderBaseKey
	s.senderChain = source.senderChain
	s.sessionVersion = source.sessionVersion
	// The guarded PQ ratchet state being replaced is destroyed rather than
	// abandoned, so a locked allocation is not stranded on every committed
	// clone. The pointer check keeps a self-copy from destroying live material.
	if s.pqRatchetState != source.pqRatchetState {
		s.pqRatchetState.Destroy()
		s.pqRatchetState = source.pqRatchetState
	}
}

// structure will return a serializable structure of the
// the given state so it can be persistently stored. The caller owns the
// returned structure and must Zeroize it once the serializer is done with it;
// on failure everything built so far is released before returning.
func (s *State) structure() (_ *StateStructure, err error) {
	// Serialize identity keys and sender base key with nil safety. These are
	// public and stay on the heap.
	var localIdentityBytes, remoteIdentityBytes, senderBaseKeyBytes []byte
	if s.localIdentityPublic != nil {
		localIdentityBytes = s.localIdentityPublic.Serialize()
	}
	if s.remoteIdentityPublic != nil {
		remoteIdentityBytes = s.remoteIdentityPublic.Serialize()
	}
	if s.senderBaseKey != nil {
		senderBaseKeyBytes = s.senderBaseKey.Serialize()
	}

	structure := &StateStructure{
		LocalIdentityPublic:  localIdentityBytes,
		LocalRegistrationID:  s.localRegistrationID,
		NeedsRefresh:         s.needsRefresh,
		PreviousCounter:      s.previousCounter,
		ReceiverChains:       make([]*ChainStructure, len(s.receiverChains)),
		RemoteIdentityPublic: remoteIdentityBytes,
		RemoteRegistrationID: s.remoteRegistrationID,
		SenderBaseKey:        senderBaseKeyBytes,
		SessionVersion:       s.sessionVersion,
	}

	// Release the partially built structure if any step below fails, so that
	// no guarded allocation outlives the failed call.
	defer func() {
		if err != nil {
			structure.Zeroize()
		}
	}()

	// Convert our receiver chains into a serializeable structure.
	for i := range s.receiverChains {
		if structure.ReceiverChains[i], err = s.receiverChains[i].structure(); err != nil {
			return nil, err
		}
	}

	// Convert our sender chain into a serializeable structure.
	if s.senderChain != nil {
		if structure.SenderChain, err = s.senderChain.structure(); err != nil {
			return nil, err
		}
	}

	// Convert our pending key exchange into a serializeable structure.
	if s.pendingKeyExchange != nil {
		if structure.PendingKeyExchange, err = s.pendingKeyExchange.structure(); err != nil {
			return nil, err
		}
	}

	// Convert our pending pre key into a serializeable structure.
	if s.pendingPreKey != nil {
		structure.PendingPreKey = s.pendingPreKey.structure()
	}

	// Move the root key and the PQ ratchet state into guarded memory.
	if s.rootKey != nil {
		if structure.RootKey, err = secret.NewValue(copyBytes(s.rootKey.Bytes())); err != nil {
			return nil, err
		}
	}
	if !s.pqRatchetState.IsDestroyed() {
		cloned, cloneErr := s.pqRatchetState.Clone()
		if cloneErr != nil {
			return nil, cloneErr
		}
		structure.PqRatchetState = secret.FromSecret(cloned)
	}

	return structure, nil
}

// copyBytes returns an independent copy of the given slice.
// This is used to safely extract bytes from guarded memory for serialization.
func copyBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
