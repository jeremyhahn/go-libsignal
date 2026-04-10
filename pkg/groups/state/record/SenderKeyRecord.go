package record

import (
	"crypto/subtle"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// SenderKeySerializer is an interface for serializing and deserializing
// SenderKey objects into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type SenderKeySerializer interface {
	Serialize(preKey *SenderKeyStructure) ([]byte, error)
	Deserialize(serialized []byte) (*SenderKeyStructure, error)
}

// NewSenderKeyFromBytes will return a prekey record from the given bytes using the given serializer.
func NewSenderKeyFromBytes(serialized []byte, serializer SenderKeySerializer,
	stateSerializer SenderKeyStateSerializer) (*SenderKey, error) {

	// Use the given serializer to decode the senderkey record
	senderKeyStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return NewSenderKeyFromStruct(senderKeyStructure, serializer, stateSerializer)
}

// NewSenderKeyFromStruct returns a SenderKey record using the given serializable structure.
func NewSenderKeyFromStruct(structure *SenderKeyStructure, serializer SenderKeySerializer,
	stateSerializer SenderKeyStateSerializer) (*SenderKey, error) {

	// Build our sender key states from structure.
	senderKeyStates := make([]*SenderKeyState, len(structure.SenderKeyStates))
	for i := range structure.SenderKeyStates {
		var err error
		senderKeyStates[i], err = NewSenderKeyStateFromStructure(structure.SenderKeyStates[i], stateSerializer)
		if err != nil {
			return nil, err
		}
	}

	// Build and return our session.
	senderKey := &SenderKey{
		senderKeyStates: senderKeyStates,
		serializer:      serializer,
	}

	return senderKey, nil

}

// NewSenderKey record returns a new sender key record that can
// be stored in a SenderKeyStore.
func NewSenderKey(serializer SenderKeySerializer,
	stateSerializer SenderKeyStateSerializer) *SenderKey {

	return &SenderKey{
		senderKeyStates: []*SenderKeyState{},
		serializer:      serializer,
		stateSerializer: stateSerializer,
	}
}

// SenderKeyStructure is a structure for serializing SenderKey records.
type SenderKeyStructure struct {
	SenderKeyStates []*SenderKeyStateStructure
}

// SenderKey record is a structure for storing pre keys inside
// a SenderKeyStore.
type SenderKey struct {
	senderKeyStates []*SenderKeyState
	serializer      SenderKeySerializer
	stateSerializer SenderKeyStateSerializer
}

// SenderKeyState will return the first sender key state in the record's
// list of sender key states.
func (k *SenderKey) SenderKeyState() (*SenderKeyState, error) {
	if len(k.senderKeyStates) > 0 {
		return k.senderKeyStates[0], nil
	}
	return nil, ErrNoSenderKeys
}

// GetSenderKeyStateByID will return the sender key state with the given
// key id.
func (k *SenderKey) GetSenderKeyStateByID(keyID uint32) (*SenderKeyState, error) {
	for i := 0; i < len(k.senderKeyStates); i++ {
		if k.senderKeyStates[i].KeyID() == keyID {
			return k.senderKeyStates[i], nil
		}
	}

	return nil, ErrNoSenderKeyForID
}

// IsEmpty will return false if there is more than one state in this
// senderkey record.
func (k *SenderKey) IsEmpty() bool {
	return len(k.senderKeyStates) == 0
}

// AddSenderKeyState adds a new state to this senderkey record with the given
// id, iteration, chainkey, and signature key.
//
// This implements the Rust reference add_sender_key_state deduplication logic:
//  1. If a state with matching (chain_id, signing_key) already exists, remove
//     it and re-insert at the front (preserving the EXISTING state's data).
//  2. Remove any states with matching chain_id but DIFFERENT signing key.
//  3. If exceeding MAX_SENDER_KEY_STATES, evict the oldest (last) state.
//  4. Push new state to the front (index 0) so SenderKeyState() returns it.
func (k *SenderKey) AddSenderKeyState(messageVersion uint32, id uint32, iteration uint32,
	chainKey []byte, signatureKey ecc.ECPublicKeyable) {

	// Step 1: Remove existing state with matching (chain_id, signing_key).
	var existingState *SenderKeyState
	for i, state := range k.senderKeyStates {
		if state.KeyID() == id && state.SigningKey().PublicKey() != nil &&
			signatureKey != nil &&
			subtle.ConstantTimeCompare(state.SigningKey().PublicKey().Serialize(), signatureKey.Serialize()) == 1 {
			existingState = state
			k.senderKeyStates = append(k.senderKeyStates[:i], k.senderKeyStates[i+1:]...)
			break
		}
	}

	// Step 2: Remove states with matching chain_id but different signing key.
	filtered := k.senderKeyStates[:0]
	for _, state := range k.senderKeyStates {
		if state.KeyID() != id {
			filtered = append(filtered, state)
		}
	}
	k.senderKeyStates = filtered

	// Step 3: Determine the state to insert. Use the existing state if found
	// (matching Rust behavior: re-insert preserves existing data), otherwise
	// create a new one.
	var stateToInsert *SenderKeyState
	if existingState != nil {
		stateToInsert = existingState
	} else {
		stateToInsert = NewSenderKeyStateFromPublicKey(messageVersion, id, iteration, chainKey, signatureKey, k.stateSerializer)
	}

	// Step 4: Evict oldest (last) if at capacity.
	for len(k.senderKeyStates) >= maxSenderKeyStates {
		k.senderKeyStates = k.senderKeyStates[:len(k.senderKeyStates)-1]
	}

	// Step 5: Push to front.
	k.senderKeyStates = append([]*SenderKeyState{stateToInsert}, k.senderKeyStates...)
}

// SetSenderKeyState replaces the current senderkey states with the given
// senderkey state.
func (k *SenderKey) SetSenderKeyState(messageVersion uint32, id uint32, iteration uint32,
	chainKey []byte, signatureKey *ecc.ECKeyPair) {

	newState := NewSenderKeyState(messageVersion, id, iteration, chainKey, signatureKey, k.stateSerializer)
	k.senderKeyStates = make([]*SenderKeyState, 0, maxSenderKeyStates)
	k.senderKeyStates = append(k.senderKeyStates, newState)
}

// Serialize will return the record as serialized bytes so it can be
// persistently stored.
func (k *SenderKey) Serialize() ([]byte, error) {
	st := k.structure()
	defer st.Zeroize()
	return k.serializer.Serialize(st)
}

// structure will return a simple serializable record structure.
// This is used for serialization to persistently store a session record.
// Each SenderKeyStateStructure is zeroized after the enclosing Serialize call
// via the deferred Zeroize on the returned SenderKeyStructure.
func (k *SenderKey) structure() *SenderKeyStructure {
	senderKeyStates := make([]*SenderKeyStateStructure, len(k.senderKeyStates))
	for i := range k.senderKeyStates {
		senderKeyStates[i] = k.senderKeyStates[i].structure()
	}
	return &SenderKeyStructure{
		SenderKeyStates: senderKeyStates,
	}
}

// Zeroize overwrites all sensitive key material in the record structure.
// Call this (via defer) after the structure has been serialized.
func (s *SenderKeyStructure) Zeroize() {
	for _, st := range s.SenderKeyStates {
		if st != nil {
			st.Zeroize()
		}
	}
}
