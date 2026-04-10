package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

const maxMessageKeys = 2000

// maxSenderKeyStates is the maximum number of sender key states stored per
// SenderKey record. This matches the Rust reference implementation constant
// MAX_SENDER_KEY_STATES = 5 in libsignal/rust/protocol/src/consts.rs.
const maxSenderKeyStates = 5

// SenderKeyStateSerializer is an interface for serializing and deserializing
// a Signal State into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type SenderKeyStateSerializer interface {
	Serialize(state *SenderKeyStateStructure) ([]byte, error)
	Deserialize(serialized []byte) (*SenderKeyStateStructure, error)
}

// NewSenderKeyStateFromBytes will return a Signal State from the given
// bytes using the given serializer.
func NewSenderKeyStateFromBytes(serialized []byte, serializer SenderKeyStateSerializer) (*SenderKeyState, error) {
	// Use the given serializer to decode the signal message.
	stateStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return NewSenderKeyStateFromStructure(stateStructure, serializer)
}

// NewSenderKeyState returns a new SenderKeyState.
func NewSenderKeyState(messageVersion uint32, keyID uint32, iteration uint32, chainKey []byte,
	signatureKey *ecc.ECKeyPair, serializer SenderKeyStateSerializer) *SenderKeyState {

	return &SenderKeyState{
		keys:           make([]*ratchet.SenderMessageKey, 0, maxMessageKeys/2),
		keyID:          keyID,
		messageVersion: messageVersion,
		senderChainKey: ratchet.NewSenderChainKey(iteration, chainKey),
		signingKeyPair: signatureKey,
		serializer:     serializer,
	}
}

// NewSenderKeyStateFromPublicKey returns a new SenderKeyState with the given publicKey.
func NewSenderKeyStateFromPublicKey(messageVersion uint32, keyID uint32, iteration uint32, chainKey []byte,
	signatureKey ecc.ECPublicKeyable, serializer SenderKeyStateSerializer) *SenderKeyState {

	keyPair := ecc.NewECKeyPair(signatureKey, nil)

	return &SenderKeyState{
		keys:           make([]*ratchet.SenderMessageKey, 0, maxMessageKeys/2),
		keyID:          keyID,
		messageVersion: messageVersion,
		senderChainKey: ratchet.NewSenderChainKey(iteration, chainKey),
		signingKeyPair: keyPair,
		serializer:     serializer,
	}
}

// NewSenderKeyStateFromStructure will return a new session state with the
// given state structure. This structure is given back from an
// implementation of the sender key state serializer.
func NewSenderKeyStateFromStructure(structure *SenderKeyStateStructure,
	serializer SenderKeyStateSerializer) (*SenderKeyState, error) {

	// Convert our ecc keys from bytes into object form.
	signingKeyPublic, err := ecc.DecodePoint(structure.SigningKeyPublic, 0)
	if err != nil {
		return nil, err
	}
	signingKeyPrivate, gErr := ecc.NewGuardedECPrivateKey(bytehelper.SliceToArray(structure.SigningKeyPrivate))
	if gErr != nil {
		return nil, gErr
	}

	// Build our sender message keys from structure
	senderMessageKeys := make([]*ratchet.SenderMessageKey, len(structure.Keys))
	for i := range structure.Keys {
		senderMessageKeys[i] = ratchet.NewSenderMessageKeyFromStruct(structure.Keys[i])
	}

	// Build our state object.
	state := &SenderKeyState{
		keys:           senderMessageKeys,
		keyID:          structure.KeyID,
		messageVersion: structure.MessageVersion,
		senderChainKey: ratchet.NewSenderChainKeyFromStruct(structure.SenderChainKey),
		signingKeyPair: ecc.NewECKeyPair(signingKeyPublic, signingKeyPrivate),
		serializer:     serializer,
	}

	return state, nil
}

// SenderKeyStateStructure is a serializeable structure of SenderKeyState.
type SenderKeyStateStructure struct {
	Keys              []*ratchet.SenderMessageKeyStructure
	KeyID             uint32
	MessageVersion    uint32
	SenderChainKey    *ratchet.SenderChainKeyStructure
	SigningKeyPrivate []byte
	SigningKeyPublic  []byte
}

// Zeroize overwrites all sensitive key material in the structure with zeros.
// Call this (via defer) after the structure has been serialized.
func (s *SenderKeyStateStructure) Zeroize() {
	crypto.Zeroize(s.SigningKeyPrivate)
	if s.SenderChainKey != nil {
		s.SenderChainKey.Zeroize()
	}
	for _, mk := range s.Keys {
		if mk != nil {
			mk.Zeroize()
		}
	}
}

// SenderKeyState is a structure for maintaining a senderkey session state.
type SenderKeyState struct {
	keys           []*ratchet.SenderMessageKey
	keyID          uint32
	messageVersion uint32
	senderChainKey *ratchet.SenderChainKey
	signingKeyPair *ecc.ECKeyPair
	serializer     SenderKeyStateSerializer
}

// SigningKey returns the signing key pair of the sender key state.
func (k *SenderKeyState) SigningKey() *ecc.ECKeyPair {
	return k.signingKeyPair
}

// SenderChainKey returns the sender chain key of the state.
func (k *SenderKeyState) SenderChainKey() *ratchet.SenderChainKey {
	return k.senderChainKey
}

// KeyID returns the state's key id.
func (k *SenderKeyState) KeyID() uint32 {
	return k.keyID
}

// MessageVersion returns the message version of this sender key state.
// If the stored version is 0, it defaults to 3 (the first SenderKey version),
// matching the Rust reference behavior.
func (k *SenderKeyState) MessageVersion() uint32 {
	if k.messageVersion == 0 {
		return 3
	}
	return k.messageVersion
}

// HasSenderMessageKey will return true if the state has a key with the
// given iteration.
func (k *SenderKeyState) HasSenderMessageKey(iteration uint32) bool {
	for i := 0; i < len(k.keys); i++ {
		if k.keys[i].Iteration() == iteration {
			return true
		}
	}
	return false
}

// AddSenderMessageKey will add the given sender message key to the state.
// If the key buffer exceeds maxMessageKeys, the oldest key is zeroized
// before being evicted.
func (k *SenderKeyState) AddSenderMessageKey(senderMsgKey *ratchet.SenderMessageKey) {
	k.keys = append(k.keys, senderMsgKey)

	if len(k.keys) > maxMessageKeys {
		k.keys[0].Zeroize()
		k.keys = k.keys[1:]
	}
}

// SetSenderChainKey will set the state's sender chain key with the given key.
func (k *SenderKeyState) SetSenderChainKey(senderChainKey *ratchet.SenderChainKey) {
	k.senderChainKey = senderChainKey
}

// RemoveSenderMessageKey will remove the key in this state with the given iteration number.
func (k *SenderKeyState) RemoveSenderMessageKey(iteration uint32) *ratchet.SenderMessageKey {
	for i := 0; i < len(k.keys); i++ {
		if k.keys[i].Iteration() == iteration {
			removed := k.keys[i]
			k.keys = append(k.keys[0:i], k.keys[i+1:]...)
			return removed
		}
	}

	return nil
}

// Serialize will return the state as bytes using the given serializer.
func (k *SenderKeyState) Serialize() ([]byte, error) {
	st := k.structure()
	defer st.Zeroize()
	return k.serializer.Serialize(st)
}

// structure will return a serializable structure of the
// the given state so it can be persistently stored.
func (k *SenderKeyState) structure() *SenderKeyStateStructure {
	// Convert our sender message keys into a serializeable structure
	keys := make([]*ratchet.SenderMessageKeyStructure, len(k.keys))
	for i := range k.keys {
		keys[i] = ratchet.NewStructFromSenderMessageKey(k.keys[i])
	}

	// Build and return our state structure.
	return &SenderKeyStateStructure{
		Keys:              keys,
		KeyID:             k.keyID,
		MessageVersion:    k.messageVersion,
		SenderChainKey:    ratchet.NewStructFromSenderChainKey(k.senderChainKey),
		SigningKeyPrivate: bytehelper.ArrayToSlice(k.signingKeyPair.PrivateKey().Serialize()),
		SigningKeyPublic:  k.signingKeyPair.PublicKey().Serialize(),
	}
}
