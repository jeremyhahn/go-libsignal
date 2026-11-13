package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
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
	// The structure decoded here is ours. Now that Deserialize returns guarded
	// fields, releasing it is mandatory rather than tidy: NewSenderKeyStateFromStructure
	// clones out of it and deliberately leaves the source intact for its owner,
	// and go-enclave sets no finalizer -- so without this every successful load
	// would strand a duplicate set of secrets mlock'd for the process lifetime.
	defer stateStructure.Zeroize()

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
	// A receiving state has no signing private key; it stays nil, as in
	// NewSenderKeyStateFromPublicKey, rather than becoming a zero-padded key.
	// A destroyed or wrong-length key is an error.
	var signingKeyPrivate ecc.ECPrivateKeyable
	gErr := structure.SigningKeyPrivate.WithBytes(func(b []byte) error {
		switch len(b) {
		case 0:
			return nil
		case 32:
		default:
			return &ratchet.KeyLengthError{Field: "signing private key", Got: len(b), Want: 32}
		}
		// SliceToArray copies the view into an array, which
		// NewGuardedECPrivateKey wipes after moving it into guarded memory.
		guarded, kErr := ecc.NewGuardedECPrivateKey(bytehelper.SliceToArray(b))
		if kErr != nil {
			return kErr
		}
		signingKeyPrivate = guarded
		return nil
	})
	if gErr != nil {
		return nil, gErr
	}

	// Populate the state as it is decoded, so that every guarded allocation made
	// so far is reachable by the cleanup below, whichever step fails.
	state := &SenderKeyState{
		keyID:          structure.KeyID,
		messageVersion: structure.MessageVersion,
		signingKeyPair: ecc.NewECKeyPair(signingKeyPublic, signingKeyPrivate),
		serializer:     serializer,
	}
	handedOver := false
	defer func() {
		if !handedOver {
			destroySenderKeyState(state)
		}
	}()

	// Build our sender message keys from structure.
	state.keys = make([]*ratchet.SenderMessageKey, len(structure.Keys))
	for i := range structure.Keys {
		var mkErr error
		if state.keys[i], mkErr = ratchet.NewSenderMessageKeyFromStruct(structure.Keys[i]); mkErr != nil {
			return nil, mkErr
		}
	}

	var ckErr error
	if state.senderChainKey, ckErr = ratchet.NewSenderChainKeyFromStruct(structure.SenderChainKey); ckErr != nil {
		return nil, ckErr
	}

	handedOver = true
	return state, nil
}

// destroySenderKeyState releases every guarded buffer a partially built state
// owns. go-enclave sets no finalizer, so a state abandoned mid-construction keeps
// its buffers mlock'd for the life of the process unless they are destroyed
// explicitly.
func destroySenderKeyState(state *SenderKeyState) {
	if state == nil {
		return
	}
	if state.senderChainKey != nil {
		state.senderChainKey.Zeroize()
	}
	for _, key := range state.keys {
		if key != nil {
			key.Zeroize()
		}
	}
	if state.signingKeyPair != nil {
		if private, ok := state.signingKeyPair.PrivateKey().(interface{ Destroy() }); ok {
			private.Destroy()
		}
	}
}

// SenderKeyStateStructure is a serializeable structure of SenderKeyState. The
// signing private key is held in guarded memory. Unlike a chain or message key
// it is long-lived — it authenticates every SenderKeyMessage in the group — so
// a plain-heap copy of it is the worst of the three to leave swappable or
// capturable in a core dump.
type SenderKeyStateStructure struct {
	Keys              []*ratchet.SenderMessageKeyStructure
	KeyID             uint32
	MessageVersion    uint32
	SenderChainKey    *ratchet.SenderChainKeyStructure
	SigningKeyPrivate secret.Secret
	SigningKeyPublic  []byte
}

// Zeroize releases all guarded key material in the structure. Call this (via
// defer) after the structure has been serialized. It is idempotent.
func (s *SenderKeyStateStructure) Zeroize() {
	s.SigningKeyPrivate.Destroy()
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
	st, err := k.structure()
	if err != nil {
		return nil, err
	}
	defer st.Zeroize()
	return k.serializer.Serialize(st)
}

// structure will return a serializable structure of the
// the given state so it can be persistently stored.
// The caller owns the returned structure and must Zeroize it once the
// serializer is done with it; on failure everything built so far is released
// before returning.
func (k *SenderKeyState) structure() (_ *SenderKeyStateStructure, err error) {
	structure := &SenderKeyStateStructure{
		Keys:             make([]*ratchet.SenderMessageKeyStructure, len(k.keys)),
		KeyID:            k.keyID,
		MessageVersion:   k.messageVersion,
		SigningKeyPublic: k.signingKeyPair.PublicKey().Serialize(),
	}

	// Registered before the first clone, so every guarded allocation made from
	// here on is covered whichever step fails.
	defer func() {
		if err != nil {
			structure.Zeroize()
		}
	}()

	for i := range k.keys {
		if structure.Keys[i], err = ratchet.NewStructFromSenderMessageKey(k.keys[i]); err != nil {
			return nil, err
		}
	}

	if structure.SenderChainKey, err = ratchet.NewStructFromSenderChainKey(k.senderChainKey); err != nil {
		return nil, err
	}

	if structure.SigningKeyPrivate, err = ecc.GuardPrivateKey(k.signingKeyPair.PrivateKey()); err != nil {
		return nil, err
	}

	return structure, nil
}
