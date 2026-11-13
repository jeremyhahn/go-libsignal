package record

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// NewReceiverChainPair will return a new ReceiverChainPair object.
func NewReceiverChainPair(receiverChain *Chain, index int) *ReceiverChainPair {
	return &ReceiverChainPair{
		ReceiverChain: receiverChain,
		Index:         index,
	}
}

// ReceiverChainPair is a structure for a receiver chain key and index number.
type ReceiverChainPair struct {
	ReceiverChain *Chain
	Index         int
}

// NewChain returns a new Chain structure for SessionState.
func NewChain(senderRatchetKeyPair *ecc.ECKeyPair, chainKey *chain.Key,
	messageKeys []*message.Keys) *Chain {

	return &Chain{
		senderRatchetKeyPair: senderRatchetKeyPair,
		chainKey:             chainKey,
		messageKeys:          messageKeys,
	}
}

// NewChainFromStructure will return a new Chain with the given
// chain structure.
//
// The ratchet private key, the chain key and every message key are moved into
// guarded memory as they are decoded. If the chain cannot be completed, all of
// them are released before returning, so a failed call leaves no locked memory
// behind.
func NewChainFromStructure(structure *ChainStructure) (*Chain, error) {
	if structure == nil {
		return nil, nil
	}
	// Alias to SliceToArray

	// Populate the chain as it is decoded so that every guarded allocation made
	// so far is reachable by the cleanup below, whichever step fails.
	chainState := &Chain{}
	handedOver := false
	defer func() {
		if !handedOver {
			destroyChain(chainState)
		}
	}()

	// Build the sender ratchet key from bytes.
	senderRatchetKeyPublic, err := ecc.DecodePoint(structure.SenderRatchetKeyPublic, 0)
	if err != nil {
		return nil, err
	}
	var senderRatchetKeyPrivate ecc.ECPrivateKeyable
	// A receiver chain has no private key (length 0). A destroyed or
	// wrong-length key is an error, not a missing key.
	privLen, lenErr := secretLen(&structure.SenderRatchetKeyPrivate)
	if lenErr != nil {
		return nil, lenErr
	}
	switch privLen {
	case 0:
	case 32:
		guardedKey, gErr := guardedPrivateKey(&structure.SenderRatchetKeyPrivate)
		if gErr != nil {
			return nil, gErr
		}
		senderRatchetKeyPrivate = guardedKey
	default:
		return nil, fmt.Errorf("record: sender ratchet private key is %d bytes, want 32", privLen)
	}
	chainState.senderRatchetKeyPair = ecc.NewECKeyPair(senderRatchetKeyPublic, senderRatchetKeyPrivate)

	// Build our message keys from the message key structures.
	chainState.messageKeys = make([]*message.Keys, len(structure.MessageKeys))
	for i := range structure.MessageKeys {
		if chainState.messageKeys[i], err = message.NewKeysFromStruct(structure.MessageKeys[i]); err != nil {
			return nil, err
		}
	}

	// Build our new chain state.
	if chainState.chainKey, err = chain.NewKeyFromStruct(structure.ChainKey, kdf.DeriveSecrets); err != nil {
		return nil, err
	}

	handedOver = true
	return chainState, nil
}

// ChainStructure is a serializeable structure for chain states. The sender
// ratchet private key is held in guarded memory; see
// PendingKeyExchangeStructure for the rationale.
type ChainStructure struct {
	SenderRatchetKeyPublic  []byte
	SenderRatchetKeyPrivate secret.Secret
	ChainKey                *chain.KeyStructure
	MessageKeys             []*message.KeysStructure
}

// Zeroize destroys the guarded sender ratchet private key and overwrites the
// remaining sensitive key material in the structure with zeros. Call this (via
// defer) after the structure has been serialized.
func (c *ChainStructure) Zeroize() {
	c.SenderRatchetKeyPrivate.Destroy()
	if c.ChainKey != nil {
		c.ChainKey.Zeroize()
	}
	for _, mk := range c.MessageKeys {
		if mk != nil {
			mk.Zeroize()
		}
	}
}

// Chain is a structure used inside the SessionState that keeps
// track of an ongoing ratcheting chain for a session.
type Chain struct {
	senderRatchetKeyPair *ecc.ECKeyPair
	chainKey             *chain.Key
	messageKeys          []*message.Keys
}

// SenderRatchetKey returns the sender's EC keypair.
func (c *Chain) SenderRatchetKey() *ecc.ECKeyPair {
	return c.senderRatchetKeyPair
}

// SetSenderRatchetKey will set the chain state with the given EC
// key pair.
func (c *Chain) SetSenderRatchetKey(key *ecc.ECKeyPair) {
	c.senderRatchetKeyPair = key
}

// ChainKey will return the chain key in the chain state.
func (c *Chain) ChainKey() *chain.Key {
	return c.chainKey
}

// SetChainKey will set the chain state's chain key. The key being replaced is
// destroyed rather than abandoned: callers ratchet forward from a copy —
// State.SenderChainKey and State.ReceiverChainKey both hand out copies — so
// the chain's own key is the last reference, and go-enclave reclaims nothing on
// its own. Without this, every message sent or accepted would cost the process
// a locked page it never gets back.
func (c *Chain) SetChainKey(key *chain.Key) {
	if c.chainKey != nil && c.chainKey != key {
		c.chainKey.Zeroize()
	}
	c.chainKey = key
}

// MessageKeys will return the message keys associated with the
// chain state.
func (c *Chain) MessageKeys() []*message.Keys {
	return c.messageKeys
}

// SetMessageKeys will set the chain state with the given message
// keys.
func (c *Chain) SetMessageKeys(keys []*message.Keys) {
	c.messageKeys = keys
}

// AddMessageKeys will append the chain state with the given
// message keys.
func (c *Chain) AddMessageKeys(keys *message.Keys) {
	c.messageKeys = append(c.messageKeys, keys)
}

// PopFirstMessageKeys will remove the first message key from
// the chain's list of message keys.
func (c *Chain) PopFirstMessageKeys() *message.Keys {
	removed := c.messageKeys[0]
	c.messageKeys = c.messageKeys[1:]

	return removed
}

// structure returns a serializeable structure of the chain state.
// The caller owns the returned structure and must Zeroize it once the
// serializer is done with it; on failure everything built so far is released
// before returning.
func (c *Chain) structure() (_ *ChainStructure, err error) {
	structure := &ChainStructure{
		SenderRatchetKeyPublic: c.senderRatchetKeyPair.PublicKey().Serialize(),
		MessageKeys:            make([]*message.KeysStructure, len(c.messageKeys)),
	}

	// Release the partially built structure if any step below fails, so that no
	// key material outlives the failed call. Registered before the first clone
	// so that every guarded allocation made from here on is covered.
	defer func() {
		if err != nil {
			structure.Zeroize()
		}
	}()

	// Convert our message keys into a serializeable structure.
	for i := range c.messageKeys {
		if structure.MessageKeys[i], err = message.NewStructFromKeys(c.messageKeys[i]); err != nil {
			return nil, err
		}
	}

	if structure.ChainKey, err = chain.NewStructFromKey(c.chainKey); err != nil {
		return nil, err
	}

	// Move the sender ratchet private key into guarded memory.
	if structure.SenderRatchetKeyPrivate, err = ecc.GuardPrivateKey(c.senderRatchetKeyPair.PrivateKey()); err != nil {
		return nil, err
	}

	return structure, nil
}
