package protocol

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// SenderKeyDistributionMessageSerializer is an interface for serializing and deserializing
// SenderKeyDistributionMessages into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type SenderKeyDistributionMessageSerializer interface {
	Serialize(signalMessage *SenderKeyDistributionMessageStructure) ([]byte, error)
	Deserialize(serialized []byte) (*SenderKeyDistributionMessageStructure, error)
}

// NewSenderKeyDistributionMessageFromBytes will return a Signal Ciphertext message from the given
// bytes using the given serializer.
//
// The message guards the chain key in locked memory, which the garbage
// collector never frees. The caller must call Release on a returned message
// once it is no longer needed. The decoder's own chain key buffer is wiped
// before this function returns.
func NewSenderKeyDistributionMessageFromBytes(serialized []byte,
	serializer SenderKeyDistributionMessageSerializer) (*SenderKeyDistributionMessage, error) {

	// Use the given serializer to decode the signal message.
	signalMessageStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}
	// The decoded structure and its chain key buffer belong to this call.
	// The message keeps only a guarded copy, so wipe the decoder's buffer on
	// every return path, including validation errors.
	if signalMessageStructure != nil {
		defer crypto.Zeroize(signalMessageStructure.ChainKey)
	}

	return NewSenderKeyDistributionMessageFromStruct(signalMessageStructure, serializer)
}

// NewSenderKeyDistributionMessageFromStruct returns a Signal Ciphertext message from the
// given serializable structure.
//
// The message guards its own copy of the chain key in locked memory, which
// the garbage collector never frees; the structure stays the caller's. The
// caller must call Release on a returned message once it is no longer needed.
func NewSenderKeyDistributionMessageFromStruct(structure *SenderKeyDistributionMessageStructure,
	serializer SenderKeyDistributionMessageSerializer) (*SenderKeyDistributionMessage, error) {

	// Throw an error if the given message structure is an unsupported version.
	if structure.Version < SenderKeyCurrentVersion {
		return nil, newLegacyVersionError("SenderKeyDistributionMessage", int(structure.Version))
	}

	// Throw an error if the given message structure is a future version.
	if structure.Version > SenderKeyCurrentVersion {
		return nil, newUnrecognizedVersionError("SenderKeyDistributionMessage", int(structure.Version))
	}

	// Throw an error if the structure is missing critical fields.
	if structure.SigningKey == nil || structure.ChainKey == nil {
		return nil, newIncompleteMessageError("SenderKeyDistributionMessage", "missing signing key or chain key")
	}

	// Validate key lengths per Rust reference (protocol.rs:724):
	// chain_key must be exactly 32 bytes, signing_key must be exactly 33 bytes
	// (0x05 type prefix + 32 key bytes).
	if len(structure.ChainKey) != 32 {
		return nil, newInvalidKeyLengthError("SenderKeyDistributionMessage.ChainKey",
			fmt.Sprintf("expected 32 bytes, got %d", len(structure.ChainKey)))
	}
	if len(structure.SigningKey) != 33 {
		return nil, newInvalidKeyLengthError("SenderKeyDistributionMessage.SigningKey",
			fmt.Sprintf("expected 33 bytes, got %d", len(structure.SigningKey)))
	}

	// Get the signing key object from bytes.
	signingKey, err := ecc.DecodePoint(structure.SigningKey, 0)
	if err != nil {
		return nil, err
	}

	// Guard a copy of the chain key; the structure stays the caller's.
	chainKey, err := guardChainKey(structure.ChainKey)
	if err != nil {
		return nil, err
	}

	// Create the signal message object from the structure.
	message := &SenderKeyDistributionMessage{
		distributionID: structure.DistributionID,
		id:             structure.ID,
		iteration:      structure.Iteration,
		chainKey:       chainKey,
		version:        structure.Version,
		signatureKey:   signingKey,
		serializer:     serializer,
	}

	// Generate the ECC key from bytes.
	message.signatureKey, err = ecc.DecodePoint(structure.SigningKey, 0)
	if err != nil {
		return nil, err
	}

	return message, nil
}

// NewSenderKeyDistributionMessage returns a Signal Ciphertext message.
// The messageVersion parameter specifies the protocol version to use for this
// distribution message, allowing it to match the version received from the
// sender rather than always using the current version constant.
//
// The message guards its own copy of chainKey in locked memory; the caller
// keeps (and wipes) chainKey. The garbage collector never frees the locked
// memory, so the caller must call Release once the message is no longer
// needed. It panics if the locked allocation fails.
func NewSenderKeyDistributionMessage(distributionID [16]byte, id uint32, iteration uint32,
	chainKey []byte, signatureKey ecc.ECPublicKeyable,
	serializer SenderKeyDistributionMessageSerializer,
	messageVersion uint32) *SenderKeyDistributionMessage {

	guarded, err := guardChainKey(chainKey)
	if err != nil {
		panic(fmt.Errorf("protocol: guard sender key distribution chain key: %w", err))
	}
	return NewSenderKeyDistributionMessageFromSecret(distributionID, id, iteration,
		guarded, signatureKey, serializer, messageVersion)
}

// NewSenderKeyDistributionMessageFromSecret returns a distribution message
// that takes ownership of chainKey, which stays in locked memory. The garbage
// collector never frees that memory, so the caller must call Release, which
// destroys chainKey, once the message is no longer needed.
func NewSenderKeyDistributionMessageFromSecret(distributionID [16]byte, id uint32, iteration uint32,
	chainKey *secret.Secret, signatureKey ecc.ECPublicKeyable,
	serializer SenderKeyDistributionMessageSerializer,
	messageVersion uint32) *SenderKeyDistributionMessage {

	return &SenderKeyDistributionMessage{
		distributionID: distributionID,
		id:             id,
		iteration:      iteration,
		chainKey:       chainKey,
		version:        messageVersion,
		signatureKey:   signatureKey,
		serializer:     serializer,
	}
}

// guardChainKey moves a copy of b into locked memory; secret.New wipes the
// copy. A nil b yields a nil Secret.
func guardChainKey(b []byte) (*secret.Secret, error) {
	if b == nil {
		return nil, nil
	}
	return secret.New(append(make([]byte, 0, len(b)), b...))
}

// Version returns the protocol version of this distribution message.
func (p *SenderKeyDistributionMessage) Version() uint32 {
	return p.version
}

// SenderKeyDistributionMessageStructure is a serializeable structure for senderkey
// distribution messages.
type SenderKeyDistributionMessageStructure struct {
	DistributionID [16]byte
	ID             uint32
	Iteration      uint32
	ChainKey       []byte
	SigningKey     []byte
	Version        uint32
}

// SenderKeyDistributionMessage is a structure for senderkey distribution messages.
type SenderKeyDistributionMessage struct {
	distributionID [16]byte
	id             uint32
	iteration      uint32
	chainKey       *secret.Secret
	version        uint32
	signatureKey   ecc.ECPublicKeyable
	serializer     SenderKeyDistributionMessageSerializer
}

// DistributionID returns the message's distribution UUID.
func (p *SenderKeyDistributionMessage) DistributionID() [16]byte {
	return p.distributionID
}

// ID will return the message's id.
func (p *SenderKeyDistributionMessage) ID() uint32 {
	return p.id
}

// Iteration will return the message's iteration.
func (p *SenderKeyDistributionMessage) Iteration() uint32 {
	return p.iteration
}

// ChainKey returns a fresh heap copy of the message's chain key, which the
// caller owns and wipes, or nil once the message is released.
func (p *SenderKeyDistributionMessage) ChainKey() []byte {
	var out []byte
	if err := p.chainKey.WithBytes(func(b []byte) error {
		if b != nil {
			out = append([]byte(nil), b...)
		}
		return nil
	}); err != nil {
		return nil
	}
	return out
}

// Release destroys the guarded chain key. It is idempotent; after it,
// ChainKey returns nil and Serialize fails.
func (p *SenderKeyDistributionMessage) Release() {
	if p == nil {
		return
	}
	p.chainKey.Destroy()
}

// SignatureKey will return the message's signature public key
func (p *SenderKeyDistributionMessage) SignatureKey() ecc.ECPublicKeyable {
	return p.signatureKey
}

// Serialize will use the given serializer and return the message as
// bytes.
func (p *SenderKeyDistributionMessage) Serialize() ([]byte, error) {
	// The chain key is serialized from inside the borrow, so no heap copy
	// of it is made; the serializer encodes it into the returned bytes.
	var out []byte
	err := p.chainKey.WithBytes(func(chainKey []byte) error {
		structure := &SenderKeyDistributionMessageStructure{
			DistributionID: p.distributionID,
			ID:             p.id,
			Iteration:      p.iteration,
			ChainKey:       chainKey,
			SigningKey:     p.signatureKey.Serialize(),
			Version:        p.version,
		}
		var serr error
		out, serr = p.serializer.Serialize(structure)
		return serr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Type will return the message's type.
func (p *SenderKeyDistributionMessage) Type() uint32 {
	return SENDERKEY_DISTRIBUTION_TYPE
}
