package protocol

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
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
func NewSenderKeyDistributionMessageFromBytes(serialized []byte,
	serializer SenderKeyDistributionMessageSerializer) (*SenderKeyDistributionMessage, error) {

	// Use the given serializer to decode the signal message.
	signalMessageStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return NewSenderKeyDistributionMessageFromStruct(signalMessageStructure, serializer)
}

// NewSenderKeyDistributionMessageFromStruct returns a Signal Ciphertext message from the
// given serializable structure.
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

	// Create the signal message object from the structure.
	message := &SenderKeyDistributionMessage{
		distributionID: structure.DistributionID,
		id:             structure.ID,
		iteration:      structure.Iteration,
		chainKey:       structure.ChainKey,
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
func NewSenderKeyDistributionMessage(distributionID [16]byte, id uint32, iteration uint32,
	chainKey []byte, signatureKey ecc.ECPublicKeyable,
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
	chainKey       []byte
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

// ChainKey will return the message's chain key in bytes.
func (p *SenderKeyDistributionMessage) ChainKey() []byte {
	return p.chainKey
}

// SignatureKey will return the message's signature public key
func (p *SenderKeyDistributionMessage) SignatureKey() ecc.ECPublicKeyable {
	return p.signatureKey
}

// Serialize will use the given serializer and return the message as
// bytes.
func (p *SenderKeyDistributionMessage) Serialize() ([]byte, error) {
	structure := &SenderKeyDistributionMessageStructure{
		DistributionID: p.distributionID,
		ID:             p.id,
		Iteration:      p.iteration,
		ChainKey:       p.chainKey,
		SigningKey:     p.signatureKey.Serialize(),
		Version:        p.version,
	}
	return p.serializer.Serialize(structure)
}

// Type will return the message's type.
func (p *SenderKeyDistributionMessage) Type() uint32 {
	return SENDERKEY_DISTRIBUTION_TYPE
}
