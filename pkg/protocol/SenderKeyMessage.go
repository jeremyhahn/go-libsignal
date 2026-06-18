package protocol

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
)

// SenderKeyMessageSerializer is an interface for serializing and deserializing
// SenderKeyMessages into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type SenderKeyMessageSerializer interface {
	Serialize(signalMessage *SenderKeyMessageStructure) ([]byte, error)
	Deserialize(serialized []byte) (*SenderKeyMessageStructure, error)
}

// NewSenderKeyMessageFromBytes will return a Signal Ciphertext message from the given
// bytes using the given serializer.
func NewSenderKeyMessageFromBytes(serialized []byte,
	serializer SenderKeyMessageSerializer) (*SenderKeyMessage, error) {

	// Use the given serializer to decode the signal message.
	senderKeyMessageStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return NewSenderKeyMessageFromStruct(senderKeyMessageStructure, serializer)
}

// NewSenderKeyMessageFromStruct returns a Signal Ciphertext message from the
// given serializable structure.
func NewSenderKeyMessageFromStruct(structure *SenderKeyMessageStructure,
	serializer SenderKeyMessageSerializer) (*SenderKeyMessage, error) {

	// Throw an error if the given message structure is an unsupported version.
	if structure.Version < SenderKeyCurrentVersion {
		return nil, newLegacyVersionError("SenderKeyMessage", int(structure.Version))
	}

	// Throw an error if the given message structure is a future version.
	if structure.Version > SenderKeyCurrentVersion {
		return nil, newUnrecognizedVersionError("SenderKeyMessage", int(structure.Version))
	}

	// Throw an error if the structure is missing critical fields.
	if structure.CipherText == nil {
		return nil, newIncompleteMessageError("SenderKeyMessage", "missing ciphertext")
	}

	// Create the signal message object from the structure.
	whisperMessage := &SenderKeyMessage{
		distributionID: structure.DistributionID,
		keyID:          structure.ID,
		version:        structure.Version,
		iteration:      structure.Iteration,
		ciphertext:     structure.CipherText,
		signature:      structure.Signature,
		serializer:     serializer,
	}

	return whisperMessage, nil
}

// NewSenderKeyMessage returns a SenderKeyMessage using SenderKeyCurrentVersion.
func NewSenderKeyMessage(distributionID [16]byte, keyID uint32, iteration uint32, ciphertext []byte,
	signatureKey ecc.ECPrivateKeyable, serializer SenderKeyMessageSerializer) (*SenderKeyMessage, error) {

	return NewSenderKeyMessageWithVersion(SenderKeyCurrentVersion, distributionID, keyID, iteration, ciphertext, signatureKey, serializer)
}

// NewSenderKeyMessageWithVersion returns a SenderKeyMessage with the specified version.
// This matches the Rust reference which reads message_version from the SenderKeyState.
func NewSenderKeyMessageWithVersion(version uint32, distributionID [16]byte, keyID uint32, iteration uint32, ciphertext []byte,
	signatureKey ecc.ECPrivateKeyable, serializer SenderKeyMessageSerializer) (*SenderKeyMessage, error) {

	// Ensure we have a valid signature key
	if signatureKey == nil {
		return nil, newIncompleteMessageError("SenderKeyMessage", "signature key is nil")
	}

	// Build our SenderKeyMessage. The struct's version field stores the
	// supplied version parameter so the wire byte high nibble encodes it
	// correctly: ((version & 0xF) << 4) | SenderKeyCurrentVersion.
	// This matches the Rust reference SenderKeyMessage::new which encodes
	// message_version in the high nibble of the wire byte while storing
	// SENDERKEY_MESSAGE_CURRENT_VERSION in the struct's message_version field
	// (rust/protocol/src/protocol.rs:551,558). Both are currently 3, making
	// the distinction latent; storing the parameter keeps the API honest for
	// future version bumps.
	senderKeyMessage := &SenderKeyMessage{
		distributionID: distributionID,
		keyID:          keyID,
		iteration:      iteration,
		ciphertext:     ciphertext,
		version:        version,
		serializer:     serializer,
	}

	// Sign the serialized message and include it in the message. This will be included
	// in the signed serialized version of the message.
	serialized, err := senderKeyMessage.Serialize()
	if err != nil {
		return nil, err
	}
	signature, err := ecc.CalculateSignature(signatureKey, serialized)
	if err != nil {
		return nil, err
	}
	senderKeyMessage.signature = bytehelper.ArrayToSlice64(signature)

	return senderKeyMessage, nil
}

// SenderKeyMessageStructure is a serializeable structure for SenderKey messages.
type SenderKeyMessageStructure struct {
	DistributionID [16]byte
	ID             uint32
	Iteration      uint32
	CipherText     []byte
	Version        uint32
	Signature      []byte
}

// SenderKeyMessage is a structure for messages using senderkey groups.
type SenderKeyMessage struct {
	distributionID [16]byte
	version        uint32
	keyID          uint32
	iteration      uint32
	ciphertext     []byte
	signature      []byte
	serializer     SenderKeyMessageSerializer
}

// DistributionID returns the SenderKeyMessage distribution UUID.
func (p *SenderKeyMessage) DistributionID() [16]byte {
	return p.distributionID
}

// KeyID returns the SenderKeyMessage key ID.
func (p *SenderKeyMessage) KeyID() uint32 {
	return p.keyID
}

// Iteration returns the SenderKeyMessage iteration.
func (p *SenderKeyMessage) Iteration() uint32 {
	return p.iteration
}

// Ciphertext returns the SenderKeyMessage encrypted ciphertext.
func (p *SenderKeyMessage) Ciphertext() []byte {
	return p.ciphertext
}

// Version returns the Signal message version of the message.
func (p *SenderKeyMessage) Version() uint32 {
	return p.version
}

// Serialize will use the given serializer to return the message as bytes
// excluding the signature. This should be used for signing and verifying
// message signatures.
func (p *SenderKeyMessage) Serialize() ([]byte, error) {
	structure := &SenderKeyMessageStructure{
		DistributionID: p.distributionID,
		ID:             p.keyID,
		Iteration:      p.iteration,
		CipherText:     p.ciphertext,
		Version:        p.version,
	}

	return p.serializer.Serialize(structure)
}

// SignedSerialize will use the given serializer to return the message as
// bytes with the message signature included. This should be used when
// sending the message over the network.
func (p *SenderKeyMessage) SignedSerialize() ([]byte, error) {
	structure := &SenderKeyMessageStructure{
		DistributionID: p.distributionID,
		ID:             p.keyID,
		Iteration:      p.iteration,
		CipherText:     p.ciphertext,
		Version:        p.version,
		Signature:      p.signature,
	}

	return p.serializer.Serialize(structure)
}

// Signature returns the SenderKeyMessage signature
func (p *SenderKeyMessage) Signature() [64]byte {
	return bytehelper.SliceToArray64(p.signature)
}

// Type returns the sender key type.
func (p *SenderKeyMessage) Type() uint32 {
	return SENDERKEY_TYPE
}
