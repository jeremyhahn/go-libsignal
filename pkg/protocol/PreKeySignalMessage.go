package protocol

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// PreKeySignalMessageSerializer is an interface for serializing and deserializing
// PreKeySignalMessages into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type PreKeySignalMessageSerializer interface {
	Serialize(signalMessage *PreKeySignalMessageStructure) ([]byte, error)
	Deserialize(serialized []byte) (*PreKeySignalMessageStructure, error)
}

// NewPreKeySignalMessageFromBytes will return a Signal Ciphertext message from the given
// bytes using the given serializer. This is the deserialization path for incoming messages
// and applies strict version and PQXDH validation matching Rust's PreKeySignalMessage::try_from.
func NewPreKeySignalMessageFromBytes(serialized []byte, serializer PreKeySignalMessageSerializer,
	msgSerializer SignalMessageSerializer) (*PreKeySignalMessage, error) {
	// Use the given serializer to decode the signal message.
	signalMessageStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	// For version 4+ (PQXDH), Kyber pre-key payload MUST be present on incoming messages.
	// This matches Rust's PreKeySignalMessage::try_from which requires kyber_payload
	// for versions above CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION.
	// This check is NOT in the constructor path (NewPreKeySignalMessageWithKyber) because
	// Rust's PreKeySignalMessage::new() does not enforce this — it is only validated on
	// deserialization of received messages.
	if signalMessageStructure.Version > PreKyberVersion {
		if signalMessageStructure.KyberPreKeyID == nil || signalMessageStructure.KyberCiphertext == nil {
			return nil, newMissingKyberPayloadError(signalMessageStructure.Version)
		}
	}

	return NewPreKeySignalMessageFromStruct(signalMessageStructure, serializer, msgSerializer)
}

// NewPreKeySignalMessageFromStruct will return a new PreKeySignalMessage from the given
// PreKeySignalMessageStructure.
func NewPreKeySignalMessageFromStruct(structure *PreKeySignalMessageStructure,
	serializer PreKeySignalMessageSerializer, msgSerializer SignalMessageSerializer) (*PreKeySignalMessage, error) {

	// Reject messages with version below the minimum supported (PreKyberVersion = 3).
	// This matches Rust's PreKeySignalMessage::try_from which rejects versions below
	// CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION.
	if structure.Version < PreKyberVersion {
		return nil, newLegacyVersionError("PreKeySignalMessage", structure.Version)
	}

	// Reject messages with version above the current version.
	if structure.Version > CurrentVersion {
		return nil, newUnrecognizedVersionError("PreKeySignalMessage", structure.Version)
	}

	// Reject messages missing critical fields.
	if structure.BaseKey == nil || structure.IdentityKey == nil || structure.Message == nil {
		return nil, newIncompleteMessageError("PreKeySignalMessage", "missing base key, identity key, or message")
	}

	// Reject asymmetric Kyber payload: both KyberPreKeyID and KyberCiphertext must
	// be present together or both absent. Having one without the other is malformed.
	hasKyberID := structure.KyberPreKeyID != nil && !structure.KyberPreKeyID.IsEmpty
	hasKyberCT := len(structure.KyberCiphertext) > 0
	if hasKyberID != hasKyberCT {
		return nil, newIncompleteMessageError("PreKeySignalMessage", "asymmetric Kyber payload: pre-key ID and ciphertext must both be present or both absent")
	}

	// Create the signal message object from the structure.
	preKeyWhisperMessage := &PreKeySignalMessage{structure: *structure, serializer: serializer}

	// Generate the base ECC key from bytes.
	var err error
	preKeyWhisperMessage.baseKey, err = ecc.DecodePoint(structure.BaseKey, 0)
	if err != nil {
		return nil, err
	}

	// Generate the identity key from bytes
	var identityKey ecc.ECPublicKeyable
	identityKey, err = ecc.DecodePoint(structure.IdentityKey, 0)
	if err != nil {
		return nil, err
	}
	preKeyWhisperMessage.identityKey = identity.NewKey(identityKey)

	// Generate the SignalMessage object from bytes.
	preKeyWhisperMessage.message, err = NewSignalMessageFromBytes(structure.Message, msgSerializer)
	if err != nil {
		return nil, err
	}

	return preKeyWhisperMessage, nil
}

// NewPreKeySignalMessage will return a new PreKeySignalMessage object.
func NewPreKeySignalMessage(version int, registrationID uint32, preKeyID *optional.Uint32, signedPreKeyID uint32,
	baseKey ecc.ECPublicKeyable, identityKey *identity.Key, message *SignalMessage, serializer PreKeySignalMessageSerializer,
	msgSerializer SignalMessageSerializer) (*PreKeySignalMessage, error) {

	return NewPreKeySignalMessageWithKyber(version, registrationID, preKeyID, signedPreKeyID,
		baseKey, identityKey, message, serializer, msgSerializer, nil, nil)
}

// NewPreKeySignalMessageWithKyber will return a new PreKeySignalMessage object with optional
// PQXDH Kyber pre-key ID and ciphertext fields.
func NewPreKeySignalMessageWithKyber(version int, registrationID uint32, preKeyID *optional.Uint32, signedPreKeyID uint32,
	baseKey ecc.ECPublicKeyable, identityKey *identity.Key, message *SignalMessage, serializer PreKeySignalMessageSerializer,
	msgSerializer SignalMessageSerializer, kyberPreKeyID *optional.Uint32, kyberCiphertext []byte) (*PreKeySignalMessage, error) {

	messageBytes, err := message.Serialize()
	if err != nil {
		return nil, err
	}

	structure := &PreKeySignalMessageStructure{
		Version:         version,
		RegistrationID:  registrationID,
		PreKeyID:        preKeyID,
		SignedPreKeyID:  signedPreKeyID,
		BaseKey:         baseKey.Serialize(),
		IdentityKey:     identityKey.PublicKey().Serialize(),
		Message:         messageBytes,
		KyberPreKeyID:   kyberPreKeyID,
		KyberCiphertext: kyberCiphertext,
	}
	return NewPreKeySignalMessageFromStruct(structure, serializer, msgSerializer)
}

// PreKeySignalMessageStructure is a serializable structure for
// PreKeySignalMessages.
type PreKeySignalMessageStructure struct {
	RegistrationID  uint32
	PreKeyID        *optional.Uint32
	SignedPreKeyID  uint32
	BaseKey         []byte
	IdentityKey     []byte
	Message         []byte
	Version         int
	KyberPreKeyID   *optional.Uint32 // Field 7 in protobuf
	KyberCiphertext []byte           // Field 8 in protobuf
}

// PreKeySignalMessage is an encrypted Signal message that is designed
// to be used when building a session with someone for the first time.
type PreKeySignalMessage struct {
	structure   PreKeySignalMessageStructure
	baseKey     ecc.ECPublicKeyable
	identityKey *identity.Key
	message     *SignalMessage
	serializer  PreKeySignalMessageSerializer
}

func (p *PreKeySignalMessage) MessageVersion() int {
	return p.structure.Version
}

func (p *PreKeySignalMessage) IdentityKey() *identity.Key {
	return p.identityKey
}

func (p *PreKeySignalMessage) RegistrationID() uint32 {
	return p.structure.RegistrationID
}

func (p *PreKeySignalMessage) PreKeyID() *optional.Uint32 {
	return p.structure.PreKeyID
}

func (p *PreKeySignalMessage) SignedPreKeyID() uint32 {
	return p.structure.SignedPreKeyID
}

func (p *PreKeySignalMessage) BaseKey() ecc.ECPublicKeyable {
	return p.baseKey
}

func (p *PreKeySignalMessage) WhisperMessage() *SignalMessage {
	return p.message
}

func (p *PreKeySignalMessage) KyberPreKeyID() *optional.Uint32 {
	return p.structure.KyberPreKeyID
}

func (p *PreKeySignalMessage) KyberCiphertext() []byte {
	return p.structure.KyberCiphertext
}

func (p *PreKeySignalMessage) Serialize() ([]byte, error) {
	return p.serializer.Serialize(&p.structure)
}

func (p *PreKeySignalMessage) Type() uint32 {
	return PREKEY_TYPE
}
