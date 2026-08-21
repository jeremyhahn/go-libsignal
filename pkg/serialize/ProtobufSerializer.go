package serialize

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/storagepb"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/wirepb"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
	"google.golang.org/protobuf/proto"
)

// NewProtobufSerializer will return a serializer for all Signal objects that will
// be responsible for converting objects to and from protobuf bytes.
func NewProtobufSerializer() *Serializer {
	serializer := NewSerializer()

	serializer.SignalMessage = &ProtobufSignalMessageSerializer{}
	serializer.PreKeySignalMessage = &ProtobufPreKeySignalMessageSerializer{}
	serializer.SignedPreKeyRecord = &ProtobufSignedPreKeyRecordSerializer{}
	serializer.PreKeyRecord = &ProtobufPreKeyRecordSerializer{}
	serializer.State = &ProtobufStateSerializer{}
	serializer.Session = &ProtobufSessionSerializer{}
	serializer.SenderKeyMessage = &ProtobufSenderKeyMessageSerializer{}
	serializer.SenderKeyDistributionMessage = &ProtobufSenderKeyDistributionMessageSerializer{}
	serializer.SenderKeyRecord = &ProtobufSenderKeyRecordSerializer{}
	serializer.SenderKeyState = &ProtobufSenderKeyStateSerializer{}

	return serializer
}

// =============================================================================
// SignalMessage
// =============================================================================

// ProtobufSignalMessageSerializer is a structure for serializing signal messages
// into and from protobuf.
type ProtobufSignalMessageSerializer struct{}

// Serialize will take a signal message structure and convert it to protobuf bytes.
// The Signal wire format is: version_byte || protobuf_body || mac
// where version_byte = (version << 4 | version).
func (s *ProtobufSignalMessageSerializer) Serialize(signalMessage *protocol.SignalMessageStructure) ([]byte, error) {
	counter := signalMessage.Counter
	previousCounter := signalMessage.PreviousCounter
	pb := &wirepb.SignalMessage{
		RatchetKey:      signalMessage.RatchetKey,
		Counter:         &counter,
		PreviousCounter: &previousCounter,
		Ciphertext:      signalMessage.CipherText,
	}
	// Only set pq_ratchet if non-empty, matching Rust behavior.
	if len(signalMessage.PqRatchetKey) > 0 {
		pb.PqRatchet = signalMessage.PqRatchetKey
	}
	// Only set addresses if non-nil (proto field 6).
	if len(signalMessage.Addresses) > 0 {
		pb.Addresses = signalMessage.Addresses
	}
	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf SignalMessage")

	// Build wire format: version_byte || protobuf_body || mac
	// Version byte: (messageVersion << 4) | CurrentVersion, matching Rust encoding.
	messageVersion := byte(signalMessage.Version)
	result := make([]byte, 0, 1+len(serialized)+len(signalMessage.Mac))
	result = append(result, ((messageVersion&0x0F)<<4)|(protocol.CurrentVersion&0x0F))
	result = append(result, serialized...)
	result = append(result, signalMessage.Mac...)

	return result, nil
}

// Deserialize will take in protobuf bytes and return a signal message structure.
// The Signal wire format is: version_byte || protobuf_body || mac
// where version_byte = (version << 4 | version) and mac is the last 8 bytes.
func (s *ProtobufSignalMessageSerializer) Deserialize(serialized []byte) (*protocol.SignalMessageStructure, error) {
	if len(serialized) < 1 {
		return nil, &MessageDeserializeError{MessageType: "signal message", Detail: fmt.Sprintf("too short: %d bytes", len(serialized))}
	}

	// Extract version from header byte.
	version := int(serialized[0] >> 4)

	// The MAC is the last 8 bytes (macLength from protocol package).
	const macLen = 8
	body := serialized[1:]
	if len(body) <= macLen {
		return nil, &MessageDeserializeError{MessageType: "signal message", Detail: "too short: missing MAC"}
	}
	mac := body[len(body)-macLen:]
	body = body[:len(body)-macLen]

	pb := &wirepb.SignalMessage{}
	err := proto.Unmarshal(body, pb)
	if err != nil {
		logger.Error("Error deserializing signal message: ", err)
		return nil, err
	}

	// Rust: rust/protocol/src/protocol.rs:299-301 returns InvalidProtobufEncoding
	// when counter is absent. Enforce the same check so deserialization of a
	// SignalMessage missing its counter field fails fast.
	if pb.Counter == nil {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "signal message", Field: "counter"}
	}

	return &protocol.SignalMessageStructure{
		Version:         version,
		RatchetKey:      pb.GetRatchetKey(),
		Counter:         pb.GetCounter(),
		PreviousCounter: pb.GetPreviousCounter(),
		CipherText:      pb.GetCiphertext(),
		PqRatchetKey:    pb.GetPqRatchet(),
		Addresses:       pb.GetAddresses(),
		Mac:             mac,
	}, nil
}

// =============================================================================
// PreKeySignalMessage
// =============================================================================

// ProtobufPreKeySignalMessageSerializer is a structure for serializing prekey
// signal messages into and from protobuf.
type ProtobufPreKeySignalMessageSerializer struct{}

// Serialize will take a prekey signal message structure and convert it to protobuf bytes.
// The version is encoded as a header byte using the Signal wire format:
// (version << 4 | version), followed by the protobuf-encoded body.
func (s *ProtobufPreKeySignalMessageSerializer) Serialize(signalMessage *protocol.PreKeySignalMessageStructure) ([]byte, error) {
	registrationID := signalMessage.RegistrationID
	signedPreKeyID := signalMessage.SignedPreKeyID
	pb := &wirepb.PreKeySignalMessage{
		RegistrationId: &registrationID,
		SignedPreKeyId: &signedPreKeyID,
		BaseKey:        signalMessage.BaseKey,
		IdentityKey:    signalMessage.IdentityKey,
		Message:        signalMessage.Message,
	}
	if signalMessage.PreKeyID != nil && !signalMessage.PreKeyID.IsEmpty {
		preKeyID := signalMessage.PreKeyID.Value
		pb.PreKeyId = &preKeyID
	}
	// Serialize Kyber fields if present.
	if signalMessage.KyberPreKeyID != nil && !signalMessage.KyberPreKeyID.IsEmpty {
		kyberPreKeyID := signalMessage.KyberPreKeyID.Value
		pb.KyberPreKeyId = &kyberPreKeyID
	}
	if len(signalMessage.KyberCiphertext) > 0 {
		pb.KyberCiphertext = signalMessage.KyberCiphertext
	}
	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf PreKeySignalMessage")

	// Prepend the version header byte: (messageVersion << 4) | CurrentVersion,
	// matching Rust encoding.
	messageVersion := byte(signalMessage.Version)
	result := make([]byte, 1+len(serialized))
	result[0] = ((messageVersion & 0x0F) << 4) | (protocol.CurrentVersion & 0x0F)
	copy(result[1:], serialized)

	return result, nil
}

// Deserialize will take in protobuf bytes and return a prekey signal message structure.
// The first byte is the version header encoded as (version << 4 | version),
// followed by the protobuf-encoded body.
func (s *ProtobufPreKeySignalMessageSerializer) Deserialize(serialized []byte) (*protocol.PreKeySignalMessageStructure, error) {
	if len(serialized) < 1 {
		return nil, &MessageDeserializeError{MessageType: "prekey signal message", Detail: fmt.Sprintf("too short: %d bytes", len(serialized))}
	}

	// Extract version from header byte.
	version := int(serialized[0] >> 4)

	pb := &wirepb.PreKeySignalMessage{}
	err := proto.Unmarshal(serialized[1:], pb)
	if err != nil {
		logger.Error("Error deserializing prekey signal message: ", err)
		return nil, err
	}

	var preKeyID *optional.Uint32
	if pb.PreKeyId != nil {
		preKeyID = optional.NewOptionalUint32(pb.GetPreKeyId())
	} else {
		preKeyID = optional.NewEmptyUint32()
	}

	// Deserialize Kyber fields if present.
	var kyberPreKeyID *optional.Uint32
	if pb.KyberPreKeyId != nil {
		kyberPreKeyID = optional.NewOptionalUint32(pb.GetKyberPreKeyId())
	}

	var kyberCiphertext []byte
	if len(pb.GetKyberCiphertext()) > 0 {
		kyberCiphertext = pb.GetKyberCiphertext()
	}

	// Rust: rust/protocol/src/protocol.rs:481-483 returns InvalidProtobufEncoding
	// when signed_pre_key_id is absent. Enforce the same check so deserialization
	// of a PreKeySignalMessage missing its signed_pre_key_id fails fast.
	if pb.SignedPreKeyId == nil {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "prekey signal message", Field: "signed_pre_key_id"}
	}

	return &protocol.PreKeySignalMessageStructure{
		Version:         version,
		RegistrationID:  pb.GetRegistrationId(),
		PreKeyID:        preKeyID,
		SignedPreKeyID:  pb.GetSignedPreKeyId(),
		BaseKey:         pb.GetBaseKey(),
		IdentityKey:     pb.GetIdentityKey(),
		Message:         pb.GetMessage(),
		KyberPreKeyID:   kyberPreKeyID,
		KyberCiphertext: kyberCiphertext,
	}, nil
}

// =============================================================================
// SenderKeyMessage
// =============================================================================

// ProtobufSenderKeyMessageSerializer is a structure for serializing senderkey
// messages to and from protobuf.
type ProtobufSenderKeyMessageSerializer struct{}

// Serialize will take a senderkey message and convert it to protobuf bytes.
// The version is encoded as a header byte using the Signal wire format:
// (version << 4 | version), followed by the protobuf-encoded body.
func (s *ProtobufSenderKeyMessageSerializer) Serialize(msg *protocol.SenderKeyMessageStructure) ([]byte, error) {
	chainID := msg.ID
	iteration := msg.Iteration
	pb := &wirepb.SenderKeyMessage{
		DistributionUuid: msg.DistributionID[:],
		ChainId:          &chainID,
		Iteration:        &iteration,
		Ciphertext:       msg.CipherText,
	}
	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf SenderKeyMessage")

	// Prepend the version header byte: (messageVersion << 4) | SenderKeyCurrentVersion,
	// matching Rust encoding. Append the 64-byte signature if present.
	messageVersion := byte(msg.Version)
	result := make([]byte, 0, 1+len(serialized)+len(msg.Signature))
	result = append(result, ((messageVersion&0x0F)<<4)|(protocol.SenderKeyCurrentVersion&0x0F))
	result = append(result, serialized...)
	if len(msg.Signature) > 0 {
		result = append(result, msg.Signature...)
	}

	return result, nil
}

// Deserialize will take in protobuf bytes and return a senderkey message structure.
// The first byte is the version header encoded as (version << 4 | version),
// followed by the protobuf-encoded body.
func (s *ProtobufSenderKeyMessageSerializer) Deserialize(serialized []byte) (*protocol.SenderKeyMessageStructure, error) {
	// Minimum length: 1 (version byte) + 64 (signature).
	if len(serialized) < 1+protocol.SenderKeySignatureLength {
		return nil, &MessageDeserializeError{MessageType: "senderkey message", Detail: fmt.Sprintf("too short: %d bytes", len(serialized))}
	}

	// Extract version from header byte.
	version := uint32(serialized[0] >> 4)

	// The signature is the last 64 bytes of the serialized message.
	// Strip it before protobuf unmarshal, matching Rust's try_from behavior.
	signature := serialized[len(serialized)-protocol.SenderKeySignatureLength:]
	protoBytes := serialized[1 : len(serialized)-protocol.SenderKeySignatureLength]

	pb := &wirepb.SenderKeyMessage{}
	err := proto.Unmarshal(protoBytes, pb)
	if err != nil {
		logger.Error("Error deserializing senderkey message: ", err)
		return nil, err
	}

	// Enforce required fields. Proto3 optional fields use pointer accessors;
	// nil pointer means the field was absent in the serialized bytes.
	// Mirrors Rust InvalidProtobufEncoding (rust/protocol/src/protocol.rs:614-657).
	if pb.ChainId == nil {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "senderkey message", Field: "chain_id"}
	}
	if pb.Iteration == nil {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "senderkey message", Field: "iteration"}
	}
	distUUID := pb.GetDistributionUuid()
	if len(distUUID) != 16 {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "senderkey message", Field: "distribution_uuid"}
	}

	var distributionID [16]byte
	copy(distributionID[:], distUUID)

	return &protocol.SenderKeyMessageStructure{
		DistributionID: distributionID,
		Version:        version,
		ID:             pb.GetChainId(),
		Iteration:      pb.GetIteration(),
		CipherText:     pb.GetCiphertext(),
		Signature:      signature,
	}, nil
}

// =============================================================================
// SenderKeyDistributionMessage
// =============================================================================

// ProtobufSenderKeyDistributionMessageSerializer is a structure for serializing
// senderkey distribution messages to and from protobuf.
type ProtobufSenderKeyDistributionMessageSerializer struct{}

// Serialize will take a senderkey distribution message and convert it to protobuf bytes.
// The version is encoded as a header byte using the Signal wire format:
// (version << 4 | version), followed by the protobuf-encoded body.
func (s *ProtobufSenderKeyDistributionMessageSerializer) Serialize(msg *protocol.SenderKeyDistributionMessageStructure) ([]byte, error) {
	chainID := msg.ID
	iteration := msg.Iteration
	pb := &wirepb.SenderKeyDistributionMessage{
		DistributionUuid: msg.DistributionID[:],
		ChainId:          &chainID,
		Iteration:        &iteration,
		ChainKey:         msg.ChainKey,
		SigningKey:       msg.SigningKey,
	}
	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf SenderKeyDistributionMessage")

	// Prepend the version header byte: (messageVersion << 4) | SenderKeyCurrentVersion,
	// matching Rust encoding.
	messageVersion := byte(msg.Version)
	result := make([]byte, 1+len(serialized))
	result[0] = ((messageVersion & 0x0F) << 4) | (protocol.SenderKeyCurrentVersion & 0x0F)
	copy(result[1:], serialized)

	return result, nil
}

// Deserialize will take in protobuf bytes and return a senderkey distribution message structure.
// The first byte is the version header, followed by the protobuf-encoded body.
func (s *ProtobufSenderKeyDistributionMessageSerializer) Deserialize(serialized []byte) (*protocol.SenderKeyDistributionMessageStructure, error) {
	if len(serialized) < 1 {
		return nil, &MessageDeserializeError{MessageType: "senderkey distribution message", Detail: fmt.Sprintf("too short: %d bytes", len(serialized))}
	}

	// Extract version from header byte.
	version := uint32(serialized[0] >> 4)

	pb := &wirepb.SenderKeyDistributionMessage{}
	err := proto.Unmarshal(serialized[1:], pb)
	if err != nil {
		logger.Error("Error deserializing senderkey distribution message: ", err)
		return nil, err
	}

	// Enforce required fields. Proto3 optional fields use pointer accessors;
	// nil pointer means the field was absent in the serialized bytes.
	// Bytes fields (chain_key, signing_key, distribution_uuid) are nil when absent.
	// Mirrors Rust InvalidProtobufEncoding (rust/protocol/src/protocol.rs:748-800).
	if pb.ChainId == nil {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "senderkey distribution message", Field: "chain_id"}
	}
	if pb.Iteration == nil {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "senderkey distribution message", Field: "iteration"}
	}

	// Validate chain_key presence and length (must be 32 bytes).
	chainKey := pb.GetChainKey()
	if len(chainKey) != 32 {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "senderkey distribution message", Field: "chain_key"}
	}

	// Validate signing_key presence and length (must be 33 bytes: 0x05 prefix + 32 bytes).
	signingKey := pb.GetSigningKey()
	if len(signingKey) != 33 {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "senderkey distribution message", Field: "signing_key"}
	}

	distUUID := pb.GetDistributionUuid()
	if len(distUUID) != 16 {
		return nil, &ErrInvalidProtobufEncoding{MessageType: "senderkey distribution message", Field: "distribution_uuid"}
	}

	var distributionID [16]byte
	copy(distributionID[:], distUUID)

	return &protocol.SenderKeyDistributionMessageStructure{
		DistributionID: distributionID,
		Version:        version,
		ID:             pb.GetChainId(),
		Iteration:      pb.GetIteration(),
		ChainKey:       chainKey,
		SigningKey:     signingKey,
	}, nil
}

// =============================================================================
// State (SessionState)
// =============================================================================

// ProtobufStateSerializer is a structure for serializing session states into
// and from protobuf.
type ProtobufStateSerializer struct{}

// Serialize will take a session state structure and convert it to protobuf bytes.
func (s *ProtobufStateSerializer) Serialize(state *record.StateStructure) ([]byte, error) {
	pb := stateStructureToProto(state)
	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf SessionStructure (state)")
	return serialized, nil
}

// Deserialize will take in protobuf bytes and return a session state structure.
func (s *ProtobufStateSerializer) Deserialize(serialized []byte) (*record.StateStructure, error) {
	pb := &storagepb.SessionStructure{}
	err := proto.Unmarshal(serialized, pb)
	if err != nil {
		logger.Error("Error deserializing session state: ", err)
		return nil, err
	}

	return protoToStateStructure(pb)
}

// =============================================================================
// Session (SessionRecord)
// =============================================================================

// ProtobufSessionSerializer is a structure for serializing session records into
// and from protobuf.
type ProtobufSessionSerializer struct{}

// Serialize will take a session structure and convert it to protobuf bytes.
func (s *ProtobufSessionSerializer) Serialize(session *record.SessionStructure) ([]byte, error) {
	// Serialize each previous state independently so they can be stored
	// as opaque bytes in the RecordStructure.
	previousSessions := make([][]byte, len(session.PreviousStates))
	for i, prevState := range session.PreviousStates {
		prevPb := stateStructureToProto(prevState)
		prevBytes, err := proto.Marshal(prevPb)
		if err != nil {
			return nil, err
		}
		previousSessions[i] = prevBytes
	}

	pb := &storagepb.RecordStructure{
		CurrentSession:   stateStructureToProto(session.SessionState),
		PreviousSessions: previousSessions,
	}

	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf RecordStructure (session)")
	return serialized, nil
}

// Deserialize will take in protobuf bytes and return a session structure.
func (s *ProtobufSessionSerializer) Deserialize(serialized []byte) (_ *record.SessionStructure, err error) {
	pb := &storagepb.RecordStructure{}
	if err = proto.Unmarshal(serialized, pb); err != nil {
		logger.Error("Error deserializing session: ", err)
		return nil, err
	}

	// Bound the archived states before decoding anything.
	// Bound to archivedStatesMaxLength (40) to prevent unbounded allocation from malformed data.
	const archivedStatesMaxLength = 40
	if len(pb.GetPreviousSessions()) > archivedStatesMaxLength {
		return nil, &BoundsExceededError{
			MessageType: "session record",
			Field:       "previous_sessions",
			Max:         archivedStatesMaxLength,
			Actual:      len(pb.GetPreviousSessions()),
		}
	}

	structure := &record.SessionStructure{
		PreviousStates: make([]*record.StateStructure, len(pb.GetPreviousSessions())),
	}

	// Release every state decoded so far if a later one fails, so that
	// malformed input cannot strand mlock'd pages.
	defer func() {
		if err != nil {
			structure.Zeroize()
		}
	}()

	// Convert the current session.
	if pb.GetCurrentSession() != nil {
		if structure.SessionState, err = protoToStateStructure(pb.GetCurrentSession()); err != nil {
			return nil, err
		}
	}

	// Convert previous sessions from opaque bytes.
	for i, prevBytes := range pb.GetPreviousSessions() {
		prevPb := &storagepb.SessionStructure{}
		if err = proto.Unmarshal(prevBytes, prevPb); err != nil {
			logger.Error("Error deserializing previous session state: ", err)
			return nil, err
		}
		if structure.PreviousStates[i], err = protoToStateStructure(prevPb); err != nil {
			return nil, err
		}
	}

	return structure, nil
}

// =============================================================================
// PreKeyRecord
// =============================================================================

// ProtobufPreKeyRecordSerializer is a structure for serializing prekey records
// into and from protobuf.
type ProtobufPreKeyRecordSerializer struct{}

// Serialize will take a prekey record structure and convert it to protobuf bytes.
func (s *ProtobufPreKeyRecordSerializer) Serialize(preKey *record.PreKeyStructure) ([]byte, error) {
	pb := &storagepb.PreKeyRecordStructure{
		Id:         preKey.ID,
		PublicKey:  preKey.PublicKey,
		PrivateKey: preKey.PrivateKey.BytesOrNil(),
	}
	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf PreKeyRecordStructure")
	return serialized, nil
}

// Deserialize will take in protobuf bytes and return a prekey record structure.
func (s *ProtobufPreKeyRecordSerializer) Deserialize(serialized []byte) (*record.PreKeyStructure, error) {
	pb := &storagepb.PreKeyRecordStructure{}
	err := proto.Unmarshal(serialized, pb)
	if err != nil {
		logger.Error("Error deserializing prekey record: ", err)
		return nil, err
	}

	privateKey, gErr := secret.NewValue(pb.GetPrivateKey())
	if gErr != nil {
		return nil, gErr
	}

	return &record.PreKeyStructure{
		ID:         pb.GetId(),
		PublicKey:  pb.GetPublicKey(),
		PrivateKey: privateKey,
	}, nil
}

// =============================================================================
// SignedPreKeyRecord
// =============================================================================

// ProtobufSignedPreKeyRecordSerializer is a structure for serializing signed
// prekey records into and from protobuf.
type ProtobufSignedPreKeyRecordSerializer struct{}

// Serialize will take a signed prekey record structure and convert it to protobuf bytes.
func (s *ProtobufSignedPreKeyRecordSerializer) Serialize(signedPreKey *record.SignedPreKeyStructure) ([]byte, error) {
	pb := &storagepb.SignedPreKeyRecordStructure{
		Id:         signedPreKey.ID,
		PublicKey:  signedPreKey.PublicKey,
		PrivateKey: signedPreKey.PrivateKey.BytesOrNil(),
		Signature:  signedPreKey.Signature,
		Timestamp:  uint64(signedPreKey.Timestamp),
	}
	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf SignedPreKeyRecordStructure")
	return serialized, nil
}

// Deserialize will take in protobuf bytes and return a signed prekey record structure.
func (s *ProtobufSignedPreKeyRecordSerializer) Deserialize(serialized []byte) (*record.SignedPreKeyStructure, error) {
	pb := &storagepb.SignedPreKeyRecordStructure{}
	err := proto.Unmarshal(serialized, pb)
	if err != nil {
		logger.Error("Error deserializing signed prekey record: ", err)
		return nil, err
	}

	privateKey, gErr := secret.NewValue(pb.GetPrivateKey())
	if gErr != nil {
		return nil, gErr
	}

	return &record.SignedPreKeyStructure{
		ID:         pb.GetId(),
		PublicKey:  pb.GetPublicKey(),
		PrivateKey: privateKey,
		Signature:  pb.GetSignature(),
		Timestamp:  int64(pb.GetTimestamp()),
	}, nil
}

// =============================================================================
// SenderKeyState
// =============================================================================

// ProtobufSenderKeyStateSerializer is a structure for serializing senderkey
// states into and from protobuf.
type ProtobufSenderKeyStateSerializer struct{}

// Serialize will take a senderkey state structure and convert it to protobuf bytes.
func (s *ProtobufSenderKeyStateSerializer) Serialize(state *groupRecord.SenderKeyStateStructure) ([]byte, error) {
	pb := senderKeyStateStructureToProto(state)
	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf SenderKeyStateStructure")
	return serialized, nil
}

// Deserialize will take in protobuf bytes and return a senderkey state structure.
func (s *ProtobufSenderKeyStateSerializer) Deserialize(serialized []byte) (*groupRecord.SenderKeyStateStructure, error) {
	pb := &storagepb.SenderKeyStateStructure{}
	err := proto.Unmarshal(serialized, pb)
	if err != nil {
		logger.Error("Error deserializing senderkey state: ", err)
		return nil, err
	}

	return protoToSenderKeyStateStructure(pb), nil
}

// =============================================================================
// SenderKeyRecord
// =============================================================================

// ProtobufSenderKeyRecordSerializer is a structure for serializing senderkey
// records into and from protobuf.
type ProtobufSenderKeyRecordSerializer struct{}

// Serialize will take a senderkey structure and convert it to protobuf bytes.
func (s *ProtobufSenderKeyRecordSerializer) Serialize(senderKey *groupRecord.SenderKeyStructure) ([]byte, error) {
	states := make([]*storagepb.SenderKeyStateStructure, len(senderKey.SenderKeyStates))
	for i, state := range senderKey.SenderKeyStates {
		states[i] = senderKeyStateStructureToProto(state)
	}

	pb := &storagepb.SenderKeyRecordStructure{
		SenderKeyStates: states,
	}

	serialized, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	logger.Debug("Serialize result: protobuf SenderKeyRecordStructure")
	return serialized, nil
}

// Deserialize will take in protobuf bytes and return a senderkey structure.
func (s *ProtobufSenderKeyRecordSerializer) Deserialize(serialized []byte) (*groupRecord.SenderKeyStructure, error) {
	pb := &storagepb.SenderKeyRecordStructure{}
	err := proto.Unmarshal(serialized, pb)
	if err != nil {
		logger.Error("Error deserializing senderkey record: ", err)
		return nil, err
	}

	// Bound to maxSenderKeyStates (5) to prevent unbounded allocation from malformed data.
	const maxSenderKeyStates = 5
	if len(pb.GetSenderKeyStates()) > maxSenderKeyStates {
		return nil, &BoundsExceededError{
			MessageType: "sender key record",
			Field:       "sender_key_states",
			Max:         maxSenderKeyStates,
			Actual:      len(pb.GetSenderKeyStates()),
		}
	}
	states := make([]*groupRecord.SenderKeyStateStructure, len(pb.GetSenderKeyStates()))
	for i, statePb := range pb.GetSenderKeyStates() {
		states[i] = protoToSenderKeyStateStructure(statePb)
	}

	return &groupRecord.SenderKeyStructure{
		SenderKeyStates: states,
	}, nil
}

// =============================================================================
// Conversion helpers: StateStructure <-> storagepb.SessionStructure
// =============================================================================

// stateStructureToProto converts a Go StateStructure to a protobuf SessionStructure.
func stateStructureToProto(state *record.StateStructure) *storagepb.SessionStructure {
	if state == nil {
		return nil
	}

	pb := &storagepb.SessionStructure{
		SessionVersion:       uint32(state.SessionVersion),
		LocalIdentityPublic:  state.LocalIdentityPublic,
		RemoteIdentityPublic: state.RemoteIdentityPublic,
		RootKey:              state.RootKey.BytesOrNil(),
		PreviousCounter:      state.PreviousCounter,
		RemoteRegistrationId: state.RemoteRegistrationID,
		LocalRegistrationId:  state.LocalRegistrationID,
		AliceBaseKey:         state.SenderBaseKey,
	}

	// Convert sender chain.
	if state.SenderChain != nil {
		pb.SenderChain = chainStructureToProto(state.SenderChain)
	}

	// Convert receiver chains.
	if state.ReceiverChains != nil {
		pb.ReceiverChains = make([]*storagepb.SessionStructure_Chain, len(state.ReceiverChains))
		for i, rc := range state.ReceiverChains {
			pb.ReceiverChains[i] = chainStructureToProto(rc)
		}
	}

	// Convert pending pre key.
	if state.PendingPreKey != nil {
		pbPending := &storagepb.SessionStructure_PendingPreKey{
			SignedPreKeyId: int32(state.PendingPreKey.SignedPreKeyID),
			BaseKey:        state.PendingPreKey.BaseKey,
			Timestamp:      state.PendingPreKey.Timestamp,
		}
		if state.PendingPreKey.PreKeyID != nil && !state.PendingPreKey.PreKeyID.IsEmpty {
			preKeyID := state.PendingPreKey.PreKeyID.Value
			pbPending.PreKeyId = &preKeyID
		}
		pb.PendingPreKey = pbPending
	}

	// Convert pending Kyber pre key (PQXDH).
	if state.PendingPreKey != nil && state.PendingPreKey.KyberPreKeyID != nil && !state.PendingPreKey.KyberPreKeyID.IsEmpty {
		pb.PendingKyberPreKey = &storagepb.SessionStructure_PendingKyberPreKey{
			PreKeyId:   state.PendingPreKey.KyberPreKeyID.Value,
			Ciphertext: state.PendingPreKey.KyberCiphertext,
		}
	}

	// Convert PQ ratchet state.
	if pqRatchetState := state.PqRatchetState.BytesOrNil(); len(pqRatchetState) > 0 {
		pb.PqRatchetState = pqRatchetState
	}

	return pb
}

// protoToStateStructure converts a protobuf SessionStructure to a Go StateStructure.
func protoToStateStructure(pb *storagepb.SessionStructure) (_ *record.StateStructure, err error) {
	if pb == nil {
		return nil, nil
	}

	rootKey, err := secret.NewValue(pb.GetRootKey())
	if err != nil {
		return nil, err
	}

	state := &record.StateStructure{
		SessionVersion:       int(pb.GetSessionVersion()),
		LocalIdentityPublic:  pb.GetLocalIdentityPublic(),
		RemoteIdentityPublic: pb.GetRemoteIdentityPublic(),
		RootKey:              rootKey,
		PreviousCounter:      pb.GetPreviousCounter(),
		RemoteRegistrationID: pb.GetRemoteRegistrationId(),
		LocalRegistrationID:  pb.GetLocalRegistrationId(),
		SenderBaseKey:        pb.GetAliceBaseKey(),
	}

	// Release the guarded material already decoded if any step below fails, so
	// that malformed input cannot strand mlock'd pages.
	defer func() {
		if err != nil {
			state.Zeroize()
		}
	}()

	// Convert sender chain.
	if state.SenderChain, err = protoToChainStructure(pb.GetSenderChain()); err != nil {
		return nil, err
	}

	// Convert receiver chains.
	// Bound to maxReceiverChains (5) to prevent unbounded allocation from malformed data.
	const maxReceiverChains = 5
	if pb.GetReceiverChains() != nil {
		if len(pb.GetReceiverChains()) > maxReceiverChains {
			return nil, &BoundsExceededError{
				MessageType: "session state",
				Field:       "receiver_chains",
				Max:         maxReceiverChains,
				Actual:      len(pb.GetReceiverChains()),
			}
		}
		state.ReceiverChains = make([]*record.ChainStructure, len(pb.GetReceiverChains()))
		for i, rc := range pb.GetReceiverChains() {
			if state.ReceiverChains[i], err = protoToChainStructure(rc); err != nil {
				return nil, err
			}
		}
	}

	// Convert pending pre key.
	if pb.GetPendingPreKey() != nil {
		ppk := pb.GetPendingPreKey()
		pendingPreKey := &record.PendingPreKeyStructure{
			SignedPreKeyID: uint32(ppk.GetSignedPreKeyId()),
			BaseKey:        ppk.GetBaseKey(),
			Timestamp:      ppk.GetTimestamp(),
		}
		if ppk.PreKeyId != nil {
			pendingPreKey.PreKeyID = optional.NewOptionalUint32(ppk.GetPreKeyId())
		} else {
			pendingPreKey.PreKeyID = optional.NewEmptyUint32()
		}
		// Merge pending Kyber pre key (PQXDH) into the same structure.
		if pb.GetPendingKyberPreKey() != nil {
			kpk := pb.GetPendingKyberPreKey()
			pendingPreKey.KyberPreKeyID = optional.NewOptionalUint32(kpk.GetPreKeyId())
			pendingPreKey.KyberCiphertext = kpk.GetCiphertext()
		}
		state.PendingPreKey = pendingPreKey
	}

	// Convert PQ ratchet state.
	if state.PqRatchetState, err = secret.NewValue(pb.GetPqRatchetState()); err != nil {
		return nil, err
	}

	return state, nil
}

// chainStructureToProto converts a Go ChainStructure to a protobuf Chain.
func chainStructureToProto(cs *record.ChainStructure) *storagepb.SessionStructure_Chain {
	if cs == nil {
		return nil
	}

	pbChain := &storagepb.SessionStructure_Chain{
		SenderRatchetKey:        cs.SenderRatchetKeyPublic,
		SenderRatchetKeyPrivate: cs.SenderRatchetKeyPrivate.BytesOrNil(),
	}

	// Convert chain key.
	if cs.ChainKey != nil {
		pbChain.ChainKey = &storagepb.SessionStructure_Chain_ChainKey{
			Index: cs.ChainKey.Index,
			Key:   cs.ChainKey.Key.BytesOrNil(),
		}
	}

	// Convert message keys.
	if cs.MessageKeys != nil {
		pbChain.MessageKeys = make([]*storagepb.SessionStructure_Chain_MessageKey, len(cs.MessageKeys))
		for i, mk := range cs.MessageKeys {
			pbChain.MessageKeys[i] = &storagepb.SessionStructure_Chain_MessageKey{
				Index:     mk.Index,
				CipherKey: mk.CipherKey.BytesOrNil(),
				MacKey:    mk.MacKey.BytesOrNil(),
				Iv:        mk.IV.BytesOrNil(),
				Seed:      mk.SeedMaterial.BytesOrNil(),
			}
		}
	}

	return pbChain
}

// protoToChainStructure converts a protobuf Chain to a Go ChainStructure.
func protoToChainStructure(pbChain *storagepb.SessionStructure_Chain) (_ *record.ChainStructure, err error) {
	if pbChain == nil {
		return nil, nil
	}

	senderRatchetKeyPrivate, err := secret.NewValue(pbChain.GetSenderRatchetKeyPrivate())
	if err != nil {
		return nil, err
	}

	cs := &record.ChainStructure{
		SenderRatchetKeyPublic:  pbChain.GetSenderRatchetKey(),
		SenderRatchetKeyPrivate: senderRatchetKeyPrivate,
	}

	// Release the guarded material already decoded if any step below fails, so
	// that malformed input cannot strand mlock'd pages.
	defer func() {
		if err != nil {
			cs.Zeroize()
		}
	}()

	// Convert chain key.
	if pbChain.GetChainKey() != nil {
		cs.ChainKey = &chain.KeyStructure{Index: pbChain.GetChainKey().GetIndex()}
		if cs.ChainKey.Key, err = secret.NewValue(pbChain.GetChainKey().GetKey()); err != nil {
			return nil, err
		}
	}

	// Convert message keys.
	// Bound to maxMessageKeys (2000) to prevent unbounded allocation from malformed data.
	const maxMessageKeys = 2000
	if pbChain.GetMessageKeys() != nil {
		if len(pbChain.GetMessageKeys()) > maxMessageKeys {
			return nil, &BoundsExceededError{
				MessageType: "chain",
				Field:       "message_keys",
				Max:         maxMessageKeys,
				Actual:      len(pbChain.GetMessageKeys()),
			}
		}
		cs.MessageKeys = make([]*message.KeysStructure, len(pbChain.GetMessageKeys()))
		for i, mk := range pbChain.GetMessageKeys() {
			// Attached to cs before any of its fields are filled, so that a
			// failure part-way through this entry still leaves what was
			// already guarded reachable by the cleanup above.
			ks := &message.KeysStructure{Index: mk.GetIndex()}
			cs.MessageKeys[i] = ks
			if ks.CipherKey, err = secret.NewValue(mk.GetCipherKey()); err != nil {
				return nil, err
			}
			if ks.MacKey, err = secret.NewValue(mk.GetMacKey()); err != nil {
				return nil, err
			}
			if ks.IV, err = secret.NewValue(mk.GetIv()); err != nil {
				return nil, err
			}
			if ks.SeedMaterial, err = secret.NewValue(mk.GetSeed()); err != nil {
				return nil, err
			}
		}
	}

	return cs, nil
}

// =============================================================================
// Conversion helpers: SenderKeyStateStructure <-> storagepb.SenderKeyStateStructure
// =============================================================================

// senderKeyStateStructureToProto converts a Go SenderKeyStateStructure to its protobuf equivalent.
func senderKeyStateStructureToProto(state *groupRecord.SenderKeyStateStructure) *storagepb.SenderKeyStateStructure {
	if state == nil {
		return nil
	}

	pb := &storagepb.SenderKeyStateStructure{
		ChainId:        state.KeyID,
		MessageVersion: state.MessageVersion,
		SenderSigningKey: &storagepb.SenderKeyStateStructure_SenderSigningKey{
			Public:  state.SigningKeyPublic,
			Private: state.SigningKeyPrivate,
		},
	}

	// Convert sender chain key.
	if state.SenderChainKey != nil {
		pb.SenderChainKey = &storagepb.SenderKeyStateStructure_SenderChainKey{
			Iteration: state.SenderChainKey.Iteration,
			Seed:      state.SenderChainKey.ChainKey,
		}
	}

	// Convert sender message keys.
	if state.Keys != nil {
		pb.SenderMessageKeys = make([]*storagepb.SenderKeyStateStructure_SenderMessageKey, len(state.Keys))
		for i, key := range state.Keys {
			pb.SenderMessageKeys[i] = &storagepb.SenderKeyStateStructure_SenderMessageKey{
				Iteration: key.Iteration,
				Seed:      key.Seed,
			}
		}
	}

	return pb
}

// protoToSenderKeyStateStructure converts a protobuf SenderKeyStateStructure to a Go SenderKeyStateStructure.
func protoToSenderKeyStateStructure(pb *storagepb.SenderKeyStateStructure) *groupRecord.SenderKeyStateStructure {
	if pb == nil {
		return nil
	}

	state := &groupRecord.SenderKeyStateStructure{
		KeyID:          pb.GetChainId(),
		MessageVersion: pb.GetMessageVersion(),
	}

	// Convert signing key.
	if pb.GetSenderSigningKey() != nil {
		state.SigningKeyPublic = pb.GetSenderSigningKey().GetPublic()
		state.SigningKeyPrivate = pb.GetSenderSigningKey().GetPrivate()
	}

	// Convert sender chain key.
	if pb.GetSenderChainKey() != nil {
		state.SenderChainKey = &ratchet.SenderChainKeyStructure{
			Iteration: pb.GetSenderChainKey().GetIteration(),
			ChainKey:  pb.GetSenderChainKey().GetSeed(),
		}
	}

	// Convert sender message keys.
	if pb.GetSenderMessageKeys() != nil {
		state.Keys = make([]*ratchet.SenderMessageKeyStructure, len(pb.GetSenderMessageKeys()))
		for i, mk := range pb.GetSenderMessageKeys() {
			state.Keys[i] = &ratchet.SenderMessageKeyStructure{
				Iteration: mk.GetIteration(),
				Seed:      mk.GetSeed(),
			}
		}
	}

	return state
}
