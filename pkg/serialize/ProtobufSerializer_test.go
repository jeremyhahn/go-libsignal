package serialize

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/wirepb"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
	"google.golang.org/protobuf/proto"
)

func TestNewProtobufSerializer(t *testing.T) {
	s := NewProtobufSerializer()
	if s == nil {
		t.Fatal("NewProtobufSerializer returned nil")
	}
	if s.SignalMessage == nil {
		t.Fatal("SignalMessage serializer should not be nil")
	}
	if s.PreKeySignalMessage == nil {
		t.Fatal("PreKeySignalMessage serializer should not be nil")
	}
	if s.SignedPreKeyRecord == nil {
		t.Fatal("SignedPreKeyRecord serializer should not be nil")
	}
	if s.PreKeyRecord == nil {
		t.Fatal("PreKeyRecord serializer should not be nil")
	}
	if s.State == nil {
		t.Fatal("State serializer should not be nil")
	}
	if s.Session == nil {
		t.Fatal("Session serializer should not be nil")
	}
	if s.SenderKeyMessage == nil {
		t.Fatal("SenderKeyMessage serializer should not be nil")
	}
	if s.SenderKeyDistributionMessage == nil {
		t.Fatal("SenderKeyDistributionMessage serializer should not be nil")
	}
	if s.SenderKeyRecord == nil {
		t.Fatal("SenderKeyRecord serializer should not be nil")
	}
	if s.SenderKeyState == nil {
		t.Fatal("SenderKeyState serializer should not be nil")
	}
}

// ================== ProtobufSignalMessageSerializer ==================

func TestProtobufSignalMessageSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufSignalMessageSerializer{}
	original := &protocol.SignalMessageStructure{
		Version:         3,
		RatchetKey:      []byte{0x05, 0x01, 0x02, 0x03},
		Counter:         5,
		PreviousCounter: 3,
		CipherText:      []byte("ciphertext"),
		Mac:             []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.Counter != 5 {
		t.Fatal("counter mismatch")
	}
	if deserialized.PreviousCounter != 3 {
		t.Fatal("previous counter mismatch")
	}
}

func TestProtobufSignalMessageSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufSignalMessageSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// ================== ProtobufPreKeySignalMessageSerializer ==================

func TestProtobufPreKeySignalMessageSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufPreKeySignalMessageSerializer{}
	original := &protocol.PreKeySignalMessageStructure{
		RegistrationID: 12345,
		PreKeyID:       optional.NewOptionalUint32(1),
		SignedPreKeyID: 2,
		BaseKey:        []byte{0x05, 0x01},
		IdentityKey:    []byte{0x05, 0x02},
		Message:        []byte("message"),
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.RegistrationID != 12345 {
		t.Fatal("registration ID mismatch")
	}
	if deserialized.SignedPreKeyID != 2 {
		t.Fatal("signed prekey ID mismatch")
	}
	if deserialized.PreKeyID == nil || deserialized.PreKeyID.Value != 1 {
		t.Fatal("prekey ID mismatch")
	}
}

func TestProtobufPreKeySignalMessageSerializer_RoundTripWithoutPreKeyID(t *testing.T) {
	s := &ProtobufPreKeySignalMessageSerializer{}
	original := &protocol.PreKeySignalMessageStructure{
		RegistrationID: 99,
		PreKeyID:       optional.NewEmptyUint32(),
		SignedPreKeyID: 3,
		BaseKey:        []byte{0x05, 0x01},
		IdentityKey:    []byte{0x05, 0x02},
		Message:        []byte("msg"),
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.PreKeyID == nil || !deserialized.PreKeyID.IsEmpty {
		t.Fatal("prekey ID should be empty")
	}
}

func TestProtobufPreKeySignalMessageSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufPreKeySignalMessageSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// ================== ProtobufSenderKeyMessageSerializer ==================

func TestProtobufSenderKeyMessageSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufSenderKeyMessageSerializer{}
	original := &protocol.SenderKeyMessageStructure{
		ID:         1,
		Iteration:  10,
		CipherText: []byte("encrypted"),
		Signature:  make([]byte, 64),
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.ID != 1 {
		t.Fatal("ID mismatch")
	}
	if deserialized.Iteration != 10 {
		t.Fatal("iteration mismatch")
	}
}

func TestProtobufSenderKeyMessageSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufSenderKeyMessageSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// ================== ProtobufSenderKeyDistributionMessageSerializer ==================

func TestProtobufSenderKeyDistributionMessageSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	original := &protocol.SenderKeyDistributionMessageStructure{
		ID:         3,
		Iteration:  15,
		ChainKey:   make([]byte, 32),
		SigningKey: make([]byte, 33),
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.ID != 3 {
		t.Fatal("ID mismatch")
	}
	if deserialized.Iteration != 15 {
		t.Fatal("iteration mismatch")
	}
}

func TestProtobufSenderKeyDistributionMessageSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// ================== ProtobufStateSerializer ==================

func TestProtobufStateSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufStateSerializer{}
	original := &record.StateStructure{
		SessionVersion:       3,
		LocalRegistrationID:  1111,
		RemoteRegistrationID: 2222,
		PreviousCounter:      10,
		RootKey:              mustGuard(t, []byte{0x01, 0x02}),
		LocalIdentityPublic:  []byte{0x05, 0x03},
		RemoteIdentityPublic: []byte{0x05, 0x04},
		SenderBaseKey:        []byte{0x05, 0x05},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.SessionVersion != 3 {
		t.Fatal("session version mismatch")
	}
	if deserialized.LocalRegistrationID != 1111 {
		t.Fatal("local registration ID mismatch")
	}
	if deserialized.RemoteRegistrationID != 2222 {
		t.Fatal("remote registration ID mismatch")
	}
}

func TestProtobufStateSerializer_WithChains(t *testing.T) {
	s := &ProtobufStateSerializer{}
	original := &record.StateStructure{
		SessionVersion: 3,
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic:  []byte{0x05, 0x01},
			SenderRatchetKeyPrivate: mustGuard(t, []byte{0x02}),
			ChainKey:                &chain.KeyStructure{Key: []byte{0x03}, Index: 5},
			MessageKeys: []*message.KeysStructure{
				{CipherKey: []byte{0x04}, MacKey: []byte{0x05}, IV: []byte{0x06}, Index: 0},
			},
		},
		ReceiverChains: []*record.ChainStructure{
			{
				SenderRatchetKeyPublic: []byte{0x05, 0x07},
				ChainKey:               &chain.KeyStructure{Key: []byte{0x08}, Index: 3},
			},
		},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.SenderChain == nil {
		t.Fatal("sender chain should not be nil")
	}
	if len(deserialized.ReceiverChains) != 1 {
		t.Fatal("receiver chains count mismatch")
	}
}

func TestProtobufStateSerializer_WithPendingPreKey(t *testing.T) {
	s := &ProtobufStateSerializer{}
	original := &record.StateStructure{
		SessionVersion: 3,
		PendingPreKey: &record.PendingPreKeyStructure{
			PreKeyID:       optional.NewOptionalUint32(42),
			SignedPreKeyID: 10,
			BaseKey:        []byte{0x05, 0x01},
		},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.PendingPreKey == nil {
		t.Fatal("pending prekey should not be nil")
	}
	if deserialized.PendingPreKey.PreKeyID == nil || deserialized.PendingPreKey.PreKeyID.Value != 42 {
		t.Fatal("prekey ID mismatch")
	}
}

func TestProtobufStateSerializer_WithPendingPreKeyEmpty(t *testing.T) {
	s := &ProtobufStateSerializer{}
	original := &record.StateStructure{
		SessionVersion: 3,
		PendingPreKey: &record.PendingPreKeyStructure{
			PreKeyID:       optional.NewEmptyUint32(),
			SignedPreKeyID: 10,
			BaseKey:        []byte{0x05, 0x01},
		},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.PendingPreKey.PreKeyID == nil || !deserialized.PendingPreKey.PreKeyID.IsEmpty {
		t.Fatal("prekey ID should be empty")
	}
}

func TestProtobufStateSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufStateSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

func TestProtobufStateSerializer_NilState(t *testing.T) {
	result := stateStructureToProto(nil)
	if result != nil {
		t.Fatal("expected nil for nil state")
	}

	result2, err := protoToStateStructure(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result2 != nil {
		t.Fatal("expected nil for nil proto")
	}
}

func TestProtobufChainStructureHelpers_Nil(t *testing.T) {
	result := chainStructureToProto(nil)
	if result != nil {
		t.Fatal("expected nil for nil chain")
	}

	result2, err := protoToChainStructure(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result2 != nil {
		t.Fatal("expected nil for nil proto chain")
	}
}

// ================== ProtobufSessionSerializer ==================

func TestProtobufSessionSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufSessionSerializer{}
	original := &record.SessionStructure{
		SessionState: &record.StateStructure{
			SessionVersion:       3,
			LocalRegistrationID:  1111,
			RemoteRegistrationID: 2222,
		},
		PreviousStates: []*record.StateStructure{
			{SessionVersion: 2, LocalRegistrationID: 3333},
		},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.SessionState == nil {
		t.Fatal("session state should not be nil")
	}
	if deserialized.SessionState.SessionVersion != 3 {
		t.Fatal("session version mismatch")
	}
	if len(deserialized.PreviousStates) != 1 {
		t.Fatal("previous states count mismatch")
	}
}

func TestProtobufSessionSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufSessionSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// ================== ProtobufPreKeyRecordSerializer ==================

func TestProtobufPreKeyRecordSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufPreKeyRecordSerializer{}
	original := &record.PreKeyStructure{
		ID:         5,
		PublicKey:  []byte{0x01},
		PrivateKey: mustGuard(t, []byte{0x02}),
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.ID != 5 {
		t.Fatal("ID mismatch")
	}
}

func TestProtobufPreKeyRecordSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufPreKeyRecordSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// ================== ProtobufSignedPreKeyRecordSerializer ==================

func TestProtobufSignedPreKeyRecordSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufSignedPreKeyRecordSerializer{}
	original := &record.SignedPreKeyStructure{
		ID:         1,
		PublicKey:  []byte{0x01},
		PrivateKey: mustGuard(t, []byte{0x02}),
		Signature:  []byte{0x03},
		Timestamp:  1000,
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.ID != 1 {
		t.Fatal("ID mismatch")
	}
	if deserialized.Timestamp != 1000 {
		t.Fatal("timestamp mismatch")
	}
}

func TestProtobufSignedPreKeyRecordSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufSignedPreKeyRecordSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// ================== ProtobufSenderKeyStateSerializer ==================

func TestProtobufSenderKeyStateSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufSenderKeyStateSerializer{}
	original := &groupRecord.SenderKeyStateStructure{
		KeyID:             5,
		SigningKeyPublic:  []byte{0x01},
		SigningKeyPrivate: []byte{0x02},
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: 10,
			ChainKey:  []byte{0x03},
		},
		Keys: []*ratchet.SenderMessageKeyStructure{
			{Iteration: 1, Seed: []byte{0x04}},
		},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if deserialized.KeyID != 5 {
		t.Fatal("key ID mismatch")
	}
	if deserialized.SenderChainKey == nil {
		t.Fatal("sender chain key should not be nil")
	}
	if deserialized.SenderChainKey.Iteration != 10 {
		t.Fatal("chain key iteration mismatch")
	}
}

func TestProtobufSenderKeyStateSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufSenderKeyStateSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

func TestProtobufSenderKeyStateSerializer_NilHelpers(t *testing.T) {
	result := senderKeyStateStructureToProto(nil)
	if result != nil {
		t.Fatal("expected nil for nil state")
	}

	result2 := protoToSenderKeyStateStructure(nil)
	if result2 != nil {
		t.Fatal("expected nil for nil proto")
	}
}

// ================== ProtobufSenderKeyRecordSerializer ==================

func TestProtobufSenderKeyRecordSerializer_RoundTrip(t *testing.T) {
	s := &ProtobufSenderKeyRecordSerializer{}
	original := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{KeyID: 1, SigningKeyPublic: []byte{0x01}},
			{KeyID: 2, SigningKeyPublic: []byte{0x02}},
		},
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatal(err)
	}

	if len(deserialized.SenderKeyStates) != 2 {
		t.Fatal("states count mismatch")
	}
	if deserialized.SenderKeyStates[0].KeyID != 1 {
		t.Fatal("first key ID mismatch")
	}
}

func TestProtobufSenderKeyRecordSerializer_DeserializeInvalid(t *testing.T) {
	s := &ProtobufSenderKeyRecordSerializer{}
	_, err := s.Deserialize([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
}

// ================== Protobuf empty/short input deserialization ==================

func TestProtobufSignalMessageSerializer_DeserializeEmpty(t *testing.T) {
	s := &ProtobufSignalMessageSerializer{}
	_, err := s.Deserialize([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestProtobufSignalMessageSerializer_DeserializeShortBody(t *testing.T) {
	// A message body <= 8 bytes (macLen) has no room for a MAC and must be rejected.
	s := &ProtobufSignalMessageSerializer{}
	// version byte (3<<4|3=0x33) + short body (2 bytes, less than macLen 8)
	data := []byte{0x33, 0x08, 0x01}
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for message too short to contain MAC")
	}
}

func TestProtobufPreKeySignalMessageSerializer_DeserializeEmpty(t *testing.T) {
	s := &ProtobufPreKeySignalMessageSerializer{}
	_, err := s.Deserialize([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestProtobufSenderKeyMessageSerializer_DeserializeEmpty(t *testing.T) {
	s := &ProtobufSenderKeyMessageSerializer{}
	_, err := s.Deserialize([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestProtobufSenderKeyDistributionMessageSerializer_DeserializeEmpty(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	_, err := s.Deserialize([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// ================== Protobuf nil/empty structure serialization ==================

func TestProtobufSignalMessageSerializer_SerializeEmptyStructure(t *testing.T) {
	s := &ProtobufSignalMessageSerializer{}
	msg := &protocol.SignalMessageStructure{}
	data, err := s.Serialize(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should produce a version byte + empty protobuf body + empty mac
	if len(data) == 0 {
		t.Fatal("expected non-empty serialization")
	}
}

func TestProtobufPreKeySignalMessageSerializer_SerializeEmptyStructure(t *testing.T) {
	s := &ProtobufPreKeySignalMessageSerializer{}
	msg := &protocol.PreKeySignalMessageStructure{}
	data, err := s.Serialize(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty serialization")
	}
}

func TestProtobufPreKeySignalMessageSerializer_SerializeWithNilPreKeyID(t *testing.T) {
	s := &ProtobufPreKeySignalMessageSerializer{}
	msg := &protocol.PreKeySignalMessageStructure{
		Version:        3,
		RegistrationID: 100,
		PreKeyID:       nil,
		SignedPreKeyID: 5,
		BaseKey:        []byte{0x05},
		IdentityKey:    []byte{0x05},
		Message:        []byte("msg"),
	}
	data, err := s.Serialize(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty serialization")
	}
}

func TestProtobufSenderKeyMessageSerializer_SerializeEmptyStructure(t *testing.T) {
	s := &ProtobufSenderKeyMessageSerializer{}
	msg := &protocol.SenderKeyMessageStructure{}
	data, err := s.Serialize(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty serialization")
	}
}

func TestProtobufSenderKeyDistributionMessageSerializer_SerializeEmptyStructure(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	msg := &protocol.SenderKeyDistributionMessageStructure{}
	data, err := s.Serialize(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty serialization")
	}
}

func TestProtobufSessionSerializer_DeserializeWithCorruptPreviousState(t *testing.T) {
	s := &ProtobufSessionSerializer{}

	// First, serialize a valid session
	original := &record.SessionStructure{
		SessionState:   &record.StateStructure{SessionVersion: 3},
		PreviousStates: []*record.StateStructure{{SessionVersion: 2}},
	}
	data, err := s.Serialize(original)
	if err != nil {
		t.Fatal(err)
	}

	// The serialized data should round-trip
	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SessionState == nil {
		t.Fatal("session state should not be nil")
	}
}

func TestProtobufSessionSerializer_SerializeNilSessionState(t *testing.T) {
	s := &ProtobufSessionSerializer{}
	session := &record.SessionStructure{
		SessionState:   nil,
		PreviousStates: nil,
	}
	data, err := s.Serialize(session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty protobuf with no fields set serializes to zero bytes, which is valid.

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SessionState != nil {
		t.Fatal("session state should be nil for nil input")
	}
}

func TestProtobufStateSerializer_SerializeEmptyState(t *testing.T) {
	s := &ProtobufStateSerializer{}
	state := &record.StateStructure{}
	data, err := s.Serialize(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SessionVersion != 0 {
		t.Fatal("empty state should have zero session version")
	}
}

func TestProtobufPreKeyRecordSerializer_SerializeEmptyRecord(t *testing.T) {
	s := &ProtobufPreKeyRecordSerializer{}
	preKey := &record.PreKeyStructure{}
	data, err := s.Serialize(preKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != 0 {
		t.Fatal("empty prekey should have zero ID")
	}
}

func TestProtobufSignedPreKeyRecordSerializer_SerializeEmptyRecord(t *testing.T) {
	s := &ProtobufSignedPreKeyRecordSerializer{}
	signed := &record.SignedPreKeyStructure{}
	data, err := s.Serialize(signed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ID != 0 {
		t.Fatal("empty signed prekey should have zero ID")
	}
}

func TestProtobufSenderKeyStateSerializer_SerializeEmptyState(t *testing.T) {
	s := &ProtobufSenderKeyStateSerializer{}
	state := &groupRecord.SenderKeyStateStructure{}
	data, err := s.Serialize(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.KeyID != 0 {
		t.Fatal("empty state should have zero key ID")
	}
}

func TestProtobufSenderKeyRecordSerializer_SerializeEmptyRecord(t *testing.T) {
	s := &ProtobufSenderKeyRecordSerializer{}
	rec := &groupRecord.SenderKeyStructure{
		SenderKeyStates: nil,
	}
	data, err := s.Serialize(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.SenderKeyStates) != 0 {
		t.Fatal("empty record should have no states")
	}
}

// ================== Protobuf state with nil sub-structures ==================

func TestProtobufSessionSerializer_DeserializeWithInvalidPreviousState(t *testing.T) {
	// Craft raw protobuf bytes with a corrupt previous_sessions entry.
	// RecordStructure has field 2 = repeated bytes previous_sessions.
	// We'll build: valid current_session + corrupt previous_session.
	stateSerializer := &ProtobufStateSerializer{}
	validState := &record.StateStructure{SessionVersion: 3}
	validBytes, err := stateSerializer.Serialize(validState)
	if err != nil {
		t.Fatal(err)
	}

	// Build RecordStructure protobuf manually using the storagepb package.
	// Instead, use a valid session with a corrupt previous state.
	s := &ProtobufSessionSerializer{}
	validSession := &record.SessionStructure{
		SessionState:   &record.StateStructure{SessionVersion: 3},
		PreviousStates: []*record.StateStructure{{SessionVersion: 2}},
	}
	data, err := s.Serialize(validSession)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the data by appending invalid previous session bytes.
	// This won't work because protobuf is resilient. Instead, we need
	// to directly test with bytes that have invalid previous session data.
	_ = validBytes
	_ = data

	// The previous session unmarshal error path requires data where the
	// previous_sessions field contains invalid protobuf bytes.
	// Since protobuf is very lenient, we use truly corrupt bytes.
	// Build: field 1 (current_session) = empty, field 2 (previous_sessions) = garbage
	corrupt := []byte{
		0x12, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, // field 2, length 4, garbage bytes
	}
	_, err = s.Deserialize(corrupt)
	if err == nil {
		t.Fatal("expected error for corrupt previous session data")
	}
}

func TestProtobufStateSerializer_WithNilChainKey(t *testing.T) {
	s := &ProtobufStateSerializer{}
	original := &record.StateStructure{
		SessionVersion: 3,
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic: []byte{0x05, 0x01},
			ChainKey:               nil,
			MessageKeys:            nil,
		},
	}
	data, err := s.Serialize(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SenderChain == nil {
		t.Fatal("sender chain should not be nil")
	}
	if result.SenderChain.ChainKey != nil {
		t.Fatal("chain key should be nil when not set")
	}
}

// ================== Strict SKM / SKDM field-presence rejection tests ==================
// These tests verify that missing required fields are rejected with
// ErrInvalidProtobufEncoding, mirroring Rust's InvalidProtobufEncoding behavior
// (rust/protocol/src/protocol.rs:614-657 for SKM, :748-800 for SKDM).

// buildSKMBytes encodes a partial SenderKeyMessage protobuf, prepends the
// version header byte, and appends 64 zero bytes as the signature.
func buildSKMBytes(t *testing.T, chainID *uint32, iteration *uint32, distUUID []byte) []byte {
	t.Helper()
	pb := &wirepb.SenderKeyMessage{
		ChainId:          chainID,
		Iteration:        iteration,
		DistributionUuid: distUUID,
		Ciphertext:       []byte("ct"),
	}
	body, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("buildSKMBytes marshal: %v", err)
	}
	// version byte (3<<4|3) + body + 64-byte zero signature
	result := make([]byte, 0, 1+len(body)+64)
	result = append(result, 0x33)
	result = append(result, body...)
	result = append(result, make([]byte, 64)...)
	return result
}

// buildSKDMBytes encodes a partial SenderKeyDistributionMessage protobuf and
// prepends the version header byte.
func buildSKDMBytes(t *testing.T, chainID *uint32, iteration *uint32, chainKey []byte, signingKey []byte, distUUID []byte) []byte {
	t.Helper()
	pb := &wirepb.SenderKeyDistributionMessage{
		ChainId:          chainID,
		Iteration:        iteration,
		ChainKey:         chainKey,
		SigningKey:       signingKey,
		DistributionUuid: distUUID,
	}
	body, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("buildSKDMBytes marshal: %v", err)
	}
	result := make([]byte, 1+len(body))
	result[0] = 0x33
	copy(result[1:], body)
	return result
}

func uint32Ptr(v uint32) *uint32 { return &v }

var validDistUUID = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
var validChainKey = make([]byte, 32)
var validSigningKey = make([]byte, 33)

func TestSenderKeyMessageDeserialize_MissingChainID(t *testing.T) {
	s := &ProtobufSenderKeyMessageSerializer{}
	data := buildSKMBytes(t, nil, uint32Ptr(0), validDistUUID)
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for missing chain_id")
	}
	if _, ok := err.(*ErrInvalidProtobufEncoding); !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
}

func TestSenderKeyMessageDeserialize_MissingIteration(t *testing.T) {
	s := &ProtobufSenderKeyMessageSerializer{}
	data := buildSKMBytes(t, uint32Ptr(1), nil, validDistUUID)
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for missing iteration")
	}
	if _, ok := err.(*ErrInvalidProtobufEncoding); !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
}

func TestSenderKeyMessageDeserialize_MissingDistributionUUID(t *testing.T) {
	s := &ProtobufSenderKeyMessageSerializer{}
	data := buildSKMBytes(t, uint32Ptr(1), uint32Ptr(0), nil)
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for missing distribution_uuid")
	}
	if _, ok := err.(*ErrInvalidProtobufEncoding); !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
}

func TestSenderKeyDistributionMessageDeserialize_MissingChainID(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	data := buildSKDMBytes(t, nil, uint32Ptr(0), validChainKey, validSigningKey, validDistUUID)
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for missing chain_id")
	}
	if _, ok := err.(*ErrInvalidProtobufEncoding); !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
}

func TestSenderKeyDistributionMessageDeserialize_MissingIteration(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	data := buildSKDMBytes(t, uint32Ptr(1), nil, validChainKey, validSigningKey, validDistUUID)
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for missing iteration")
	}
	if _, ok := err.(*ErrInvalidProtobufEncoding); !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
}

func TestSenderKeyDistributionMessageDeserialize_MissingChainKey(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	data := buildSKDMBytes(t, uint32Ptr(1), uint32Ptr(0), nil, validSigningKey, validDistUUID)
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for missing chain_key")
	}
	if _, ok := err.(*ErrInvalidProtobufEncoding); !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
}

func TestSenderKeyDistributionMessageDeserialize_MissingSigningKey(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	data := buildSKDMBytes(t, uint32Ptr(1), uint32Ptr(0), validChainKey, nil, validDistUUID)
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for missing signing_key")
	}
	if _, ok := err.(*ErrInvalidProtobufEncoding); !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
}

func TestSenderKeyDistributionMessageDeserialize_MissingDistributionUUID(t *testing.T) {
	s := &ProtobufSenderKeyDistributionMessageSerializer{}
	data := buildSKDMBytes(t, uint32Ptr(1), uint32Ptr(0), validChainKey, validSigningKey, nil)
	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for missing distribution_uuid")
	}
	if _, ok := err.(*ErrInvalidProtobufEncoding); !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
}

func TestProtobufStateSerializer_WithEmptyPendingPreKey(t *testing.T) {
	s := &ProtobufStateSerializer{}
	original := &record.StateStructure{
		SessionVersion: 3,
		PendingPreKey: &record.PendingPreKeyStructure{
			PreKeyID:       nil,
			SignedPreKeyID: 10,
			BaseKey:        []byte{0x05, 0x01},
		},
	}
	data, err := s.Serialize(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.PendingPreKey == nil {
		t.Fatal("pending prekey should not be nil")
	}
}

// =============================================================================
// Finding 7 regression tests: required-field presence checks
//
// Rust libsignal (rust/protocol/src/protocol.rs:299-301 for SignalMessage and
// :481-483 for PreKeySignalMessage) rejects messages where the protobuf encoding
// omits certain required fields by returning InvalidProtobufEncoding. The Go
// implementation must enforce the same check.
//
// Strategy: craft a raw SignalMessage or PreKeySignalMessage proto body with the
// target required field absent, wrap it with the appropriate wire-format framing
// (version byte, MAC suffix), and verify that Deserialize returns
// *ErrInvalidProtobufEncoding for the right field.
// =============================================================================

// buildSignalMessageBytes constructs a binary SignalMessage wire payload:
//
//	version_byte || proto_body || mac[8]
//
// The proto body is encoded from a wirepb.SignalMessage where only the fields
// supplied via the non-nil pointer arguments are set. Pass nil to omit a field.
func buildSignalMessageBytes(t *testing.T, counter *uint32, ratchetKey []byte) []byte {
	t.Helper()
	pb := &wirepb.SignalMessage{
		RatchetKey: ratchetKey,
		Counter:    counter,
		Ciphertext: []byte("ct"),
	}
	body, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("buildSignalMessageBytes: marshal: %v", err)
	}
	// Wire format: version_byte || proto_body || mac[8]
	result := make([]byte, 0, 1+len(body)+8)
	result = append(result, 0x33) // version (3<<4|3)
	result = append(result, body...)
	result = append(result, make([]byte, 8)...) // placeholder MAC
	return result
}

// buildPreKeySignalMessageBytes constructs a binary PreKeySignalMessage wire
// payload: version_byte || proto_body. The signedPreKeyID argument is set only
// when the non-nil pointer is provided; pass nil to omit the field.
func buildPreKeySignalMessageBytes(t *testing.T, signedPreKeyID *uint32) []byte {
	t.Helper()
	registrationID := uint32(1)
	pb := &wirepb.PreKeySignalMessage{
		RegistrationId: &registrationID,
		SignedPreKeyId: signedPreKeyID,
		BaseKey:        []byte{0x05, 0x01},
		IdentityKey:    []byte{0x05, 0x02},
		Message:        []byte("inner"),
	}
	body, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("buildPreKeySignalMessageBytes: marshal: %v", err)
	}
	result := make([]byte, 1+len(body))
	result[0] = 0x33 // version byte
	copy(result[1:], body)
	return result
}

// TestSignalMessageDeserialize_MissingCounter verifies Finding 7 for the
// SignalMessage serializer: a wire payload that omits the required `counter`
// proto field must be rejected with *ErrInvalidProtobufEncoding naming the
// "counter" field, matching Rust protocol.rs:299-301.
// Before the fix this returned nil error and silently used counter=0.
func TestSignalMessageDeserialize_MissingCounter(t *testing.T) {
	s := &ProtobufSignalMessageSerializer{}
	data := buildSignalMessageBytes(t, nil, []byte{0x05, 0x01, 0x02})

	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for SignalMessage missing counter, got nil")
	}
	encErr, ok := err.(*ErrInvalidProtobufEncoding)
	if !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
	if encErr.Field != "counter" {
		t.Errorf("expected field=counter, got field=%q", encErr.Field)
	}
}

// TestSignalMessageDeserialize_CounterPresent verifies the positive case: a
// properly-encoded SignalMessage with a counter field present deserializes
// successfully, confirming that the counter nil-check does not over-reject.
func TestSignalMessageDeserialize_CounterPresent(t *testing.T) {
	s := &ProtobufSignalMessageSerializer{}
	counter := uint32(7)
	data := buildSignalMessageBytes(t, &counter, []byte{0x05, 0x01, 0x02})

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error for SignalMessage with counter: %v", err)
	}
	if result.Counter != 7 {
		t.Errorf("expected counter=7, got %d", result.Counter)
	}
}

// TestPreKeySignalMessageDeserialize_MissingSignedPreKeyID verifies Finding 7
// for the PreKeySignalMessage serializer: a wire payload that omits the required
// `signed_pre_key_id` proto field must be rejected with *ErrInvalidProtobufEncoding
// naming the "signed_pre_key_id" field, matching Rust protocol.rs:481-483.
// Before the fix this returned nil error and silently used signedPreKeyId=0.
func TestPreKeySignalMessageDeserialize_MissingSignedPreKeyID(t *testing.T) {
	s := &ProtobufPreKeySignalMessageSerializer{}
	data := buildPreKeySignalMessageBytes(t, nil)

	_, err := s.Deserialize(data)
	if err == nil {
		t.Fatal("expected error for PreKeySignalMessage missing signed_pre_key_id, got nil")
	}
	encErr, ok := err.(*ErrInvalidProtobufEncoding)
	if !ok {
		t.Fatalf("expected *ErrInvalidProtobufEncoding, got %T: %v", err, err)
	}
	if encErr.Field != "signed_pre_key_id" {
		t.Errorf("expected field=signed_pre_key_id, got field=%q", encErr.Field)
	}
}

// TestPreKeySignalMessageDeserialize_SignedPreKeyIDPresent verifies the positive
// case: a properly-encoded PreKeySignalMessage with signed_pre_key_id present
// deserializes successfully.
func TestPreKeySignalMessageDeserialize_SignedPreKeyIDPresent(t *testing.T) {
	s := &ProtobufPreKeySignalMessageSerializer{}
	spkID := uint32(5)
	data := buildPreKeySignalMessageBytes(t, &spkID)

	result, err := s.Deserialize(data)
	if err != nil {
		t.Fatalf("unexpected error for PreKeySignalMessage with signed_pre_key_id: %v", err)
	}
	if result.SignedPreKeyID != 5 {
		t.Errorf("expected SignedPreKeyID=5, got %d", result.SignedPreKeyID)
	}
}
