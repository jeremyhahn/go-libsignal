package serialize

import (
	"testing"

	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

func TestNewJSONSerializer(t *testing.T) {
	s := NewJSONSerializer()
	if s == nil {
		t.Fatal("NewJSONSerializer returned nil")
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

// ================== JSONSignalMessageSerializer ==================

func TestJSONSignalMessageSerializer_RoundTrip(t *testing.T) {
	s := &JSONSignalMessageSerializer{}
	original := &protocol.SignalMessageStructure{
		RatchetKey:      []byte{0x01, 0x02, 0x03},
		Counter:         5,
		PreviousCounter: 3,
		CipherText:      []byte("ciphertext"),
		Version:         3,
		Mac:             []byte{0xaa, 0xbb},
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
	if deserialized.Version != 3 {
		t.Fatal("version mismatch")
	}
}

func TestJSONSignalMessageSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONSignalMessageSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONPreKeySignalMessageSerializer ==================

func TestJSONPreKeySignalMessageSerializer_RoundTrip(t *testing.T) {
	s := &JSONPreKeySignalMessageSerializer{}
	original := &protocol.PreKeySignalMessageStructure{
		RegistrationID: 12345,
		PreKeyID:       optional.NewOptionalUint32(1),
		SignedPreKeyID: 2,
		BaseKey:        []byte{0x05, 0x01, 0x02},
		IdentityKey:    []byte{0x05, 0x03, 0x04},
		Message:        []byte("message"),
		Version:        3,
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
}

func TestJSONPreKeySignalMessageSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONPreKeySignalMessageSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONSignedPreKeyRecordSerializer ==================

func TestJSONSignedPreKeyRecordSerializer_RoundTrip(t *testing.T) {
	s := &JSONSignedPreKeyRecordSerializer{}
	original := &record.SignedPreKeyStructure{
		ID:         1,
		PublicKey:  []byte{0x01},
		PrivateKey: []byte{0x02},
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

func TestJSONSignedPreKeyRecordSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONSignedPreKeyRecordSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONPreKeyRecordSerializer ==================

func TestJSONPreKeyRecordSerializer_RoundTrip(t *testing.T) {
	s := &JSONPreKeyRecordSerializer{}
	original := &record.PreKeyStructure{
		ID:         5,
		PublicKey:  []byte{0x01},
		PrivateKey: []byte{0x02},
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

func TestJSONPreKeyRecordSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONPreKeyRecordSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONStateSerializer ==================

func TestJSONStateSerializer_RoundTrip(t *testing.T) {
	s := &JSONStateSerializer{}
	original := &record.StateStructure{
		SessionVersion:       3,
		LocalRegistrationID:  1111,
		RemoteRegistrationID: 2222,
		PreviousCounter:      10,
		RootKey:              []byte{0x01, 0x02},
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
}

func TestJSONStateSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONStateSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONSessionSerializer ==================

func TestJSONSessionSerializer_RoundTrip(t *testing.T) {
	s := &JSONSessionSerializer{}
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

	if deserialized.SessionState.SessionVersion != 3 {
		t.Fatal("session version mismatch")
	}
	if len(deserialized.PreviousStates) != 1 {
		t.Fatal("previous states count mismatch")
	}
}

func TestJSONSessionSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONSessionSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONSenderKeyDistributionMessageSerializer ==================

func TestJSONSenderKeyDistributionMessageSerializer_RoundTrip(t *testing.T) {
	s := &JSONSenderKeyDistributionMessageSerializer{}
	original := &protocol.SenderKeyDistributionMessageStructure{
		ID:        1,
		Iteration: 5,
		ChainKey:  []byte{0x01},
		SigningKey: []byte{0x02},
		Version:   3,
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
	if deserialized.Iteration != 5 {
		t.Fatal("iteration mismatch")
	}
}

func TestJSONSenderKeyDistributionMessageSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONSenderKeyDistributionMessageSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONSenderKeyMessageSerializer ==================

func TestJSONSenderKeyMessageSerializer_RoundTrip(t *testing.T) {
	s := &JSONSenderKeyMessageSerializer{}
	original := &protocol.SenderKeyMessageStructure{
		ID:         1,
		Iteration:  10,
		CipherText: []byte("encrypted"),
		Version:    3,
		Signature:  []byte("sig"),
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

func TestJSONSenderKeyMessageSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONSenderKeyMessageSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONSenderKeyStateSerializer ==================

func TestJSONSenderKeyStateSerializer_RoundTrip(t *testing.T) {
	s := &JSONSenderKeyStateSerializer{}
	original := &groupRecord.SenderKeyStateStructure{
		KeyID:            5,
		SigningKeyPublic: []byte{0x01},
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
}

func TestJSONSenderKeyStateSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONSenderKeyStateSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSONSenderKeySessionSerializer ==================

func TestJSONSenderKeySessionSerializer_RoundTrip(t *testing.T) {
	s := &JSONSenderKeySessionSerializer{}
	original := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{KeyID: 1},
			{KeyID: 2},
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
}

func TestJSONSenderKeySessionSerializer_DeserializeInvalid(t *testing.T) {
	s := &JSONSenderKeySessionSerializer{}
	_, err := s.Deserialize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ================== JSON state with chain and message keys ==================

func TestJSONStateSerializer_WithChains(t *testing.T) {
	s := &JSONStateSerializer{}
	original := &record.StateStructure{
		SessionVersion: 3,
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic: []byte{0x05, 0x01},
			ChainKey:               &chain.KeyStructure{Key: []byte{0x01}, Index: 0},
			MessageKeys: []*message.KeysStructure{
				{CipherKey: []byte{0x01}, MacKey: []byte{0x02}, IV: []byte{0x03}, Index: 0},
			},
		},
		ReceiverChains: []*record.ChainStructure{
			{
				SenderRatchetKeyPublic: []byte{0x05, 0x02},
				ChainKey:               &chain.KeyStructure{Key: []byte{0x03}, Index: 1},
			},
		},
		PendingPreKey: &record.PendingPreKeyStructure{
			PreKeyID:       optional.NewOptionalUint32(42),
			SignedPreKeyID: 10,
			BaseKey:        []byte{0x05, 0x04},
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
	if deserialized.PendingPreKey == nil {
		t.Fatal("pending prekey should not be nil")
	}
}
