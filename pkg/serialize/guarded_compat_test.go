package serialize

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// The persisted-state private key fields moved from plain []byte into guarded
// memory. encoding/json renders a []byte as a base64 string (or null when it
// is nil), and *secret.Secret is encoded the same way, so stored records keep
// their exact byte layout. The literals below are that layout: they must both
// load into the guarded structures and be reproduced verbatim when those
// structures are written back out.

const (
	legacyPreKeyJSON       = `{"ID":5,"PublicKey":"AQ==","PrivateKey":"Ag=="}`
	legacySignedPreKeyJSON = `{"ID":1,"PublicKey":"AQ==","PrivateKey":"Ag==","Signature":"Aw==","Timestamp":1000}`
	legacyStateJSON        = `{"LocalIdentityPublic":null,"LocalRegistrationID":0,"NeedsRefresh":false,` +
		`"PendingKeyExchange":null,"PendingPreKey":null,"PreviousCounter":0,"ReceiverChains":null,` +
		`"RemoteIdentityPublic":null,"RemoteRegistrationID":0,"RootKey":"AQI=","SenderBaseKey":null,` +
		`"SenderChain":null,"SessionVersion":3,"PqRatchetState":"CQ=="}`
)

func TestJSONPreKeyRecordSerializerLegacyLayout(t *testing.T) {
	s := &JSONPreKeyRecordSerializer{}

	structure, err := s.Deserialize([]byte(legacyPreKeyJSON))
	if err != nil {
		t.Fatalf("Deserialize legacy record: %v", err)
	}
	defer structure.Zeroize()

	if structure.ID != 5 {
		t.Errorf("ID = %d, want 5", structure.ID)
	}
	if !structure.PrivateKey.EqualTo([]byte{0x02}) {
		t.Error("private key did not load into guarded memory")
	}

	serialized, err := s.Serialize(structure)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if string(serialized) != legacyPreKeyJSON {
		t.Errorf("re-serialized layout changed:\ngot  %s\nwant %s", serialized, legacyPreKeyJSON)
	}
}

func TestJSONSignedPreKeyRecordSerializerLegacyLayout(t *testing.T) {
	s := &JSONSignedPreKeyRecordSerializer{}

	structure, err := s.Deserialize([]byte(legacySignedPreKeyJSON))
	if err != nil {
		t.Fatalf("Deserialize legacy record: %v", err)
	}
	defer structure.Zeroize()

	if !structure.PrivateKey.EqualTo([]byte{0x02}) {
		t.Error("private key did not load into guarded memory")
	}

	serialized, err := s.Serialize(structure)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if string(serialized) != legacySignedPreKeyJSON {
		t.Errorf("re-serialized layout changed:\ngot  %s\nwant %s", serialized, legacySignedPreKeyJSON)
	}
}

func TestJSONStateSerializerLegacyLayout(t *testing.T) {
	s := &JSONStateSerializer{}

	structure, err := s.Deserialize([]byte(legacyStateJSON))
	if err != nil {
		t.Fatalf("Deserialize legacy state: %v", err)
	}
	defer structure.Zeroize()

	if !structure.RootKey.EqualTo([]byte{0x01, 0x02}) {
		t.Error("root key did not load into guarded memory")
	}
	if !structure.PqRatchetState.EqualTo([]byte{0x09}) {
		t.Error("PQ ratchet state did not load into guarded memory")
	}

	serialized, err := s.Serialize(structure)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if string(serialized) != legacyStateJSON {
		t.Errorf("re-serialized layout changed:\ngot  %s\nwant %s", serialized, legacyStateJSON)
	}
}

// TestProtobufStateSerializerGuardedRoundTrip covers the protobuf path, where
// the guarded material has to be read out of guarded memory on the way in and
// moved back into it on the way out, without changing the wire bytes.
func TestProtobufStateSerializerGuardedRoundTrip(t *testing.T) {
	s := &ProtobufStateSerializer{}
	rootKey := bytes.Repeat([]byte{0x0C}, 32)
	ratchetPrivate := bytes.Repeat([]byte{0x0D}, 32)

	original := &record.StateStructure{
		SessionVersion: 4,
		RootKey:        mustGuard(t, rootKey),
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic:  bytes.Repeat([]byte{0x05}, 33),
			SenderRatchetKeyPrivate: mustGuard(t, ratchetPrivate),
		},
	}
	defer original.Zeroize()

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	decoded, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer decoded.Zeroize()

	if !decoded.RootKey.EqualTo(rootKey) {
		t.Error("root key did not survive the protobuf round trip")
	}
	if !decoded.SenderChain.SenderRatchetKeyPrivate.EqualTo(ratchetPrivate) {
		t.Error("sender ratchet private key did not survive the protobuf round trip")
	}

	decoded.Zeroize()
	if !decoded.RootKey.IsDestroyed() || !decoded.SenderChain.SenderRatchetKeyPrivate.IsDestroyed() {
		t.Error("Zeroize left guarded material alive")
	}
}

// TestProtobufStateSerializerRejectsTooManyReceiverChains covers the bounds
// check that runs after the root key has already been moved into guarded
// memory: the failed decode must not strand that allocation.
func TestProtobufStateSerializerRejectsTooManyReceiverChains(t *testing.T) {
	s := &ProtobufStateSerializer{}
	original := &record.StateStructure{
		SessionVersion: 4,
		RootKey:        mustGuard(t, bytes.Repeat([]byte{0x0C}, 32)),
	}
	defer original.Zeroize()

	for i := 0; i < 6; i++ {
		original.ReceiverChains = append(original.ReceiverChains, &record.ChainStructure{
			SenderRatchetKeyPublic:  bytes.Repeat([]byte{0x05}, 33),
			SenderRatchetKeyPrivate: mustGuard(t, bytes.Repeat([]byte{byte(i)}, 32)),
		})
	}

	serialized, err := s.Serialize(original)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	decoded, err := s.Deserialize(serialized)
	if err == nil {
		decoded.Zeroize()
		t.Fatal("expected a bounds error for six receiver chains")
	}
	if decoded != nil {
		t.Error("a failed decode must not return a structure")
	}
}

// TestProtobufSessionSerializerRejectsTooManyPreviousSessions covers the bound
// on archived states. It is enforced before anything is decoded, so no guarded
// allocation is made for a record that is refused outright.
func TestProtobufSessionSerializerRejectsTooManyPreviousSessions(t *testing.T) {
	s := &ProtobufSessionSerializer{}
	stateSerializer := &ProtobufStateSerializer{}

	state := &record.StateStructure{
		SessionVersion: 4,
		RootKey:        mustGuard(t, bytes.Repeat([]byte{0x0C}, 32)),
	}
	defer state.Zeroize()
	stateBytes, err := stateSerializer.Serialize(state)
	if err != nil {
		t.Fatalf("Serialize state: %v", err)
	}

	structure := &record.SessionStructure{}
	for i := 0; i < 41; i++ {
		previous, dErr := stateSerializer.Deserialize(stateBytes)
		if dErr != nil {
			t.Fatalf("Deserialize state: %v", dErr)
		}
		structure.PreviousStates = append(structure.PreviousStates, previous)
	}
	defer structure.Zeroize()

	serialized, err := s.Serialize(structure)
	if err != nil {
		t.Fatalf("Serialize session: %v", err)
	}

	decoded, err := s.Deserialize(serialized)
	if err == nil {
		decoded.Zeroize()
		t.Fatal("expected a bounds error for 41 previous sessions")
	}
	if decoded != nil {
		t.Error("a failed decode must not return a structure")
	}
}

// TestProtobufSessionSerializerRejectsMalformedPreviousSession covers a failure
// that lands after the current session and an earlier previous session have
// already been decoded into guarded memory.
func TestProtobufSessionSerializerRejectsMalformedPreviousSession(t *testing.T) {
	s := &ProtobufSessionSerializer{}
	stateSerializer := &ProtobufStateSerializer{}

	state := &record.StateStructure{
		SessionVersion: 4,
		RootKey:        mustGuard(t, bytes.Repeat([]byte{0x0C}, 32)),
	}
	defer state.Zeroize()
	stateBytes, err := stateSerializer.Serialize(state)
	if err != nil {
		t.Fatalf("Serialize state: %v", err)
	}

	current, err := stateSerializer.Deserialize(stateBytes)
	if err != nil {
		t.Fatalf("Deserialize state: %v", err)
	}
	previous, err := stateSerializer.Deserialize(stateBytes)
	if err != nil {
		t.Fatalf("Deserialize state: %v", err)
	}
	structure := &record.SessionStructure{
		SessionState:   current,
		PreviousStates: []*record.StateStructure{previous},
	}
	defer structure.Zeroize()

	serialized, err := s.Serialize(structure)
	if err != nil {
		t.Fatalf("Serialize session: %v", err)
	}

	// Append a second previous session (field 2) whose payload is not a valid
	// SessionStructure, so the failure lands after two states are decoded.
	malformed := append(append([]byte{}, serialized...), 2<<3|2, 0x02, 0xFF, 0xFF)

	decoded, err := s.Deserialize(malformed)
	if err == nil {
		decoded.Zeroize()
		t.Fatal("expected an error for a malformed previous session")
	}
	if decoded != nil {
		t.Error("a failed decode must not return a structure")
	}
}

// TestJSONPreKeyRecordSerializerNullSupersedingValue covers a stored record in
// which a null supersedes an earlier occurrence of the private key. The
// decode has to end with no material and, critically, must not leave the
// allocation made for the first occurrence behind.
func TestJSONPreKeyRecordSerializerNullSupersedingValue(t *testing.T) {
	s := &JSONPreKeyRecordSerializer{}

	structure, err := s.Deserialize([]byte(`{"ID":5,"PublicKey":"AQ==","PrivateKey":"Ag==","PrivateKey":null}`))
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer structure.Zeroize()

	if !structure.PrivateKey.IsDestroyed() {
		t.Error("the superseded private key was not released")
	}
	if structure.PrivateKey.BytesOrNil() != nil {
		t.Error("expected no private key material after the null")
	}
}

// TestJSONStateSerializerDecodeOverPopulatedStructure covers encoding/json
// reusing a structure that already holds guarded material: the material being
// replaced must be destroyed rather than abandoned.
func TestJSONStateSerializerDecodeOverPopulatedStructure(t *testing.T) {
	var structure record.StateStructure
	if err := json.Unmarshal([]byte(legacyStateJSON), &structure); err != nil {
		t.Fatalf("first decode: %v", err)
	}
	// A copy of the field shares the same guarded buffer, so it can observe
	// what the second decode does with it.
	previousRootKey := structure.RootKey
	previousPqState := structure.PqRatchetState

	if err := json.Unmarshal([]byte(legacyStateJSON), &structure); err != nil {
		t.Fatalf("second decode: %v", err)
	}
	defer structure.Zeroize()

	if !previousRootKey.IsDestroyed() {
		t.Error("the replaced root key was abandoned instead of destroyed")
	}
	if !previousPqState.IsDestroyed() {
		t.Error("the replaced PQ ratchet state was abandoned instead of destroyed")
	}
	if !structure.RootKey.EqualTo([]byte{0x01, 0x02}) {
		t.Error("the second decode did not repopulate the root key")
	}
}
