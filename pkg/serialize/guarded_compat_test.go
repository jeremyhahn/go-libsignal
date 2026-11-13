package serialize

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
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

	// The chain key and the message key components made the same move, one
	// commit later. This literal is the layout the []byte fields produced,
	// captured from the tree immediately before the conversion. It carries both
	// message-key forms deliberately: the derived form, where SeedMaterial is
	// absent entirely (the field's omitempty, now omitzero), and the seed-only
	// form, where the other three are present as null.
	legacyChainStateJSON = `{"LocalIdentityPublic":null,"LocalRegistrationID":0,"NeedsRefresh":false,` +
		`"PendingKeyExchange":null,"PendingPreKey":null,"PreviousCounter":0,` +
		`"ReceiverChains":[{"SenderRatchetKeyPublic":"BQI=","SenderRatchetKeyPrivate":null,` +
		`"ChainKey":{"Key":"Dw==","Index":6},"MessageKeys":null}],` +
		`"RemoteIdentityPublic":null,"RemoteRegistrationID":0,"RootKey":"AQI=","SenderBaseKey":null,` +
		`"SenderChain":{"SenderRatchetKeyPublic":"BQE=","SenderRatchetKeyPrivate":"Ag==",` +
		`"ChainKey":{"Key":"Cg==","Index":4},"MessageKeys":[` +
		`{"CipherKey":"Cw==","MacKey":"DA==","IV":"DQ==","Index":1},` +
		`{"CipherKey":null,"MacKey":null,"IV":null,"Index":2,"SeedMaterial":"Dg=="}]},` +
		`"SessionVersion":3,"PqRatchetState":"CQ=="}`

	// The same fixture through the protobuf serializer, captured from the same
	// pre-conversion tree.
	legacyChainStateProtoHex = "08032202010232220a0205011201021a05080412010a220b080112010b1a010c22010d" +
		"220508022a010e3a0b0a0205021a05080612010f7a0109"
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

// chainStateFixture builds the state whose encodings the two legacy literals
// above record: a sender chain with a chain key and both message-key forms,
// plus a receiver chain carrying only a chain key.
func chainStateFixture(t *testing.T) *record.StateStructure {
	t.Helper()
	return &record.StateStructure{
		SessionVersion: 3,
		RootKey:        mustGuard(t, []byte{0x01, 0x02}),
		PqRatchetState: mustGuard(t, []byte{0x09}),
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic:  []byte{0x05, 0x01},
			SenderRatchetKeyPrivate: mustGuard(t, []byte{0x02}),
			ChainKey:                &chain.KeyStructure{Key: mustGuard(t, []byte{0x0a}), Index: 4},
			MessageKeys: []*message.KeysStructure{
				{
					CipherKey: mustGuard(t, []byte{0x0b}),
					MacKey:    mustGuard(t, []byte{0x0c}),
					IV:        mustGuard(t, []byte{0x0d}),
					Index:     1,
				},
				{Index: 2, SeedMaterial: mustGuard(t, []byte{0x0e})},
			},
		},
		ReceiverChains: []*record.ChainStructure{{
			SenderRatchetKeyPublic: []byte{0x05, 0x02},
			ChainKey:               &chain.KeyStructure{Key: mustGuard(t, []byte{0x0f}), Index: 6},
		}},
	}
}

// TestJSONStateSerializerLegacyChainLayout is the byte-identity gate for moving
// the chain key and the message key components into guarded memory. It asserts
// in both directions: a record written before the conversion still loads, and
// what this tree writes is byte-for-byte what the []byte fields wrote.
func TestJSONStateSerializerLegacyChainLayout(t *testing.T) {
	s := &JSONStateSerializer{}

	t.Run("this tree writes the legacy layout", func(t *testing.T) {
		fixture := chainStateFixture(t)
		defer fixture.Zeroize()

		serialized, err := s.Serialize(fixture)
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		if string(serialized) != legacyChainStateJSON {
			t.Errorf("layout changed:\ngot  %s\nwant %s", serialized, legacyChainStateJSON)
		}
	})

	t.Run("a legacy record still loads and re-serializes verbatim", func(t *testing.T) {
		structure, err := s.Deserialize([]byte(legacyChainStateJSON))
		if err != nil {
			t.Fatalf("Deserialize legacy state: %v", err)
		}
		defer structure.Zeroize()

		if !structure.SenderChain.ChainKey.Key.EqualTo([]byte{0x0a}) {
			t.Error("chain key did not load into guarded memory")
		}
		derived := structure.SenderChain.MessageKeys[0]
		if !derived.CipherKey.EqualTo([]byte{0x0b}) || !derived.MacKey.EqualTo([]byte{0x0c}) ||
			!derived.IV.EqualTo([]byte{0x0d}) {
			t.Error("derived message key components did not load into guarded memory")
		}
		if !derived.SeedMaterial.IsZero() {
			t.Error("derived form must carry no seed material")
		}
		if !structure.SenderChain.MessageKeys[1].SeedMaterial.EqualTo([]byte{0x0e}) {
			t.Error("seed material did not load into guarded memory")
		}

		serialized, err := s.Serialize(structure)
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		if string(serialized) != legacyChainStateJSON {
			t.Errorf("re-serialized layout changed:\ngot  %s\nwant %s", serialized, legacyChainStateJSON)
		}
	})
}

// TestProtobufStateSerializerLegacyChainLayout is the same gate for the wire
// format, which is the one interoperability actually depends on.
func TestProtobufStateSerializerLegacyChainLayout(t *testing.T) {
	s := &ProtobufStateSerializer{}
	fixture := chainStateFixture(t)
	defer fixture.Zeroize()

	serialized, err := s.Serialize(fixture)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if got := hex.EncodeToString(serialized); got != legacyChainStateProtoHex {
		t.Errorf("wire bytes changed:\ngot  %s\nwant %s", got, legacyChainStateProtoHex)
	}

	decoded, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer decoded.Zeroize()

	if !decoded.SenderChain.ChainKey.Key.EqualTo([]byte{0x0a}) {
		t.Error("chain key did not survive the protobuf round trip in guarded memory")
	}
	if !decoded.SenderChain.MessageKeys[1].SeedMaterial.EqualTo([]byte{0x0e}) {
		t.Error("seed material did not survive the protobuf round trip in guarded memory")
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
	if secrettest.Bytes(&structure.PrivateKey) != nil {
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

// The sender-key (group messaging) structures made the same move: the signing
// private key, the sender chain key, and each sender message key's IV, cipher
// key and seed. These literals are the layout the []byte fields produced,
// captured from the tree immediately before that conversion.
//
// The fixture carries both message-key shapes on purpose: one fully populated,
// and one seed-only, where the other two fields render as null. The protobuf
// schema for a sender message key carries only iteration and seed, so the IV
// and cipher key appear in the JSON literal and not the wire one — which is
// exactly the sort of asymmetry a hand-written expectation gets wrong.
const (
	legacySenderKeyStateJSON = `{"Keys":[{"Iteration":1,"IV":"QQ==","CipherKey":"Qg==","Seed":"Qw=="},` +
		`{"Iteration":2,"IV":null,"CipherKey":null,"Seed":"RA=="}],"KeyID":7,"MessageVersion":3,` +
		`"SenderChainKey":{"Iteration":4,"ChainKey":"MTI="},"SigningKeyPrivate":"IiM=",` +
		`"SigningKeyPublic":"BRE="}`

	legacySenderKeyStateProtoHex = "080712060804120231321a080a020511120222232205080112014322050802120144" +
		"2803"
)

// senderKeyStateFixture builds the state whose encodings the two literals above
// record.
func senderKeyStateFixture(t *testing.T) *groupRecord.SenderKeyStateStructure {
	t.Helper()
	return &groupRecord.SenderKeyStateStructure{
		KeyID:             7,
		MessageVersion:    3,
		SigningKeyPublic:  []byte{0x05, 0x11},
		SigningKeyPrivate: mustGuard(t, []byte{0x22, 0x23}),
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: 4,
			ChainKey:  mustGuard(t, []byte{0x31, 0x32}),
		},
		Keys: []*ratchet.SenderMessageKeyStructure{
			{
				Iteration: 1,
				IV:        mustGuard(t, []byte{0x41}),
				CipherKey: mustGuard(t, []byte{0x42}),
				Seed:      mustGuard(t, []byte{0x43}),
			},
			{Iteration: 2, Seed: mustGuard(t, []byte{0x44})},
		},
	}
}

// TestJSONSenderKeyStateSerializerLegacyLayout is the byte-identity gate for
// moving the sender-key material into guarded memory, asserted in both
// directions: what this tree writes must match what the []byte fields wrote,
// and a record written before the conversion must still load.
func TestJSONSenderKeyStateSerializerLegacyLayout(t *testing.T) {
	s := &JSONSenderKeyStateSerializer{}

	t.Run("this tree writes the legacy layout", func(t *testing.T) {
		fixture := senderKeyStateFixture(t)
		defer fixture.Zeroize()

		serialized, err := s.Serialize(fixture)
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		if string(serialized) != legacySenderKeyStateJSON {
			t.Errorf("layout changed:\ngot  %s\nwant %s", serialized, legacySenderKeyStateJSON)
		}
	})

	t.Run("a legacy record still loads and re-serializes verbatim", func(t *testing.T) {
		structure, err := s.Deserialize([]byte(legacySenderKeyStateJSON))
		if err != nil {
			t.Fatalf("Deserialize legacy state: %v", err)
		}
		defer structure.Zeroize()

		if !structure.SigningKeyPrivate.EqualTo([]byte{0x22, 0x23}) {
			t.Error("signing private key did not load into guarded memory")
		}
		if !structure.SenderChainKey.ChainKey.EqualTo([]byte{0x31, 0x32}) {
			t.Error("sender chain key did not load into guarded memory")
		}
		if !structure.Keys[0].IV.EqualTo([]byte{0x41}) || !structure.Keys[0].CipherKey.EqualTo([]byte{0x42}) {
			t.Error("message key components did not load into guarded memory")
		}
		if !structure.Keys[1].IV.IsZero() {
			t.Error("the seed-only key must carry no IV")
		}

		serialized, err := s.Serialize(structure)
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		if string(serialized) != legacySenderKeyStateJSON {
			t.Errorf("re-serialized layout changed:\ngot  %s\nwant %s", serialized, legacySenderKeyStateJSON)
		}
	})
}

// TestProtobufSenderKeyStateSerializerLegacyLayout is the same gate for the
// wire format.
func TestProtobufSenderKeyStateSerializerLegacyLayout(t *testing.T) {
	s := &ProtobufSenderKeyStateSerializer{}
	fixture := senderKeyStateFixture(t)
	defer fixture.Zeroize()

	serialized, err := s.Serialize(fixture)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if got := hex.EncodeToString(serialized); got != legacySenderKeyStateProtoHex {
		t.Errorf("wire bytes changed:\ngot  %s\nwant %s", got, legacySenderKeyStateProtoHex)
	}

	decoded, err := s.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer decoded.Zeroize()

	if !decoded.SigningKeyPrivate.EqualTo([]byte{0x22, 0x23}) {
		t.Error("signing private key did not survive the protobuf round trip in guarded memory")
	}
	if !decoded.SenderChainKey.ChainKey.EqualTo([]byte{0x31, 0x32}) {
		t.Error("sender chain key did not survive the protobuf round trip in guarded memory")
	}
}
