package serialize

import (
	"bytes"
	"errors"
	"testing"

	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"google.golang.org/protobuf/proto"
)

// captureOwnedCopies records the buffers every tracker a serializer creates
// owns at each encode (wipe clears the tracker afterwards), and makes the
// encoder fail with fail when it is non-nil.
func captureOwnedCopies(t *testing.T, fail error) *[][]byte {
	t.Helper()
	var trackers []*ownedCopies
	got := new([][]byte)
	origNew, origMarshal := newOwnedCopies, marshalRecord
	t.Cleanup(func() { newOwnedCopies, marshalRecord = origNew, origMarshal })
	newOwnedCopies = func() *ownedCopies {
		o := &ownedCopies{}
		trackers = append(trackers, o)
		return o
	}
	marshalRecord = func(m proto.Message) ([]byte, error) {
		for _, o := range trackers {
			*got = append(*got, o.bufs...)
		}
		if fail != nil {
			return nil, fail
		}
		return proto.Marshal(m)
	}
	return got
}

func assertOwnedWiped(t *testing.T, what string, bufs [][]byte) {
	t.Helper()
	n := 0
	for i, b := range bufs {
		if len(b) == 0 {
			continue
		}
		n++
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s: owned copy %d not wiped: %x", what, i, b)
		}
	}
	if n == 0 {
		t.Fatalf("%s: no owned copies captured", what)
	}
}

// TestRecordSerializers_WipeOwnedCopies checks, through each record
// serializer's Serialize, that the secret copies the tracker owns are zeroed
// after success and after an encoding failure, while the live keys and the
// returned bytes stay intact.
func TestRecordSerializers_WipeOwnedCopies(t *testing.T) {
	session := &record.SessionStructure{
		SessionState:   chainStateFixture(t),
		PreviousStates: []*record.StateStructure{chainStateFixture(t)},
	}
	preKey := &record.PreKeyStructure{ID: 5, PublicKey: []byte{0x01}, PrivateKey: mustGuard(t, []byte{0x02})}
	signed := &record.SignedPreKeyStructure{ID: 6, PublicKey: []byte{0x01}, PrivateKey: mustGuard(t, []byte{0x03})}
	senderKey := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{senderKeyStateFixture(t)},
	}

	for _, tc := range []struct {
		name      string
		serialize func() ([]byte, error)
	}{
		{"state", func() ([]byte, error) { return (&ProtobufStateSerializer{}).Serialize(session.SessionState) }},
		{"session", func() ([]byte, error) { return (&ProtobufSessionSerializer{}).Serialize(session) }},
		{"prekey", func() ([]byte, error) { return (&ProtobufPreKeyRecordSerializer{}).Serialize(preKey) }},
		{"signed prekey", func() ([]byte, error) { return (&ProtobufSignedPreKeyRecordSerializer{}).Serialize(signed) }},
		{"sender key state", func() ([]byte, error) {
			return (&ProtobufSenderKeyStateSerializer{}).Serialize(senderKey.SenderKeyStates[0])
		}},
		{"sender key record", func() ([]byte, error) { return (&ProtobufSenderKeyRecordSerializer{}).Serialize(senderKey) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trackers := captureOwnedCopies(t, nil)
			out, err := tc.serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			assertOwnedWiped(t, "success", *trackers)

			trackers = captureOwnedCopies(t, errors.New("injected encode failure"))
			if _, err := tc.serialize(); err == nil {
				t.Fatal("want the injected failure")
			}
			assertOwnedWiped(t, "failure", *trackers)

			_ = captureOwnedCopies(t, nil)
			again, err := tc.serialize()
			if err != nil || !bytes.Equal(out, again) {
				t.Fatalf("returned bytes or live keys changed: equal=%v err=%v", bytes.Equal(out, again), err)
			}
		})
	}
}
