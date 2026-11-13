package spqr

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/pqratchetpb"
	"google.golang.org/protobuf/proto"
)

// captureStateMessage replaces marshalStateMessage for one test. It records
// the authenticator copies the inner V1 message carries and the chain
// copies, then encodes normally or fails with fail.
func captureStateMessage(t *testing.T, fail error) (auth *[][]byte, chain *[][]byte) {
	t.Helper()
	auth, chain = new([][]byte), new([][]byte)
	orig := marshalStateMessage
	t.Cleanup(func() { marshalStateMessage = orig })
	marshalStateMessage = func(pb *pqratchetpb.PqRatchetState) ([]byte, error) {
		a := pb.GetV1().GetKeysUnsampled().GetUc().GetAuth()
		for _, b := range [][]byte{a.GetRootKey(), a.GetMacKey()} {
			if len(b) > 0 {
				*auth = append(*auth, b)
			}
		}
		c := pb.GetChain()
		*chain = append(*chain, c.GetNextRoot())
		for _, l := range c.GetLinks() {
			for _, b := range [][]byte{l.GetSend().GetNext(), l.GetSend().GetPrev(), l.GetRecv().GetNext(), l.GetRecv().GetPrev()} {
				if len(b) > 0 {
					*chain = append(*chain, b)
				}
			}
		}
		if fail != nil {
			return nil, fail
		}
		return proto.Marshal(pb)
	}
	return auth, chain
}

// newBraidSPQR returns a SPQR whose braid is a KeysUnsampled state with a
// live authenticator, so the marshaled message carries authenticator copies.
func newBraidSPQR(t *testing.T) *SPQR {
	t.Helper()
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysUnsampled, 0, mlkembraid.DefaultChunkSize,
		makeTestAuth(t, 61), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}
	s, err := Init(sharedSecretForTest(61), DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.braid = mlkembraid.BraidFromState(state, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	return s
}

func assertWiped(t *testing.T, what string, bufs [][]byte) {
	t.Helper()
	if len(bufs) == 0 {
		t.Fatalf("%s: no copies captured", what)
	}
	for i, b := range bufs {
		if len(b) == 0 || !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s copy %d not wiped: %x", what, i, b)
		}
	}
}

// TestMarshalStateProto_WipesBraidCopies checks, through MarshalStateProto,
// that the authenticator copies the braid tracker owns are zeroed after a
// successful marshal and after an encoding failure, while the live
// authenticator and the returned bytes stay intact.
func TestMarshalStateProto_WipesBraidCopies(t *testing.T) {
	s := newBraidSPQR(t)
	defer s.Zeroize()
	liveRoot := append([]byte(nil), mustCopy(s.braid.State().ProtoAuth().ProtoAuthRootKey())...)

	auth, _ := captureStateMessage(t, nil)
	out, err := MarshalStateProto(s)
	if err != nil {
		t.Fatalf("MarshalStateProto: %v", err)
	}
	assertWiped(t, "success: auth", *auth)
	again, err := MarshalStateProto(s)
	if err != nil || !bytes.Equal(out, again) {
		t.Fatalf("returned bytes or live state changed: equal=%v err=%v", bytes.Equal(out, again), err)
	}
	if got := mustCopy(s.braid.State().ProtoAuth().ProtoAuthRootKey()); !bytes.Equal(got, liveRoot) {
		t.Fatal("wiping the copies changed the live root key")
	}

	auth, _ = captureStateMessage(t, errors.New("injected encode failure"))
	if _, err := MarshalStateProto(s); err == nil {
		t.Fatal("want the injected failure")
	}
	assertWiped(t, "failure: auth", *auth)
	if got := mustCopy(s.braid.State().ProtoAuth().ProtoAuthRootKey()); !bytes.Equal(got, liveRoot) {
		t.Fatal("the failure path changed the live root key")
	}
}

func TestBraidCopies_NilSafe(t *testing.T) {
	var o *braidCopies
	if got := o.keep([]byte{1}); !bytes.Equal(got, []byte{1}) {
		t.Fatalf("keep on nil tracker returned %x", got)
	}
	o.wipe()
}
