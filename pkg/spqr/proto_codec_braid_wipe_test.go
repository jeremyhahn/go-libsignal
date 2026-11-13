package spqr

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/pqratchetpb"
)

// TestBraidCopies_WipedOnConversionFailure checks that the authenticator
// copies a failed braid conversion already took are recorded and wiped,
// and that wiping them leaves the live state's keys intact.
func TestBraidCopies_WipedOnConversionFailure(t *testing.T) {
	auth := makeTestAuth(t, 61)
	// HeaderSent with no dk: authToProto copies the keys, then the
	// conversion fails on the missing dk.
	state, err := mlkembraid.ProtoSetFromFields(
		mlkembraid.StateHeaderSent, 0, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil,
		makeTestEncoder(t, mlkembraid.MLKEM768EKSize),
		nil, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("ProtoSetFromFields: %v", err)
	}

	o := &braidCopies{}
	if err := stateKindToInnerState(state, &pqratchetpb.V1State{}, o); err == nil {
		t.Fatal("expected the missing-dk conversion to fail")
	}
	if len(o.bufs) == 0 {
		t.Fatal("the authenticator copies were not recorded")
	}
	bufs := append([][]byte(nil), o.bufs...)
	o.wipe()
	for i, b := range bufs {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("recorded copy %d not wiped", i)
		}
	}

	live := state.ProtoAuth().ProtoAuthRootKey()
	if len(live) == 0 || bytes.Equal(live, make([]byte, len(live))) {
		t.Fatal("wiping the copies zeroed the live root key")
	}
}

func TestBraidCopies_NilSafe(t *testing.T) {
	var o *braidCopies
	if got := o.keep([]byte{1}); !bytes.Equal(got, []byte{1}) {
		t.Fatalf("keep on nil tracker returned %x", got)
	}
	o.wipe()
}
