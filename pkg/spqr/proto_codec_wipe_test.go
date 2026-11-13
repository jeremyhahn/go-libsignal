package spqr

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/proto/pqratchetpb"
)

func TestWipeChainProto_ZeroizesOwnedCopies(t *testing.T) {
	fill := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	c := &pqratchetpb.Chain{
		NextRoot: fill(1),
		Links: []*pqratchetpb.Chain_Epoch{
			{
				Send: &pqratchetpb.Chain_Epoch_EpochDirection{Next: fill(2)},
				Recv: &pqratchetpb.Chain_Epoch_EpochDirection{Next: fill(3), Prev: fill(4)},
			},
			nil,
			{Send: nil, Recv: &pqratchetpb.Chain_Epoch_EpochDirection{Next: fill(5)}},
		},
	}
	bufs := [][]byte{c.NextRoot, c.Links[0].Send.Next, c.Links[0].Recv.Next, c.Links[0].Recv.Prev, c.Links[2].Recv.Next}

	wipeChainProto(c)

	zero := make([]byte, 32)
	for i, b := range bufs {
		if !bytes.Equal(b, zero) {
			t.Errorf("buffer %d not wiped: %x", i, b)
		}
	}
	wipeChainProto(nil) // nil-safe
}

// TestMarshalStateProto_WipesChainCopies checks, through MarshalStateProto,
// that the root and epoch key copies the chain message carries are zeroed
// after a successful marshal and after an encoding failure, while the live
// chain and the returned bytes stay intact.
func TestMarshalStateProto_WipesChainCopies(t *testing.T) {
	s, err := Init(sharedSecretForTest(62), DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	_, chain := captureStateMessage(t, nil)
	out, err := MarshalStateProto(s)
	if err != nil {
		t.Fatalf("MarshalStateProto: %v", err)
	}
	assertWiped(t, "success: chain", *chain)
	again, err := MarshalStateProto(s)
	if err != nil || !bytes.Equal(out, again) {
		t.Fatalf("returned bytes or live chain changed: equal=%v err=%v", bytes.Equal(out, again), err)
	}

	_, chain = captureStateMessage(t, errors.New("injected encode failure"))
	if _, err := MarshalStateProto(s); err == nil {
		t.Fatal("want the injected failure")
	}
	assertWiped(t, "failure: chain", *chain)

	_, _ = captureStateMessage(t, nil)
	after, err := MarshalStateProto(s)
	if err != nil || !bytes.Equal(out, after) {
		t.Fatalf("the failure path changed the live chain: equal=%v err=%v", bytes.Equal(out, after), err)
	}
}
