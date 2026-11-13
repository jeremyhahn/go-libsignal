package spqr

import (
	"bytes"
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
