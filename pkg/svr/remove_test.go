package svr

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

func TestRemove4Requests(t *testing.T) {
	r := Remove4{}

	t.Run("single request", func(t *testing.T) {
		b, err := r.Requests()
		if err != nil {
			t.Fatalf("Requests() failed: %v", err)
		}
		req := &svrpb.Request4{}
		if err := proto.Unmarshal(b, req); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if _, ok := req.Inner.(*svrpb.Request4_Remove_); !ok {
			t.Fatal("expected Remove inner type")
		}
	})

	t.Run("requests n", func(t *testing.T) {
		reqs, err := r.RequestsN(5)
		if err != nil {
			t.Fatalf("RequestsN(5) failed: %v", err)
		}
		if len(reqs) != 5 {
			t.Fatalf("got %d requests, want 5", len(reqs))
		}
		for i, b := range reqs {
			req := &svrpb.Request4{}
			if err := proto.Unmarshal(b, req); err != nil {
				t.Fatalf("unmarshal request %d failed: %v", i, err)
			}
			if _, ok := req.Inner.(*svrpb.Request4_Remove_); !ok {
				t.Fatalf("request %d: expected Remove inner type", i)
			}
		}
	})

	t.Run("deterministic content", func(t *testing.T) {
		b1, _ := r.Requests()
		b2, _ := r.Requests()
		if len(b1) != len(b2) {
			t.Fatal("request lengths differ")
		}
		for i := range b1 {
			if b1[i] != b2[i] {
				t.Fatal("requests should be identical")
			}
		}
	})
}
