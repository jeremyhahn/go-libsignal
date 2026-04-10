package svr

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

func TestQuery4Requests(t *testing.T) {
	q := Query4{}

	t.Run("single request", func(t *testing.T) {
		b, err := q.Requests()
		if err != nil {
			t.Fatalf("Requests() failed: %v", err)
		}
		req := &svrpb.Request4{}
		if err := proto.Unmarshal(b, req); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if _, ok := req.Inner.(*svrpb.Request4_Query_); !ok {
			t.Fatal("expected Query inner type")
		}
	})

	t.Run("requests n", func(t *testing.T) {
		reqs, err := q.RequestsN(3)
		if err != nil {
			t.Fatalf("RequestsN(3) failed: %v", err)
		}
		if len(reqs) != 3 {
			t.Fatalf("got %d requests, want 3", len(reqs))
		}
		for i, b := range reqs {
			req := &svrpb.Request4{}
			if err := proto.Unmarshal(b, req); err != nil {
				t.Fatalf("unmarshal request %d failed: %v", i, err)
			}
			if _, ok := req.Inner.(*svrpb.Request4_Query_); !ok {
				t.Fatalf("request %d: expected Query inner type", i)
			}
		}
	})
}

func TestQuery4Finalize(t *testing.T) {
	q := Query4{}

	t.Run("single OK response", func(t *testing.T) {
		resp := makeQueryResponse(svrpb.Response4_OK, 5)
		tries, err := q.Finalize([][]byte{resp})
		if err != nil {
			t.Fatalf("Finalize failed: %v", err)
		}
		if tries != 5 {
			t.Fatalf("tries = %d, want 5", tries)
		}
	})

	t.Run("multiple OK responses min tries", func(t *testing.T) {
		r1 := makeQueryResponse(svrpb.Response4_OK, 10)
		r2 := makeQueryResponse(svrpb.Response4_OK, 3)
		r3 := makeQueryResponse(svrpb.Response4_OK, 7)
		tries, err := q.Finalize([][]byte{r1, r2, r3})
		if err != nil {
			t.Fatalf("Finalize failed: %v", err)
		}
		if tries != 3 {
			t.Fatalf("tries = %d, want 3", tries)
		}
	})

	t.Run("missing status", func(t *testing.T) {
		resp := makeQueryResponse(svrpb.Response4_MISSING, 0)
		_, err := q.Finalize([][]byte{resp})
		if err == nil {
			t.Fatal("expected error for MISSING status")
		}
		var svrErr *Error
		if !errors.As(err, &svrErr) {
			t.Fatalf("expected *Error, got %T", err)
		}
	})

	t.Run("empty responses", func(t *testing.T) {
		_, err := q.Finalize(nil)
		if err == nil {
			t.Fatal("expected error for empty responses")
		}
	})

	t.Run("bad protobuf", func(t *testing.T) {
		_, err := q.Finalize([][]byte{{0xff, 0xff}})
		if err == nil {
			t.Fatal("expected error for bad protobuf")
		}
	})

	t.Run("wrong response type", func(t *testing.T) {
		resp := &svrpb.Response4{
			Inner: &svrpb.Response4_Remove_{
				Remove: &svrpb.Response4_Remove{},
			},
		}
		b, _ := proto.Marshal(resp)
		_, err := q.Finalize([][]byte{b})
		if err == nil {
			t.Fatal("expected error for wrong response type")
		}
	})

	t.Run("error status returns error", func(t *testing.T) {
		resp := makeQueryResponse(svrpb.Response4_ERROR, 2)
		_, err := q.Finalize([][]byte{resp})
		if err == nil {
			t.Fatal("expected error for ERROR status")
		}
		var svrErr *Error
		if !errors.As(err, &svrErr) {
			t.Fatalf("expected *Error, got %T", err)
		}
		if svrErr.Status() != ResponseStatus(svrpb.Response4_ERROR) {
			t.Fatalf("status = %v, want ERROR", svrErr.Status())
		}
	})
}

func makeQueryResponse(status svrpb.Response4_Status, tries uint32) []byte {
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Query_{
			Query: &svrpb.Response4_Query{
				Status:         status,
				TriesRemaining: tries,
			},
		},
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		panic(err)
	}
	return b
}
