package svr

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

func TestFinalizeBackup4(t *testing.T) {
	t.Run("single OK response", func(t *testing.T) {
		resp := makeCreateResponse(svrpb.Response4_OK, 10)
		tries, err := FinalizeBackup4([][]byte{resp})
		if err != nil {
			t.Fatalf("FinalizeBackup4 failed: %v", err)
		}
		if tries != 10 {
			t.Fatalf("tries = %d, want 10", tries)
		}
	})

	t.Run("multiple OK responses min tries", func(t *testing.T) {
		r1 := makeCreateResponse(svrpb.Response4_OK, 10)
		r2 := makeCreateResponse(svrpb.Response4_OK, 5)
		r3 := makeCreateResponse(svrpb.Response4_OK, 8)
		tries, err := FinalizeBackup4([][]byte{r1, r2, r3})
		if err != nil {
			t.Fatalf("FinalizeBackup4 failed: %v", err)
		}
		if tries != 5 {
			t.Fatalf("tries = %d, want 5", tries)
		}
	})

	t.Run("error status", func(t *testing.T) {
		resp := makeCreateResponse(svrpb.Response4_ERROR, 0)
		_, err := FinalizeBackup4([][]byte{resp})
		if err == nil {
			t.Fatal("expected error for ERROR status")
		}
		var svrErr *Error
		if !errors.As(err, &svrErr) {
			t.Fatalf("expected *Error, got %T", err)
		}
	})

	t.Run("empty responses", func(t *testing.T) {
		_, err := FinalizeBackup4(nil)
		if err == nil {
			t.Fatal("expected error for empty responses")
		}
	})

	t.Run("bad protobuf", func(t *testing.T) {
		_, err := FinalizeBackup4([][]byte{{0xff, 0xff}})
		if err == nil {
			t.Fatal("expected error for bad protobuf")
		}
	})

	t.Run("wrong response type", func(t *testing.T) {
		resp := &svrpb.Response4{
			Inner: &svrpb.Response4_Query_{
				Query: &svrpb.Response4_Query{},
			},
		}
		b, _ := proto.Marshal(resp)
		_, err := FinalizeBackup4([][]byte{b})
		if err == nil {
			t.Fatal("expected error for wrong response type")
		}
	})
}

func TestOPRFBackup4RequestCount(t *testing.T) {
	serverIDs := []uint64{1, 2, 3, 4, 5}
	backup, err := NewOPRFBackup4(serverIDs, []byte("pass"), 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}
	if len(backup.Requests) != 5 {
		t.Fatalf("got %d requests, want 5", len(backup.Requests))
	}
	// Each request should be a valid Create message.
	for i, b := range backup.Requests {
		req := &svrpb.Request4{}
		if err := proto.Unmarshal(b, req); err != nil {
			t.Fatalf("request %d: unmarshal failed: %v", i, err)
		}
		inner, ok := req.Inner.(*svrpb.Request4_Create_)
		if !ok {
			t.Fatalf("request %d: expected Create inner type", i)
		}
		cr := inner.Create
		if cr.MaxTries != 10 {
			t.Fatalf("request %d: MaxTries = %d, want 10", i, cr.MaxTries)
		}
		if len(cr.OprfSecretshare) != 32 {
			t.Fatalf("request %d: OprfSecretshare length = %d, want 32", i, len(cr.OprfSecretshare))
		}
		if len(cr.AuthCommitment) != 32 {
			t.Fatalf("request %d: AuthCommitment length = %d, want 32", i, len(cr.AuthCommitment))
		}
		if len(cr.EncryptionSecretshare) != 32 {
			t.Fatalf("request %d: EncryptionSecretshare length = %d, want 32", i, len(cr.EncryptionSecretshare))
		}
		if len(cr.ZeroSecretshare) != 32 {
			t.Fatalf("request %d: ZeroSecretshare length = %d, want 32", i, len(cr.ZeroSecretshare))
		}
	}
}

func makeCreateResponse(status svrpb.Response4_Status, tries uint32) []byte {
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Create_{
			Create: &svrpb.Response4_Create{
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
