package net

import (
	"encoding/hex"
	"testing"
)

func TestEnclaveKind_URLPath(t *testing.T) {
	mrEnclave := []byte{0xAB, 0xCD, 0xEF}
	enclaveHex := hex.EncodeToString(mrEnclave)

	t.Run("CDSI", func(t *testing.T) {
		path := EnclaveKindCDSI.URLPath(mrEnclave)
		expected := "/v1/" + enclaveHex + "/discovery"
		if path != expected {
			t.Errorf("URLPath = %q, want %q", path, expected)
		}
	})

	t.Run("SvrSgx", func(t *testing.T) {
		path := EnclaveKindSvrSgx.URLPath(mrEnclave)
		expected := "/v1/" + enclaveHex
		if path != expected {
			t.Errorf("URLPath = %q, want %q", path, expected)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		path := EnclaveKind(99).URLPath(mrEnclave)
		expected := "/v1/" + enclaveHex
		if path != expected {
			t.Errorf("URLPath = %q, want %q", path, expected)
		}
	})
}

func TestSvrSgxHandshaker_NilRaftConfig(t *testing.T) {
	h := &SvrSgxHandshaker{}
	params := &EndpointParams{
		MrEnclave:  MrEnclave{Value: []byte{1, 2, 3}, Kind: EnclaveKindSvrSgx},
		RaftConfig: nil,
	}
	_, err := h.NewHandshake(params, []byte("msg"))
	if err == nil {
		t.Fatal("expected error for nil raft config")
	}
}
