// Conformance test: SPQR pq_ratchet field-byte parity vs Rust libsignal.
//
// Rust source: SparsePostQuantumRatchet crate v1.5.1 (tag v1.5.1) — spqr::send.
//
// The bytes under test are exactly what rides in SignalMessage.pq_ratchet
// (proto field 5): the serialized post-quantum ratchet message. The fixture is
// emitted by tests/interop/rust/src/bin/wire_emitter.rs::emit_spqr_pq_ratchet,
// which runs the Rust SPQR send step against a fixed auth_key and a deterministic
// RNG seed.
//
// Loads the Rust-emitted wire/spqr_pq_ratchet.json fixture and verifies:
//  1. The pq_ratchet message begins with the SCKA wire version byte 0x01.
//  2. Go's pkg/spqr.Recv accepts the Rust-emitted pq_ratchet bytes without error,
//     when the receiver is initialized from the same shared auth_key.
//  3. The receiver-derived message key is byte-identical to the sender key the
//     Rust side derived for the same message.
//
// This closes the gap where SPQR byte-compatibility was only proven by the live
// harness (which shells out to the Rust binary at test time) or Go-internal
// round-trips. Here the bytes are a static Rust-emitted fixture, and Go must
// independently match them.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type spqrPqRatchetFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			AuthKeyHex string `json:"auth_key_hex"`
			Direction  string `json:"direction"`
			Version    uint32 `json:"version"`
			MinVersion uint32 `json:"min_version"`
			MaxJump    uint32 `json:"max_jump"`
			MaxOOOKeys uint32 `json:"max_ooo_keys"`
			SendSeed   uint64 `json:"send_seed"`
		} `json:"inputs"`
		Expected struct {
			PqRatchetHex string `json:"pq_ratchet_hex"`
			SenderKeyHex string `json:"sender_key_hex"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestSPQRPqRatchetWire validates that Go's pkg/spqr accepts the Rust-emitted
// pq_ratchet wire bytes and derives a byte-identical message key.
func TestSPQRPqRatchetWire(t *testing.T) {
	raw := loader.MustRead("wire/spqr_pq_ratchet.json")

	var fx spqrPqRatchetFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			authKey := mustHex(t, v.Inputs.AuthKeyHex)
			pqRatchet := mustHex(t, v.Expected.PqRatchetHex)
			wantKey := mustHex(t, v.Expected.SenderKeyHex)

			if len(authKey) != 32 {
				t.Fatalf("auth_key must be 32 bytes, got %d", len(authKey))
			}
			if len(pqRatchet) == 0 {
				t.Fatal("pq_ratchet message is empty")
			}

			// The pq_ratchet message must begin with the SCKA wire version byte.
			if pqRatchet[0] != 0x01 {
				t.Errorf("pq_ratchet version byte: got 0x%02x, want 0x01", pqRatchet[0])
			}

			// The Rust sender used direction A2B; the Go receiver must use the
			// opposite direction (B2A) so the send/receive chain keys line up.
			if v.Inputs.Direction != "a2b" {
				t.Fatalf("unexpected fixture direction %q (expected a2b)", v.Inputs.Direction)
			}

			// Initialize a B2A receiver from the same shared auth_key. MinVersion
			// V1 forces negotiation to resolve on the first received message, and
			// the chain params match spqr ChainParams::default() (25000 / 2000).
			receiverState, err := spqr.InitialStateWithParams(spqr.Params{
				AuthKey:    authKey,
				Version:    spqr.Version(v.Inputs.Version),
				Direction:  spqr.DirectionB2A,
				MinVersion: spqr.Version(v.Inputs.MinVersion),
				MaxJump:    v.Inputs.MaxJump,
				MaxOOOKeys: v.Inputs.MaxOOOKeys,
			})
			if err != nil {
				t.Fatalf("spqr.InitialStateWithParams: %v", err)
			}

			// Go must accept the Rust-emitted pq_ratchet bytes.
			_, gotKey, err := spqr.Recv(receiverState, pqRatchet)
			if err != nil {
				t.Fatalf("spqr.Recv rejected Rust pq_ratchet bytes: %v", err)
			}
			if gotKey == nil {
				t.Fatal("spqr.Recv returned a nil message key")
			}

			// The derived key must be byte-identical to the Rust sender key.
			if hex.EncodeToString(gotKey) != hex.EncodeToString(wantKey) {
				t.Errorf("message key mismatch:\n  go:   %x\n  rust: %x", gotKey, wantKey)
			}
		})
	}
}
