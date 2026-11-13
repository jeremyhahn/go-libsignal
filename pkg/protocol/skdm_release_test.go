//go:build !fips140only

package protocol

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// TestSenderKeyDistributionMessage_ReleaseWipesSeed checks that the message
// keeps its chain key seed guarded, serializes it from inside the borrow,
// and that Release destroys it so no copy of the seed is left behind.
func TestSenderKeyDistributionMessage_ReleaseWipesSeed(t *testing.T) {
	serializer := &jsonSenderKeyDistributionMessageSerializer{}
	signingKey := newTestKeyPair(t)
	chainKey := validChainKey()
	want := append([]byte(nil), chainKey...)

	msg := NewSenderKeyDistributionMessage([16]byte{}, 1, 10, chainKey, signingKey.PublicKey(), serializer, SenderKeyCurrentVersion)
	if !bytes.Equal(chainKey, want) {
		t.Fatal("the constructor wiped the caller's chain key")
	}
	if msg.chainKey.IsDestroyed() {
		t.Fatal("the seed is not held guarded")
	}
	if !secrettest.Matches(t, msg.chainKey, want) {
		t.Fatal("the guarded seed does not match the input chain key")
	}
	out, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	parsed, err := NewSenderKeyDistributionMessageFromBytes(out, serializer)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer parsed.Release()
	if !secrettest.Matches(t, parsed.chainKey, want) {
		t.Fatal("the round-tripped seed does not match the input chain key")
	}

	msg.Release()
	if !msg.chainKey.IsDestroyed() {
		t.Fatal("Release left the seed alive")
	}
	if !secrettest.Empty(msg.chainKey) {
		t.Fatal("the seed still lends material after Release")
	}
	if msg.ChainKey() != nil {
		t.Fatal("ChainKey after Release: want nil")
	}
	if _, err := msg.Serialize(); err == nil {
		t.Fatal("Serialize after Release: want an error")
	}
	msg.Release() // idempotent
	(*SenderKeyDistributionMessage)(nil).Release()
}

// recordingSKDMSerializer wraps a serializer and keeps the structure its
// Deserialize returns, so a test can check what FromBytes leaves in the
// decoder's buffers. mutate, if set, edits the structure before FromBytes
// sees it.
type recordingSKDMSerializer struct {
	SenderKeyDistributionMessageSerializer
	decoded *SenderKeyDistributionMessageStructure
	mutate  func(*SenderKeyDistributionMessageStructure)
}

func (r *recordingSKDMSerializer) Deserialize(b []byte) (*SenderKeyDistributionMessageStructure, error) {
	s, err := r.SenderKeyDistributionMessageSerializer.Deserialize(b)
	if s != nil && r.mutate != nil {
		r.mutate(s)
	}
	r.decoded = s
	return s, err
}

// requireWipedDecoderSeed fails unless the decoder's chain key buffer is a
// 32-byte buffer that holds only zeros.
func requireWipedDecoderSeed(t *testing.T, decoded *SenderKeyDistributionMessageStructure) {
	t.Helper()
	if decoded == nil || len(decoded.ChainKey) != 32 {
		t.Fatal("the decoder did not hand FromBytes a 32-byte chain key")
	}
	for i, v := range decoded.ChainKey {
		if v != 0 {
			t.Fatalf("FromBytes left the decoder's chain key unwiped at byte %d", i)
		}
	}
}

// TestSenderKeyDistributionMessageFromBytes_WipesDecoderSeed checks that
// FromBytes wipes the chain key buffer the decoder allocated, both when it
// returns a message and when validation fails after decoding. The parsed
// seed is checked inside the borrow.
func TestSenderKeyDistributionMessageFromBytes_WipesDecoderSeed(t *testing.T) {
	signingKey := newTestKeyPair(t)
	want := validChainKey()
	msg := NewSenderKeyDistributionMessage([16]byte{}, 1, 10, want, signingKey.PublicKey(),
		&jsonSenderKeyDistributionMessageSerializer{}, SenderKeyCurrentVersion)
	defer msg.Release()
	out, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	t.Run("success", func(t *testing.T) {
		rec := &recordingSKDMSerializer{SenderKeyDistributionMessageSerializer: &jsonSenderKeyDistributionMessageSerializer{}}
		parsed, err := NewSenderKeyDistributionMessageFromBytes(out, rec)
		if err != nil {
			t.Fatalf("FromBytes: %v", err)
		}
		defer parsed.Release()
		requireWipedDecoderSeed(t, rec.decoded)
		if !secrettest.Matches(t, parsed.chainKey, want) {
			t.Fatal("the parsed seed does not match the serialized chain key")
		}
	})

	t.Run("validation error", func(t *testing.T) {
		rec := &recordingSKDMSerializer{
			SenderKeyDistributionMessageSerializer: &jsonSenderKeyDistributionMessageSerializer{},
			mutate: func(s *SenderKeyDistributionMessageStructure) {
				s.SigningKey = s.SigningKey[:len(s.SigningKey)-1]
			},
		}
		parsed, err := NewSenderKeyDistributionMessageFromBytes(out, rec)
		if err == nil {
			parsed.Release()
			t.Fatal("FromBytes with a short signing key: want an error")
		}
		requireWipedDecoderSeed(t, rec.decoded)
	})
}
