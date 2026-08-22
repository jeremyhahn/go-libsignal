package ratchet

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewSenderChainKey(t *testing.T) {
	chainKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}

	tests := []struct {
		name      string
		iteration uint32
		chainKey  []byte
	}{
		{
			name:      "zero iteration",
			iteration: 0,
			chainKey:  chainKey,
		},
		{
			name:      "nonzero iteration",
			iteration: 42,
			chainKey:  chainKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := NewSenderChainKey(tt.iteration, tt.chainKey)
			if key.Iteration() != tt.iteration {
				t.Errorf("Iteration() = %d, want %d", key.Iteration(), tt.iteration)
			}
			if !bytes.Equal(key.Seed(), tt.chainKey) {
				t.Errorf("Seed() = %v, want %v", key.Seed(), tt.chainKey)
			}
		})
	}
}

func TestSenderChainKeyNext(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	key := NewSenderChainKey(0, chainKey)

	next, err := key.Next()
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}
	if next.Iteration() != 1 {
		t.Errorf("Next().Iteration() = %d, want 1", next.Iteration())
	}
	if bytes.Equal(next.Seed(), key.Seed()) {
		t.Error("Next().Seed() should differ from original seed")
	}
}

func TestSenderChainKeyNextChain(t *testing.T) {
	// Verify deterministic chain: same seed produces same chain
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i + 10)
	}

	key1 := NewSenderChainKey(0, chainKey)
	key2 := NewSenderChainKey(0, chainKey)

	next1, err := key1.Next()
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}
	next2, err := key2.Next()
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if !bytes.Equal(next1.Seed(), next2.Seed()) {
		t.Error("Deterministic chain: same seed should produce identical next keys")
	}
}

func TestSenderChainKeySenderMessageKey(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	key := NewSenderChainKey(5, chainKey)

	msgKey, err := key.SenderMessageKey()
	if err != nil {
		t.Fatalf("SenderMessageKey() error: %v", err)
	}
	if msgKey == nil {
		t.Fatal("SenderMessageKey() returned nil")
	}
	if msgKey.Iteration() != 5 {
		t.Errorf("SenderMessageKey().Iteration() = %d, want 5", msgKey.Iteration())
	}
}

func TestSenderChainKeySenderMessageKeyDeterministic(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}

	key1 := NewSenderChainKey(0, chainKey)
	key2 := NewSenderChainKey(0, chainKey)

	mk1, err := key1.SenderMessageKey()
	if err != nil {
		t.Fatalf("SenderMessageKey() error: %v", err)
	}
	mk2, err := key2.SenderMessageKey()
	if err != nil {
		t.Fatalf("SenderMessageKey() error: %v", err)
	}

	if !bytes.Equal(mk1.Iv(), mk2.Iv()) {
		t.Error("Same chain key should produce same IV")
	}
	if !bytes.Equal(mk1.CipherKey(), mk2.CipherKey()) {
		t.Error("Same chain key should produce same cipher key")
	}
}

func TestNewSenderChainKeyFromStruct(t *testing.T) {
	structure := &SenderChainKeyStructure{
		Iteration: 10,
		ChainKey:  mustGuard(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}),
	}

	key, err := NewSenderChainKeyFromStruct(structure)

	if err != nil {

		t.Fatalf("NewSenderChainKeyFromStruct: %v", err)

	}
	if key.Iteration() != 10 {
		t.Errorf("Iteration() = %d, want 10", key.Iteration())
	}
	if !bytes.Equal(key.Seed(), structure.ChainKey.BytesOrNil()) {
		t.Error("Seed does not match structure ChainKey")
	}
}

func TestNewSenderChainKeyFromStructZeroIteration(t *testing.T) {
	structure := &SenderChainKeyStructure{
		Iteration: 0,
		ChainKey:  mustGuard(t, make([]byte, 32)),
	}
	key, err := NewSenderChainKeyFromStruct(structure)
	if err != nil {
		t.Fatalf("NewSenderChainKeyFromStruct: %v", err)
	}
	if key.Iteration() != 0 {
		t.Errorf("Iteration() = %d, want 0", key.Iteration())
	}
}

func TestNewStructFromSenderChainKey(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i + 5)
	}
	key := NewSenderChainKey(99, chainKey)

	structure, err := NewStructFromSenderChainKey(key)

	if err != nil {

		t.Fatalf("NewStructFromSenderChainKey: %v", err)

	}
	if structure.Iteration != 99 {
		t.Errorf("Structure.Iteration = %d, want 99", structure.Iteration)
	}
	if !bytes.Equal(structure.ChainKey.BytesOrNil(), chainKey) {
		t.Error("Structure.ChainKey.BytesOrNil() does not match original chain key")
	}
}

func TestSenderChainKeyRoundTrip(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i * 3)
	}
	original := NewSenderChainKey(77, chainKey)

	structure, err := NewStructFromSenderChainKey(original)

	if err != nil {

		t.Fatalf("NewStructFromSenderChainKey: %v", err)

	}
	restored, err := NewSenderChainKeyFromStruct(structure)
	if err != nil {
		t.Fatalf("NewSenderChainKeyFromStruct: %v", err)
	}
	if original.Iteration() != restored.Iteration() {
		t.Errorf("Iteration mismatch: %d vs %d", original.Iteration(), restored.Iteration())
	}
	if !bytes.Equal(original.Seed(), restored.Seed()) {
		t.Error("Seed mismatch after round trip")
	}
}

func TestSenderChainKeyZeroize(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i + 1)
	}
	key := NewSenderChainKey(0, chainKey)

	// Verify key material is accessible before Zeroize.
	if len(key.Seed()) != 32 {
		t.Fatal("expected 32-byte seed before Zeroize")
	}

	key.Zeroize()

	if !key.chainKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy the guarded chain key memory")
	}
}

func TestSenderChainKeyZeroizeIdempotent(t *testing.T) {
	chainKey := make([]byte, 32)
	key := NewSenderChainKey(0, chainKey)
	key.Zeroize()
	// Calling Zeroize again must not panic.
	key.Zeroize()
}

func TestSenderChainKeyZeroizeNilChainKey(t *testing.T) {
	// A SenderChainKey with nil chainKey should not panic on Zeroize.
	key := &SenderChainKey{iteration: 0, chainKey: nil}
	key.Zeroize() // must not panic
}

func TestSenderChainKeyNextOverflow(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	key := NewSenderChainKey(^uint32(0), chainKey) // math.MaxUint32

	_, err := key.Next()
	if err == nil {
		t.Fatal("Next() at MaxUint32 should return error")
	}
	var chainErr *ErrChainTooLong
	if !errors.As(err, &chainErr) {
		t.Errorf("Next() error = %T, want *ErrChainTooLong", err)
	}
}

func TestSenderChainKeyNextNotAtOverflow(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i)
	}
	key := NewSenderChainKey(^uint32(0)-1, chainKey) // math.MaxUint32 - 1

	next, err := key.Next()
	if err != nil {
		t.Fatalf("Next() at MaxUint32-1 should succeed, got: %v", err)
	}
	if next.Iteration() != ^uint32(0) {
		t.Errorf("Next().Iteration() = %d, want %d", next.Iteration(), ^uint32(0))
	}
}

func TestSenderChainKeyDoesNotMutateInput(t *testing.T) {
	original := make([]byte, 32)
	for i := range original {
		original[i] = byte(i + 10)
	}
	snapshot := make([]byte, 32)
	copy(snapshot, original)

	key := NewSenderChainKey(0, original)
	// Mutate the original to verify the chain key holds an independent copy.
	original[0] = 0xFF

	if !bytes.Equal(key.Seed(), snapshot) {
		t.Fatal("NewSenderChainKey should copy the input, not reference it")
	}
}
