package ratchet

import (
	"errors"
	"testing"
)

// TestErrChainTooLongError verifies that ErrChainTooLong.Error() returns a
// non-empty message and that the type satisfies the error interface.
func TestErrChainTooLongError(t *testing.T) {
	err := &ErrChainTooLong{}
	msg := err.Error()
	if msg == "" {
		t.Fatal("ErrChainTooLong.Error() must return a non-empty string")
	}
	// Verify it is usable as a plain error value.
	var target *ErrChainTooLong
	if !errors.As(err, &target) {
		t.Fatal("errors.As should find *ErrChainTooLong in itself")
	}
}

// TestNewSenderMessageKeyEmptySeed verifies that NewSenderMessageKey works
// with a minimal (all-zero) seed, exercising the successful code path when
// KDF succeeds.
func TestNewSenderMessageKeyEmptySeed(t *testing.T) {
	seed := make([]byte, 32) // all zeros
	key, err := NewSenderMessageKey(0, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey with zero seed failed: %v", err)
	}
	if len(key.Iv()) != 16 {
		t.Errorf("IV length = %d, want 16", len(key.Iv()))
	}
	if len(key.CipherKey()) != 32 {
		t.Errorf("CipherKey length = %d, want 32", len(key.CipherKey()))
	}
	if len(key.Seed()) != 32 {
		t.Errorf("Seed length = %d, want 32", len(key.Seed()))
	}
}

// TestSenderChainKeyNextAtMaxUint32MinusTwo verifies that Next does not error
// when iteration is two below MaxUint32, and that successive calls reach
// MaxUint32 without error.
func TestSenderChainKeyNextAtMaxUint32MinusTwo(t *testing.T) {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i + 7)
	}
	key := NewSenderChainKey(^uint32(0)-2, chainKey)

	// First Next: MaxUint32 - 1
	next1, err := key.Next()
	if err != nil {
		t.Fatalf("Next() at MaxUint32-2 should succeed: %v", err)
	}
	if next1.Iteration() != ^uint32(0)-1 {
		t.Errorf("next1.Iteration() = %d, want %d", next1.Iteration(), ^uint32(0)-1)
	}

	// Second Next: MaxUint32
	next2, err := next1.Next()
	if err != nil {
		t.Fatalf("Next() at MaxUint32-1 should succeed: %v", err)
	}
	if next2.Iteration() != ^uint32(0) {
		t.Errorf("next2.Iteration() = %d, want %d", next2.Iteration(), ^uint32(0))
	}

	// Third Next: must overflow
	_, err = next2.Next()
	if err == nil {
		t.Fatal("Next() at MaxUint32 should return error")
	}
	var chainErr *ErrChainTooLong
	if !errors.As(err, &chainErr) {
		t.Errorf("expected *ErrChainTooLong, got %T", err)
	}
}

// TestNewSenderMessageKeyFromStructOnlyIV exercises the branch where only the
// IV is present in the structure; CipherKey and Seed are nil.
func TestNewSenderMessageKeyFromStructOnlyIV(t *testing.T) {
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	structure := &SenderMessageKeyStructure{
		Iteration: 3,
		IV:        mustGuard(t, iv),
	}
	key, err := NewSenderMessageKeyFromStruct(structure)
	if err != nil {
		t.Fatalf("NewSenderMessageKeyFromStruct: %v", err)
	}
	if key.Iteration() != 3 {
		t.Errorf("Iteration() = %d, want 3", key.Iteration())
	}
	if key.Iv() == nil {
		t.Error("Iv() should not be nil when IV was provided")
	}
	if key.CipherKey() != nil {
		t.Error("CipherKey() should be nil when not provided")
	}
	if key.Seed() != nil {
		t.Error("Seed() should be nil when not provided")
	}
}

// TestNewSenderMessageKeyFromStructOnlySeed exercises the branch where only the
// Seed is present; IV and CipherKey are nil.
func TestNewSenderMessageKeyFromStructOnlySeed(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 200)
	}
	structure := &SenderMessageKeyStructure{
		Iteration: 9,
		Seed:      mustGuard(t, seed),
	}
	key, err := NewSenderMessageKeyFromStruct(structure)
	if err != nil {
		t.Fatalf("NewSenderMessageKeyFromStruct: %v", err)
	}
	if key.Iteration() != 9 {
		t.Errorf("Iteration() = %d, want 9", key.Iteration())
	}
	if key.Iv() != nil {
		t.Error("Iv() should be nil when not provided")
	}
	if key.CipherKey() != nil {
		t.Error("CipherKey() should be nil when not provided")
	}
	if key.Seed() == nil {
		t.Error("Seed() should not be nil when Seed was provided")
	}
}

// TestNewSenderMessageKeyFromStructOnlyCipherKey exercises the branch where
// only CipherKey is present; IV and Seed are nil.
func TestNewSenderMessageKeyFromStructOnlyCipherKey(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(i + 5)
	}
	structure := &SenderMessageKeyStructure{
		Iteration: 11,
		CipherKey: mustGuard(t, ck),
	}
	key, err := NewSenderMessageKeyFromStruct(structure)
	if err != nil {
		t.Fatalf("NewSenderMessageKeyFromStruct: %v", err)
	}
	if key.Iteration() != 11 {
		t.Errorf("Iteration() = %d, want 11", key.Iteration())
	}
	if key.Iv() != nil {
		t.Error("Iv() should be nil when not provided")
	}
	if key.CipherKey() == nil {
		t.Error("CipherKey() should not be nil when CipherKey was provided")
	}
	if key.Seed() != nil {
		t.Error("Seed() should be nil when not provided")
	}
}
