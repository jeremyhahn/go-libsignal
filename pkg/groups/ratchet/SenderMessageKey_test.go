package ratchet

import (
	"bytes"
	"testing"
)

func TestNewSenderMessageKey(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	key, err := NewSenderMessageKey(5, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}
	if key.Iteration() != 5 {
		t.Errorf("Iteration() = %d, want 5", key.Iteration())
	}
	if len(key.Iv()) != 16 {
		t.Errorf("IV length = %d, want 16", len(key.Iv()))
	}
	if len(key.CipherKey()) != 32 {
		t.Errorf("CipherKey length = %d, want 32", len(key.CipherKey()))
	}
	if !bytes.Equal(key.Seed(), seed) {
		t.Error("Seed() does not match input seed")
	}
}

func TestNewSenderMessageKeyDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	key1, err := NewSenderMessageKey(0, seed)
	if err != nil {
		t.Fatalf("first NewSenderMessageKey() error: %v", err)
	}
	key2, err := NewSenderMessageKey(0, seed)
	if err != nil {
		t.Fatalf("second NewSenderMessageKey() error: %v", err)
	}

	if !bytes.Equal(key1.Iv(), key2.Iv()) {
		t.Error("Same seed should produce same IV")
	}
	if !bytes.Equal(key1.CipherKey(), key2.CipherKey()) {
		t.Error("Same seed should produce same CipherKey")
	}
}

func TestNewSenderMessageKeyDifferentSeeds(t *testing.T) {
	seed1 := make([]byte, 32)
	seed2 := make([]byte, 32)
	for i := range seed1 {
		seed1[i] = byte(i)
		seed2[i] = byte(i + 100)
	}

	key1, err := NewSenderMessageKey(0, seed1)
	if err != nil {
		t.Fatalf("first NewSenderMessageKey() error: %v", err)
	}
	key2, err := NewSenderMessageKey(0, seed2)
	if err != nil {
		t.Fatalf("second NewSenderMessageKey() error: %v", err)
	}

	if bytes.Equal(key1.Iv(), key2.Iv()) {
		t.Error("Different seeds should produce different IVs")
	}
	if bytes.Equal(key1.CipherKey(), key2.CipherKey()) {
		t.Error("Different seeds should produce different CipherKeys")
	}
}

func TestNewSenderMessageKeyFromStruct(t *testing.T) {
	structure := &SenderMessageKeyStructure{
		Iteration: 42,
		IV:        make([]byte, 16),
		CipherKey: make([]byte, 32),
		Seed:      make([]byte, 32),
	}
	for i := range structure.IV {
		structure.IV[i] = byte(i)
	}
	for i := range structure.CipherKey {
		structure.CipherKey[i] = byte(i + 16)
	}
	for i := range structure.Seed {
		structure.Seed[i] = byte(i + 48)
	}

	key := NewSenderMessageKeyFromStruct(structure)

	if key.Iteration() != 42 {
		t.Errorf("Iteration() = %d, want 42", key.Iteration())
	}
	if !bytes.Equal(key.Iv(), structure.IV) {
		t.Error("IV does not match")
	}
	if !bytes.Equal(key.CipherKey(), structure.CipherKey) {
		t.Error("CipherKey does not match")
	}
	if !bytes.Equal(key.Seed(), structure.Seed) {
		t.Error("Seed does not match")
	}
}

func TestNewSenderMessageKeyFromStructEmpty(t *testing.T) {
	structure := &SenderMessageKeyStructure{
		Iteration: 0,
		IV:        nil,
		CipherKey: nil,
		Seed:      nil,
	}

	key := NewSenderMessageKeyFromStruct(structure)
	if key.Iteration() != 0 {
		t.Errorf("Iteration() = %d, want 0", key.Iteration())
	}
	if key.Iv() != nil {
		t.Error("Expected nil IV")
	}
}

func TestNewStructFromSenderMessageKey(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	key, err := NewSenderMessageKey(10, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}

	structure := NewStructFromSenderMessageKey(key)

	if structure.Iteration != 10 {
		t.Errorf("Structure.Iteration = %d, want 10", structure.Iteration)
	}
	if !bytes.Equal(structure.IV, key.Iv()) {
		t.Error("Structure.IV does not match key IV")
	}
	if !bytes.Equal(structure.CipherKey, key.CipherKey()) {
		t.Error("Structure.CipherKey does not match key CipherKey")
	}
	if !bytes.Equal(structure.Seed, key.Seed()) {
		t.Error("Structure.Seed does not match key Seed")
	}
}

func TestSenderMessageKeyRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i * 7)
	}

	original, err := NewSenderMessageKey(33, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}

	structure := NewStructFromSenderMessageKey(original)
	restored := NewSenderMessageKeyFromStruct(structure)

	if original.Iteration() != restored.Iteration() {
		t.Errorf("Iteration mismatch: %d vs %d", original.Iteration(), restored.Iteration())
	}
	if !bytes.Equal(original.Iv(), restored.Iv()) {
		t.Error("IV mismatch after round trip")
	}
	if !bytes.Equal(original.CipherKey(), restored.CipherKey()) {
		t.Error("CipherKey mismatch after round trip")
	}
	if !bytes.Equal(original.Seed(), restored.Seed()) {
		t.Error("Seed mismatch after round trip")
	}
}

func TestSenderMessageKeyAccessors(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 50)
	}

	key, err := NewSenderMessageKey(100, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}

	// Verify all accessors return non-nil values
	if key.Iv() == nil {
		t.Error("Iv() should not be nil")
	}
	if key.CipherKey() == nil {
		t.Error("CipherKey() should not be nil")
	}
	if key.Seed() == nil {
		t.Error("Seed() should not be nil")
	}
	if key.Iteration() != 100 {
		t.Errorf("Iteration() = %d, want 100", key.Iteration())
	}
}

func TestSenderMessageKeyZeroize(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key, err := NewSenderMessageKey(0, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}

	// Verify fields are populated before Zeroize.
	if key.Iv() == nil || key.CipherKey() == nil || key.Seed() == nil {
		t.Fatal("key fields should be non-nil before Zeroize")
	}

	key.Zeroize()

	if !key.iv.IsDestroyed() {
		t.Fatal("Zeroize should destroy iv guarded memory")
	}
	if !key.cipherKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy cipherKey guarded memory")
	}
	if !key.seed.IsDestroyed() {
		t.Fatal("Zeroize should destroy seed guarded memory")
	}
}

func TestSenderMessageKeyZeroizeIdempotent(t *testing.T) {
	seed := make([]byte, 32)
	key, err := NewSenderMessageKey(0, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey() error: %v", err)
	}
	key.Zeroize()
	// Calling Zeroize again must not panic.
	key.Zeroize()
}

func TestSenderMessageKeyZeroizeNilFields(t *testing.T) {
	// A SenderMessageKey with nil secret fields should not panic on Zeroize.
	key := &SenderMessageKey{iteration: 0}
	key.Zeroize() // must not panic
}

func TestSenderMessageKeyNilFieldAccessors(t *testing.T) {
	// Verify nil-guard paths in CipherKey() and Seed() accessors.
	key := &SenderMessageKey{iteration: 5}

	if key.Iv() != nil {
		t.Error("Iv() should return nil when iv is nil")
	}
	if key.CipherKey() != nil {
		t.Error("CipherKey() should return nil when cipherKey is nil")
	}
	if key.Seed() != nil {
		t.Error("Seed() should return nil when seed is nil")
	}
}

func TestNewSenderMessageKeyFromStructPartialFields(t *testing.T) {
	// Test with only IV set (CipherKey and Seed nil) to exercise nil-guard branches.
	structure := &SenderMessageKeyStructure{
		Iteration: 7,
		IV:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		CipherKey: nil,
		Seed:      nil,
	}

	key := NewSenderMessageKeyFromStruct(structure)
	if key.Iteration() != 7 {
		t.Errorf("Iteration() = %d, want 7", key.Iteration())
	}
	if key.Iv() == nil {
		t.Error("Iv() should not be nil when IV was provided")
	}
	if key.CipherKey() != nil {
		t.Error("CipherKey() should be nil when CipherKey was not provided")
	}
	if key.Seed() != nil {
		t.Error("Seed() should be nil when Seed was not provided")
	}
}

func TestNewStructFromSenderMessageKeyNilFields(t *testing.T) {
	// Exercise the nil-guard branches in NewStructFromSenderMessageKey
	// with a SenderMessageKey that has nil secret fields.
	key := &SenderMessageKey{iteration: 3}
	structure := NewStructFromSenderMessageKey(key)

	if structure.Iteration != 3 {
		t.Errorf("Iteration = %d, want 3", structure.Iteration)
	}
	if structure.IV != nil {
		t.Error("IV should be nil when source iv is nil")
	}
	if structure.CipherKey != nil {
		t.Error("CipherKey should be nil when source cipherKey is nil")
	}
	if structure.Seed != nil {
		t.Error("Seed should be nil when source seed is nil")
	}
}
