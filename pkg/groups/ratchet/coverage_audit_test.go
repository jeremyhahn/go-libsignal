package ratchet

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// TestSenderChainKeyStructure_Zeroize verifies that Zeroize overwrites the
// ChainKey bytes in the structure with zeros.
func TestSenderChainKeyStructure_Zeroize(t *testing.T) {
	structure := &SenderChainKeyStructure{
		Iteration: 5,
		ChainKey:  mustGuard(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}),
	}

	// Verify non-zero before zeroize.
	allZero := secrettest.IsZero(t, &structure.ChainKey)
	if allZero {
		t.Fatal("test setup: ChainKey should be non-zero before Zeroize")
	}

	structure.Zeroize()

	if !secrettest.Empty(&structure.ChainKey) {
		t.Error("ChainKey still lends material after Zeroize")
	}
}

func TestSenderChainKeyStructure_Zeroize_NilChainKey(t *testing.T) {
	// A structure with nil ChainKey should not panic on Zeroize.
	structure := &SenderChainKeyStructure{
		Iteration: 0,
	}
	structure.Zeroize() // must not panic
}

func TestSenderChainKeyStructure_Zeroize_EmptyChainKey(t *testing.T) {
	structure := &SenderChainKeyStructure{
		Iteration: 1,
		ChainKey:  mustGuard(t, []byte{}),
	}
	structure.Zeroize() // must not panic
}

// TestSenderMessageKeyStructure_Zeroize verifies that Zeroize overwrites all
// sensitive byte fields (IV, CipherKey, Seed) with zeros.
func TestSenderMessageKeyStructure_Zeroize(t *testing.T) {
	structure := &SenderMessageKeyStructure{
		Iteration: 7,
		IV:        mustGuard(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
		CipherKey: mustGuard(t, []byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48}),
		Seed:      mustGuard(t, []byte{49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80}),
	}

	structure.Zeroize()

	if !secrettest.Empty(&structure.IV) {
		t.Error("IV still lends material after Zeroize")
	}
	if !secrettest.Empty(&structure.CipherKey) {
		t.Error("CipherKey still lends material after Zeroize")
	}
	if !secrettest.Empty(&structure.Seed) {
		t.Error("Seed still lends material after Zeroize")
	}
}

func TestSenderMessageKeyStructure_Zeroize_NilFields(t *testing.T) {
	// A structure with nil fields should not panic on Zeroize.
	structure := &SenderMessageKeyStructure{
		Iteration: 0,
	}
	structure.Zeroize() // must not panic
}

// TestSenderMessageKeyStructure_Zeroize_PartialFields tests Zeroize when
// only some fields are populated.
func TestSenderMessageKeyStructure_Zeroize_PartialFields(t *testing.T) {
	structure := &SenderMessageKeyStructure{
		Iteration: 3,
		IV:        mustGuard(t, []byte{0x01, 0x02, 0x03, 0x04}),
		Seed:      mustGuard(t, []byte{0xAA, 0xBB}),
	}
	structure.Zeroize() // must not panic and must zero the non-nil fields

	if !secrettest.Empty(&structure.IV) {
		t.Error("IV still lends material after Zeroize")
	}
	if !secrettest.Empty(&structure.Seed) {
		t.Error("Seed still lends material after Zeroize")
	}
}

// TestNewSenderChainKey_CopiesInput exercises the copy-not-reference path in
// NewSenderChainKey and verifies the panic path is NOT triggered by valid input.
// The error branch of secret.New is an OOM path that cannot be forced in tests.
func TestNewSenderChainKey_MultipleLengths(t *testing.T) {
	lengths := []int{16, 20, 32, 48, 64}
	for _, n := range lengths {
		key := make([]byte, n)
		for i := range key {
			key[i] = byte(i + n)
		}
		ck := NewSenderChainKey(uint32(n), key)
		if ck.Iteration() != uint32(n) {
			t.Errorf("length %d: Iteration() = %d, want %d", n, ck.Iteration(), uint32(n))
		}
		if !bytes.Equal(ck.Seed(), key) {
			t.Errorf("length %d: Seed does not match input", n)
		}
	}
}

// TestNewSenderMessageKey_IterationPreserved tests that the iteration value
// is preserved across multiple calls and exercises the successful KDF path.
func TestNewSenderMessageKey_IterationPreserved(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 42)
	}

	iterations := []uint32{0, 1, 100, 65535, 4294967295}
	for _, it := range iterations {
		key, err := NewSenderMessageKey(it, seed)
		if err != nil {
			t.Fatalf("iteration %d: NewSenderMessageKey failed: %v", it, err)
		}
		if key.Iteration() != it {
			t.Errorf("iteration %d: Iteration() = %d, want %d", it, key.Iteration(), it)
		}
		if len(key.Iv()) != 16 {
			t.Errorf("iteration %d: IV length = %d, want 16", it, len(key.Iv()))
		}
		if len(key.CipherKey()) != 32 {
			t.Errorf("iteration %d: CipherKey length = %d, want 32", it, len(key.CipherKey()))
		}
		key.Zeroize()
	}
}

// TestSenderChainKey_ChainProgression exercises the full chain-progression path
// through multiple Next() calls, verifying each key differs from the previous.
func TestSenderChainKey_ChainProgression(t *testing.T) {
	initial := make([]byte, 32)
	for i := range initial {
		initial[i] = byte(i + 1)
	}

	key := NewSenderChainKey(0, initial)
	prevSeed := key.Seed()

	for i := 0; i < 5; i++ {
		next, err := key.Next()
		if err != nil {
			t.Fatalf("step %d: Next() failed: %v", i, err)
		}
		if next.Iteration() != key.Iteration()+1 {
			t.Errorf("step %d: iteration = %d, want %d", i, next.Iteration(), key.Iteration()+1)
		}
		if bytes.Equal(next.Seed(), prevSeed) {
			t.Errorf("step %d: seed must differ from previous", i)
		}
		prevSeed = make([]byte, len(next.Seed()))
		copy(prevSeed, next.Seed())
		key = next
	}
}

// TestSenderMessageKey_SeedIsPreservedAfterConstruction verifies that the
// seed field retains the original seed bytes after KDF derivation, covering
// the seedCopy+secret.New path in NewSenderMessageKey.
func TestSenderMessageKey_SeedIsPreservedAfterConstruction(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 200)
	}
	seedSnapshot := make([]byte, 32)
	copy(seedSnapshot, seed)

	key, err := NewSenderMessageKey(77, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey failed: %v", err)
	}

	if !bytes.Equal(key.Seed(), seedSnapshot) {
		t.Error("Seed() must equal the original seed bytes")
	}
}

// TestSenderMessageKeyStructure_RoundTripWithZeroize verifies that the
// Zeroize method of the structure does not corrupt the key it was built from,
// since the structure holds independent copies.
func TestSenderMessageKeyStructure_RoundTripWithZeroize(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 77)
	}

	key, err := NewSenderMessageKey(42, seed)
	if err != nil {
		t.Fatalf("NewSenderMessageKey failed: %v", err)
	}

	structure, err := NewStructFromSenderMessageKey(key)

	if err != nil {

		t.Fatalf("NewStructFromSenderMessageKey: %v", err)

	}
	// Save copies of the structure values before zeroize.
	ivDigest := secrettest.Digest(t, &structure.IV)

	// Zeroize the structure.
	structure.Zeroize()

	// The original key's IV must still be accessible (independent memory).
	if sha256.Sum256(key.Iv()) != ivDigest {
		t.Error("zeroizing the structure must not affect the original key's IV")
	}

	key.Zeroize()
}
