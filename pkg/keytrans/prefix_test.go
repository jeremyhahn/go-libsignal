package keytrans

import (
	"crypto/sha256"
	"testing"
)

func TestUint32ToBeBytes(t *testing.T) {
	tests := []struct {
		v    uint32
		want [4]byte
	}{
		{0, [4]byte{0, 0, 0, 0}},
		{1, [4]byte{0, 0, 0, 1}},
		{256, [4]byte{0, 0, 1, 0}},
		{0xDEADBEEF, [4]byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}

	for _, tt := range tests {
		got := uint32ToBeBytes(tt.v)
		var gotArr [4]byte
		copy(gotArr[:], got)
		if gotArr != tt.want {
			t.Errorf("uint32ToBeBytes(%d) = %v, want %v", tt.v, got, tt.want)
		}
	}
}

func TestUint64ToBeBytes(t *testing.T) {
	tests := []struct {
		v    uint64
		want [8]byte
	}{
		{0, [8]byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{1, [8]byte{0, 0, 0, 0, 0, 0, 0, 1}},
		{0xDEADBEEFCAFEBABE, [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}},
	}

	for _, tt := range tests {
		got := uint64ToBeBytes(tt.v)
		var gotArr [8]byte
		copy(gotArr[:], got)
		if gotArr != tt.want {
			t.Errorf("uint64ToBeBytes(%d) = %v, want %v", tt.v, got, tt.want)
		}
	}
}

func TestInt64ToBeBytes(t *testing.T) {
	// Should be same as uint64ToBeBytes for the same bit pattern
	got := int64ToBeBytes(1)
	expected := uint64ToBeBytes(1)
	for i := range got {
		if got[i] != expected[i] {
			t.Errorf("int64ToBeBytes(1) differs from uint64ToBeBytes(1) at byte %d", i)
		}
	}
}

func TestUint16ToBeBytes(t *testing.T) {
	tests := []struct {
		v    uint16
		want [2]byte
	}{
		{0, [2]byte{0, 0}},
		{1, [2]byte{0, 1}},
		{256, [2]byte{1, 0}},
		{0xBEEF, [2]byte{0xBE, 0xEF}},
	}

	for _, tt := range tests {
		got := uint16ToBeBytes(tt.v)
		var gotArr [2]byte
		copy(gotArr[:], got)
		if gotArr != tt.want {
			t.Errorf("uint16ToBeBytes(%d) = %v, want %v", tt.v, got, tt.want)
		}
	}
}

func TestPrefixLeafHash(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		key := &[32]byte{1, 2, 3}
		h1 := prefixLeafHash(key, 5, 10)
		h2 := prefixLeafHash(key, 5, 10)
		if h1 != h2 {
			t.Fatal("same inputs should produce same hash")
		}
	})

	t.Run("different counter produces different hash", func(t *testing.T) {
		key := &[32]byte{1, 2, 3}
		h1 := prefixLeafHash(key, 5, 10)
		h2 := prefixLeafHash(key, 6, 10)
		if h1 == h2 {
			t.Fatal("different counter should produce different hash")
		}
	})

	t.Run("different pos produces different hash", func(t *testing.T) {
		key := &[32]byte{1, 2, 3}
		h1 := prefixLeafHash(key, 5, 10)
		h2 := prefixLeafHash(key, 5, 11)
		if h1 == h2 {
			t.Fatal("different pos should produce different hash")
		}
	})

	t.Run("includes domain separator", func(t *testing.T) {
		key := &[32]byte{1, 2, 3}
		hash := prefixLeafHash(key, 0, 0)
		// Just verify it produces a valid 32-byte hash
		if hash == [32]byte{} {
			t.Fatal("hash should not be all zeros")
		}
	})
}

func TestPrefixParentHash(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		left := &[32]byte{1, 2, 3}
		right := &[32]byte{4, 5, 6}
		h1 := prefixParentHash(left, right)
		h2 := prefixParentHash(left, right)
		if h1 != h2 {
			t.Fatal("same inputs should produce same hash")
		}
	})

	t.Run("order matters", func(t *testing.T) {
		left := &[32]byte{1, 2, 3}
		right := &[32]byte{4, 5, 6}
		h1 := prefixParentHash(left, right)
		h2 := prefixParentHash(right, left)
		if h1 == h2 {
			t.Fatal("swapping left and right should produce different hash")
		}
	})

	t.Run("uses 0x01 domain separator", func(t *testing.T) {
		left := &[32]byte{}
		right := &[32]byte{}
		hash := prefixParentHash(left, right)
		// Manually compute expected hash
		h := sha256.New()
		h.Write([]byte{0x01})
		h.Write(left[:])
		h.Write(right[:])
		var expected [32]byte
		copy(expected[:], h.Sum(nil))
		if hash != expected {
			t.Fatal("hash should match manual computation with 0x01 separator")
		}
	})
}

func TestEvaluatePrefixProof(t *testing.T) {
	t.Run("wrong proof length", func(t *testing.T) {
		key := &[32]byte{1}
		value := &[32]byte{2}
		_, err := evaluatePrefixProof(key, value, make([][]byte, 100))
		if err != ErrMalformedPrefixProof {
			t.Errorf("expected ErrMalformedPrefixProof, got %v", err)
		}
	})

	t.Run("wrong element size", func(t *testing.T) {
		key := &[32]byte{1}
		value := &[32]byte{2}
		proof := make([][]byte, 256)
		for i := range proof {
			proof[i] = make([]byte, 32)
		}
		// Make one element wrong size
		proof[0] = make([]byte, 16)
		_, err := evaluatePrefixProof(key, value, proof)
		if err != ErrMalformedPrefixProof {
			t.Errorf("expected ErrMalformedPrefixProof, got %v", err)
		}
	})

	t.Run("valid proof produces 32 byte result", func(t *testing.T) {
		key := &[32]byte{1}
		value := &[32]byte{2}
		proof := make([][]byte, 256)
		for i := range proof {
			proof[i] = make([]byte, 32)
		}
		result, err := evaluatePrefixProof(key, value, proof)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// A zero result is possible but very unlikely; we just verify no error occurred.
		_ = result
	})
}

func TestEvaluatePrefix(t *testing.T) {
	t.Run("wrong proof length returns error", func(t *testing.T) {
		key := &[32]byte{1}
		proof := &PrefixProof{
			Proof:   make([][]byte, 10),
			Counter: 1,
		}
		_, err := EvaluatePrefix(key, 0, proof)
		if err == nil {
			t.Fatal("expected error for wrong proof length")
		}
	})

	t.Run("valid proof structure", func(t *testing.T) {
		key := &[32]byte{1}
		proofElements := make([][]byte, 256)
		for i := range proofElements {
			proofElements[i] = make([]byte, 32)
		}
		proof := &PrefixProof{
			Proof:   proofElements,
			Counter: 5,
		}
		result, err := EvaluatePrefix(key, 10, proof)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = result
	})
}
