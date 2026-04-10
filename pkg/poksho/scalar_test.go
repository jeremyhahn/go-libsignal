package poksho

import (
	"bytes"
	"testing"
)

func TestScalarFromSliceWide(t *testing.T) {
	t.Run("valid 64-byte input", func(t *testing.T) {
		input := make([]byte, 64)
		for i := range input {
			input[i] = byte(i)
		}
		result, err := ScalarFromSliceWide(input)
		if err != nil {
			t.Fatalf("ScalarFromSliceWide failed: %v", err)
		}
		// Result should be non-zero.
		if result == [32]byte{} {
			t.Error("result is all zeros")
		}
	})

	t.Run("wrong size", func(t *testing.T) {
		_, err := ScalarFromSliceWide(make([]byte, 32))
		if err == nil {
			t.Fatal("expected error for 32-byte input")
		}
	})

	t.Run("zero input", func(t *testing.T) {
		input := make([]byte, 64)
		result, err := ScalarFromSliceWide(input)
		if err != nil {
			t.Fatalf("ScalarFromSliceWide failed: %v", err)
		}
		if result != [32]byte{} {
			t.Error("zero input should produce zero scalar")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		input := bytes.Repeat([]byte{0xFF}, 64)
		r1, _ := ScalarFromSliceWide(input)
		r2, _ := ScalarFromSliceWide(input)
		if r1 != r2 {
			t.Error("same input produced different results")
		}
	})

	t.Run("result is reduced mod L", func(t *testing.T) {
		// All 0xFF should be reduced to something less than L.
		input := bytes.Repeat([]byte{0xFF}, 64)
		result, err := ScalarFromSliceWide(input)
		if err != nil {
			t.Fatalf("ScalarFromSliceWide failed: %v", err)
		}
		// Verify result is canonical (< L).
		_, err = ScalarFromSliceCanonical(result[:])
		if err != nil {
			t.Fatalf("result is not canonical: %v", err)
		}
	})
}

func TestScalarFromSliceCanonical(t *testing.T) {
	t.Run("zero is canonical", func(t *testing.T) {
		input := make([]byte, 32)
		result, err := ScalarFromSliceCanonical(input)
		if err != nil {
			t.Fatalf("ScalarFromSliceCanonical failed: %v", err)
		}
		if result != [32]byte{} {
			t.Error("zero input should produce zero result")
		}
	})

	t.Run("one is canonical", func(t *testing.T) {
		input := make([]byte, 32)
		input[0] = 1 // little-endian 1
		_, err := ScalarFromSliceCanonical(input)
		if err != nil {
			t.Fatalf("ScalarFromSliceCanonical failed: %v", err)
		}
	})

	t.Run("wrong size", func(t *testing.T) {
		_, err := ScalarFromSliceCanonical(make([]byte, 16))
		if err == nil {
			t.Fatal("expected error for wrong size")
		}
	})

	t.Run("value >= L is rejected", func(t *testing.T) {
		// L in little-endian is:
		// ed d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14
		// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
		// A value of all 0xFF is certainly >= L.
		input := bytes.Repeat([]byte{0xFF}, 32)
		_, err := ScalarFromSliceCanonical(input)
		if err == nil {
			t.Fatal("expected error for value >= L")
		}
	})
}
