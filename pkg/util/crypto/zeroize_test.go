package crypto

import (
	"testing"
)

func TestZeroize_NonEmptySlice(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0xFF, 0xAB}
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("Zeroize did not zero byte at index %d: got %d", i, v)
		}
	}
}

func TestZeroize_EmptySlice(t *testing.T) {
	b := []byte{}
	Zeroize(b) // should not panic
	if len(b) != 0 {
		t.Fatal("expected empty slice to remain empty")
	}
}

func TestZeroize_AllZeros(t *testing.T) {
	b := make([]byte, 10)
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte at index %d is not zero: %d", i, v)
		}
	}
}

func TestZeroizeArray32_NonZeroArray(t *testing.T) {
	var arr [32]byte
	for i := range arr {
		arr[i] = byte(i + 1)
	}
	ZeroizeArray32(&arr)
	for i, v := range arr {
		if v != 0 {
			t.Fatalf("ZeroizeArray32 did not zero byte at index %d: got %d", i, v)
		}
	}
}

func TestZeroizeArray32_AlreadyZero(t *testing.T) {
	var arr [32]byte
	ZeroizeArray32(&arr)
	for i, v := range arr {
		if v != 0 {
			t.Fatalf("byte at index %d is not zero: %d", i, v)
		}
	}
}

func TestZeroizeArray64_NonZeroArray(t *testing.T) {
	var arr [64]byte
	for i := range arr {
		arr[i] = 0xFF
	}
	ZeroizeArray64(&arr)
	for i, v := range arr {
		if v != 0 {
			t.Fatalf("ZeroizeArray64 did not zero byte at index %d: got %d", i, v)
		}
	}
}

func TestZeroizeArray64_AlreadyZero(t *testing.T) {
	var arr [64]byte
	ZeroizeArray64(&arr)
	for i, v := range arr {
		if v != 0 {
			t.Fatalf("byte at index %d is not zero: %d", i, v)
		}
	}
}
