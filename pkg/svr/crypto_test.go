package svr

import (
	"testing"

	"github.com/gtank/ristretto255"
)

func TestArrXOR(t *testing.T) {
	t.Run("basic xor", func(t *testing.T) {
		from := []byte{0xFF, 0x00, 0xAA}
		into := []byte{0x00, 0xFF, 0x55}
		arrXOR(from, into)
		want := []byte{0xFF, 0xFF, 0xFF}
		for i := range want {
			if into[i] != want[i] {
				t.Fatalf("byte %d: got %02x, want %02x", i, into[i], want[i])
			}
		}
	})

	t.Run("xor with self is zero", func(t *testing.T) {
		data := []byte{1, 2, 3, 4}
		into := make([]byte, len(data))
		copy(into, data)
		arrXOR(data, into)
		for i, b := range into {
			if b != 0 {
				t.Fatalf("byte %d: got %02x, want 0", i, b)
			}
		}
	})
}

func TestArrXORPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for mismatched lengths")
		}
	}()
	arrXOR([]byte{1}, []byte{1, 2})
}

func TestScalarsSummingTo(t *testing.T) {
	for n := 1; n <= 5; n++ {
		target := randomScalar()
		shares := scalarsSummingTo(n, target)
		if len(shares) != n {
			t.Fatalf("n=%d: got %d shares", n, len(shares))
		}
		sum := ristretto255.NewScalar()
		for _, s := range shares {
			sum.Add(sum, s)
		}
		if sum.Equal(target) != 1 {
			t.Fatalf("n=%d: shares do not sum to target", n)
		}
	}
}

func TestScalarsSummingToPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n <= 0")
		}
	}()
	scalarsSummingTo(0, ristretto255.NewScalar())
}

func TestBytesXORingTo(t *testing.T) {
	target := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for n := 1; n <= 5; n++ {
		shares := bytesXORingTo(n, target)
		if len(shares) != n {
			t.Fatalf("n=%d: got %d shares", n, len(shares))
		}
		result := make([]byte, len(target))
		for _, share := range shares {
			if len(share) != len(target) {
				t.Fatalf("n=%d: share has wrong length", n)
			}
			arrXOR(share, result)
		}
		for i := range target {
			if result[i] != target[i] {
				t.Fatalf("n=%d: XOR result mismatch at byte %d", n, i)
			}
		}
	}
}

func TestBytesXORingToPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for n <= 0")
		}
	}()
	bytesXORingTo(0, []byte{1})
}

func TestPasswordToUniformInput(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		a := passwordToUniformInput([]byte("password"))
		b := passwordToUniformInput([]byte("password"))
		if a != b {
			t.Fatal("same password should produce same output")
		}
	})

	t.Run("different passwords", func(t *testing.T) {
		a := passwordToUniformInput([]byte("password1"))
		b := passwordToUniformInput([]byte("password2"))
		if a == b {
			t.Fatal("different passwords should produce different output")
		}
	})
}

func TestUint64ToBeBytes(t *testing.T) {
	got := uint64ToBeBytes(0x0102030405060708)
	want := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDecodeElementInvalid(t *testing.T) {
	_, err := decodeElement([]byte{0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid element bytes")
	}
}

func TestDecodeScalarInvalid(t *testing.T) {
	_, err := decodeScalar([]byte{0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid scalar bytes")
	}
}

func TestDecodeElementValid(t *testing.T) {
	pt := ristretto255.NewIdentityElement().ScalarBaseMult(randomScalar())
	encoded := pt.Bytes()
	decoded, err := decodeElement(encoded)
	if err != nil {
		t.Fatalf("decodeElement failed: %v", err)
	}
	if decoded.Equal(pt) != 1 {
		t.Fatal("decoded element does not match original")
	}
}

func TestDecodeScalarValid(t *testing.T) {
	s := randomScalar()
	encoded := s.Bytes()
	decoded, err := decodeScalar(encoded)
	if err != nil {
		t.Fatalf("decodeScalar failed: %v", err)
	}
	if decoded.Equal(s) != 1 {
		t.Fatal("decoded scalar does not match original")
	}
}

func TestKDF32And64(t *testing.T) {
	info := []byte("test-info")
	input1 := []byte("input1")
	input2 := []byte("input2")

	t.Run("kdf32 deterministic", func(t *testing.T) {
		a := kdf32(info, input1, input2)
		b := kdf32(info, input1, input2)
		if a != b {
			t.Fatal("kdf32 should be deterministic")
		}
	})

	t.Run("kdf64 deterministic", func(t *testing.T) {
		a := kdf64(info, input1, input2)
		b := kdf64(info, input1, input2)
		if a != b {
			t.Fatal("kdf64 should be deterministic")
		}
	})

	t.Run("different info", func(t *testing.T) {
		a := kdf32([]byte("info-a"), input1, input2)
		b := kdf32([]byte("info-b"), input1, input2)
		if a == b {
			t.Fatal("different info should produce different keys")
		}
	})
}
