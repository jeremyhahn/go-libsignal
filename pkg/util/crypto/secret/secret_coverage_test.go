package secret

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// TestNew_ZeroLengthSlice covers the empty-slice path in New (not nil).
func TestNew_ZeroLengthAllocRecovery(t *testing.T) {
	// Empty (non-nil) slice should succeed and produce a zero-size secret.
	s, err := New([]byte{})
	if err != nil {
		t.Fatalf("New(empty) should succeed: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil secret for empty slice")
	}
	defer s.Destroy()
	if s.Size() != 0 {
		t.Errorf("Size() = %d, want 0", s.Size())
	}
}

// TestNewRandom_PositiveSize validates NewRandom covers the non-panic path fully.
func TestNewRandom_PositiveSize(t *testing.T) {
	sizes := []int{1, 16, 32, 64, 128}
	for _, size := range sizes {
		s, err := NewRandom(size)
		if err != nil {
			t.Fatalf("NewRandom(%d) returned error: %v", size, err)
		}
		if s == nil {
			t.Fatalf("NewRandom(%d) returned nil secret", size)
		}
		if s.Size() != size {
			t.Errorf("NewRandom(%d) Size() = %d, want %d", size, s.Size(), size)
		}
		s.Destroy()
	}
}

// TestNewEmpty_PositiveSizes validates NewEmpty covers the non-panic path for various sizes.
func TestNewEmpty_PositiveSizes(t *testing.T) {
	sizes := []int{1, 16, 32, 64}
	for _, size := range sizes {
		s, err := NewEmpty(size)
		if err != nil {
			t.Fatalf("NewEmpty(%d) returned error: %v", size, err)
		}
		if s == nil {
			t.Fatalf("NewEmpty(%d) returned nil secret", size)
		}
		if s.Size() != size {
			t.Errorf("NewEmpty(%d) Size() = %d, want %d", size, s.Size(), size)
		}
		// All bytes must be zero.
		for i, b := range secrettest.Bytes(s) {
			if b != 0 {
				t.Errorf("NewEmpty(%d) Bytes()[%d] = %d, want 0", size, i, b)
				break
			}
		}
		s.Destroy()
	}
}

// TestNewSecret32_ZeroArray creates a Secret32 from an all-zero array.
func TestNewSecret32_ZeroArray(t *testing.T) {
	var data [32]byte
	s, err := NewSecret32(data)
	if err != nil {
		t.Fatalf("NewSecret32(zero) failed: %v", err)
	}
	defer s.Destroy()

	arr := secrettest.Array(s)
	for i, b := range arr {
		if b != 0 {
			t.Errorf("Array()[%d] = %d, want 0", i, b)
			break
		}
	}
}

// TestNewSecret32_ZeroizeOnError validates the zeroization branch in NewSecret32.
// This path is taken when New() fails. We simulate this by checking that no
// error occurs on a valid allocation, confirming coverage of the normal path.
func TestNewSecret32_NormalPath_NonZeroData(t *testing.T) {
	var data [32]byte
	for i := range data {
		data[i] = byte(i + 1)
	}
	s, err := NewSecret32(data)
	if err != nil {
		t.Fatalf("NewSecret32 failed: %v", err)
	}
	defer s.Destroy()

	expected := [32]byte{}
	for i := range expected {
		expected[i] = byte(i + 1)
	}
	if !s.EqualTo(expected) {
		t.Error("NewSecret32 content mismatch")
	}
}

// TestNewSecret32FromSlice_AllocFailBranch covers the error branch where New()
// fails inside NewSecret32FromSlice. This can only be triggered indirectly;
// we validate the normal path runs cleanly.
func TestNewSecret32FromSlice_ExactSize(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i + 200)
	}
	s, err := NewSecret32FromSlice(data)
	if err != nil {
		t.Fatalf("NewSecret32FromSlice failed: %v", err)
	}
	defer s.Destroy()

	b := secrettest.Bytes(s)
	if len(b) != 32 {
		t.Errorf("Bytes() length = %d, want 32", len(b))
	}
	for i, v := range b {
		if v != byte(i+200) {
			t.Errorf("Bytes()[%d] = %d, want %d", i, v, byte(i+200))
			break
		}
	}
}

// TestNewSecret32Random_ProducesValidSize validates the full success path.
func TestNewSecret32Random_SizeIsAlways32(t *testing.T) {
	for i := 0; i < 3; i++ {
		s, err := NewSecret32Random()
		if err != nil {
			t.Fatalf("iteration %d: NewSecret32Random() error: %v", i, err)
		}
		if len(secrettest.Bytes(s)) != 32 {
			t.Errorf("iteration %d: Bytes() length = %d, want 32", i, len(secrettest.Bytes(s)))
		}
		s.Destroy()
	}
}

// TestSecret32_EqualTo_AfterDestroyReturnsFalse verifies destroyed Secret32 EqualTo.
func TestSecret32_EqualTo_Destroyed_ReturnsFalse(t *testing.T) {
	var data [32]byte
	data[0] = 0xAB
	s, err := NewSecret32(data)
	if err != nil {
		t.Fatalf("NewSecret32 failed: %v", err)
	}
	s.Destroy()

	if s.EqualTo(data) {
		t.Error("EqualTo on destroyed Secret32 should return false")
	}
}

// TestNewEmpty_NegativeSizeIsRejected pins that a negative size is invalid
// input, not a zero-length secret: the zero special-case is exactly size 0, and
// anything below it must surface an allocation error rather than reaching the
// locked-memory allocator with a nonsense size.
func TestNewEmpty_NegativeSizeIsRejected(t *testing.T) {
	s, err := NewEmpty(-1)
	if err == nil {
		t.Fatal("NewEmpty(-1) should return an error")
	}
	if s != nil {
		t.Error("NewEmpty(-1) should return a nil secret on error")
	}
	if !errors.Is(err, &Error{kind: errSecretAlloc}) {
		t.Errorf("NewEmpty(-1) error = %v, want an allocation error", err)
	}
}

// TestNewRandom_NegativeSizeIsRejected is the NewRandom counterpart.
func TestNewRandom_NegativeSizeIsRejected(t *testing.T) {
	s, err := NewRandom(-1)
	if err == nil {
		t.Fatal("NewRandom(-1) should return an error")
	}
	if s != nil {
		t.Error("NewRandom(-1) should return a nil secret on error")
	}
	if !errors.Is(err, &Error{kind: errSecretAlloc}) {
		t.Errorf("NewRandom(-1) error = %v, want an allocation error", err)
	}
}

// TestSecret_Size_NilReceiver pins the nil-receiver contract that lets callers
// hold an optional *Secret without a nil guard at every use.
func TestSecret_Size_NilReceiver(t *testing.T) {
	var s *Secret
	if got := s.Size(); got != 0 {
		t.Errorf("(*Secret)(nil).Size() = %d, want 0", got)
	}
}

// TestSecret32_Destroy_NilReceiver pins that Destroy is safe on a nil Secret32,
// so it can always be deferred.
func TestSecret32_Destroy_NilReceiver(t *testing.T) {
	var s *Secret32
	s.Destroy() // must not panic
}
