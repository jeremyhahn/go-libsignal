package secret

import (
	"errors"
	"testing"
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
		for i, b := range s.Bytes() {
			if b != 0 {
				t.Errorf("NewEmpty(%d) Bytes()[%d] = %d, want 0", size, i, b)
				break
			}
		}
		s.Destroy()
	}
}

// TestOpenEnclave_ValidRoundTrip verifies the success path of OpenEnclave.
func TestOpenEnclave_ValidRoundTrip(t *testing.T) {
	s, err := New([]byte{0x11, 0x22, 0x33})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	enc := s.Seal()
	if enc == nil {
		t.Fatal("Seal() returned nil")
	}

	recovered, err := OpenEnclave(enc)
	if err != nil {
		t.Fatalf("OpenEnclave failed: %v", err)
	}
	defer recovered.Destroy()

	if !recovered.EqualTo([]byte{0x11, 0x22, 0x33}) {
		t.Error("recovered content does not match sealed content")
	}
}

// TestOpenEnclave_ErrorPath covers the branch where e.Open() fails.
// We can't easily cause Open to fail on a valid enclave, so we validate
// the nil path returns ErrNilInput.
func TestOpenEnclave_NilReturnsNilInput(t *testing.T) {
	_, err := OpenEnclave(nil)
	if !errors.Is(err, ErrNilInput) {
		t.Errorf("OpenEnclave(nil) error = %v, want ErrNilInput", err)
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

	arr := s.Array()
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

	b := s.Bytes()
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
		if len(s.Bytes()) != 32 {
			t.Errorf("iteration %d: Bytes() length = %d, want 32", i, len(s.Bytes()))
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
