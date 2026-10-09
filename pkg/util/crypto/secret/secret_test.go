package secret

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

func TestError_ErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		contains string
	}{
		{
			name:     "destroyed",
			err:      &Error{kind: errSecretDestroyed},
			contains: "destroyed secret",
		},
		{
			name:     "size mismatch",
			err:      newSizeMismatchError(32, 16),
			contains: "expected 32 bytes, got 16",
		},
		{
			name:     "alloc with cause",
			err:      newAllocError(enclave.ErrLockedMemoryUnavailable),
			contains: "allocation failed: enclave: could not allocate locked memory",
		},
		{
			name:     "alloc without cause",
			err:      &Error{kind: errSecretAlloc},
			contains: "allocation failed",
		},
		{
			name:     "nil input",
			err:      &Error{kind: errNilInput},
			contains: "nil input",
		},
		{
			name:     "invalid budget",
			err:      &Error{kind: errInvalidBudget},
			contains: "budget must be positive",
		},
		{
			name:     "allocator already set",
			err:      &Error{kind: errAllocatorAlreadySet},
			contains: "SetAllocator already called",
		},
		{
			name:     "allocator after allocation",
			err:      &Error{kind: errAllocatorAfterAllocation},
			contains: "after the first allocation",
		},
		{
			name:     "unknown kind",
			err:      &Error{kind: 0},
			contains: "unknown error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("Error() returned empty string")
			}
			if !bytes.Contains([]byte(msg), []byte(tc.contains)) {
				t.Errorf("Error() = %q, want substring %q", msg, tc.contains)
			}
		})
	}
}

func TestError_ImplementsErrorInterface(t *testing.T) {
	var _ error = (*Error)(nil)
	var _ error = ErrSecretDestroyed
	var _ error = ErrNilInput
}

func TestError_Is_MatchesByKind(t *testing.T) {
	err := &Error{kind: errNilInput}
	if !errors.Is(err, ErrNilInput) {
		t.Error("errors.Is should match ErrNilInput sentinel by kind")
	}
	if errors.Is(err, ErrSecretDestroyed) {
		t.Error("errors.Is should not match different kind")
	}
}

func TestError_Is_NonErrorTarget(t *testing.T) {
	err := &Error{kind: errNilInput}
	if errors.Is(err, errors.New("unrelated")) {
		t.Error("errors.Is should return false for non-*Error target")
	}
}

func TestError_Is_SizeMismatchKind(t *testing.T) {
	a := newSizeMismatchError(32, 10)
	b := newSizeMismatchError(64, 20)
	if !errors.Is(a, b) {
		t.Error("size mismatch errors should match by kind regardless of values")
	}
}

func TestError_Is_AllocKind(t *testing.T) {
	a := newAllocError(enclave.ErrLockedMemoryUnavailable)
	b := newAllocError(enclave.ErrBudgetExhausted)
	if !errors.Is(a, b) {
		t.Error("alloc errors should match by kind regardless of cause")
	}
}

// ---------------------------------------------------------------------------
// Secret constructor tests
// ---------------------------------------------------------------------------

func TestNew_HappyPath(t *testing.T) {
	data := []byte("hello secret world")
	s, err := New(data)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	defer s.Destroy()

	if s.Size() != len("hello secret world") {
		t.Errorf("Size() = %d, want %d", s.Size(), len("hello secret world"))
	}
	if !s.EqualTo([]byte("hello secret world")) {
		t.Error("secret content does not match original data")
	}
}

func TestNew_NilInput(t *testing.T) {
	s, err := New(nil)
	if s != nil {
		t.Error("New(nil) should return nil secret")
	}
	if err == nil {
		t.Fatal("New(nil) should return error")
	}
	if !errors.Is(err, ErrNilInput) {
		t.Errorf("New(nil) error = %v, want ErrNilInput", err)
	}
}

func TestNew_EmptySlice(t *testing.T) {
	s, err := New([]byte{})
	if err != nil {
		t.Fatalf("New(empty) returned error: %v", err)
	}
	defer s.Destroy()

	if s.Size() != 0 {
		t.Errorf("Size() = %d, want 0", s.Size())
	}
}

func TestNewRandom_HappyPath(t *testing.T) {
	s, err := NewRandom(64)
	if err != nil {
		t.Fatalf("NewRandom(64) returned error: %v", err)
	}
	defer s.Destroy()

	if s.Size() != 64 {
		t.Errorf("Size() = %d, want 64", s.Size())
	}
	// Verify it is not all zeros (astronomically unlikely for 64 random bytes).
	allZero := true
	for _, b := range s.Bytes() {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("NewRandom produced all-zero bytes, extremely unlikely")
	}
}

func TestNewRandom_ZeroSize(t *testing.T) {
	s, err := NewRandom(0)
	if err != nil {
		t.Fatalf("NewRandom(0) returned error: %v", err)
	}
	defer s.Destroy()

	if s.Size() != 0 {
		t.Errorf("Size() = %d, want 0", s.Size())
	}
}

func TestNewEmpty_HappyPath(t *testing.T) {
	s, err := NewEmpty(16)
	if err != nil {
		t.Fatalf("NewEmpty(16) returned error: %v", err)
	}
	defer s.Destroy()

	if s.Size() != 16 {
		t.Errorf("Size() = %d, want 16", s.Size())
	}
	for i, b := range s.Bytes() {
		if b != 0 {
			t.Errorf("Bytes()[%d] = %d, want 0", i, b)
		}
	}
}

func TestNewEmpty_ZeroSize(t *testing.T) {
	s, err := NewEmpty(0)
	if err != nil {
		t.Fatalf("NewEmpty(0) returned error: %v", err)
	}
	defer s.Destroy()

	if s.Size() != 0 {
		t.Errorf("Size() = %d, want 0", s.Size())
	}
}

// ---------------------------------------------------------------------------
// Secret method tests
// ---------------------------------------------------------------------------

func TestSecret_Bytes_PanicsAfterDestroy(t *testing.T) {
	s, err := New([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Bytes() should panic after Destroy()")
		}
	}()
	_ = s.Bytes()
}

func TestSecret_Size_AfterDestroy(t *testing.T) {
	s, err := New([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	if got := s.Size(); got != 0 {
		t.Errorf("Size() after destroy = %d, want 0", got)
	}
}

func TestSecret_Destroy_Idempotent(t *testing.T) {
	s, err := New([]byte{0xAA, 0xBB, 0xCC})
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()
	// Second call should not panic.
	s.Destroy()
	// Third call for good measure.
	s.Destroy()

	if !s.IsDestroyed() {
		t.Error("IsDestroyed() should return true after Destroy()")
	}
}

func TestSecret_IsDestroyed_BeforeAndAfter(t *testing.T) {
	s, err := New([]byte("alive"))
	if err != nil {
		t.Fatal(err)
	}
	if s.IsDestroyed() {
		t.Error("IsDestroyed() should return false before Destroy()")
	}
	s.Destroy()
	if !s.IsDestroyed() {
		t.Error("IsDestroyed() should return true after Destroy()")
	}
}

func TestSecret_IsDestroyed_NilBuf(t *testing.T) {
	s := &Secret{enc: nil}
	if !s.IsDestroyed() {
		t.Error("IsDestroyed() should return true when enc is nil")
	}
}

func TestSecret_Clone_HappyPath(t *testing.T) {
	original, err := New([]byte("clone me"))
	if err != nil {
		t.Fatal(err)
	}
	defer original.Destroy()

	cloned, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone() returned error: %v", err)
	}
	defer cloned.Destroy()

	if !cloned.EqualTo([]byte("clone me")) {
		t.Error("cloned content does not match original")
	}
}

func TestSecret_Clone_Independence(t *testing.T) {
	original, err := New([]byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatal(err)
	}

	cloned, err := original.Clone()
	if err != nil {
		t.Fatal(err)
	}

	// Destroy original, clone should still be alive.
	original.Destroy()

	if cloned.IsDestroyed() {
		t.Error("clone should be independent from original")
	}
	if !cloned.EqualTo([]byte{0x01, 0x02, 0x03, 0x04}) {
		t.Error("clone content should survive original destruction")
	}
	cloned.Destroy()
}

// TestSecret_Clone_DoesNotStageOnTheHeap is the regression test for the review
// finding on PR #18: Clone used to allocate an ordinary []byte, copy the
// plaintext into it and hand that to New, putting every cloned key on a
// swappable, core-dumpable page. Independence and equality tests cannot see
// that — the clone is correct either way — so the property has to be measured.
//
// Guarded memory is mmap'd rather than heap-allocated, so a guarded-to-guarded
// copy leaves heap growth flat while a staged copy grows it by at least the
// secret's size. The threshold is a quarter of the payload: far above the
// bookkeeping a correct Clone allocates, far below the payload a staged one
// must.
func TestSecret_Clone_DoesNotStageOnTheHeap(t *testing.T) {
	const size = 1 << 20 // 1 MiB, large enough to dwarf incidental allocation

	original, err := NewRandom(size)
	if err != nil {
		t.Fatalf("NewRandom: %v", err)
	}
	defer original.Destroy()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	cloned, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	defer cloned.Destroy()

	runtime.ReadMemStats(&after)

	grew := after.TotalAlloc - before.TotalAlloc
	if grew > size/4 {
		t.Errorf("Clone allocated %d heap bytes for a %d-byte secret; the payload "+
			"is being staged on the heap instead of copied guarded-to-guarded", grew, size)
	}

	// The copy still has to be a correct one.
	if !cloned.EqualTo(original.Bytes()) {
		t.Error("clone does not match the original")
	}
	if cloned.Size() != size {
		t.Errorf("clone size = %d, want %d", cloned.Size(), size)
	}
}

func TestSecret_Clone_AfterDestroy(t *testing.T) {
	s, err := New([]byte("temp"))
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	_, err = s.Clone()
	if err == nil {
		t.Fatal("Clone() after Destroy() should return error")
	}
	if !errors.Is(err, ErrSecretDestroyed) {
		t.Errorf("Clone() error = %v, want ErrSecretDestroyed", err)
	}
}

func TestSecret_EqualTo_SameContent(t *testing.T) {
	data := []byte("compare me")
	s, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	if !s.EqualTo([]byte("compare me")) {
		t.Error("EqualTo should return true for matching content")
	}
}

func TestSecret_EqualTo_DifferentContent(t *testing.T) {
	s, err := New([]byte("aaa"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	if s.EqualTo([]byte("bbb")) {
		t.Error("EqualTo should return false for different content")
	}
}

func TestSecret_EqualTo_DifferentLength(t *testing.T) {
	s, err := New([]byte("short"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	if s.EqualTo([]byte("much longer string")) {
		t.Error("EqualTo should return false for different lengths")
	}
}

func TestSecret_EqualTo_AfterDestroy(t *testing.T) {
	s, err := New([]byte("gone"))
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	if s.EqualTo([]byte("gone")) {
		t.Error("EqualTo should return false after Destroy()")
	}
}

// ---------------------------------------------------------------------------
// Secret32 constructor tests
// ---------------------------------------------------------------------------

func TestNewSecret32_HappyPath(t *testing.T) {
	var data [32]byte
	for i := range data {
		data[i] = byte(i)
	}
	s, err := NewSecret32(data)
	if err != nil {
		t.Fatalf("NewSecret32() returned error: %v", err)
	}
	defer s.Destroy()

	expected := [32]byte{}
	for i := range expected {
		expected[i] = byte(i)
	}
	if !s.EqualTo(expected) {
		t.Error("Secret32 content does not match input")
	}
}

func TestNewSecret32FromSlice_HappyPath(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i + 100)
	}
	s, err := NewSecret32FromSlice(data)
	if err != nil {
		t.Fatalf("NewSecret32FromSlice() returned error: %v", err)
	}
	defer s.Destroy()

	expected := [32]byte{}
	for i := range expected {
		expected[i] = byte(i + 100)
	}
	if !s.EqualTo(expected) {
		t.Error("Secret32 content does not match input")
	}
}

func TestNewSecret32FromSlice_WrongSize(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", make([]byte, 16)},
		{"too long", make([]byte, 64)},
		{"one byte", make([]byte, 1)},
		{"empty", make([]byte, 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSecret32FromSlice(tc.data)
			if s != nil {
				t.Error("should return nil for wrong size")
			}
			if err == nil {
				t.Fatal("should return error for wrong size")
			}
			var secretErr *Error
			if !errors.As(err, &secretErr) {
				t.Fatal("error should be *Error type")
			}
			if secretErr.kind != errSecretSizeMismatch {
				t.Errorf("error kind = %d, want errSecretSizeMismatch", secretErr.kind)
			}
		})
	}
}

func TestNewSecret32FromSlice_NilInput(t *testing.T) {
	s, err := NewSecret32FromSlice(nil)
	if s != nil {
		t.Error("should return nil for nil input")
	}
	if !errors.Is(err, ErrNilInput) {
		t.Errorf("error = %v, want ErrNilInput", err)
	}
}

func TestNewSecret32Random_HappyPath(t *testing.T) {
	s, err := NewSecret32Random()
	if err != nil {
		t.Fatalf("NewSecret32Random() returned error: %v", err)
	}
	defer s.Destroy()

	b := s.Bytes()
	if len(b) != 32 {
		t.Errorf("len(Bytes()) = %d, want 32", len(b))
	}
	// Verify not all zeros.
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("NewSecret32Random produced all-zero bytes, extremely unlikely")
	}
}

func TestNewSecret32Random_Uniqueness(t *testing.T) {
	s1, err := NewSecret32Random()
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Destroy()

	s2, err := NewSecret32Random()
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Destroy()

	if s1.EqualTo(s2.Array()) {
		t.Error("two random Secret32 values should differ (astronomically unlikely collision)")
	}
}

// ---------------------------------------------------------------------------
// Secret32 method tests
// ---------------------------------------------------------------------------

func TestSecret32_Array(t *testing.T) {
	var input [32]byte
	for i := range input {
		input[i] = byte(i * 3)
	}
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	arr := s.Array()
	for i := range arr {
		if arr[i] != byte(i*3) {
			t.Errorf("Array()[%d] = %d, want %d", i, arr[i], byte(i*3))
			break
		}
	}
}

func TestSecret32_Array_IsCopy(t *testing.T) {
	var input [32]byte
	input[0] = 0x42
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	arr := s.Array()
	arr[0] = 0xFF // Modify the copy.
	// Original should be unchanged.
	if s.Bytes()[0] != 0x42 {
		t.Error("Array() should return a copy, not a reference")
	}
}

func TestSecret32_Ptr(t *testing.T) {
	var input [32]byte
	input[0] = 0xAB
	input[31] = 0xCD
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	ptr := s.Ptr()
	if ptr == nil {
		t.Fatal("Ptr() returned nil")
	}
	if ptr[0] != 0xAB || ptr[31] != 0xCD {
		t.Errorf("Ptr() content mismatch: got [0]=%x [31]=%x", ptr[0], ptr[31])
	}
}

func TestSecret32_Ptr_PanicsAfterDestroy(t *testing.T) {
	var input [32]byte
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Ptr() should panic after Destroy()")
		}
	}()
	_ = s.Ptr()
}

func TestSecret32_Bytes_PanicsAfterDestroy(t *testing.T) {
	var input [32]byte
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Bytes() should panic after Destroy()")
		}
	}()
	_ = s.Bytes()
}

func TestSecret32_Destroy_Idempotent(t *testing.T) {
	var input [32]byte
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()
	s.Destroy()
	s.Destroy()

	if !s.IsDestroyed() {
		t.Error("IsDestroyed() should return true")
	}
}

func TestSecret32_IsDestroyed_BeforeAndAfter(t *testing.T) {
	var input [32]byte
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	if s.IsDestroyed() {
		t.Error("should not be destroyed initially")
	}
	s.Destroy()
	if !s.IsDestroyed() {
		t.Error("should be destroyed after Destroy()")
	}
}

func TestSecret32_Clone_HappyPath(t *testing.T) {
	var input [32]byte
	for i := range input {
		input[i] = byte(i + 50)
	}
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	cloned, err := s.Clone()
	if err != nil {
		t.Fatalf("Clone() returned error: %v", err)
	}
	defer cloned.Destroy()

	expected := [32]byte{}
	for i := range expected {
		expected[i] = byte(i + 50)
	}
	if !cloned.EqualTo(expected) {
		t.Error("cloned content does not match original")
	}
}

func TestSecret32_Clone_Independence(t *testing.T) {
	var input [32]byte
	input[0] = 0xFF
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}

	cloned, err := s.Clone()
	if err != nil {
		t.Fatal(err)
	}

	s.Destroy()

	if cloned.IsDestroyed() {
		t.Error("clone should survive original destruction")
	}
	if cloned.Bytes()[0] != 0xFF {
		t.Error("clone content should be preserved")
	}
	cloned.Destroy()
}

func TestSecret32_Clone_AfterDestroy(t *testing.T) {
	var input [32]byte
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	_, err = s.Clone()
	if err == nil {
		t.Fatal("Clone() after Destroy() should return error")
	}
	if !errors.Is(err, ErrSecretDestroyed) {
		t.Errorf("error = %v, want ErrSecretDestroyed", err)
	}
}

func TestSecret32_EqualTo_SameContent(t *testing.T) {
	var input [32]byte
	for i := range input {
		input[i] = byte(i)
	}
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	compare := [32]byte{}
	for i := range compare {
		compare[i] = byte(i)
	}
	if !s.EqualTo(compare) {
		t.Error("EqualTo should return true for same content")
	}
}

func TestSecret32_EqualTo_DifferentContent(t *testing.T) {
	var input [32]byte
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()

	diff := [32]byte{0xFF}
	if s.EqualTo(diff) {
		t.Error("EqualTo should return false for different content")
	}
}

func TestSecret32_EqualTo_AfterDestroy(t *testing.T) {
	var input [32]byte
	s, err := NewSecret32(input)
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	if s.EqualTo(input) {
		t.Error("EqualTo should return false after Destroy()")
	}
}

// ---------------------------------------------------------------------------
// Helper factory: newSizeMismatchError / newAllocError
// ---------------------------------------------------------------------------

func TestNewSizeMismatchError(t *testing.T) {
	err := newSizeMismatchError(32, 10)
	if err.kind != errSecretSizeMismatch {
		t.Errorf("kind = %d, want errSecretSizeMismatch", err.kind)
	}
	if err.expected != 32 || err.got != 10 {
		t.Errorf("expected=%d got=%d, want expected=32 got=10", err.expected, err.got)
	}
	msg := err.Error()
	if !bytes.Contains([]byte(msg), []byte("32")) || !bytes.Contains([]byte(msg), []byte("10")) {
		t.Errorf("Error() = %q, should contain 32 and 10", msg)
	}
}

func TestNewAllocError(t *testing.T) {
	err := newAllocError(enclave.ErrBudgetExhausted)
	if err.kind != errSecretAlloc {
		t.Errorf("kind = %d, want errSecretAlloc", err.kind)
	}
	if !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Errorf("errors.Is(%v, enclave.ErrBudgetExhausted) = false, want the cause unwrapped", err)
	}
}
