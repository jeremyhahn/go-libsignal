package bytehelper

import (
	"bytes"
	"testing"
)

func TestSliceToArray(t *testing.T) {
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i)
	}
	arr := SliceToArray(input)
	if arr != [32]byte(input) {
		t.Fatal("SliceToArray did not produce expected array")
	}
}

func TestSliceToArray_ShortSlice(t *testing.T) {
	input := []byte{1, 2, 3}
	arr := SliceToArray(input)
	if arr[0] != 1 || arr[1] != 2 || arr[2] != 3 {
		t.Fatal("first 3 bytes should match input")
	}
	for i := 3; i < 32; i++ {
		if arr[i] != 0 {
			t.Fatalf("byte %d should be zero, got %d", i, arr[i])
		}
	}
}

func TestSliceToArray64(t *testing.T) {
	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(i)
	}
	arr := SliceToArray64(input)
	for i := 0; i < 64; i++ {
		if arr[i] != byte(i) {
			t.Fatalf("mismatch at index %d", i)
		}
	}
}

func TestSliceToArray64_ShortSlice(t *testing.T) {
	input := []byte{0xAA, 0xBB}
	arr := SliceToArray64(input)
	if arr[0] != 0xAA || arr[1] != 0xBB {
		t.Fatal("first bytes should match")
	}
	for i := 2; i < 64; i++ {
		if arr[i] != 0 {
			t.Fatalf("byte %d should be zero", i)
		}
	}
}

func TestArrayToSlice(t *testing.T) {
	var arr [32]byte
	for i := range arr {
		arr[i] = byte(i * 2)
	}
	sl := ArrayToSlice(arr)
	if len(sl) != 32 {
		t.Fatalf("expected length 32, got %d", len(sl))
	}
	for i := 0; i < 32; i++ {
		if sl[i] != byte(i*2) {
			t.Fatalf("mismatch at index %d", i)
		}
	}
}

func TestArrayToSlice64(t *testing.T) {
	var arr [64]byte
	arr[0] = 0xFF
	arr[63] = 0x01
	sl := ArrayToSlice64(arr)
	if len(sl) != 64 {
		t.Fatalf("expected length 64, got %d", len(sl))
	}
	if sl[0] != 0xFF || sl[63] != 0x01 {
		t.Fatal("boundary values mismatch")
	}
}

func TestSplit(t *testing.T) {
	input := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	parts, err := Split(input, 4, 6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	if !bytes.Equal(parts[0], []byte{1, 2, 3, 4}) {
		t.Fatalf("first part mismatch: %v", parts[0])
	}
	if !bytes.Equal(parts[1], []byte{5, 6, 7, 8, 9, 10}) {
		t.Fatalf("second part mismatch: %v", parts[1])
	}
}

func TestSplit_EqualHalves(t *testing.T) {
	input := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	parts, err := Split(input, 2, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(parts[0], []byte{0xAA, 0xBB}) {
		t.Fatal("first half mismatch")
	}
	if !bytes.Equal(parts[1], []byte{0xCC, 0xDD}) {
		t.Fatal("second half mismatch")
	}
}

func TestSplit_NilInput(t *testing.T) {
	_, err := Split(nil, 1, 1)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, ok := err.(*ErrNilInput); !ok {
		t.Fatalf("expected *ErrNilInput, got %T", err)
	}
}

func TestSplit_InputTooSmall(t *testing.T) {
	_, err := Split([]byte{1, 2}, 3, 3)
	if err == nil {
		t.Fatal("expected error for input too small")
	}
	e, ok := err.(*ErrInputTooSmall)
	if !ok {
		t.Fatalf("expected *ErrInputTooSmall, got %T", err)
	}
	if e.Required != 6 || e.Got != 2 {
		t.Fatalf("expected Required=6, Got=2, got Required=%d, Got=%d", e.Required, e.Got)
	}
}

func TestSplit_NegativeLength(t *testing.T) {
	_, err := Split([]byte{1, 2, 3}, -1, 1)
	if err == nil {
		t.Fatal("expected error for negative length")
	}
	if _, ok := err.(*ErrNegativeLength); !ok {
		t.Fatalf("expected *ErrNegativeLength, got %T", err)
	}
}

func TestSplitThree_Valid(t *testing.T) {
	input := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	parts, err := SplitThree(input, 3, 3, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	if !bytes.Equal(parts[0], []byte{1, 2, 3}) {
		t.Fatal("first part mismatch")
	}
	if !bytes.Equal(parts[1], []byte{4, 5, 6}) {
		t.Fatal("second part mismatch")
	}
	if !bytes.Equal(parts[2], []byte{7, 8, 9}) {
		t.Fatal("third part mismatch")
	}
}

func TestSplitThree_NilInput(t *testing.T) {
	_, err := SplitThree(nil, 1, 1, 1)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, ok := err.(*ErrNilInput); !ok {
		t.Fatalf("expected *ErrNilInput, got %T", err)
	}
}

func TestSplitThree_InputTooSmall(t *testing.T) {
	_, err := SplitThree([]byte{1, 2}, 2, 2, 2)
	if err == nil {
		t.Fatal("expected error for input too small")
	}
	e, ok := err.(*ErrInputTooSmall)
	if !ok {
		t.Fatalf("expected *ErrInputTooSmall, got %T", err)
	}
	if e.Required != 6 || e.Got != 2 {
		t.Fatalf("expected Required=6, Got=2, got Required=%d, Got=%d", e.Required, e.Got)
	}
}

func TestSplitThree_NegativeLength(t *testing.T) {
	_, err := SplitThree([]byte{1, 2, 3}, -1, 1, 1)
	if err == nil {
		t.Fatal("expected error for negative length")
	}
	if _, ok := err.(*ErrNegativeLength); !ok {
		t.Fatalf("expected *ErrNegativeLength, got %T", err)
	}
}

func TestTrim(t *testing.T) {
	input := []byte{10, 20, 30, 40, 50}
	result := Trim(input, 3)
	if !bytes.Equal(result, []byte{10, 20, 30}) {
		t.Fatalf("expected [10 20 30], got %v", result)
	}
}

func TestTrim_FullLength(t *testing.T) {
	input := []byte{1, 2, 3}
	result := Trim(input, 3)
	if !bytes.Equal(result, input) {
		t.Fatal("trimming to full length should produce equal slice")
	}
}

func TestBytes5ToInt64(t *testing.T) {
	tests := []struct {
		name   string
		bytes  []byte
		offset int
		want   int64
	}{
		{
			name:   "all zeros",
			bytes:  []byte{0, 0, 0, 0, 0},
			offset: 0,
			want:   0,
		},
		{
			name:   "all ones",
			bytes:  []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			offset: 0,
			want:   0xFFFFFFFFFF,
		},
		{
			name:   "with offset",
			bytes:  []byte{0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			offset: 2,
			want:   (int64(0x01) << 32) | (int64(0x02) << 24) | (int64(0x03) << 16) | (int64(0x04) << 8) | int64(0x05),
		},
		{
			name:   "single byte value",
			bytes:  []byte{0, 0, 0, 0, 42},
			offset: 0,
			want:   42,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Bytes5ToInt64(tc.bytes, tc.offset)
			if got != tc.want {
				t.Fatalf("Bytes5ToInt64(%v, %d) = %d, want %d", tc.bytes, tc.offset, got, tc.want)
			}
		})
	}
}

func TestCopySlice(t *testing.T) {
	original := []byte{1, 2, 3, 4, 5}
	cp := CopySlice(original)
	if !bytes.Equal(cp, original) {
		t.Fatal("copy should equal original")
	}
	// Modify original, copy should not change
	original[0] = 99
	if cp[0] == 99 {
		t.Fatal("copy should be independent of original")
	}
}

func TestCopySlice_Empty(t *testing.T) {
	cp := CopySlice([]byte{})
	if len(cp) != 0 {
		t.Fatal("copy of empty slice should be empty")
	}
}
