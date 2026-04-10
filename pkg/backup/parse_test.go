package backup

import (
	"bytes"
	"testing"
)

func TestVarintDelimitedReaderEmpty(t *testing.T) {
	r := NewVarintDelimitedReader(bytes.NewReader(nil))
	frame, err := r.ReadNext()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if frame != nil {
		t.Fatalf("expected nil frame, got %v", frame)
	}
}

func TestVarintDelimitedReaderTruncated(t *testing.T) {
	// Varint says 10 bytes but only 9 are available.
	buf := []byte{10, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	r := NewVarintDelimitedReader(bytes.NewReader(buf))
	_, err := r.ReadNext()
	if err == nil {
		t.Fatal("expected error for truncated message")
	}
}

func TestVarintDelimitedReaderMultipleMessages(t *testing.T) {
	var buf bytes.Buffer

	msg1 := []byte("12345")
	msg2 := []byte("abcdefg")
	msg3 := make([]byte, 256)
	for i := range msg3 {
		msg3[i] = 0xab
	}

	if err := WriteVarintDelimited(&buf, msg1); err != nil {
		t.Fatal(err)
	}
	if err := WriteVarintDelimited(&buf, msg2); err != nil {
		t.Fatal(err)
	}
	if err := WriteVarintDelimited(&buf, msg3); err != nil {
		t.Fatal(err)
	}

	r := NewVarintDelimitedReader(bytes.NewReader(buf.Bytes()))

	got1, err := r.ReadNext()
	if err != nil {
		t.Fatalf("reading first: %v", err)
	}
	if !bytes.Equal(got1, msg1) {
		t.Errorf("first message: got %q, want %q", got1, msg1)
	}

	got2, err := r.ReadNext()
	if err != nil {
		t.Fatalf("reading second: %v", err)
	}
	if !bytes.Equal(got2, msg2) {
		t.Errorf("second message: got %q, want %q", got2, msg2)
	}

	got3, err := r.ReadNext()
	if err != nil {
		t.Fatalf("reading third: %v", err)
	}
	if !bytes.Equal(got3, msg3) {
		t.Errorf("third message length: got %d, want %d", len(got3), len(msg3))
	}

	// EOF
	eof, err := r.ReadNext()
	if err != nil {
		t.Fatalf("reading past end: %v", err)
	}
	if eof != nil {
		t.Fatalf("expected nil at EOF, got %v", eof)
	}
}

func TestWriteVarintDelimited(t *testing.T) {
	var buf bytes.Buffer
	data := []byte("hello")
	if err := WriteVarintDelimited(&buf, data); err != nil {
		t.Fatal(err)
	}

	// First byte should be the length (5).
	raw := buf.Bytes()
	if raw[0] != 5 {
		t.Errorf("varint byte: got %d, want 5", raw[0])
	}
	if !bytes.Equal(raw[1:], data) {
		t.Errorf("data mismatch: got %q, want %q", raw[1:], data)
	}
}
