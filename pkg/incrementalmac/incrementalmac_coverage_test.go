package incrementalmac

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestNewValidatingValidatesChunkSize(t *testing.T) {
	key := testKey()
	tests := []struct {
		name      string
		chunkSize int
		wantErr   error
	}{
		// Rust asserts only chunk_size > 0 (incremental_mac.rs:50).
		{"zero", 0, ErrChunkSizeTooSmall},
		{"negative", -1, ErrChunkSizeTooSmall},
		// Sub-MinChunkSize values are now accepted (matching Rust).
		{"rust test chunk size", 32, nil},
		{"below old minimum", MinChunkSize - 1, nil},
		{"minimum", MinChunkSize, nil},
		{"maximum", MaxChunkSize, nil},
		{"too large", MaxChunkSize + 1, ErrChunkSizeTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewValidating(key, tt.chunkSize, nil)
			if err != tt.wantErr {
				t.Errorf("NewValidating() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatingFinalizeTooFewMACs(t *testing.T) {
	// Finalize with no remaining expected MACs should return ErrTooFewMACs.
	key := testKey()
	chunkSize := MinChunkSize

	data := make([]byte, chunkSize/2)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	// Provide zero expected MACs.
	v, err := NewValidating(key, chunkSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Update(data); err != nil {
		t.Fatalf("Update: %v", err)
	}
	err = v.Finalize()
	if err != ErrTooFewMACs {
		t.Errorf("expected ErrTooFewMACs, got %v", err)
	}
}

func TestValidatingFinalizeMACMismatchOnTrailing(t *testing.T) {
	// Finalize with remaining data where the final MAC does not match.
	key := testKey()
	chunkSize := MinChunkSize

	data := make([]byte, chunkSize/2)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	inc, err := New(key, chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Corrupt the final MAC.
	badMACs := make([][]byte, len(macs))
	for i, m := range macs {
		c := make([]byte, len(m))
		copy(c, m)
		badMACs[i] = c
	}
	badMACs[len(badMACs)-1][0] ^= 0xFF

	v, err := NewValidating(key, chunkSize, badMACs)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Update(data); err != nil {
		t.Fatalf("Update: %v", err)
	}
	err = v.Finalize()
	if err != ErrMACMismatch {
		t.Errorf("expected ErrMACMismatch, got %v", err)
	}
}

func TestValidatingEmptyDataNoMACs(t *testing.T) {
	// No data, no MACs: Finalize should fail because there is always
	// a final MAC (Rust's finalize() always produces one).
	key := testKey()
	v, err := NewValidating(key, MinChunkSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Finalize()
	if err != ErrTooFewMACs {
		t.Errorf("expected ErrTooFewMACs for empty validation with no MACs, got %v", err)
	}
}

func TestValidatingEmptyDataWithOneMAC(t *testing.T) {
	// No data fed, but one MAC provided: should validate successfully
	// if the MAC matches HMAC(key, "").
	key := testKey()
	emptyMAC := fullHMAC(key, nil)
	v, err := NewValidating(key, MinChunkSize, [][]byte{emptyMAC})
	if err != nil {
		t.Fatal(err)
	}
	err = v.Finalize()
	if err != nil {
		t.Errorf("expected success, got %v", err)
	}
}

func TestValidatingEmptyDataWithExtraMACs(t *testing.T) {
	// No data but multiple MACs: should return ErrUnconsumedMACs.
	key := testKey()
	fakeMAC := make([]byte, DigestLength)
	v, err := NewValidating(key, MinChunkSize, [][]byte{fakeMAC, fakeMAC})
	if err != nil {
		t.Fatal(err)
	}
	err = v.Finalize()
	if err != ErrUnconsumedMACs {
		t.Errorf("expected ErrUnconsumedMACs, got %v", err)
	}
}

func TestIncrementalFinalizeNoData(t *testing.T) {
	// Finalize without any Update calls: should produce 1 MAC (the final).
	key := testKey()
	inc, err := New(key, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
	if len(macs) != 1 {
		t.Errorf("expected 1 MAC for no data, got %d", len(macs))
	}
	// Should equal HMAC(key, "").
	expected := fullHMAC(key, nil)
	if !bytes.Equal(macs[0], expected) {
		t.Error("no-data final MAC should equal HMAC(key, empty)")
	}
}

func TestBytesEmpty(t *testing.T) {
	// Bytes before Finalize should return empty.
	key := testKey()
	inc, err := New(key, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	b := inc.Bytes()
	if len(b) != 0 {
		t.Errorf("expected empty Bytes() before Finalize, got %d bytes", len(b))
	}
}

func TestValidatingTooFewMACsOnChunkBoundary(t *testing.T) {
	// Feed data that crosses a chunk boundary with zero MACs available.
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize+1)

	v, err := NewValidating(key, chunkSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Update(data)
	if err != ErrTooFewMACs {
		t.Errorf("expected ErrTooFewMACs during Update, got %v", err)
	}
}

func TestMultipleUpdatesValidation(t *testing.T) {
	// Feed data in multiple small Update calls and validate successfully.
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize*2+500)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	inc, _ := New(key, chunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	v, _ := NewValidating(key, chunkSize, macs)
	step := 1000
	for i := 0; i < len(data); i += step {
		end := i + step
		if end > len(data) {
			end = len(data)
		}
		if err := v.Update(data[i:end]); err != nil {
			t.Fatalf("Update at offset %d: %v", i, err)
		}
	}
	if err := v.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
}

func TestIncrementalChainingVerification(t *testing.T) {
	// Verify the prefix-accumulating property: tampering with the first
	// chunk invalidates all MACs (since each covers the full prefix).
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize*3)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	inc, _ := New(key, chunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[0] ^= 0xFF

	inc2, _ := New(key, chunkSize)
	if _, err := inc2.Update(tampered); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	tamperedMACs, err := inc2.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// All MACs should differ because each covers a prefix that includes
	// the tampered byte.
	for i := range macs {
		if bytes.Equal(macs[i], tamperedMACs[i]) {
			t.Errorf("MAC %d should differ after tampering first byte", i)
		}
	}
}

func TestCalculateChunkSizeNearMaxBoundary(t *testing.T) {
	dataLength := int64(MaxChunkSize) * 1001
	got := CalculateChunkSize(dataLength)
	if got != MaxChunkSize {
		t.Errorf("CalculateChunkSize(%d) = %d, want %d", dataLength, got, MaxChunkSize)
	}
}

func TestCalculateChunkSizeMidRange(t *testing.T) {
	// 200 MB: 200*1024*1024 / 256 = 819200 = 800 KB
	got := CalculateChunkSize(200 * 1024 * 1024)
	want := 800 * 1024
	if got != want {
		t.Errorf("CalculateChunkSize(200MB) = %d, want %d", got, want)
	}
}

func TestErrorMessages(t *testing.T) {
	// Verify typed errors have meaningful messages.
	errors := []*Error{
		ErrChunkSizeTooSmall,
		ErrChunkSizeTooLarge,
		ErrMACMismatch,
		ErrTooFewMACs,
		ErrUnconsumedMACs,
		ErrAlreadyFinalized,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Error("error message should not be empty")
		}
	}
}

func TestValidatingExactBoundary(t *testing.T) {
	// Data exactly at chunk boundary: produces intermediate + final (duplicate).
	// Validation must accept both.
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	inc, _ := New(key, chunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	v, _ := NewValidating(key, chunkSize, macs)
	if err := v.Update(data); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := v.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
}
