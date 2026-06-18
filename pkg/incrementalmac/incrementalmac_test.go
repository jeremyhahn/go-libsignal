package incrementalmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func testKey() []byte {
	return bytes.Repeat([]byte{0xAB}, 32)
}

// fullHMAC computes HMAC-SHA256(key, data) in a single shot.
func fullHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func TestNewValidatesChunkSize(t *testing.T) {
	key := testKey()
	tests := []struct {
		name      string
		chunkSize int
		wantErr   error
	}{
		// Rust asserts only chunk_size > 0 (incremental_mac.rs:50).
		// Zero and negative are the only invalid cases.
		{"zero", 0, ErrChunkSizeTooSmall},
		{"negative", -1, ErrChunkSizeTooSmall},
		// Sub-MinChunkSize values are now accepted (matching Rust).
		{"small positive", 1, nil},
		{"rust test chunk size", 32, nil},
		{"below old minimum", MinChunkSize - 1, nil},
		{"minimum", MinChunkSize, nil},
		{"maximum", MaxChunkSize, nil},
		{"too large", MaxChunkSize + 1, ErrChunkSizeTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(key, tt.chunkSize)
			if err != tt.wantErr {
				t.Errorf("New() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSingleChunkFinalMAC(t *testing.T) {
	// Data smaller than chunk size: only the final MAC is produced.
	// That MAC should equal HMAC(key, data).
	key := testKey()
	data := make([]byte, MinChunkSize/2)
	for i := range data {
		data[i] = byte(i % 256)
	}

	inc, err := New(key, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	n, err := inc.Update(data)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if n != 0 {
		t.Errorf("Update produced %d MACs, want 0 (data smaller than chunk)", n)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
	// Only the final MAC.
	if len(macs) != 1 {
		t.Fatalf("got %d MACs, want 1", len(macs))
	}

	expected := fullHMAC(key, data)
	if !bytes.Equal(macs[0], expected) {
		t.Error("MAC does not match HMAC(key, data)")
	}
}

func TestExactChunkBoundary(t *testing.T) {
	// Data exactly one chunk: Update produces 1 intermediate MAC,
	// Finalize produces 1 final MAC (identical to the intermediate).
	key := testKey()
	data := make([]byte, MinChunkSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	inc, err := New(key, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	n, err := inc.Update(data)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if n != 1 {
		t.Errorf("Update produced %d MACs, want 1", n)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
	// 1 intermediate + 1 final (identical since no more data).
	if len(macs) != 2 {
		t.Fatalf("got %d MACs, want 2", len(macs))
	}

	expected := fullHMAC(key, data)
	if !bytes.Equal(macs[0], expected) {
		t.Error("intermediate MAC mismatch")
	}
	// Final MAC equals intermediate since no additional data.
	if !bytes.Equal(macs[0], macs[1]) {
		t.Error("final MAC should equal intermediate when at exact boundary")
	}
}

func TestMultipleChunksWithTrailing(t *testing.T) {
	// 2 full chunks + partial trailing data.
	// Should produce 2 intermediate MACs + 1 final MAC.
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize*2+100)
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
	if len(macs) != 3 {
		t.Fatalf("got %d MACs, want 3", len(macs))
	}

	// Verify clone-and-finalize semantics: each MAC covers a prefix.
	// MAC_0 = HMAC(key, data[:chunkSize])
	mac0 := fullHMAC(key, data[:chunkSize])
	if !bytes.Equal(macs[0], mac0) {
		t.Error("MAC_0 mismatch: should be HMAC of first chunk")
	}

	// MAC_1 = HMAC(key, data[:2*chunkSize])
	mac1 := fullHMAC(key, data[:2*chunkSize])
	if !bytes.Equal(macs[1], mac1) {
		t.Error("MAC_1 mismatch: should be HMAC of first two chunks")
	}

	// MAC_2 (final) = HMAC(key, data[:])
	mac2 := fullHMAC(key, data)
	if !bytes.Equal(macs[2], mac2) {
		t.Error("MAC_2 mismatch: should be HMAC of all data")
	}
}

func TestIncrementalUpdates(t *testing.T) {
	// Feeding data in one shot vs byte-by-byte must produce identical MACs.
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize*3)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	inc1, _ := New(key, chunkSize)
	if _, err := inc1.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs1, err := inc1.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	inc2, _ := New(key, chunkSize)
	for i := 0; i < len(data); i++ {
		if _, err := inc2.Update(data[i : i+1]); err != nil {
			t.Fatalf("Update byte %d failed: %v", i, err)
		}
	}
	macs2, err := inc2.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	if len(macs1) != len(macs2) {
		t.Fatalf("MAC count differs: %d vs %d", len(macs1), len(macs2))
	}
	for i := range macs1 {
		if !bytes.Equal(macs1[i], macs2[i]) {
			t.Errorf("MAC %d differs between single-shot and incremental", i)
		}
	}
}

func TestFinalMACEqualsFullHMAC(t *testing.T) {
	// The final MAC should always equal HMAC(key, all_data) regardless of
	// how the data was chunked.
	key := testKey()
	chunkSize := MinChunkSize

	for _, dataLen := range []int{0, 1, chunkSize / 2, chunkSize, chunkSize + 1, chunkSize*3 + 42} {
		data := make([]byte, dataLen)
		if dataLen > 0 {
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
		}

		inc, _ := New(key, chunkSize)
		if _, err := inc.Update(data); err != nil {
			t.Fatalf("Update failed: %v", err)
		}
		macs, err := inc.Finalize()
		if err != nil {
			t.Fatalf("Finalize failed: %v", err)
		}

		expected := fullHMAC(key, data)
		finalMAC := macs[len(macs)-1]
		if !bytes.Equal(finalMAC, expected) {
			t.Errorf("dataLen=%d: final MAC != HMAC(key, all_data)", dataLen)
		}
	}
}

func TestBytes(t *testing.T) {
	key := testKey()
	data := make([]byte, MinChunkSize+100)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	inc, _ := New(key, MinChunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if _, err := inc.Finalize(); err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	b := inc.Bytes()
	// 1 intermediate + 1 final = 2 MACs.
	if len(b) != 2*DigestLength {
		t.Fatalf("Bytes() length = %d, want %d", len(b), 2*DigestLength)
	}
}

func TestValidatingSuccess(t *testing.T) {
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

	v, err := NewValidating(key, chunkSize, macs)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if err := v.Finalize(); err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
}

func TestValidatingDetectsTampering(t *testing.T) {
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

	// Tamper with the second chunk.
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[chunkSize+1] ^= 0xFF

	v, _ := NewValidating(key, chunkSize, macs)
	verr := v.Update(tampered)
	if verr == nil {
		verr = v.Finalize()
	}
	if verr != ErrMACMismatch {
		t.Errorf("expected ErrMACMismatch, got %v", verr)
	}
}

func TestValidatingTooFewMACs(t *testing.T) {
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize*3)

	inc, _ := New(key, chunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Provide only the first MAC.
	v, _ := NewValidating(key, chunkSize, macs[:1])
	verr := v.Update(data)
	if verr == nil {
		verr = v.Finalize()
	}
	if verr != ErrTooFewMACs {
		t.Errorf("expected ErrTooFewMACs, got %v", verr)
	}
}

func TestValidatingUnconsumedMACs(t *testing.T) {
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize/2) // less than one chunk

	inc, _ := New(key, chunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Add an extra fake MAC.
	extraMACs := append(macs, make([]byte, DigestLength))
	v, _ := NewValidating(key, chunkSize, extraMACs)
	if err := v.Update(data); err != nil {
		t.Fatal(err)
	}
	if err := v.Finalize(); err != ErrUnconsumedMACs {
		t.Errorf("expected ErrUnconsumedMACs, got %v", err)
	}
}

func TestFinalizedGuardUpdate(t *testing.T) {
	key := testKey()
	inc, _ := New(key, MinChunkSize)
	data := make([]byte, 100)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if _, err := inc.Finalize(); err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Update after Finalize should return ErrAlreadyFinalized.
	_, err := inc.Update(data)
	if err != ErrAlreadyFinalized {
		t.Errorf("Update after Finalize: got %v, want ErrAlreadyFinalized", err)
	}
}

func TestFinalizedGuardFinalize(t *testing.T) {
	key := testKey()
	inc, _ := New(key, MinChunkSize)
	data := make([]byte, 100)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if _, err := inc.Finalize(); err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Second Finalize should return ErrAlreadyFinalized.
	_, err := inc.Finalize()
	if err != ErrAlreadyFinalized {
		t.Errorf("double Finalize: got %v, want ErrAlreadyFinalized", err)
	}
}

func TestCalculateChunkSize(t *testing.T) {
	kibibyte := int64(1024)
	mebibyte := 1024 * kibibyte
	gibibyte := 1024 * mebibyte

	tests := []struct {
		name       string
		dataLength int64
		want       int
	}{
		{"zero", 0, MinChunkSize},
		{"negative", -1, MinChunkSize},
		{"1 KB", kibibyte, MinChunkSize},
		{"10 KB", 10 * kibibyte, MinChunkSize},
		{"100 KB", 100 * kibibyte, MinChunkSize},
		{"1 MB", mebibyte, MinChunkSize},
		{"10 MB", 10 * mebibyte, MinChunkSize},
		{"20 MB", 20 * mebibyte, int(80 * kibibyte)},
		{"100 MB", 100 * mebibyte, int(400 * kibibyte)},
		{"200 MB", 200 * mebibyte, int(800 * kibibyte)},
		{"256 MB", 256 * mebibyte, int(mebibyte)},
		{"512 MB", 512 * mebibyte, int(2 * mebibyte)},
		{"1 GB", gibibyte, int(2 * mebibyte)},
		{"2 GB", 2 * gibibyte, int(2 * mebibyte)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateChunkSize(tt.dataLength)
			if got != tt.want {
				t.Errorf("CalculateChunkSize(%d) = %d, want %d", tt.dataLength, got, tt.want)
			}
		})
	}
}

func TestCalculateChunkSizeAlwaysInBounds(t *testing.T) {
	// Sweep a range of data sizes and verify bounds.
	for _, dataLen := range []int64{0, 1, 1000, 1 << 20, 1 << 25, 1 << 30, 1 << 35} {
		got := CalculateChunkSize(dataLen)
		if got < MinChunkSize {
			t.Errorf("CalculateChunkSize(%d) = %d < MinChunkSize", dataLen, got)
		}
		if got > MaxChunkSize {
			t.Errorf("CalculateChunkSize(%d) = %d > MaxChunkSize", dataLen, got)
		}
	}
}

func BenchmarkUpdate(b *testing.B) {
	key := testKey()
	data := make([]byte, MinChunkSize)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	inc, _ := New(key, MinChunkSize)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := inc.Update(data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestValidatingUpdateReturnsDeferredError(t *testing.T) {
	// Verify that Update processes all chunks in a single call and
	// returns ErrMACMismatch after all chunks are processed, matching
	// the Rust reference behavior of deferred mismatch reporting.
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize*3)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	// Compute correct MACs.
	inc, _ := New(key, chunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Corrupt first intermediate MAC.
	badMACs := make([][]byte, len(macs))
	for i, m := range macs {
		c := make([]byte, len(m))
		copy(c, m)
		badMACs[i] = c
	}
	badMACs[0][0] ^= 0xFF

	v, _ := NewValidating(key, chunkSize, badMACs)
	// Feed exactly one chunk to trigger comparison of first MAC.
	err = v.Update(data[:chunkSize])
	if err != ErrMACMismatch {
		t.Fatalf("expected ErrMACMismatch from Update, got %v", err)
	}
}

func TestValidatingUpdateDefersMismatchAcrossChunks(t *testing.T) {
	// Verify that when multiple chunks are processed in a single Update
	// call and the first chunk mismatches, all chunks are still processed
	// before the error is returned.
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize*3)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	// Compute correct MACs.
	inc, _ := New(key, chunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Corrupt first intermediate MAC only.
	badMACs := make([][]byte, len(macs))
	for i, m := range macs {
		c := make([]byte, len(m))
		copy(c, m)
		badMACs[i] = c
	}
	badMACs[0][0] ^= 0xFF

	v, _ := NewValidating(key, chunkSize, badMACs)
	// Feed all three chunks at once. The mismatch on chunk 0 should
	// not prevent chunks 1 and 2 from being processed.
	err = v.Update(data)
	if err != ErrMACMismatch {
		t.Fatalf("expected ErrMACMismatch from Update, got %v", err)
	}
}

func TestValidatingUpdateSucceedsWithCorrectMACs(t *testing.T) {
	// Verify that Update returns nil when all intermediate MACs match.
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
	if err := v.Update(data); err != nil {
		t.Fatalf("Update should succeed with correct MACs: %v", err)
	}
	if err := v.Finalize(); err != nil {
		t.Fatalf("Finalize should succeed with correct MACs: %v", err)
	}
}

func TestValidatingFinalMACMismatchDetected(t *testing.T) {
	// Verify that Finalize catches a corrupt final MAC even when
	// all intermediate MACs are correct.
	key := testKey()
	chunkSize := MinChunkSize
	data := make([]byte, chunkSize+500)
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

	// Corrupt only the final MAC (last one).
	badMACs := make([][]byte, len(macs))
	for i, m := range macs {
		c := make([]byte, len(m))
		copy(c, m)
		badMACs[i] = c
	}
	badMACs[len(badMACs)-1][0] ^= 0xFF

	v, _ := NewValidating(key, chunkSize, badMACs)
	if err := v.Update(data); err != nil {
		t.Fatalf("Update should succeed (only final MAC corrupted): %v", err)
	}
	if err := v.Finalize(); err != ErrMACMismatch {
		t.Fatalf("Finalize should return ErrMACMismatch, got %v", err)
	}
}
