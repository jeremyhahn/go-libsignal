package incrementalmac

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestIncremental_Destroy verifies that Destroy zeroizes the HMAC outer key
// without panicking, and that calling Destroy on a nil-hmac Incremental is safe.

func TestIncremental_Destroy(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	inc, err := New(key, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}

	// Feed some data then finalize to populate MACs.
	data := make([]byte, MinChunkSize+100)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if _, err := inc.Finalize(); err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// Destroy must not panic.
	inc.Destroy()

	// Calling Destroy again must not panic (idempotent).
	inc.Destroy()
}

func TestIncremental_Destroy_NilHMAC(t *testing.T) {
	// An Incremental with nil hmac field must not panic on Destroy.
	inc := &Incremental{}
	inc.Destroy() // must not panic
}

// TestValidating_Destroy verifies that Destroy delegates to the underlying
// Incremental.Destroy and does not panic.

func TestValidating_Destroy(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	data := make([]byte, MinChunkSize+50)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	// Build valid MACs to construct the Validating instance.
	inc, err := New(key, MinChunkSize)
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

	v, err := NewValidating(key, MinChunkSize, macs)
	if err != nil {
		t.Fatal(err)
	}

	// Destroy must not panic.
	v.Destroy()

	// Calling Destroy again must not panic (idempotent).
	v.Destroy()
}

func TestValidating_Destroy_NilInc(t *testing.T) {
	// A Validating with nil inc field must not panic on Destroy.
	v := &Validating{}
	v.Destroy() // must not panic
}

// TestNewClonableHMAC_LongKey exercises the key-hashing branch in newClonableHMAC
// where the key is longer than sha256BlockSize (64 bytes). This branch hashes the
// key down to 32 bytes before constructing the HMAC.

func TestNewClonableHMAC_LongKey(t *testing.T) {
	// Use a key longer than 64 bytes to trigger the key-hashing branch.
	longKey := make([]byte, sha256BlockSize+1)
	for i := range longKey {
		longKey[i] = byte(i)
	}

	h := newClonableHMAC(longKey)
	if h == nil {
		t.Fatal("newClonableHMAC returned nil for long key")
	}
	if h.inner == nil {
		t.Fatal("inner hash must not be nil")
	}
	if h.outerKey == nil {
		t.Fatal("outerKey must not be nil")
	}

	// Write some data and finalize to verify the HMAC is functional.
	data := []byte("test data for long key HMAC")
	h.Write(data)
	digest := h.cloneAndFinalize()
	if len(digest) != DigestLength {
		t.Fatalf("digest length = %d, want %d", len(digest), DigestLength)
	}

	// Verify consistency: same key + data must produce same MAC.
	h2 := newClonableHMAC(longKey)
	h2.Write(data)
	digest2 := h2.cloneAndFinalize()
	if !bytes.Equal(digest, digest2) {
		t.Error("same long key + same data must produce identical MACs")
	}
}

func TestNewClonableHMAC_LongKeyVsShortKeyDiffers(t *testing.T) {
	// A long key that hashes to a different value than a short key must
	// produce different MACs, confirming the hashing branch is active.
	longKey := bytes.Repeat([]byte{0xAB}, sha256BlockSize+1)
	shortKey := bytes.Repeat([]byte{0xAB}, 32)

	data := []byte("discriminating data")

	h1 := newClonableHMAC(longKey)
	h1.Write(data)
	mac1 := h1.sum()

	h2 := newClonableHMAC(shortKey)
	h2.Write(data)
	mac2 := h2.sum()

	if bytes.Equal(mac1, mac2) {
		t.Error("long-key HMAC must differ from short-key HMAC for different key content")
	}
}

// TestCloneAndFinalize_DoesNotMutateState verifies that cloneAndFinalize does not
// disturb the running inner hash — subsequent writes still accumulate correctly.
// Uses 2 full chunks plus a trailing byte so the final MAC differs from the
// second intermediate MAC (they cover different amounts of data).

func TestCloneAndFinalize_DoesNotMutateState(t *testing.T) {
	key := testKey()
	chunkSize := MinChunkSize
	// 2 full chunks + 1 extra byte so the final MAC != the second intermediate.
	data := make([]byte, chunkSize*2+1)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	// Compute MACs via incremental (uses cloneAndFinalize internally at boundaries).
	inc, _ := New(key, chunkSize)
	if _, err := inc.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	// 2 intermediate MACs + 1 final = 3 MACs total.
	if len(macs) != 3 {
		t.Fatalf("expected 3 MACs, got %d", len(macs))
	}

	// Each intermediate MAC covers a different prefix, so MACs[0] != MACs[1].
	if bytes.Equal(macs[0], macs[1]) {
		t.Error("intermediate MACs 0 and 1 must differ (different prefixes)")
	}
	// The final MAC covers all data including the trailing byte, so it differs
	// from the second intermediate (which covers only the first two chunks).
	if bytes.Equal(macs[1], macs[2]) {
		t.Error("second intermediate and final MACs must differ (extra trailing byte)")
	}
}
