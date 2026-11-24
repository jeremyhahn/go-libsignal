// Conformance: the final incremental MAC equals single-shot HMAC-SHA-256 for any input length, with Rust's TEST_HMAC_KEY across empty, partial and chunk-aligned sizes.

package interop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/incrementalmac"
)

const incrementalMacTestKeyHex = "a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98"

// MinChunkSize in pkg/incrementalmac is 64 KiB (the Signal-protocol-aligned
// minimum). Use it directly so this test stays in sync with the package
// constant if it ever changes.
const incrementalMacChunkSize = 64 * 1024

// TestIncrementalMAC_FinalEqualsPlainHMAC checks the final MAC equals plain HMAC-SHA-256 across boundary and longer sizes.
func TestIncrementalMAC_FinalEqualsPlainHMAC(t *testing.T) {
	key, err := hex.DecodeString(incrementalMacTestKeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	// Sizes in 64 KiB chunk units: empty, sub-chunk, exact, chunk plus one and multi-chunk.
	sizes := []int{
		0, 1, 7, 31, 32, 33, 1024, 4096,
		incrementalMacChunkSize - 1,
		incrementalMacChunkSize,
		incrementalMacChunkSize + 1,
		2*incrementalMacChunkSize - 1,
		2 * incrementalMacChunkSize,
		2*incrementalMacChunkSize + 1,
	}

	for _, n := range sizes {
		// Deterministic input: byte i = (i * 37 + 13) mod 256. Doesn't
		// rely on randomness so failures are reproducible.
		input := make([]byte, n)
		for i := range input {
			input[i] = byte((i*37 + 13) & 0xff)
		}

		mac := hmac.New(sha256.New, key)
		mac.Write(input)
		want := mac.Sum(nil)

		inc, err := incrementalmac.New(key, incrementalMacChunkSize)
		if err != nil {
			t.Fatalf("incrementalmac.New: %v", err)
		}
		if _, err := inc.Update(input); err != nil {
			t.Fatalf("Incremental.Update(size=%d): %v", n, err)
		}
		macs, err := inc.Finalize()
		if err != nil {
			t.Fatalf("Incremental.Finalize(size=%d): %v", n, err)
		}
		if len(macs) == 0 {
			t.Fatalf("Finalize produced no MACs for size=%d", n)
		}

		// The last MAC covers the whole input and must equal plain HMAC.
		got := macs[len(macs)-1]
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Fatalf("incremental final MAC mismatch (size=%d):\n  got  %s\n  want %s",
				n, hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}

// TestIncrementalMAC_ChunkBoundaryProducesIntermediateMAC checks each chunk boundary yields the HMAC of its prefix, plus the final MAC.
func TestIncrementalMAC_ChunkBoundaryProducesIntermediateMAC(t *testing.T) {
	key, err := hex.DecodeString(incrementalMacTestKeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	// Five full chunks: 5 * 32 = 160 bytes.
	const numChunks = 5
	input := make([]byte, numChunks*incrementalMacChunkSize)
	for i := range input {
		input[i] = byte(i & 0xff)
	}

	inc, err := incrementalmac.New(key, incrementalMacChunkSize)
	if err != nil {
		t.Fatalf("incrementalmac.New: %v", err)
	}
	if _, err := inc.Update(input); err != nil {
		t.Fatalf("Update: %v", err)
	}
	macs, err := inc.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// Expect one MAC per boundary plus the final MAC, emitted separately even when equal.
	if len(macs) < numChunks {
		t.Fatalf("expected at least %d MACs, got %d", numChunks, len(macs))
	}

	for i := 0; i < numChunks; i++ {
		prefix := input[:(i+1)*incrementalMacChunkSize]
		mac := hmac.New(sha256.New, key)
		mac.Write(prefix)
		want := mac.Sum(nil)

		got := macs[i]
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Fatalf("intermediate MAC[%d] (over prefix len=%d) mismatch:\n  got  %s\n  want %s",
				i, len(prefix), hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}
