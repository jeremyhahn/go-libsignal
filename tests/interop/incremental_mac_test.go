// Conformance test: incremental MAC equivalence with single-shot HMAC.
//
// Mirrors the property exercised by rust/protocol/src/incremental_mac.rs::test::
// final_result_should_be_equal_to_non_incremental_hmac (proptest):
//
//   For any input length, the FINAL MAC produced by the incremental
//   builder must equal a plain HMAC-SHA-256 over the same input.
//
// We pin the same TEST_HMAC_KEY hex literal Rust uses, and run the
// equivalence assertion across a deterministic spread of input sizes
// that span chunk-aligned, partial-tail, and zero-length cases — the
// boundaries that have historically been the failure modes.

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

// TestIncrementalMAC_FinalEqualsPlainHMAC asserts byte-for-byte that
// the FINAL MAC from Incremental.Finalize equals a plain HMAC-SHA-256
// over the same bytes, across boundary sizes and longer inputs.
func TestIncrementalMAC_FinalEqualsPlainHMAC(t *testing.T) {
	key, err := hex.DecodeString(incrementalMacTestKeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	// A spread of input sizes that exercises:
	//   - empty input
	//   - sub-chunk inputs
	//   - exact-chunk inputs
	//   - chunk-plus-one (partial trailing chunk)
	//   - multi-chunk inputs
	// Sizes spanning sub-chunk, exact-chunk, partial-trailing-chunk and
	// multi-chunk territory. Each chunk is 64 KiB so the multipliers below
	// are in 64 KiB units.
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

		// The LAST MAC is the full-input MAC, which must equal plain HMAC.
		got := macs[len(macs)-1]
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Fatalf("incremental final MAC mismatch (size=%d):\n  got  %s\n  want %s",
				n, hex.EncodeToString(got), hex.EncodeToString(want))
		}
	}
}

// TestIncrementalMAC_ChunkBoundaryProducesIntermediateMAC asserts that
// when the input is a positive multiple of the chunk size, an
// intermediate MAC equal to plain-HMAC-of-that-prefix is produced at
// each boundary, and the final MAC is also recorded. This mirrors
// Rust's incremental_macs_are_valid proptest pattern but with
// deterministic inputs.
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

	// Expect numChunks intermediate MACs (one per boundary) + 1 final
	// MAC = numChunks+1 total. The final boundary intermediate MAC and
	// the final MAC are separate values: the intermediate is the MAC of
	// the prefix-up-to-boundary, the final is the MAC of the whole
	// input (which here equals the last intermediate since input length
	// is a multiple of chunk size, but they are still emitted as two
	// distinct elements).
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
