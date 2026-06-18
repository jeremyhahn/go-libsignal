package zkcredential

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gtank/ristretto255"
)

// makeTestEndorsementResponse issues a small EndorsementResponse using
// deterministic inputs so the test is self-contained.
func makeTestEndorsementResponse(t *testing.T) *EndorsementResponse {
	t.Helper()
	var rootRandomness [RandomnessLen]byte
	for i := range rootRandomness {
		rootRandomness[i] = byte(i + 1)
	}
	rootKP, err := GenerateServerRootKeyPair(rootRandomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair: %v", err)
	}

	tagSho := NewShoHmacSha256Ext("TestEndorsementSerialization")
	tagSho.AbsorbAndRatchet(rootRandomness[:])
	derivedKP, err := rootKP.DeriveKey(tagSho)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	// Two hidden attribute points from a deterministic SHO.
	pointSho := NewShoSha256Ext("TestPoints")
	p1 := pointSho.MustGetPoint()
	p2 := pointSho.MustGetPoint()

	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 43)
	}
	resp, err := IssueEndorsements([]*ristretto255.Element{p1, p2}, derivedKP, issueRandomness)
	if err != nil {
		t.Fatalf("IssueEndorsements: %v", err)
	}
	return resp
}

func TestEndorsementResponseSerialization_RoundTrip(t *testing.T) {
	original := makeTestEndorsementResponse(t)

	encoded := SerializeEndorsementResponse(original)

	decoded, err := DeserializeEndorsementResponse(encoded)
	if err != nil {
		t.Fatalf("DeserializeEndorsementResponse: %v", err)
	}

	if len(decoded.R) != len(original.R) {
		t.Fatalf("R length mismatch: got %d, want %d", len(decoded.R), len(original.R))
	}
	for i := range decoded.R {
		if !bytes.Equal(decoded.R[i], original.R[i]) {
			t.Errorf("R[%d] mismatch", i)
		}
	}

	if !bytes.Equal(decoded.Proof, original.Proof) {
		t.Errorf("Proof mismatch:\n  got  %x\n  want %x", decoded.Proof, original.Proof)
	}
}

func TestEndorsementResponseSerialization_WireLayout(t *testing.T) {
	// Verify the wire layout byte-by-byte matches the expected bincode format.
	resp := makeTestEndorsementResponse(t)
	encoded := SerializeEndorsementResponse(resp)

	off := 0

	// First 8 bytes: LE u64 count of R points.
	if len(encoded) < 8 {
		t.Fatal("encoded too short for R length field")
	}
	nR := int(binary.LittleEndian.Uint64(encoded[off : off+8]))
	if nR != len(resp.R) {
		t.Errorf("R count field: got %d, want %d", nR, len(resp.R))
	}
	off += 8

	// Each R point is 32 bytes.
	for i := range resp.R {
		if !bytes.Equal(encoded[off:off+32], resp.R[i]) {
			t.Errorf("R[%d] bytes mismatch in wire layout", i)
		}
		off += 32
	}

	// Next 8 bytes: LE u64 proof length.
	if len(encoded) < off+8 {
		t.Fatal("encoded too short for proof length field")
	}
	nProof := int(binary.LittleEndian.Uint64(encoded[off : off+8]))
	if nProof != len(resp.Proof) {
		t.Errorf("proof length field: got %d, want %d", nProof, len(resp.Proof))
	}
	off += 8

	// Proof bytes.
	if !bytes.Equal(encoded[off:off+nProof], resp.Proof) {
		t.Error("proof bytes mismatch in wire layout")
	}
	off += nProof

	if off != len(encoded) {
		t.Errorf("unexpected trailing bytes: consumed %d of %d", off, len(encoded))
	}
}

func TestEndorsementResponseDeserialization_Truncated(t *testing.T) {
	resp := makeTestEndorsementResponse(t)
	encoded := SerializeEndorsementResponse(resp)

	// Truncate at various points; all should return an error.
	truncationPoints := []int{0, 1, 4, 7, 9}
	for _, n := range truncationPoints {
		if n >= len(encoded) {
			continue
		}
		_, err := DeserializeEndorsementResponse(encoded[:n])
		if err == nil {
			t.Errorf("expected error for truncation at byte %d, got nil", n)
		}
	}

	// One byte short of complete should also fail.
	if len(encoded) > 0 {
		_, err := DeserializeEndorsementResponse(encoded[:len(encoded)-1])
		if err == nil {
			t.Errorf("expected error for data truncated by 1 byte, got nil")
		}
	}
}

func TestEndorsementResponseDeserialization_TrailingBytes(t *testing.T) {
	resp := makeTestEndorsementResponse(t)
	encoded := SerializeEndorsementResponse(resp)

	// Append a trailing byte; bincode rejects trailing bytes.
	withTrail := append(encoded, 0xFF)
	_, err := DeserializeEndorsementResponse(withTrail)
	if err == nil {
		t.Fatal("expected error for trailing bytes, got nil")
	}
}

func TestEndorsementResponseDeserialization_BadLengthPrefix(t *testing.T) {
	resp := makeTestEndorsementResponse(t)
	encoded := SerializeEndorsementResponse(resp)

	// Set R count to a huge number so the data appears far too short.
	corrupt := make([]byte, len(encoded))
	copy(corrupt, encoded)
	binary.LittleEndian.PutUint64(corrupt[0:8], 1<<60)

	_, err := DeserializeEndorsementResponse(corrupt)
	if err == nil {
		t.Fatal("expected error for corrupt R length prefix, got nil")
	}
}

// TestEndorsementResponseDeserialization_BadProofLengthPrefix verifies that a
// proof length prefix set to a value larger than the remaining data causes a
// typed error rather than panicking or integer-overflowing in the diagnostic
// Need value (LOW-9 fix: narrowing cast through ReadBincodeU64Len).
func TestEndorsementResponseDeserialization_BadProofLengthPrefix(t *testing.T) {
	resp := makeTestEndorsementResponse(t)
	encoded := SerializeEndorsementResponse(resp)

	// The proof length prefix sits after the 8-byte R-count and the R points.
	nR := len(resp.R)
	proofLenOffset := 8 + nR*32

	corrupt := make([]byte, len(encoded))
	copy(corrupt, encoded)
	// Write a u64 that is far larger than the remaining input, triggering the
	// narrowing-cast guard in ReadBincodeU64Len.
	binary.LittleEndian.PutUint64(corrupt[proofLenOffset:proofLenOffset+8], 1<<62)

	_, err := DeserializeEndorsementResponse(corrupt)
	if err == nil {
		t.Fatal("expected error for corrupt proof length prefix, got nil")
	}
	// The error must be a typed ErrEndorsementResponseTruncated — not a panic.
	if _, ok := err.(*ErrEndorsementResponseTruncated); !ok {
		t.Errorf("expected *ErrEndorsementResponseTruncated, got %T: %v", err, err)
	}
}

func TestReadEndorsementResponse_PartialConsumption(t *testing.T) {
	// ReadEndorsementResponse must leave the suffix for the caller.
	resp := makeTestEndorsementResponse(t)
	encoded := SerializeEndorsementResponse(resp)

	suffix := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	combined := append(encoded, suffix...)

	parsed, tail, err := ReadEndorsementResponse(combined)
	if err != nil {
		t.Fatalf("ReadEndorsementResponse: %v", err)
	}
	if !bytes.Equal(tail, suffix) {
		t.Errorf("tail mismatch: got %x, want %x", tail, suffix)
	}
	if len(parsed.R) != len(resp.R) {
		t.Errorf("R count mismatch: got %d, want %d", len(parsed.R), len(resp.R))
	}
	if !bytes.Equal(parsed.Proof, resp.Proof) {
		t.Error("Proof mismatch after partial read")
	}
}

func TestEndorsementResponseSerialization_PreservesVerifiability(t *testing.T) {
	// Serialize → Deserialize must produce a response that still verifies.
	var rootRandomness [RandomnessLen]byte
	for i := range rootRandomness {
		rootRandomness[i] = byte(i + 7)
	}
	rootKP, err := GenerateServerRootKeyPair(rootRandomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair: %v", err)
	}

	tagSho := NewShoHmacSha256Ext("TestVerify")
	tagSho.AbsorbAndRatchet(rootRandomness[:])
	derivedKP, err := rootKP.DeriveKey(tagSho)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	pointSho := NewShoSha256Ext("TestVerifyPoints")
	points := make([]*ristretto255.Element, 3)
	for i := range points {
		points[i] = pointSho.MustGetPoint()
	}

	var issueRandomness [RandomnessLen]byte
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 77)
	}
	original, err := IssueEndorsements(points, derivedKP, issueRandomness)
	if err != nil {
		t.Fatalf("IssueEndorsements: %v", err)
	}

	// Serialize and deserialize.
	encoded := SerializeEndorsementResponse(original)
	restored, err := DeserializeEndorsementResponse(encoded)
	if err != nil {
		t.Fatalf("DeserializeEndorsementResponse: %v", err)
	}

	// The restored response must verify correctly.
	pubTagSho := NewShoHmacSha256Ext("TestVerify")
	pubTagSho.AbsorbAndRatchet(rootRandomness[:])
	pubKey, err := rootKP.PublicKey().DeriveKey(pubTagSho)
	if err != nil {
		t.Fatalf("DeriveKey (public): %v", err)
	}

	_, err = restored.Receive(points, pubKey)
	if err != nil {
		t.Fatalf("Receive on restored EndorsementResponse: %v", err)
	}
}
