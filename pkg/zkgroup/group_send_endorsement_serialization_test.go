package zkgroup

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// makeTestGroupSendEndorsementsResponse builds a deterministic
// GroupSendEndorsementsResponse for serialization testing.
func makeTestGroupSendEndorsementsResponse(t *testing.T) *GroupSendEndorsementsResponse {
	t.Helper()

	var rootRandomness [zkcredential.RandomnessLen]byte
	for i := range rootRandomness {
		rootRandomness[i] = byte(i + 1)
	}
	rootKP, err := zkcredential.GenerateServerRootKeyPair(rootRandomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair: %v", err)
	}

	expiration := NewTimestamp(2 * SecondsPerDay)
	keyPair, err := ForExpiration(expiration, rootKP)
	if err != nil {
		t.Fatalf("ForExpiration: %v", err)
	}

	var groupRandomness RandomnessBytes
	for i := range groupRandomness {
		groupRandomness[i] = byte(i + 11)
	}
	groupParams, err := GenerateGroupSecretParams(groupRandomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	uuid1 := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	uuid2 := [UUIDLen]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	ct1 := groupParams.EncryptServiceID(NewACI(uuid1))
	ct2 := groupParams.EncryptServiceID(NewACI(uuid2))

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 55)
	}
	resp, err := IssueGroupSendEndorsements([]*UUIDCiphertext{ct1, ct2}, keyPair, issueRandomness)
	if err != nil {
		t.Fatalf("IssueGroupSendEndorsements: %v", err)
	}
	return resp
}

func TestGroupSendEndorsementsResponseSerialization_RoundTrip(t *testing.T) {
	original := makeTestGroupSendEndorsementsResponse(t)

	encoded := SerializeGroupSendEndorsementsResponse(original)

	decoded, err := DeserializeGroupSendEndorsementsResponse(encoded)
	if err != nil {
		t.Fatalf("DeserializeGroupSendEndorsementsResponse: %v", err)
	}

	// Expiration must be preserved.
	if decoded.Expiration != original.Expiration {
		t.Errorf("Expiration mismatch: got %d, want %d",
			decoded.Expiration.EpochSeconds(), original.Expiration.EpochSeconds())
	}

	// Endorsements R vector must match.
	if len(decoded.Endorsements.R) != len(original.Endorsements.R) {
		t.Fatalf("R length mismatch: got %d, want %d",
			len(decoded.Endorsements.R), len(original.Endorsements.R))
	}
	for i := range decoded.Endorsements.R {
		if !bytes.Equal(decoded.Endorsements.R[i], original.Endorsements.R[i]) {
			t.Errorf("R[%d] mismatch", i)
		}
	}

	// Proof must match.
	if !bytes.Equal(decoded.Endorsements.Proof, original.Endorsements.Proof) {
		t.Errorf("Proof mismatch:\n  got  %x\n  want %x",
			decoded.Endorsements.Proof, original.Endorsements.Proof)
	}
}

func TestGroupSendEndorsementsResponseSerialization_WireLayout(t *testing.T) {
	resp := makeTestGroupSendEndorsementsResponse(t)
	encoded := SerializeGroupSendEndorsementsResponse(resp)

	// Byte 0: reserved byte must be 0x00.
	if encoded[0] != 0x00 {
		t.Errorf("reserved byte: got 0x%02x, want 0x00", encoded[0])
	}
	off := 1

	// Bytes 1–8: LE u64 count of R points.
	nR := int(binary.LittleEndian.Uint64(encoded[off : off+8]))
	if nR != len(resp.Endorsements.R) {
		t.Errorf("R count: got %d, want %d", nR, len(resp.Endorsements.R))
	}
	off += 8

	// 32 bytes per R point.
	for i := range resp.Endorsements.R {
		if !bytes.Equal(encoded[off:off+32], resp.Endorsements.R[i]) {
			t.Errorf("R[%d] mismatch in wire layout", i)
		}
		off += 32
	}

	// LE u64 proof length.
	nProof := int(binary.LittleEndian.Uint64(encoded[off : off+8]))
	if nProof != len(resp.Endorsements.Proof) {
		t.Errorf("proof length: got %d, want %d", nProof, len(resp.Endorsements.Proof))
	}
	off += 8

	// Proof bytes.
	if !bytes.Equal(encoded[off:off+nProof], resp.Endorsements.Proof) {
		t.Error("proof bytes mismatch in wire layout")
	}
	off += nProof

	// Last 8 bytes: expiration as LE u64.
	if off+8 != len(encoded) {
		t.Errorf("expiration field offset wrong: off=%d, len=%d", off, len(encoded))
	}
	expSecs := binary.LittleEndian.Uint64(encoded[off : off+8])
	if expSecs != resp.Expiration.EpochSeconds() {
		t.Errorf("expiration: got %d, want %d", expSecs, resp.Expiration.EpochSeconds())
	}
}

func TestGroupSendEndorsementsResponseDeserialization_WrongReservedByte(t *testing.T) {
	resp := makeTestGroupSendEndorsementsResponse(t)
	encoded := SerializeGroupSendEndorsementsResponse(resp)

	corrupt := make([]byte, len(encoded))
	copy(corrupt, encoded)
	corrupt[0] = 0x01

	_, err := DeserializeGroupSendEndorsementsResponse(corrupt)
	if err == nil {
		t.Fatal("expected error for wrong reserved byte, got nil")
	}
	if _, ok := err.(*ErrUnexpectedReservedByte); !ok {
		t.Errorf("wrong error type: got %T, want *ErrUnexpectedReservedByte", err)
	}
}

func TestGroupSendEndorsementsResponseDeserialization_Truncated(t *testing.T) {
	resp := makeTestGroupSendEndorsementsResponse(t)
	encoded := SerializeGroupSendEndorsementsResponse(resp)

	truncationPoints := []int{0, 1, 2, 8, 9, len(encoded) - 1}
	for _, n := range truncationPoints {
		if n >= len(encoded) {
			continue
		}
		_, err := DeserializeGroupSendEndorsementsResponse(encoded[:n])
		if err == nil {
			t.Errorf("expected error for truncation at byte %d, got nil", n)
		}
	}
}

func TestGroupSendEndorsementsResponseDeserialization_TrailingBytes(t *testing.T) {
	resp := makeTestGroupSendEndorsementsResponse(t)
	encoded := SerializeGroupSendEndorsementsResponse(resp)

	withTrail := append(encoded, 0xFF)
	_, err := DeserializeGroupSendEndorsementsResponse(withTrail)
	if err == nil {
		t.Fatal("expected error for trailing bytes, got nil")
	}
}

func TestGroupSendEndorsementsResponseSerialization_PreservesVerifiability(t *testing.T) {
	// Serialize → Deserialize must produce a response that verifies correctly.
	var rootRandomness [zkcredential.RandomnessLen]byte
	for i := range rootRandomness {
		rootRandomness[i] = byte(i + 3)
	}
	rootKP, err := zkcredential.GenerateServerRootKeyPair(rootRandomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair: %v", err)
	}
	rootPubKey := rootKP.PublicKey()

	expiration := NewTimestamp(3 * SecondsPerDay)
	keyPair, err := ForExpiration(expiration, rootKP)
	if err != nil {
		t.Fatalf("ForExpiration: %v", err)
	}

	var groupRandomness RandomnessBytes
	for i := range groupRandomness {
		groupRandomness[i] = byte(i + 23)
	}
	groupParams, err := GenerateGroupSecretParams(groupRandomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	uuid1 := [UUIDLen]byte{0xAA}
	uuid2 := [UUIDLen]byte{0xBB}
	ct1 := groupParams.EncryptServiceID(NewACI(uuid1))
	ct2 := groupParams.EncryptServiceID(NewACI(uuid2))
	memberCTs := []*UUIDCiphertext{ct1, ct2}

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 88)
	}
	original, err := IssueGroupSendEndorsements(memberCTs, keyPair, issueRandomness)
	if err != nil {
		t.Fatalf("IssueGroupSendEndorsements: %v", err)
	}

	encoded := SerializeGroupSendEndorsementsResponse(original)
	restored, err := DeserializeGroupSendEndorsementsResponse(encoded)
	if err != nil {
		t.Fatalf("DeserializeGroupSendEndorsementsResponse: %v", err)
	}

	// now = 1 day after epoch; expiration is 3 days, so remaining = 2 days (valid).
	now := NewTimestamp(SecondsPerDay)
	received, err := restored.ReceiveWithCiphertexts(memberCTs, now, rootPubKey)
	if err != nil {
		t.Fatalf("ReceiveWithCiphertexts on restored response: %v", err)
	}
	if len(received) != len(memberCTs) {
		t.Errorf("received count: got %d, want %d", len(received), len(memberCTs))
	}
}
