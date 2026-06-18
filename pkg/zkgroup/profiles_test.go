package zkgroup

import (
	"testing"
)

func TestGenerateProfileKey(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i)
	}
	pk := GenerateProfileKey(randomness)
	if pk == nil {
		t.Fatal("returned nil")
	}

	// Deterministic
	pk2 := GenerateProfileKey(randomness)
	if pk.Bytes != pk2.Bytes {
		t.Error("not deterministic")
	}

	// Different randomness
	var randomness2 RandomnessBytes
	for i := range randomness2 {
		randomness2[i] = byte(i + 100)
	}
	pk3 := GenerateProfileKey(randomness2)
	if pk.Bytes == pk3.Bytes {
		t.Error("different randomness produced same key")
	}
}

func TestNewProfileKey(t *testing.T) {
	var bytes ProfileKeyBytes
	for i := range bytes {
		bytes[i] = byte(i)
	}
	pk := NewProfileKey(bytes)
	if pk.Bytes != bytes {
		t.Error("bytes mismatch")
	}
	if pk.GetBytes() != bytes {
		t.Error("GetBytes mismatch")
	}
}

func TestProfileKey_GetCommitment(t *testing.T) {
	var bytes ProfileKeyBytes
	for i := range bytes {
		bytes[i] = byte(i)
	}
	pk := NewProfileKey(bytes)
	uuid := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid := NewACI(uuid)

	commitment := pk.GetCommitment(sid)
	if commitment == nil {
		t.Fatal("returned nil")
	}
	if commitment.Commitment == nil {
		t.Fatal("Commitment is nil")
	}
}

func TestProfileKey_GetProfileKeyVersion(t *testing.T) {
	var bytes ProfileKeyBytes
	for i := range bytes {
		bytes[i] = byte(i)
	}
	pk := NewProfileKey(bytes)
	uuid := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid := NewACI(uuid)

	version := pk.GetProfileKeyVersion(sid)
	if version == nil {
		t.Fatal("returned nil")
	}

	str := version.String()
	if len(str) != ProfileKeyVersionEncodedLen {
		t.Errorf("version string length = %d, want %d", len(str), ProfileKeyVersionEncodedLen)
	}

	// Deterministic
	version2 := pk.GetProfileKeyVersion(sid)
	if version.String() != version2.String() {
		t.Error("not deterministic")
	}
}
