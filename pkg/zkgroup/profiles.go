package zkgroup

import (
	"encoding/hex"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// ProfileKey is a 32-byte key used to encrypt a user's profile.
type ProfileKey struct {
	Bytes ProfileKeyBytes
}

// GenerateProfileKey creates a new ProfileKey from randomness.
func GenerateProfileKey(randomness RandomnessBytes) *ProfileKey {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20200424_Random_ProfileKey_Generate",
	)
	sho.AbsorbAndRatchet(randomness[:])
	var bytes ProfileKeyBytes
	copy(bytes[:], sho.SqueezeAndRatchet(ProfileKeyLen))
	return &ProfileKey{Bytes: bytes}
}

// NewProfileKey creates a ProfileKey from raw bytes.
func NewProfileKey(bytes ProfileKeyBytes) *ProfileKey {
	return &ProfileKey{Bytes: bytes}
}

// GetBytes returns the raw profile key bytes.
func (pk *ProfileKey) GetBytes() ProfileKeyBytes {
	return pk.Bytes
}

// GetCommitment computes the profile key commitment for this key and user.
func (pk *ProfileKey) GetCommitment(userID ServiceID) *ProfileKeyCommitment {
	uidBytes := userID.RawUUID
	pkStruct := NewProfileKeyStruct(pk.Bytes, uidBytes)
	commitment := NewProfileKeyCommitmentWithSecretNonce(pkStruct, uidBytes)
	return &ProfileKeyCommitment{
		Commitment: commitment.GetCommitment(),
	}
}

// GetProfileKeyVersion computes the profile key version for this key and user.
func (pk *ProfileKey) GetProfileKeyVersion(userID ServiceID) *ProfileKeyVersion {
	uidBytes := userID.RawUUID
	combined := make([]byte, ProfileKeyLen+UUIDLen)
	copy(combined[:ProfileKeyLen], pk.Bytes[:])
	copy(combined[ProfileKeyLen:], uidBytes[:])

	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_GetProfileKeyVersion",
	)
	sho.AbsorbAndRatchet(combined)

	versionBytes := sho.SqueezeAndRatchet(ProfileKeyVersionLen)
	encoded := hex.EncodeToString(versionBytes)

	var ascii ProfileKeyVersionEncodedBytes
	copy(ascii[:], []byte(encoded))

	return &ProfileKeyVersion{ASCII: ascii}
}

// ProfileKeyCommitment is a commitment to a (profile key, user ID) pair.
type ProfileKeyCommitment struct {
	Commitment *ProfileKeyCommitmentInternal
}

// ProfileKeyVersion is an identifier for a particular (profile key, ACI)
// combination, encoded as a hexadecimal ASCII string.
type ProfileKeyVersion struct {
	ASCII ProfileKeyVersionEncodedBytes
}

// String returns the version as a string.
func (v *ProfileKeyVersion) String() string {
	return string(v.ASCII[:])
}
