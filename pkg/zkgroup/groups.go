package zkgroup

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// GroupMasterKey is the root key for a Signal group.
type GroupMasterKey struct {
	Bytes GroupMasterKeyBytes
}

// NewGroupMasterKey creates a GroupMasterKey from raw bytes.
func NewGroupMasterKey(bytes GroupMasterKeyBytes) GroupMasterKey {
	return GroupMasterKey{Bytes: bytes}
}

// GroupSecretParams contains the secret parameters for a Signal group, derived
// from the group master key.
type GroupSecretParams struct {
	MasterKey           GroupMasterKey
	GroupID             GroupIdentifierBytes
	BlobKey             AESKeyBytes
	UIDEncKeyPair       *zkcredential.KeyPair
	ProfileKeyEncKeyPair *zkcredential.KeyPair
}

// GenerateGroupSecretParams creates new group secret parameters from randomness.
func GenerateGroupSecretParams(randomness RandomnessBytes) (*GroupSecretParams, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20200424_Random_GroupSecretParams_Generate",
	)
	sho.AbsorbAndRatchet(randomness[:])

	var masterKeyBytes GroupMasterKeyBytes
	copy(masterKeyBytes[:], sho.SqueezeAndRatchet(GroupMasterKeyLen))
	return DeriveGroupSecretParams(NewGroupMasterKey(masterKeyBytes))
}

// DeriveGroupSecretParams derives group secret parameters from a master key.
func DeriveGroupSecretParams(masterKey GroupMasterKey) (*GroupSecretParams, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey",
	)
	sho.AbsorbAndRatchet(masterKey.Bytes[:])

	var groupID GroupIdentifierBytes
	copy(groupID[:], sho.SqueezeAndRatchet(GroupIdentifierLen))

	var blobKey AESKeyBytes
	copy(blobKey[:], sho.SqueezeAndRatchet(AESKeyLen))

	uidDomain := UIDEncryptionDomain{}
	uidKP, err := zkcredential.DeriveKeyPair(sho, uidDomain)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to derive uid enc key pair: " + err.Error()}
	}

	pkDomain := ProfileKeyEncryptionDomain{}
	pkKP, err := zkcredential.DeriveKeyPair(sho, pkDomain)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "failed to derive profile key enc key pair: " + err.Error()}
	}

	return &GroupSecretParams{
		MasterKey:           masterKey,
		GroupID:             groupID,
		BlobKey:             blobKey,
		UIDEncKeyPair:       uidKP,
		ProfileKeyEncKeyPair: pkKP,
	}, nil
}

// GetMasterKey returns the group master key.
func (g *GroupSecretParams) GetMasterKey() GroupMasterKey {
	return g.MasterKey
}

// GetGroupIdentifier returns the group identifier.
func (g *GroupSecretParams) GetGroupIdentifier() GroupIdentifierBytes {
	return g.GroupID
}

// GetPublicParams derives the public parameters from the group secret params.
func (g *GroupSecretParams) GetPublicParams() *GroupPublicParams {
	return &GroupPublicParams{
		GroupID:             g.GroupID,
		UIDEncPublicKey:     g.UIDEncKeyPair.PublicKey,
		ProfileKeyEncPublicKey: g.ProfileKeyEncKeyPair.PublicKey,
	}
}

// Zeroize overwrites all secret key material in GroupSecretParams with zeros.
// Call this (via defer) when the params are no longer needed.
func (g *GroupSecretParams) Zeroize() {
	crypto.Zeroize(g.MasterKey.Bytes[:])
	crypto.Zeroize(g.BlobKey[:])
}

// encryptedBlobPaddingLenSize is the size of the padding length prefix in
// encrypted blobs (4 bytes, big-endian u32).
const encryptedBlobPaddingLenSize = 4

// EncryptBlob encrypts plaintext using the group's blob key with AES-256-GCM-SIV.
// The nonce is derived from randomness via SHO, and the output format is:
// ciphertext || tag || nonce (12 bytes) || reserved byte (0x00).
//
// This matches Rust GroupSecretParams::encrypt_blob.
func (g *GroupSecretParams) EncryptBlob(randomness [32]byte, plaintext []byte) ([]byte, error) {
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20200424_Random_GroupSecretParams_EncryptBlob",
	)
	sho.AbsorbAndRatchet(randomness[:])
	nonceBytes := sho.SqueezeAndRatchet(AESGCMNonceLen)

	ciphertext, err := cipher.AESGCMSIVEncrypt(g.BlobKey[:], nonceBytes, plaintext, nil)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "blob encrypt: " + err.Error()}
	}

	// Output: ciphertext || nonce || reserved(0x00)
	out := make([]byte, 0, len(ciphertext)+AESGCMNonceLen+1)
	out = append(out, ciphertext...)
	out = append(out, nonceBytes...)
	out = append(out, 0) // reserved byte
	return out, nil
}

// EncryptBlobWithPadding encrypts plaintext with zero-padding using the group's
// blob key. The plaintext is prefixed with a 4-byte big-endian padding length,
// then zero-padded to (4 + len(plaintext) + paddingLen) bytes before encryption.
//
// This matches Rust GroupSecretParams::encrypt_blob_with_padding.
func (g *GroupSecretParams) EncryptBlobWithPadding(randomness [32]byte, plaintext []byte, paddingLen int) ([]byte, error) {
	if paddingLen < 0 {
		return nil, &ZkGroupVerificationFailure{Context: "blob encrypt: negative padding length"}
	}

	fullLength := encryptedBlobPaddingLenSize + len(plaintext) + paddingLen
	padded := make([]byte, fullLength)
	binary.BigEndian.PutUint32(padded[:encryptedBlobPaddingLenSize], uint32(paddingLen))
	copy(padded[encryptedBlobPaddingLenSize:], plaintext)
	// Remaining bytes are already zero (padding).

	return g.EncryptBlob(randomness, padded)
}

// DecryptBlob decrypts ciphertext encrypted with EncryptBlob.
// The input format is: ciphertext || tag || nonce (12 bytes) || reserved byte.
//
// This matches Rust GroupSecretParams::decrypt_blob.
func (g *GroupSecretParams) DecryptBlob(ciphertext []byte) ([]byte, error) {
	// Minimum: AES-GCM nonce (12) + reserved byte (1)
	minLen := AESGCMNonceLen + 1
	if len(ciphertext) < minLen {
		return nil, &ZkGroupVerificationFailure{Context: "blob decrypt: ciphertext too short"}
	}

	// Strip reserved byte, then extract nonce from the end.
	unreservedLen := len(ciphertext) - 1
	data := ciphertext[:unreservedLen]

	nonceStart := len(data) - AESGCMNonceLen
	ct := data[:nonceStart]
	nonce := data[nonceStart:]

	// Minimum ciphertext must include the tag.
	if len(ct) < AESGCMTagLen {
		return nil, &ZkGroupVerificationFailure{Context: "blob decrypt: ciphertext too short for tag"}
	}

	plaintext, err := cipher.AESGCMSIVDecrypt(g.BlobKey[:], nonce, ct, nil)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "blob decrypt: " + err.Error()}
	}
	return plaintext, nil
}

// DecryptBlobWithPadding decrypts ciphertext and strips the padding that was
// added by EncryptBlobWithPadding. The first 4 bytes of the decrypted plaintext
// are a big-endian u32 indicating the padding length, which is stripped along
// with the trailing zero-padding bytes.
//
// This matches Rust GroupSecretParams::decrypt_blob_with_padding.
func (g *GroupSecretParams) DecryptBlobWithPadding(ciphertext []byte) ([]byte, error) {
	decrypted, err := g.DecryptBlob(ciphertext)
	if err != nil {
		return nil, err
	}

	if len(decrypted) < encryptedBlobPaddingLenSize {
		return nil, &ZkGroupVerificationFailure{Context: "blob decrypt: decrypted data too short for padding header"}
	}

	paddingLen := binary.BigEndian.Uint32(decrypted[:encryptedBlobPaddingLenSize])
	plaintextPlusPadding := decrypted[encryptedBlobPaddingLenSize:]

	if int(paddingLen) > len(plaintextPlusPadding) {
		return nil, &ZkGroupVerificationFailure{Context: "blob decrypt: padding length exceeds data"}
	}

	// Return only the plaintext portion (without the padding length prefix and padding).
	plaintextLen := len(plaintextPlusPadding) - int(paddingLen)
	return plaintextPlusPadding[:plaintextLen], nil
}

// EncryptServiceID encrypts a ServiceID under the group's UID encryption key.
func (g *GroupSecretParams) EncryptServiceID(sid ServiceID) *UUIDCiphertext {
	uid := NewUIDStructFromServiceID(sid)
	ct := g.UIDEncKeyPair.Encrypt(uid)
	return &UUIDCiphertext{Ciphertext: ct}
}

// DecryptServiceID decrypts a UUIDCiphertext back to a ServiceID.
//
// The ciphertext is decrypted using the group's UID encryption key pair:
//  1. Decrypt to recover M2 via DecryptToSecondPoint
//  2. LizardDecode M2 to recover the raw UUID bytes
//  3. Compute M1 for both ACI and PNI candidates
//  4. Compare decrypted M1 against both to determine the ServiceID type
//
// This matches Rust UidEncryptionDomain::decrypt.
func (g *GroupSecretParams) DecryptServiceID(ct *UUIDCiphertext) (ServiceID, error) {
	m2, err := g.UIDEncKeyPair.DecryptToSecondPoint(ct.Ciphertext)
	if err != nil {
		return ServiceID{}, ErrVerificationFailure
	}

	uuidBytes, ok := LizardDecode(m2)
	if !ok {
		return ServiceID{}, ErrVerificationFailure
	}

	// Recover M1: M1 = a1^{-1} * EA1
	a1Inv := new(ristretto255.Scalar).Invert(g.UIDEncKeyPair.A1)
	decryptedM1 := new(ristretto255.Element).ScalarMult(a1Inv, ct.Ciphertext.EA1)

	// Try both ACI and PNI — constant-time to avoid leaking which type matched.
	aciSID := NewACI(uuidBytes)
	pniSID := NewPNI(uuidBytes)

	aciUID := NewUIDStructFromServiceID(aciSID)
	pniUID := NewUIDStructFromServiceID(pniSID)

	// Both comparisons always execute regardless of match.
	aciMatch := decryptedM1.Equal(aciUID.M1) // 1 if match, 0 otherwise
	pniMatch := decryptedM1.Equal(pniUID.M1)

	// Constant-time select: build result bytes without branching.
	// ServiceID is {Type (1 byte), RawUUID (16 bytes)}.
	var resultType [1]byte
	aciType := [1]byte{byte(aciSID.Type)}
	pniType := [1]byte{byte(pniSID.Type)}
	subtle.ConstantTimeCopy(aciMatch, resultType[:], aciType[:])
	subtle.ConstantTimeCopy(pniMatch, resultType[:], pniType[:])

	var resultUUID [UUIDLen]byte
	subtle.ConstantTimeCopy(aciMatch, resultUUID[:], aciSID.RawUUID[:])
	subtle.ConstantTimeCopy(pniMatch, resultUUID[:], pniSID.RawUUID[:])

	matched := aciMatch | pniMatch
	if matched != 1 {
		return ServiceID{}, ErrVerificationFailure
	}

	return ServiceID{Type: ServiceIDType(resultType[0]), RawUUID: resultUUID}, nil
}

// EncryptProfileKey encrypts a profile key under the group's profile key
// encryption key.
func (g *GroupSecretParams) EncryptProfileKey(
	profileKey *ProfileKey,
	userID ServiceID,
) *ProfileKeyCiphertext {
	return g.EncryptProfileKeyBytes(profileKey.Bytes, userID)
}

// EncryptProfileKeyBytes encrypts raw profile key bytes.
func (g *GroupSecretParams) EncryptProfileKeyBytes(
	profileKeyBytes ProfileKeyBytes,
	userID ServiceID,
) *ProfileKeyCiphertext {
	pkStruct := NewProfileKeyStruct(profileKeyBytes, userID.RawUUID)
	ct := g.ProfileKeyEncKeyPair.Encrypt(pkStruct)
	return &ProfileKeyCiphertext{Ciphertext: ct}
}

// DecryptProfileKey decrypts a ProfileKeyCiphertext back to a ProfileKey.
//
// The algorithm matches Rust ProfileKeyEncryptionDomain::decrypt:
//  1. Decrypt to recover M4 via DecryptToSecondPoint
//  2. Use Decode253Bits on M4 to get up to 8 candidate 32-byte field elements
//  3. For each valid candidate, try all 8 combinations of the 3 cleared bits
//  4. Compute M3 for each and compare against the decrypted M1 (target_M3)
//  5. Return the matching profile key
func (g *GroupSecretParams) DecryptProfileKey(
	ct *ProfileKeyCiphertext,
	userID ServiceID,
) (*ProfileKey, error) {
	m4, err := g.ProfileKeyEncKeyPair.DecryptToSecondPoint(ct.Ciphertext)
	if err != nil {
		return nil, ErrVerificationFailure
	}

	mask, candidates, ok := Decode253Bits(m4)
	if !ok {
		return nil, ErrVerificationFailure
	}

	// Compute target M3 by decrypting the first point:
	// target_M3 = a1^{-1} * EA1
	a1Inv := new(ristretto255.Scalar).Invert(g.ProfileKeyEncKeyPair.A1)
	targetM3 := new(ristretto255.Element).ScalarMult(a1Inv, ct.Ciphertext.EA1)

	uidBytes := userID.RawUUID
	var result ProfileKeyBytes
	nFound := 0

	for i := 0; i < 8; i++ {
		if mask&(1<<i) == 0 {
			continue
		}

		candidateBytes := candidates[i]

		// The original profile key had bits cleared: [0] &= 254, [31] &= 63.
		// Try all 8 combinations of those 3 bits.
		for j := 0; j < 8; j++ {
			var pk ProfileKeyBytes
			copy(pk[:], candidateBytes[:])

			if (j>>2)&1 == 1 {
				pk[0] |= 0x01
			}
			if (j>>1)&1 == 1 {
				pk[31] |= 0x80
			}
			if j&1 == 1 {
				pk[31] |= 0x40
			}

			candidateM3 := calcProfileKeyM3(pk, uidBytes)
			match := candidateM3.Equal(targetM3) // 1 if match, 0 otherwise
			// Constant-time copy: overwrites result only when match==1,
			// avoiding early-return branching that leaks timing.
			subtle.ConstantTimeCopy(match, result[:], pk[:])
			nFound += match
		}
	}

	if nFound != 1 {
		return nil, ErrVerificationFailure
	}

	return &ProfileKey{Bytes: result}, nil
}

// GroupPublicParams contains the public parameters for a Signal group.
type GroupPublicParams struct {
	GroupID                GroupIdentifierBytes
	UIDEncPublicKey        *zkcredential.PublicKey
	ProfileKeyEncPublicKey *zkcredential.PublicKey
}

// GetGroupIdentifier returns the group identifier.
func (g *GroupPublicParams) GetGroupIdentifier() GroupIdentifierBytes {
	return g.GroupID
}

// UUIDCiphertext is a user identifier encrypted under a group's UID encryption
// key.
type UUIDCiphertext struct {
	Ciphertext *zkcredential.Ciphertext
}

// ProfileKeyCiphertext is a profile key encrypted under a group's profile key
// encryption key.
type ProfileKeyCiphertext struct {
	Ciphertext *zkcredential.Ciphertext
}
