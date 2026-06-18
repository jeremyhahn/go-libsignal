package zkgroup

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/crypto/elligator"
	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// zeroScalar overwrites a ristretto255.Scalar with the zero value.
// runtime.KeepAlive prevents the compiler from eliminating the zeroing as dead writes.
func zeroScalar(s *ristretto255.Scalar) {
	if s != nil {
		s.Zero()
		runtime.KeepAlive(s)
	}
}

// LegacyCredentialConfig defines the storage length and attribute count for
// a legacy zkgroup credential type. StorageLen controls how many y-scalars
// are drawn from the SHO during key generation; NumAttrs controls how many
// Gy points are used in the public key I computation.
type LegacyCredentialConfig struct {
	StorageLen int
	NumAttrs   int
}

// Legacy credential types with their storage and attribute counts.
// These match the Rust zkgroup::crypto::credentials module where each
// credential type draws a specific number of y-scalars from the SHO
// and uses a specific number of Gy points.
var (
	LegacyAuthCredentialConfig               = LegacyCredentialConfig{StorageLen: 4, NumAttrs: 3}
	LegacyProfileKeyCredentialConfig         = LegacyCredentialConfig{StorageLen: 4, NumAttrs: 4}
	LegacyReceiptCredentialConfig            = LegacyCredentialConfig{StorageLen: 4, NumAttrs: 2}
	LegacyPNICredentialConfig                = LegacyCredentialConfig{StorageLen: 6, NumAttrs: 6}
	LegacyExpiringProfileKeyCredentialConfig = LegacyCredentialConfig{StorageLen: 5, NumAttrs: 5}
	LegacyAuthWithPNICredentialConfig        = LegacyCredentialConfig{StorageLen: 5, NumAttrs: 5}
)

// SignatureKeyPair is a key pair for Schnorr-like signatures.
type SignatureKeyPair struct {
	SigningKey *ristretto255.Scalar
	PublicKey  *ristretto255.Element
}

// GenerateSignatureKeyPair creates a new signature key pair from the SHO state.
func GenerateSignatureKeyPair(sho *zkcredential.ShoExt) (*SignatureKeyPair, error) {
	sk, err := sho.GetScalar()
	if err != nil {
		return nil, &ErrGeneratingSigningKey{Err: err}
	}
	pk := new(ristretto255.Element).ScalarBaseMult(sk)
	return &SignatureKeyPair{
		SigningKey: sk,
		PublicKey:  pk,
	}, nil
}

// Zeroize overwrites the signing key scalar with zero and nils all references.
// This should be called when the key pair is no longer needed.
func (kp *SignatureKeyPair) Zeroize() {
	zeroScalar(kp.SigningKey)
	kp.SigningKey = nil
	kp.PublicKey = nil
}

// GetPublicKey returns the public key.
func (kp *SignatureKeyPair) GetPublicKey() *SignaturePublicKey {
	return &SignaturePublicKey{PublicKey: kp.PublicKey}
}

// Sign produces a Schnorr-style signature over message using the
// supplied 32-byte synthetic randomness. The output is binding to both
// message and the keypair's public key.
//
// Mirrors Rust libsignal's zkgroup::SignatureKeyPair::sign at
// rust/zkgroup/src/crypto/signature.rs. Output bytes are byte-identical
// for the same inputs.
func (kp *SignatureKeyPair) Sign(message, randomness []byte) ([]byte, error) {
	return poksho.Sign(kp.SigningKey, kp.PublicKey, message, randomness)
}

// SignaturePublicKey is a public key used to verify signatures.
type SignaturePublicKey struct {
	PublicKey *ristretto255.Element
}

// Verify checks a Schnorr-style signature produced by SignatureKeyPair.Sign.
// Returns nil on success, a typed proof error otherwise.
//
// Mirrors Rust libsignal's zkgroup::PublicKey::verify_signature at
// rust/zkgroup/src/crypto/signature.rs.
func (pk *SignaturePublicKey) Verify(message, signature []byte) error {
	return poksho.Verify(signature, pk.PublicKey, message)
}

// TimestampStruct wraps a Timestamp for use in credential attribute computations.
type TimestampStruct struct {
	Timestamp Timestamp
}

// NewTimestampStruct creates a new TimestampStruct.
func NewTimestampStruct(ts Timestamp) *TimestampStruct {
	return &TimestampStruct{Timestamp: ts}
}

// CalcM computes the scalar representation of this timestamp.
func (ts *TimestampStruct) CalcM() *ristretto255.Scalar {
	return CalcTimestampM(ts.Timestamp)
}

// CalcTimestampM derives a scalar from a timestamp using the standard SHO label.
func CalcTimestampM(ts Timestamp) *ristretto255.Scalar {
	b := ts.ToBeBytes()
	sho := zkcredential.NewShoHmacSha256Ext("Signal_ZKGroup_20220524_Timestamp_Calc_m")
	sho.AbsorbAndRatchet(b[:])
	return sho.MustGetScalar()
}

// uidEncryptionSystemHardcoded contains the hardcoded generator points for UID
// encryption from the Rust reference implementation (2 Ristretto255 points, 64 bytes).
var uidEncryptionSystemHardcoded = [64]byte{
	0xa6, 0x32, 0x4c, 0x36, 0x8d, 0xf7, 0x34, 0x69, 0x11, 0x47, 0x98, 0x13, 0x48, 0xb6, 0xe7,
	0xeb, 0x42, 0xc3, 0x30, 0x7e, 0x71, 0x1b, 0x6c, 0x7e, 0xcc, 0xd3, 0x03, 0x2d, 0x45, 0x69,
	0x3f, 0x5a, 0x04, 0x80, 0x13, 0x52, 0x5b, 0x76, 0x12, 0x4b, 0xf2, 0x64, 0x0c, 0x5e, 0x93,
	0x69, 0xc7, 0x6e, 0xfb, 0xe8, 0x0a, 0xba, 0x2a, 0x24, 0xaa, 0x5d, 0x8e, 0x18, 0xa9, 0x8e,
	0xba, 0x14, 0xf8, 0x37,
}

// profileKeyEncryptionSystemHardcoded contains the hardcoded generator points for
// profile key encryption from the Rust reference implementation (2 Ristretto255 points, 64 bytes).
var profileKeyEncryptionSystemHardcoded = [64]byte{
	0xf6, 0xba, 0xa3, 0x17, 0xce, 0x18, 0x39, 0xc9, 0x3d, 0x61, 0x7e, 0x0c, 0xd8, 0x37, 0xd1,
	0x9d, 0xa9, 0xc8, 0xa4, 0xc5, 0x20, 0xbf, 0x7c, 0x51, 0xb1, 0xe6, 0xc2, 0xcb, 0x2a, 0x04,
	0x9c, 0x61, 0x2e, 0x01, 0x75, 0x89, 0x4c, 0x87, 0x30, 0xb2, 0x03, 0xab, 0x3b, 0xd9, 0x8e,
	0xcb, 0x2d, 0x81, 0xab, 0xac, 0xb6, 0x5f, 0x8a, 0x61, 0x24, 0xf4, 0x97, 0x71, 0xd1, 0x4a,
	0x98, 0x52, 0x12, 0x0c,
}

// parseHardcodedPoints parses a byte slice into two Ristretto255 points.
func parseHardcodedPoints(blob []byte) [2]*ristretto255.Element {
	p1 := ristretto255.NewIdentityElement()
	if _, err := p1.SetCanonicalBytes(blob[:32]); err != nil {
		panic(fmt.Sprintf("zkgroup: invalid hardcoded point at offset 0: %v", err))
	}
	p2 := ristretto255.NewIdentityElement()
	if _, err := p2.SetCanonicalBytes(blob[32:64]); err != nil {
		panic(fmt.Sprintf("zkgroup: invalid hardcoded point at offset 32: %v", err))
	}
	return [2]*ristretto255.Element{p1, p2}
}

// UIDEncryptionDomain is the domain identifier for UID encryption keys.
type UIDEncryptionDomain struct{}

// ID returns the domain ID string.
func (UIDEncryptionDomain) ID() string {
	return "Signal_ZKGroup_20230419_UidEncryption"
}

// Ga returns the hardcoded generator points for UID encryption, matching the
// Rust reference implementation.
func (d UIDEncryptionDomain) Ga() [2]*ristretto255.Element {
	return parseHardcodedPoints(uidEncryptionSystemHardcoded[:])
}

// ProfileKeyEncryptionDomain is the domain identifier for profile key encryption.
type ProfileKeyEncryptionDomain struct{}

// ID returns the domain ID string.
func (ProfileKeyEncryptionDomain) ID() string {
	return "Signal_ZKGroup_20231011_ProfileKeyEncryption"
}

// Ga returns the hardcoded generator points for profile key encryption, matching
// the Rust reference implementation.
func (d ProfileKeyEncryptionDomain) Ga() [2]*ristretto255.Element {
	return parseHardcodedPoints(profileKeyEncryptionSystemHardcoded[:])
}

// UIDEncryptionKeyPair is a key pair for encrypting user identifiers.
type UIDEncryptionKeyPair = zkcredential.KeyPair

// UIDEncryptionPublicKey is a public key for UID encryption.
type UIDEncryptionPublicKey = zkcredential.PublicKey

// UIDEncryptionCiphertext is an encrypted user identifier.
type UIDEncryptionCiphertext = zkcredential.Ciphertext

// ProfileKeyEncryptionKeyPair is a key pair for encrypting profile keys.
type ProfileKeyEncryptionKeyPair = zkcredential.KeyPair

// ProfileKeyEncryptionPublicKey is a public key for profile key encryption.
type ProfileKeyEncryptionPublicKey = zkcredential.PublicKey

// ProfileKeyEncryptionCiphertext is an encrypted profile key.
type ProfileKeyEncryptionCiphertext = zkcredential.Ciphertext

// UIDStruct represents a user identifier as ristretto255 points for
// attribute-based credential operations.
//
// Mirrors Rust's UidStruct in zkgroup/src/crypto/uid_struct.rs. The
// raw_uuid_bytes field is serialized as the first 16 bytes of the 80-byte
// bincode wire format: bytes:16 ‖ M1:32 ‖ M2:32.
type UIDStruct struct {
	// RawUUIDBytes holds the raw 16-byte UUID from the ServiceID.
	// This field is serialized first in the bincode wire format, matching
	// the Rust #[serde(rename = "bytes")] raw_uuid_bytes field.
	RawUUIDBytes [16]byte
	M1           *ristretto255.Element
	M2           *ristretto255.Element
}

// NewUIDStructFromServiceID creates a UIDStruct from a ServiceID.
//
// M1 is derived via SHO using the service ID's binary representation
// (16 bytes for ACI, 17 bytes for PNI) with label "Signal_ZKGroup_20200424_UID_CalcM1".
//
// M2 is derived via Lizard encoding of the raw UUID bytes, which provides
// a reversible mapping from 16-byte data to a Ristretto255 point.
//
// Mirrors Rust's UidStruct::from_service_id in zkgroup/src/crypto/uid_struct.rs.
func NewUIDStructFromServiceID(sid ServiceID) *UIDStruct {
	// ZK-C1: Use correct SHO label matching Rust uid_struct.rs:46
	sho := zkcredential.NewShoHmacSha256Ext("Signal_ZKGroup_20200424_UID_CalcM1")
	// ZK-C3: Absorb service_id_binary (16 bytes for ACI, 17 for PNI)
	sho.AbsorbAndRatchet(sid.ServiceIdBinary())
	m1 := sho.MustGetPoint()
	// ZK-C2: M2 uses Lizard encoding of the raw UUID bytes
	m2 := LizardEncode(sid.RawUUID)
	return &UIDStruct{
		RawUUIDBytes: sid.RawUUID,
		M1:           m1,
		M2:           m2,
	}
}

// UIDStructLen is the byte length of a serialized UIDStruct:
// 16 (raw UUID bytes) + 32 (M1) + 32 (M2).
const UIDStructLen = 80

// Serialize encodes the UIDStruct into 80 bytes:
// bytes:16 ‖ M1:32 ‖ M2:32.
//
// This matches the Rust bincode wire format for UidStruct with
// serde field order: raw_uuid_bytes, M1, M2.
func (u *UIDStruct) Serialize() []byte {
	out := make([]byte, 0, UIDStructLen)
	out = append(out, u.RawUUIDBytes[:]...)
	out = append(out, u.M1.Bytes()...)
	out = append(out, u.M2.Bytes()...)
	return out
}

// DeserializeUIDStruct decodes a UIDStruct from exactly 80 bytes.
// The layout is: bytes:16 ‖ M1:32 ‖ M2:32.
func DeserializeUIDStruct(data []byte) (*UIDStruct, error) {
	if len(data) != UIDStructLen {
		return nil, &ErrInvalidCredentialLength{Got: len(data), Want: UIDStructLen}
	}
	var rawUUID [16]byte
	copy(rawUUID[:], data[:16])

	m1 := ristretto255.NewIdentityElement()
	if _, err := m1.SetCanonicalBytes(data[16:48]); err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "UIDStruct M1"}
	}
	m2 := ristretto255.NewIdentityElement()
	if _, err := m2.SetCanonicalBytes(data[48:80]); err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "UIDStruct M2"}
	}
	return &UIDStruct{
		RawUUIDBytes: rawUUID,
		M1:           m1,
		M2:           m2,
	}, nil
}

// LizardEncode maps 16 bytes of data to a Ristretto255 point using the Lizard
// encoding method. This is a reversible mapping: the original bytes can be
// recovered from the point via LizardDecode.
//
// The algorithm:
//  1. Hash the 16-byte data with SHA-256 to get 32 bytes
//  2. Overlay the original data at bytes[8..24]
//  3. Clear the low bit of byte[0] (ensure positive field element)
//  4. Clear the top 2 bits of byte[31] (reduce to valid range)
//  5. Map the resulting field element to a Ristretto point via single Elligator
func LizardEncode(data [16]byte) *ristretto255.Element {
	// Hash data with SHA-256
	hash := sha256.Sum256(data[:])

	// Build the field element bytes
	var feBytes [32]byte
	copy(feBytes[:], hash[:])

	// Overlay original data at bytes[8..24]
	copy(feBytes[8:24], data[:])

	// Clear bits to ensure valid positive field element
	feBytes[0] &= 254 // clear low bit (make positive since Elligator on r and -r is the same)
	feBytes[31] &= 63 // clear top 2 bits

	// Map to Ristretto point using single Elligator.
	// SetUniformBytes(a || b) computes MAP(a) + MAP(b).
	// MAP(zeros) = identity in the Ristretto group, so
	// SetUniformBytes(feBytes || zeros) = MAP(feBytes) + identity = MAP(feBytes).
	var uniform [64]byte
	copy(uniform[:32], feBytes[:])
	// Second 32 bytes remain zero.

	e := ristretto255.NewIdentityElement()
	if _, err := e.SetUniformBytes(uniform[:]); err != nil {
		panic(fmt.Sprintf("zkgroup: lizard encode failed: %v", err))
	}
	return e
}

// LizardDecode recovers the original 16 bytes from a Lizard-encoded
// ristretto255 point by inverting the Elligator map and checking which
// candidate field element matches the Lizard encoding structure.
//
// Returns the decoded 16 bytes and true on success, or a zero array and
// false if the point was not created via LizardEncode.
//
// This matches Rust curve25519-dalek-signal's lizard_decode method.
func LizardDecode(point *ristretto255.Element) ([16]byte, bool) {
	encoded := point.Bytes()
	mask, candidates, ok := elligator.ElligatorRistrettoFlavorInverse(encoded)
	if !ok {
		return [16]byte{}, false
	}

	var result [16]byte
	nFound := 0

	for j := 0; j < 8; j++ {
		if mask&(1<<j) == 0 {
			continue
		}
		fe := candidates[j]

		// Extract the 16 data bytes from positions [8:24]
		var candidate [16]byte
		copy(candidate[:], fe[8:24])

		// Verify the Lizard structure: hash the candidate, overlay, clear bits
		h := sha256.Sum256(candidate[:])
		copy(h[8:24], candidate[:])
		h[0] &= 254
		h[31] &= 63

		if h == fe {
			result = candidate
			nFound++
		}
	}

	if nFound == 1 {
		return result, true
	}
	return [16]byte{}, false
}

// Decode253Bits recovers up to 8 candidate 32-byte field elements from a
// ristretto255 point by inverting the Elligator map.
//
// Returns a bitmask indicating which candidates are valid, and the candidates
// themselves. This is used for profile key decryption where the 32-byte
// profile key was encoded via single Elligator with bit clearing.
//
// This matches Rust curve25519-dalek-signal's decode_253_bits method.
func Decode253Bits(point *ristretto255.Element) (mask uint8, candidates [8][32]byte, ok bool) {
	encoded := point.Bytes()
	return elligator.ElligatorRistrettoFlavorInverse(encoded)
}

// AsPoints implements the zkcredential.Attribute interface.
func (u *UIDStruct) AsPoints() [2]*ristretto255.Element {
	return [2]*ristretto255.Element{u.M1, u.M2}
}

// ProfileKeyStruct represents a profile key as ristretto255 points.
type ProfileKeyStruct struct {
	RawBytes ProfileKeyBytes
	M3       *ristretto255.Element
	M4       *ristretto255.Element
}

// NewProfileKeyStruct creates a ProfileKeyStruct from raw profile key bytes and
// a user ID. This matches Rust's ProfileKeyStruct::new which uses:
//   - M3: SHO with label "Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_CalcM3",
//     absorbs profileKeyBytes||uidBytes, then single-Elligator map (32-byte squeeze).
//   - M4: profile key bytes with bits cleared ([0]&=254, [31]&=63), then single-Elligator
//     map directly (no SHO involvement).
func NewProfileKeyStruct(profileKeyBytes ProfileKeyBytes, uidBytes UIDBytes) *ProfileKeyStruct {
	// M3: seed with correct label, absorb combined data, single-Elligator map.
	m3 := calcProfileKeyM3(profileKeyBytes, uidBytes)

	// M4: clear bits on profile key and apply single Elligator directly.
	var encodedProfileKey [32]byte
	copy(encodedProfileKey[:], profileKeyBytes[:])
	encodedProfileKey[0] &= 254
	encodedProfileKey[31] &= 63

	m4, err := zkcredential.PointFromSingleElligator(encodedProfileKey[:])
	if err != nil {
		panic(fmt.Sprintf("zkgroup: M4 single elligator failed: %v", err))
	}

	return &ProfileKeyStruct{
		RawBytes: profileKeyBytes,
		M3:       m3,
		M4:       m4,
	}
}

// calcProfileKeyM3 computes the M3 point for a ProfileKeyStruct.
// This matches Rust's ProfileKeyStruct::calc_M3 with seed_M3().
func calcProfileKeyM3(profileKeyBytes ProfileKeyBytes, uidBytes UIDBytes) *ristretto255.Element {
	sho := zkcredential.NewShoHmacSha256Ext("Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_CalcM3")
	combined := make([]byte, ProfileKeyLen+UUIDLen)
	copy(combined[:ProfileKeyLen], profileKeyBytes[:])
	copy(combined[ProfileKeyLen:], uidBytes[:])
	sho.AbsorbAndRatchet(combined)
	return sho.MustGetPointSingleElligator()
}

// AsPoints implements the zkcredential.Attribute interface.
func (pk *ProfileKeyStruct) AsPoints() [2]*ristretto255.Element {
	return [2]*ristretto255.Element{pk.M3, pk.M4}
}

// profileKeyCommitmentSystemHardcoded contains the hardcoded system parameters
// for profile key commitments from the Rust reference implementation (3 Ristretto255
// points, 96 bytes).
var profileKeyCommitmentSystemHardcoded = [96]byte{
	0xa8, 0xca, 0x0b, 0xbd, 0x11, 0x48, 0xc4, 0x66, 0x72, 0x58, 0x60, 0x64, 0x0a, 0xc5, 0x3d,
	0x27, 0x72, 0xb1, 0x4e, 0xea, 0xe0, 0x17, 0x0a, 0x38, 0xc6, 0x2c, 0x7b, 0x3d, 0xd2, 0x9c,
	0x3e, 0x4a, 0x14, 0xb9, 0x46, 0x2d, 0x94, 0x8f, 0x05, 0x94, 0x50, 0x79, 0x9f, 0x4c, 0xc2,
	0xa0, 0x6e, 0x55, 0xde, 0xc8, 0x07, 0x73, 0x56, 0x70, 0xb9, 0x4a, 0x5c, 0xe8, 0x0f, 0x59,
	0xf1, 0x95, 0x08, 0x61, 0xb0, 0xc0, 0xf7, 0xb9, 0x1f, 0x6e, 0xf9, 0xc7, 0x55, 0x60, 0x93,
	0xd8, 0x93, 0x0a, 0x86, 0xbd, 0x36, 0x18, 0x8c, 0xec, 0x74, 0x05, 0x54, 0x65, 0x7d, 0x92,
	0xdc, 0xd8, 0x6a, 0xad, 0x25, 0x1c,
}

// ProfileKeyCommitmentSystemParams holds the hardcoded system parameters for
// profile key commitments.
type ProfileKeyCommitmentSystemParams struct {
	GJ1 *ristretto255.Element
	GJ2 *ristretto255.Element
	GJ3 *ristretto255.Element
}

// GenerateProfileKeyCommitmentSystemParams returns the hardcoded system params
// for profile key commitments, parsed from the Rust reference implementation blob.
func GenerateProfileKeyCommitmentSystemParams() *ProfileKeyCommitmentSystemParams {
	blob := profileKeyCommitmentSystemHardcoded[:]
	gj1 := ristretto255.NewIdentityElement()
	if _, err := gj1.SetCanonicalBytes(blob[:32]); err != nil {
		panic(fmt.Sprintf("zkgroup: invalid hardcoded profile key commitment point G_j1: %v", err))
	}
	gj2 := ristretto255.NewIdentityElement()
	if _, err := gj2.SetCanonicalBytes(blob[32:64]); err != nil {
		panic(fmt.Sprintf("zkgroup: invalid hardcoded profile key commitment point G_j2: %v", err))
	}
	gj3 := ristretto255.NewIdentityElement()
	if _, err := gj3.SetCanonicalBytes(blob[64:96]); err != nil {
		panic(fmt.Sprintf("zkgroup: invalid hardcoded profile key commitment point G_j3: %v", err))
	}
	return &ProfileKeyCommitmentSystemParams{
		GJ1: gj1,
		GJ2: gj2,
		GJ3: gj3,
	}
}

// ProfileKeyCommitmentInternal is the internal commitment value.
type ProfileKeyCommitmentInternal struct {
	J1 *ristretto255.Element
	J2 *ristretto255.Element
	J3 *ristretto255.Element
}

// ProfileKeyCommitmentWithSecretNonce includes the secret nonce.
type ProfileKeyCommitmentWithSecretNonce struct {
	J1  *ristretto255.Element
	J2  *ristretto255.Element
	J3  *ristretto255.Element
	J3s *ristretto255.Scalar
}

// NewProfileKeyCommitmentWithSecretNonce creates a commitment from a profile key
// and user ID.
func NewProfileKeyCommitmentWithSecretNonce(
	profileKey *ProfileKeyStruct,
	uidBytes UIDBytes,
) *ProfileKeyCommitmentWithSecretNonce {
	system := GenerateProfileKeyCommitmentSystemParams()
	j3 := calcJ3(profileKey.RawBytes, uidBytes)

	j1 := new(ristretto255.Element).ScalarMult(j3, system.GJ1)
	j1 = j1.Add(j1, profileKey.M3)

	j2 := new(ristretto255.Element).ScalarMult(j3, system.GJ2)
	j2 = j2.Add(j2, profileKey.M4)

	j3pt := new(ristretto255.Element).ScalarMult(j3, system.GJ3)

	return &ProfileKeyCommitmentWithSecretNonce{
		J1:  j1,
		J2:  j2,
		J3:  j3pt,
		J3s: j3,
	}
}

// GetCommitment returns the public commitment.
func (c *ProfileKeyCommitmentWithSecretNonce) GetCommitment() *ProfileKeyCommitmentInternal {
	return &ProfileKeyCommitmentInternal{
		J1: c.J1,
		J2: c.J2,
		J3: c.J3,
	}
}

func calcJ3(profileKeyBytes ProfileKeyBytes, uidBytes UIDBytes) *ristretto255.Scalar {
	combined := make([]byte, ProfileKeyLen+UUIDLen)
	copy(combined[:ProfileKeyLen], profileKeyBytes[:])
	copy(combined[ProfileKeyLen:], uidBytes[:])
	sho := zkcredential.NewShoHmacSha256Ext(
		"Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKeyCommitment_Calcj3",
	)
	sho.AbsorbAndRatchet(combined)
	return sho.MustGetScalar()
}

// ReceiptStruct holds the components of a receipt credential.
type ReceiptStruct struct {
	ReceiptSerialBytes    ReceiptSerialBytes
	ReceiptExpirationTime Timestamp
	ReceiptLevel          ReceiptLevel
}

// NewReceiptStruct creates a new ReceiptStruct.
func NewReceiptStruct(
	serialBytes ReceiptSerialBytes,
	expirationTime Timestamp,
	level ReceiptLevel,
) *ReceiptStruct {
	return &ReceiptStruct{
		ReceiptSerialBytes:    serialBytes,
		ReceiptExpirationTime: expirationTime,
		ReceiptLevel:          level,
	}
}

// CalcM1 computes the M1 scalar for this receipt, derived from the expiration
// time and receipt level using SHO. Matches Rust receipt_struct.rs:41-53.
func (r *ReceiptStruct) CalcM1() *ristretto255.Scalar {
	return CalcReceiptM1(r.ReceiptExpirationTime, r.ReceiptLevel)
}

// CalcReceiptM1 computes the M1 scalar from a receipt expiration time and level.
// The derivation concatenates the big-endian bytes of the timestamp (8 bytes)
// and receipt level (8 bytes), then uses SHO with label
// "Signal_ZKGroup_20210919_Receipt_CalcM1".
func CalcReceiptM1(expirationTime Timestamp, level ReceiptLevel) *ristretto255.Scalar {
	var combined [16]byte
	expBytes := expirationTime.ToBeBytes()
	copy(combined[:8], expBytes[:])
	binary.BigEndian.PutUint64(combined[8:], level)

	sho := zkcredential.NewShoHmacSha256Ext("Signal_ZKGroup_20210919_Receipt_CalcM1")
	sho.AbsorbAndRatchet(combined[:])
	return sho.MustGetScalar()
}

// ConvertToPointsReceiptStruct converts receipt attributes to Ristretto points
// using the legacy G_m generator points from the credential system parameters.
// This matches Rust credentials.rs:195-202.
func ConvertToPointsReceiptStruct(receipt *ReceiptStruct) []*ristretto255.Element {
	system := zkcredential.GetLegacySystemParams()
	m1 := receipt.CalcM1()
	receiptSerialScalar := encodeReceiptSerialBytes(receipt.ReceiptSerialBytes)
	return []*ristretto255.Element{
		new(ristretto255.Element).ScalarMult(m1, system.Gm[0]),
		new(ristretto255.Element).ScalarMult(receiptSerialScalar, system.Gm[1]),
	}
}

// ConvertToPointM2ReceiptSerialBytes converts receipt serial bytes to a single
// Ristretto point using the legacy G_m2 generator. This matches Rust
// credentials.rs:204-210.
func ConvertToPointM2ReceiptSerialBytes(receiptSerialBytes ReceiptSerialBytes) *ristretto255.Element {
	system := zkcredential.GetLegacySystemParams()
	s := encodeReceiptSerialBytes(receiptSerialBytes)
	return new(ristretto255.Element).ScalarMult(s, system.Gm[1])
}
