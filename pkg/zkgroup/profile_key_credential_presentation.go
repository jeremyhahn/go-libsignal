package zkgroup

import (
	"encoding/binary"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// Byte sizes for V1/V2 presentation serialization, mirroring the Rust
// bincode layout exactly.
//
// A V1 or V2 presentation serializes as:
//
//	[0]         version byte (0x00 for V1, 0x01 for V2)
//	[1..257]    8 × 32-byte compressed Ristretto255 points (proof commitment points)
//	[257..265]  8-byte little-endian u64 length of poksho_proof
//	[265..N]    poksho_proof bytes (320 bytes when well-formed)
//	[N..N+64]   uid_enc_ciphertext  (EA1 ∥ EA2, each 32 bytes)
//	[N+64..]    profile_key_enc_ciphertext (EA1 ∥ EA2, each 32 bytes)
//
// Total: 1 + 256 + 8 + 320 + 64 + 64 = 713 bytes.
// (PROFILE_KEY_CREDENTIAL_PRESENTATION_V1_LEN = PROFILE_KEY_CREDENTIAL_PRESENTATION_V2_LEN = 713)
const (
	presentationPointSize       = 32
	presentationProofPointCount = 8                                                   // C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_V, C_z
	presentationProofPointsLen  = presentationProofPointCount * presentationPointSize // 256
	presentationProofLenSize    = 8                                                   // bincode u64 length prefix
	presentationCiphertextSize  = 64                                                  // EA1 (32) + EA2 (32)

	// presentationV1MinLen is the minimum meaningful length: version + 8 points + 8-byte vec-len prefix.
	presentationV1MinLen = 1 + presentationProofPointsLen + presentationProofLenSize // 265
)

// profileKeyCredentialPresentationProofV1 holds the commitment points and
// poksho proof bytes for a V1 or V2 profile key credential presentation.
// Matches Rust crypto::proofs::ProfileKeyCredentialPresentationProofV1 and
// ProfileKeyCredentialPresentationProofV2 (same structure, different statement).
//
// These proof types are kept for deserialization only. No new V1/V2 credentials
// are issued; Signal migrated to ExpiringProfileKeyCredentialPresentation (V3/V4).
type profileKeyCredentialPresentationProofV1 struct {
	Cx0         *ristretto255.Element
	Cx1         *ristretto255.Element
	Cy1         *ristretto255.Element
	Cy2         *ristretto255.Element
	Cy3         *ristretto255.Element
	Cy4         *ristretto255.Element
	CV          *ristretto255.Element
	Cz          *ristretto255.Element
	PokshoProof []byte
}

// decodeProfileKeyCredentialPresentationProofV1 decodes a proof from the
// contiguous byte slice starting at offset 0. The slice must begin immediately
// after the version byte. Returns the proof and the number of bytes consumed.
func decodeProfileKeyCredentialPresentationProofV1(data []byte) (*profileKeyCredentialPresentationProofV1, int, error) {
	const minLen = presentationProofPointsLen + presentationProofLenSize
	if len(data) < minLen {
		return nil, 0, &ErrDataTooShort{}
	}

	points := make([]*ristretto255.Element, presentationProofPointCount)
	for i := range points {
		off := i * presentationPointSize
		el := ristretto255.NewIdentityElement()
		if _, err := el.SetCanonicalBytes(data[off : off+presentationPointSize]); err != nil {
			return nil, 0, &ZkGroupDeserializationFailure{TypeName: "ProfileKeyCredentialPresentationProof point"}
		}
		points[i] = el
	}

	vecLenOff := presentationProofPointsLen
	// zkcredential.ReadBincodeU64Len guards against u64 values >= 2^63 (which
	// wrap negative on int cast) and against lengths that exceed the remaining
	// input, matching Rust's reject_trailing_bytes + bounded-alloc behavior.
	proofLen, err := zkcredential.ReadBincodeU64Len(data, vecLenOff, 1, "poksho_proof")
	if err != nil {
		return nil, 0, &ErrDataTooShort{}
	}
	consumed := presentationProofPointsLen + presentationProofLenSize + proofLen
	if len(data) < consumed {
		return nil, 0, &ErrDataTooShort{}
	}

	proofBytes := make([]byte, proofLen)
	copy(proofBytes, data[vecLenOff+presentationProofLenSize:consumed])

	proof := &profileKeyCredentialPresentationProofV1{
		Cx0:         points[0],
		Cx1:         points[1],
		Cy1:         points[2],
		Cy2:         points[3],
		Cy3:         points[4],
		Cy4:         points[5],
		CV:          points[6],
		Cz:          points[7],
		PokshoProof: proofBytes,
	}
	return proof, consumed, nil
}

// decodeCiphertextAt decodes a zkcredential.Ciphertext (64 bytes) from data
// starting at offset off.
func decodeCiphertextAt(data []byte, off int) (*zkcredential.Ciphertext, error) {
	if len(data) < off+presentationCiphertextSize {
		return nil, &ErrDataTooShort{}
	}
	ct, err := zkcredential.DecodeCiphertext(data[off : off+presentationCiphertextSize])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ciphertext"}
	}
	return ct, nil
}

// decodeRistrettoPoint decodes a single compressed Ristretto255 point from
// a 32-byte slice.
func decodeRistrettoPoint(b []byte, name string) (*ristretto255.Element, error) {
	el := ristretto255.NewIdentityElement()
	if _, err := el.SetCanonicalBytes(b); err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "presentation point " + name}
	}
	return el, nil
}

// deserializeExpiringProfileKeyCredentialPresentation decodes a V3 or V4
// ExpiringProfileKeyCredentialPresentation from wire bytes. The version byte
// at data[0] must have already been validated by the caller.
//
// Wire layout (Rust bincode, matches ExpiringProfileKeyCredentialPresentation<V>):
//
//	[0]         version byte (0x02 for V3, 0x03 for V4)
//	[1..257]    8 × 32-byte points: C_x0, C_x1, C_y1, C_y2, C_y3, C_y4, C_y5, C_V
//	[257..265]  8-byte LE u64: poksho_proof length
//	[265..N]    poksho_proof bytes
//	[N..N+64]   uid_enc_ciphertext (EA1 ∥ EA2)
//	[N+64..N+128] profile_key_enc_ciphertext (EA1 ∥ EA2)
//	[N+128..N+136] credential_expiration_time (8-byte LE u64, seconds since epoch)
func deserializeExpiringProfileKeyCredentialPresentation(data []byte) (*ExpiringProfileKeyCredentialPresentation, error) {
	// 8 proof points + 8-byte vec length prefix, minimum before proof bytes.
	const minLen = 1 + presentationProofPointsLen + presentationProofLenSize
	if len(data) < minLen {
		return nil, &ErrDataTooShort{}
	}

	off := 1 // skip version byte
	pts := make([]*ristretto255.Element, 8)
	names := [8]string{"C_x0", "C_x1", "C_y1", "C_y2", "C_y3", "C_y4", "C_y5", "C_V"}
	for i := range pts {
		p, err := decodeRistrettoPoint(data[off:off+32], names[i])
		if err != nil {
			return nil, err
		}
		pts[i] = p
		off += 32
	}

	// zkcredential.ReadBincodeU64Len guards against u64 values >= 2^63 and
	// lengths that exceed remaining input, matching Rust's bounded-alloc behavior.
	proofLen, err := zkcredential.ReadBincodeU64Len(data, off, 1, "poksho_proof")
	if err != nil {
		return nil, &ErrDataTooShort{}
	}
	off += 8
	if len(data)-off < proofLen+128+8 {
		return nil, &ErrDataTooShort{}
	}

	pokshoProof := make([]byte, proofLen)
	copy(pokshoProof, data[off:off+proofLen])
	off += proofLen

	uidCT, err := decodeCiphertextAt(data, off)
	if err != nil {
		return nil, err
	}
	off += presentationCiphertextSize

	pkCT, err := decodeCiphertextAt(data, off)
	if err != nil {
		return nil, err
	}
	off += presentationCiphertextSize

	if len(data) < off+8 {
		return nil, &ErrDataTooShort{}
	}
	expSeconds := binary.LittleEndian.Uint64(data[off : off+8])
	off += 8

	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "ExpiringProfileKeyCredentialPresentation", Count: len(data) - off}
	}

	return &ExpiringProfileKeyCredentialPresentation{
		Cx0:                      pts[0],
		Cx1:                      pts[1],
		Cy1:                      pts[2],
		Cy2:                      pts[3],
		Cy3:                      pts[4],
		Cy4:                      pts[5],
		Cy5:                      pts[6],
		CV:                       pts[7],
		PokshoProof:              pokshoProof,
		UIDEncCiphertext:         &UUIDCiphertext{Ciphertext: uidCT},
		ProfileKeyEncCiphertext:  &ProfileKeyCiphertext{Ciphertext: pkCT},
		CredentialExpirationTime: NewTimestamp(expSeconds),
	}, nil
}

// ProfileKeyCredentialPresentationV1 is a legacy V1 profile key credential
// presentation. V1 presentations are identified by a leading 0x00 version byte.
//
// No new V1 credentials are issued; this type exists for deserialization of
// wire-format bytes sent by older clients. Proof verification is not supported
// (the Rust reference also marks V1 verification as removed), but the
// ciphertexts remain structurally accessible.
type ProfileKeyCredentialPresentationV1 struct {
	proof                   *profileKeyCredentialPresentationProofV1
	UIDEncCiphertext        *UUIDCiphertext
	ProfileKeyEncCiphertext *ProfileKeyCiphertext
}

// GetUUIDCiphertext returns the encrypted user identifier from the presentation.
func (p *ProfileKeyCredentialPresentationV1) GetUUIDCiphertext() *UUIDCiphertext {
	return p.UIDEncCiphertext
}

// GetProfileKeyCiphertext returns the encrypted profile key from the presentation.
func (p *ProfileKeyCredentialPresentationV1) GetProfileKeyCiphertext() *ProfileKeyCiphertext {
	return p.ProfileKeyEncCiphertext
}

// ProfileKeyCredentialPresentationV2 is a legacy V2 profile key credential
// presentation. V2 presentations are identified by a leading 0x01 version byte.
//
// V2 uses an optimized proof relative to V1 but shares the same wire-format
// structure. Like V1, it is deserialization-only; no new V2 credentials are
// issued.
type ProfileKeyCredentialPresentationV2 struct {
	proof                   *profileKeyCredentialPresentationProofV1
	UIDEncCiphertext        *UUIDCiphertext
	ProfileKeyEncCiphertext *ProfileKeyCiphertext
}

// GetUUIDCiphertext returns the encrypted user identifier from the presentation.
func (p *ProfileKeyCredentialPresentationV2) GetUUIDCiphertext() *UUIDCiphertext {
	return p.UIDEncCiphertext
}

// GetProfileKeyCiphertext returns the encrypted profile key from the presentation.
func (p *ProfileKeyCredentialPresentationV2) GetProfileKeyCiphertext() *ProfileKeyCiphertext {
	return p.ProfileKeyEncCiphertext
}

// deserializeProfileKeyCredentialPresentationV1 parses a full V1 presentation
// from bytes. The leading version byte must already have been validated as
// PresentationVersion1 (0x00) by the caller.
func deserializeProfileKeyCredentialPresentationV1(data []byte) (*ProfileKeyCredentialPresentationV1, error) {
	if len(data) < presentationV1MinLen {
		return nil, &ErrDataTooShort{}
	}
	proof, consumed, err := decodeProfileKeyCredentialPresentationProofV1(data[1:])
	if err != nil {
		return nil, err
	}
	off := 1 + consumed
	uidCT, err := decodeCiphertextAt(data, off)
	if err != nil {
		return nil, err
	}
	off += presentationCiphertextSize
	pkCT, err := decodeCiphertextAt(data, off)
	if err != nil {
		return nil, err
	}
	off += presentationCiphertextSize
	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "ProfileKeyCredentialPresentationV1", Count: len(data) - off}
	}
	return &ProfileKeyCredentialPresentationV1{
		proof:                   proof,
		UIDEncCiphertext:        &UUIDCiphertext{Ciphertext: uidCT},
		ProfileKeyEncCiphertext: &ProfileKeyCiphertext{Ciphertext: pkCT},
	}, nil
}

// deserializeProfileKeyCredentialPresentationV2 parses a full V2 presentation
// from bytes. The leading version byte must already have been validated as
// PresentationVersion2 (0x01) by the caller.
func deserializeProfileKeyCredentialPresentationV2(data []byte) (*ProfileKeyCredentialPresentationV2, error) {
	if len(data) < presentationV1MinLen {
		return nil, &ErrDataTooShort{}
	}
	proof, consumed, err := decodeProfileKeyCredentialPresentationProofV1(data[1:])
	if err != nil {
		return nil, err
	}
	off := 1 + consumed
	uidCT, err := decodeCiphertextAt(data, off)
	if err != nil {
		return nil, err
	}
	off += presentationCiphertextSize
	pkCT, err := decodeCiphertextAt(data, off)
	if err != nil {
		return nil, err
	}
	off += presentationCiphertextSize
	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "ProfileKeyCredentialPresentationV2", Count: len(data) - off}
	}
	return &ProfileKeyCredentialPresentationV2{
		proof:                   proof,
		UIDEncCiphertext:        &UUIDCiphertext{Ciphertext: uidCT},
		ProfileKeyEncCiphertext: &ProfileKeyCiphertext{Ciphertext: pkCT},
	}, nil
}

// SerializeExpiringProfileKeyCredentialPresentation encodes an
// ExpiringProfileKeyCredentialPresentation to the Rust bincode wire format.
// The version argument must be PresentationVersion3 or PresentationVersion4.
//
// This is the inverse of deserializeExpiringProfileKeyCredentialPresentation
// and is provided to support round-trip testing and wire-format interoperability.
func SerializeExpiringProfileKeyCredentialPresentation(
	version byte,
	p *ExpiringProfileKeyCredentialPresentation,
) []byte {
	proofLen := uint64(len(p.PokshoProof))
	// Capacity: 1 (version) + 256 (8 points) + 8 (vec len) + proof + 64 + 64 + 8
	outCap := 1 + 256 + 8 + int(proofLen) + 64 + 64 + 8
	out := make([]byte, 0, outCap)

	out = append(out, version)
	for _, pt := range []*ristretto255.Element{
		p.Cx0, p.Cx1, p.Cy1, p.Cy2, p.Cy3, p.Cy4, p.Cy5, p.CV,
	} {
		out = append(out, pt.Bytes()...)
	}

	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], proofLen)
	out = append(out, lenBuf[:]...)
	out = append(out, p.PokshoProof...)

	out = append(out, zkcredential.EncodeCiphertext(p.UIDEncCiphertext.Ciphertext)...)
	out = append(out, zkcredential.EncodeCiphertext(p.ProfileKeyEncCiphertext.Ciphertext)...)

	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], p.CredentialExpirationTime.EpochSeconds())
	out = append(out, tsBuf[:]...)

	return out
}

// AnyProfileKeyCredentialPresentation is a discriminated union that holds any
// version of a profile key credential presentation (V1–V4). The Version field
// reflects the first byte of the wire-format bytes and corresponds to the
// PresentationVersion1..PresentationVersion4 constants.
//
// Exactly one of V1, V2, V3, or V4 is non-nil; the others are nil.
//
// V3 and V4 are ExpiringProfileKeyCredentialPresentation types (V4 uses an
// updated proof). V1 and V2 are legacy non-expiring types retained for
// backward compatibility with older client-produced presentations.
type AnyProfileKeyCredentialPresentation struct {
	// Version is the presentation version byte (PresentationVersion1..4).
	Version byte
	// V1 is set when Version == PresentationVersion1.
	V1 *ProfileKeyCredentialPresentationV1
	// V2 is set when Version == PresentationVersion2.
	V2 *ProfileKeyCredentialPresentationV2
	// V3 is set when Version == PresentationVersion3. Matches Rust's
	// ExpiringProfileKeyCredentialPresentation<PRESENTATION_VERSION_3>.
	V3 *ExpiringProfileKeyCredentialPresentation
	// V4 is set when Version == PresentationVersion4. Matches Rust's
	// ExpiringProfileKeyCredentialPresentationV2 (same struct, version-4 byte).
	V4 *ExpiringProfileKeyCredentialPresentation
}

// GetUUIDCiphertext returns the encrypted UUID from any presentation version.
func (p *AnyProfileKeyCredentialPresentation) GetUUIDCiphertext() *UUIDCiphertext {
	switch p.Version {
	case PresentationVersion1:
		if p.V1 != nil {
			return p.V1.GetUUIDCiphertext()
		}
	case PresentationVersion2:
		if p.V2 != nil {
			return p.V2.GetUUIDCiphertext()
		}
	case PresentationVersion3:
		if p.V3 != nil {
			return p.V3.GetUUIDCiphertext()
		}
	case PresentationVersion4:
		if p.V4 != nil {
			return p.V4.GetUUIDCiphertext()
		}
	}
	return nil
}

// GetProfileKeyCiphertext returns the encrypted profile key from any presentation version.
func (p *AnyProfileKeyCredentialPresentation) GetProfileKeyCiphertext() *ProfileKeyCiphertext {
	switch p.Version {
	case PresentationVersion1:
		if p.V1 != nil {
			return p.V1.GetProfileKeyCiphertext()
		}
	case PresentationVersion2:
		if p.V2 != nil {
			return p.V2.GetProfileKeyCiphertext()
		}
	case PresentationVersion3:
		if p.V3 != nil {
			return p.V3.GetProfileKeyCiphertext()
		}
	case PresentationVersion4:
		if p.V4 != nil {
			return p.V4.GetProfileKeyCiphertext()
		}
	}
	return nil
}

// GetExpirationTime returns the credential expiration time and whether the
// presentation carries one. V1 and V2 presentations do not expire and return
// a zero Timestamp with false. V3 and V4 presentations return the embedded
// expiration time with true.
func (p *AnyProfileKeyCredentialPresentation) GetExpirationTime() (Timestamp, bool) {
	switch p.Version {
	case PresentationVersion3:
		if p.V3 != nil {
			return p.V3.GetExpirationTime(), true
		}
	case PresentationVersion4:
		if p.V4 != nil {
			return p.V4.GetExpirationTime(), true
		}
	}
	return Timestamp{}, false
}

// ToStructurallyValidV1PresentationBytes re-encodes any presentation version as
// a V1 wire blob that passes structural parsing but carries an invalid proof.
//
// This matches Rust's AnyProfileKeyCredentialPresentation::to_structurally_valid_v1_presentation_bytes
// (api/profiles/profile_key_credential_presentation.rs). The method is used to
// confirm that V3/V4 ExpiringProfileKeyCredential presentations preserve their
// ciphertexts when down-cast to a V1 structural frame, which is the semantic
// tested by Rust's test_profile_key_credential_presentation_expiring_as_v1.
//
// Wire layout (713 bytes):
//
//	[0]         0x00  (V1 version byte)
//	[1..257]    8 × 32-byte Ristretto255 basepoint bytes (invalid proof points)
//	[257..265]  u64le = 320 (fake proof length)
//	[265..585]  320 zero bytes (fake proof body)
//	[585..649]  uid_enc_ciphertext (64 bytes)
//	[649..713]  profile_key_enc_ciphertext (64 bytes)
func (p *AnyProfileKeyCredentialPresentation) ToStructurallyValidV1PresentationBytes() []byte {
	const fakeProofLen = 0x0140 // 320, the hardcoded length Rust uses
	// Total: 1 + 8*32 + 8 + 320 + 64 + 64 = 713 bytes.
	out := make([]byte, 0, 713)

	// Version byte.
	out = append(out, PresentationVersion1)

	// 8 copies of the Ristretto255 basepoint (matches Rust from_invalid_proof).
	basepoint := ristretto255.NewGeneratorElement()
	basepointBytes := basepoint.Bytes()
	for range 8 {
		out = append(out, basepointBytes...)
	}

	// u64le length prefix for the fake proof.
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], fakeProofLen)
	out = append(out, lenBuf[:]...)

	// 320 zero bytes as the fake proof body.
	out = append(out, make([]byte, fakeProofLen)...)

	// Ciphertexts from the actual presentation (type-agnostic).
	uidCT := p.GetUUIDCiphertext()
	pkCT := p.GetProfileKeyCiphertext()
	out = append(out, zkcredential.EncodeCiphertext(uidCT.Ciphertext)...)
	out = append(out, zkcredential.EncodeCiphertext(pkCT.Ciphertext)...)

	return out
}

// DeserializeAnyProfileKeyCredentialPresentation parses a serialized profile
// key credential presentation of any version (V1–V4) by dispatching on the
// first byte of data.
//
// Version byte mapping (matches Rust PRESENTATION_VERSION_* constants):
//
//	0x00 → V1 (ProfileKeyCredentialPresentationV1, legacy non-expiring)
//	0x01 → V2 (ProfileKeyCredentialPresentationV2, legacy non-expiring, optimized proof)
//	0x02 → V3 (ExpiringProfileKeyCredentialPresentation, current)
//	0x03 → V4 (ExpiringProfileKeyCredentialPresentation with V2 proof, current)
//
// Scope: V1 and V2 support deserialization and structural inspection only.
// V1/V2 proof verification is deliberately absent here to maintain parity with
// upstream: the Rust libsignal reference removed support for verifying V1/V2
// profile-key-credential presentations (Signal no longer issues V1/V2
// credentials), so this is an intentional upstream removal rather than
// unfinished work. V3/V4 presentations can be verified via
// VerifyExpiringProfileKeyCredentialPresentation.
//
// Returns ErrUnknownPresentationVersion for unrecognized version bytes,
// ErrDataTooShort for empty or truncated input, and ZkGroupDeserializationFailure
// for malformed point encodings.
func DeserializeAnyProfileKeyCredentialPresentation(data []byte) (*AnyProfileKeyCredentialPresentation, error) {
	if len(data) == 0 {
		return nil, &ErrDataTooShort{}
	}
	version := data[0]
	switch version {
	case PresentationVersion1:
		v1, err := deserializeProfileKeyCredentialPresentationV1(data)
		if err != nil {
			return nil, err
		}
		return &AnyProfileKeyCredentialPresentation{Version: PresentationVersion1, V1: v1}, nil

	case PresentationVersion2:
		v2, err := deserializeProfileKeyCredentialPresentationV2(data)
		if err != nil {
			return nil, err
		}
		return &AnyProfileKeyCredentialPresentation{Version: PresentationVersion2, V2: v2}, nil

	case PresentationVersion3:
		v3, err := deserializeExpiringProfileKeyCredentialPresentation(data)
		if err != nil {
			return nil, err
		}
		return &AnyProfileKeyCredentialPresentation{Version: PresentationVersion3, V3: v3}, nil

	case PresentationVersion4:
		v4, err := deserializeExpiringProfileKeyCredentialPresentation(data)
		if err != nil {
			return nil, err
		}
		return &AnyProfileKeyCredentialPresentation{Version: PresentationVersion4, V4: v4}, nil

	default:
		return nil, &ErrUnknownPresentationVersion{Version: version}
	}
}
