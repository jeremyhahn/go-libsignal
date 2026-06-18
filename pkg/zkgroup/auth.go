package zkgroup

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// authCredentialWithPniZkcLen is the wire length of a serialized
// AuthCredentialWithPniZkc in bincode format:
// 1 (version) + 96 (Credential: t:32 ‖ U:32 ‖ V:32)
// + 80 (UIDStruct ACI: bytes:16 ‖ M1:32 ‖ M2:32)
// + 80 (UIDStruct PNI: bytes:16 ‖ M1:32 ‖ M2:32)
// + 8 (redemption_time LE u64)
// = 265 bytes.
//
// Matches Rust constant AUTH_CREDENTIAL_WITH_PNI_LEN = 265 in
// zkgroup/src/common/constants.rs.
const authCredentialWithPniZkcLen = 265

// authCredentialWithPniZkcLabel is the credential label for zkcredential-based
// auth credentials. Matches Rust CREDENTIAL_LABEL in zkc.rs.
var authCredentialWithPniZkcLabel = []byte("20240222_Signal_AuthCredentialZkc")

// Presentation version constants.
const (
	PresentationVersion1 = 0
	PresentationVersion2 = 1
	PresentationVersion3 = 2
	PresentationVersion4 = 3
)

// AuthCredentialWithPniVersion identifies the version of an auth credential.
type AuthCredentialWithPniVersion byte

const (
	// AuthCredentialWithPniVersionZkc is the current (zkcredential-based) version.
	AuthCredentialWithPniVersionZkc AuthCredentialWithPniVersion = 3
)

// AuthCredentialWithPniZkc is an auth credential issued via the zkcredential
// system, binding an ACI and PNI together with a redemption time.
type AuthCredentialWithPniZkc struct {
	Credential     *zkcredential.Credential
	ACI            *UIDStruct
	PNI            *UIDStruct
	RedemptionTime Timestamp
}

// AuthCredentialWithPniZkcResponse is the server's response for a
// zkcredential-based auth credential.
type AuthCredentialWithPniZkcResponse struct {
	Proof          *zkcredential.IssuanceProof
	RedemptionTime Timestamp
}

// AuthCredentialWithPniZkcPresentation is a presentation of a zkcredential-based
// auth credential.
type AuthCredentialWithPniZkcPresentation struct {
	Proof              *zkcredential.PresentationProof
	ACICiphertext      *UUIDCiphertext
	PNICiphertext      *UUIDCiphertext
	RedemptionTimeSecs Timestamp
}

// ACICiphertextValue returns the ACI ciphertext.
func (p *AuthCredentialWithPniZkcPresentation) ACICiphertextValue() *UUIDCiphertext {
	return p.ACICiphertext
}

// PNICiphertextValue returns the PNI ciphertext.
func (p *AuthCredentialWithPniZkcPresentation) PNICiphertextValue() *UUIDCiphertext {
	return p.PNICiphertext
}

// RedemptionTime returns the redemption time.
func (p *AuthCredentialWithPniZkcPresentation) RedemptionTime() Timestamp {
	return p.RedemptionTimeSecs
}

// AuthCredentialWithPni wraps the different versions of auth credentials
// with PNI.
type AuthCredentialWithPni struct {
	Version    AuthCredentialWithPniVersion
	Credential *AuthCredentialWithPniZkc
}

// AuthCredentialWithPniResponse wraps the different versions of auth credential
// responses.
type AuthCredentialWithPniResponse struct {
	Version  AuthCredentialWithPniVersion
	Response *AuthCredentialWithPniZkcResponse
}

// AnyAuthCredentialPresentation holds any version of auth credential
// presentation.
type AnyAuthCredentialPresentation struct {
	Version      byte
	Presentation *AuthCredentialWithPniZkcPresentation
}

// GetACICiphertext returns the ACI ciphertext from any presentation version.
func (p *AnyAuthCredentialPresentation) GetACICiphertext() *UUIDCiphertext {
	return p.Presentation.ACICiphertext
}

// GetPNICiphertext returns the PNI ciphertext from any presentation version.
func (p *AnyAuthCredentialPresentation) GetPNICiphertext() *UUIDCiphertext {
	return p.Presentation.PNICiphertext
}

// GetRedemptionTime returns the redemption time from any presentation version.
func (p *AnyAuthCredentialPresentation) GetRedemptionTime() Timestamp {
	return p.Presentation.RedemptionTimeSecs
}

// Serialize encodes the AuthCredentialWithPniZkc to its 265-byte bincode wire
// format, which clients store locally.
//
// Wire layout (matches Rust bincode derive on AuthCredentialWithPniZkc):
//
//	[0]          version byte (AuthCredentialWithPniVersionZkc == 0x03)
//	[1..97]      Credential: t:32 ‖ U:32 ‖ V:32
//	[97..177]    UIDStruct ACI: raw_uuid_bytes:16 ‖ M1:32 ‖ M2:32
//	[177..257]   UIDStruct PNI: raw_uuid_bytes:16 ‖ M1:32 ‖ M2:32
//	[257..265]   redemption_time (8-byte LE u64, seconds since epoch)
//
// Matches Rust AUTH_CREDENTIAL_WITH_PNI_LEN = 265 from
// zkgroup/src/common/constants.rs.
func (c *AuthCredentialWithPniZkc) Serialize() ([]byte, error) {
	credBytes := zkcredential.EncodeCredential(c.Credential)
	aciBytes := c.ACI.Serialize()
	pniBytes := c.PNI.Serialize()

	out := make([]byte, 0, authCredentialWithPniZkcLen)
	out = append(out, byte(AuthCredentialWithPniVersionZkc))
	out = append(out, credBytes...)
	out = append(out, aciBytes...)
	out = append(out, pniBytes...)

	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], c.RedemptionTime.EpochSeconds())
	out = append(out, tsBuf[:]...)

	return out, nil
}

// DeserializeAuthCredentialWithPniZkc decodes an AuthCredentialWithPniZkc from
// exactly 265 bytes of bincode wire-format data.
//
// Returns ErrInvalidCredentialLength if the input is not exactly 265 bytes.
// Returns ZkGroupDeserializationFailure for malformed point or scalar encodings.
//
// Wire layout:
//
//	[0]          version byte (must be AuthCredentialWithPniVersionZkc == 0x03)
//	[1..97]      Credential: t:32 ‖ U:32 ‖ V:32
//	[97..177]    UIDStruct ACI: raw_uuid_bytes:16 ‖ M1:32 ‖ M2:32
//	[177..257]   UIDStruct PNI: raw_uuid_bytes:16 ‖ M1:32 ‖ M2:32
//	[257..265]   redemption_time (8-byte LE u64, seconds since epoch)
//
// Mirrors Rust bincode::deserialize::<AuthCredentialWithPniZkc> from
// zkgroup/src/api/auth/auth_credential_with_pni/zkc.rs.
func DeserializeAuthCredentialWithPniZkc(b []byte) (*AuthCredentialWithPniZkc, error) {
	if len(b) != authCredentialWithPniZkcLen {
		return nil, &ErrInvalidCredentialLength{Got: len(b), Want: authCredentialWithPniZkcLen}
	}
	if b[0] != byte(AuthCredentialWithPniVersionZkc) {
		return nil, &ErrUnknownPresentationVersion{Version: b[0]}
	}

	// Credential: bytes [1..97]
	cred, err := zkcredential.DecodeCredential(b[1:97])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "AuthCredentialWithPniZkc Credential"}
	}

	// ACI UIDStruct: bytes [97..177]
	aci, err := DeserializeUIDStruct(b[97:177])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "AuthCredentialWithPniZkc ACI"}
	}

	// PNI UIDStruct: bytes [177..257]
	pni, err := DeserializeUIDStruct(b[177:257])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "AuthCredentialWithPniZkc PNI"}
	}

	// Redemption time: bytes [257..265] LE u64
	redemptionSecs := binary.LittleEndian.Uint64(b[257:265])

	return &AuthCredentialWithPniZkc{
		Credential:     cred,
		ACI:            aci,
		PNI:            pni,
		RedemptionTime: NewTimestamp(redemptionSecs),
	}, nil
}

// IssueAuthCredentialWithPniZkc issues an auth credential with PNI using the
// zkcredential system. This is a server-side operation.
//
// Matches Rust AuthCredentialWithPniZkcResponse::issue_credential.
func (s *ServerSecretParams) IssueAuthCredentialWithPniZkc(
	aci ServiceID,
	pni ServiceID,
	redemptionTime Timestamp,
	randomness RandomnessBytes,
) (*AuthCredentialWithPniZkcResponse, error) {
	aciStruct := NewUIDStructFromServiceID(aci)
	pniStruct := NewUIDStructFromServiceID(pni)

	builder := zkcredential.NewIssuanceProofBuilder(authCredentialWithPniZkcLabel)
	if err := builder.AddAttribute(aciStruct); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc issue: add aci attribute: " + err.Error()}
	}
	if err := builder.AddAttribute(pniStruct); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc issue: add pni attribute: " + err.Error()}
	}
	builder.AddPublicAttribute(redemptionTime)

	proof, err := builder.Issue(s.GenericCredentialKeyPair, randomness)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc issue: " + err.Error()}
	}

	return &AuthCredentialWithPniZkcResponse{
		Proof:          proof,
		RedemptionTime: redemptionTime,
	}, nil
}

// ReceiveAuthCredentialWithPniZkc verifies and receives an auth credential
// with PNI. This is a client-side operation.
//
// Matches Rust AuthCredentialWithPniZkcResponse::receive.
func (pub *ServerPublicParams) ReceiveAuthCredentialWithPniZkc(
	aci ServiceID,
	pni ServiceID,
	redemptionTime Timestamp,
	response *AuthCredentialWithPniZkcResponse,
) (*AuthCredentialWithPniZkc, error) {
	if !redemptionTime.IsDayAligned() {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc receive: redemption time not day-aligned"}
	}

	aciStruct := NewUIDStructFromServiceID(aci)
	pniStruct := NewUIDStructFromServiceID(pni)

	builder := zkcredential.NewIssuanceProofBuilder(authCredentialWithPniZkcLabel)
	if err := builder.AddAttribute(aciStruct); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc receive: add aci attribute: " + err.Error()}
	}
	if err := builder.AddAttribute(pniStruct); err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc receive: add pni attribute: " + err.Error()}
	}
	builder.AddPublicAttribute(redemptionTime)

	credential, err := builder.Verify(pub.GenericCredentialPublicKey, response.Proof)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc receive: verification failed"}
	}

	return &AuthCredentialWithPniZkc{
		Credential:     credential,
		ACI:            aciStruct,
		PNI:            pniStruct,
		RedemptionTime: redemptionTime,
	}, nil
}

// CreateAuthCredentialWithPniZkcPresentation creates a zero-knowledge
// presentation of an auth credential with PNI. This is a client-side operation.
//
// Matches Rust AuthCredentialWithPniZkc::present.
func (pub *ServerPublicParams) CreateAuthCredentialWithPniZkcPresentation(
	credential *AuthCredentialWithPniZkc,
	groupSecretParams *GroupSecretParams,
	randomness RandomnessBytes,
) (*AuthCredentialWithPniZkcPresentation, error) {
	builder := zkcredential.NewPresentationProofBuilder(authCredentialWithPniZkcLabel)
	builder.AddAttribute(credential.ACI, groupSecretParams.UIDEncKeyPair)
	builder.AddAttribute(credential.PNI, groupSecretParams.UIDEncKeyPair)

	proof, err := builder.Present(
		pub.GenericCredentialPublicKey,
		credential.Credential,
		randomness,
	)
	if err != nil {
		return nil, &ZkGroupVerificationFailure{Context: "auth zkc present: " + err.Error()}
	}

	// Encrypt the UIDStructs directly using the key pair,
	// matching how Rust does it.
	aciCT := &UUIDCiphertext{Ciphertext: groupSecretParams.UIDEncKeyPair.Encrypt(credential.ACI)}
	pniCT := &UUIDCiphertext{Ciphertext: groupSecretParams.UIDEncKeyPair.Encrypt(credential.PNI)}

	return &AuthCredentialWithPniZkcPresentation{
		Proof:              proof,
		ACICiphertext:      aciCT,
		PNICiphertext:      pniCT,
		RedemptionTimeSecs: credential.RedemptionTime,
	}, nil
}

// VerifyAuthCredentialWithPniZkcPresentation verifies an auth credential
// with PNI presentation. This is a server-side operation.
//
// Matches Rust AuthCredentialWithPniZkcPresentation::verify.
func (s *ServerSecretParams) VerifyAuthCredentialWithPniZkcPresentation(
	groupPublicParams *GroupPublicParams,
	presentation *AuthCredentialWithPniZkcPresentation,
	redemptionTime Timestamp,
) error {
	verifier := zkcredential.NewPresentationProofVerifier(authCredentialWithPniZkcLabel)
	verifier.AddAttribute(
		presentation.ACICiphertext.Ciphertext,
		groupPublicParams.UIDEncPublicKey,
	)
	verifier.AddAttribute(
		presentation.PNICiphertext.Ciphertext,
		groupPublicParams.UIDEncPublicKey,
	)
	verifier.AddPublicAttribute(redemptionTime)

	if err := verifier.Verify(s.GenericCredentialKeyPair, presentation.Proof); err != nil {
		return &ZkGroupVerificationFailure{Context: "auth zkc verify: verification failed"}
	}

	return nil
}

// DeserializeAnyAuthCredentialPresentation parses a serialized
// AnyAuthCredentialPresentation from wire-format bytes, mirroring the behavior
// of Rust's AnyAuthCredentialPresentation::new.
//
// Only V4 presentations (first byte == PresentationVersion4 == 0x03) are
// accepted. V1–V3 and any unrecognized version byte return
// ErrDeserializationFailure, matching the Rust implementation which removed
// support for V1–V3 auth credential presentations.
//
// Wire layout (Rust bincode, AuthCredentialWithPniZkcPresentation):
//
//	[0]         version byte (must be 0x03)
//	[1..]       PresentationProof in Rust bincode format
//	[proof+0..proof+64]   aci_ciphertext (EA1 ∥ EA2, each 32 bytes)
//	[proof+64..proof+128] pni_ciphertext (EA1 ∥ EA2, each 32 bytes)
//	[proof+128..proof+136] redemption_time (8-byte LE u64, seconds since epoch)
//
// Returns ErrUnknownPresentationVersion for any version byte other than 0x03,
// ErrDataTooShort for empty or truncated input, and ZkGroupDeserializationFailure
// for malformed point encodings.
func DeserializeAnyAuthCredentialPresentation(data []byte) (*AnyAuthCredentialPresentation, error) {
	if len(data) == 0 {
		return nil, &ErrDataTooShort{}
	}
	version := data[0]
	if version != PresentationVersion4 {
		// Rust rejects V1–V3; only V4 is a valid auth credential presentation.
		return nil, &ErrUnknownPresentationVersion{Version: version}
	}

	proof, consumed, err := zkcredential.DecodePresentationProofBincode(data[1:])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "AnyAuthCredentialPresentation proof"}
	}
	off := 1 + consumed

	aciCT, err := decodeCiphertextAt(data, off)
	if err != nil {
		return nil, err
	}
	off += presentationCiphertextSize

	pniCT, err := decodeCiphertextAt(data, off)
	if err != nil {
		return nil, err
	}
	off += presentationCiphertextSize

	if len(data) < off+8 {
		return nil, &ErrDataTooShort{}
	}
	redemptionSecs := binary.LittleEndian.Uint64(data[off : off+8])
	off += 8

	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "AnyAuthCredentialPresentation", Count: len(data) - off}
	}

	pres := &AuthCredentialWithPniZkcPresentation{
		Proof:              proof,
		ACICiphertext:      &UUIDCiphertext{Ciphertext: aciCT},
		PNICiphertext:      &UUIDCiphertext{Ciphertext: pniCT},
		RedemptionTimeSecs: NewTimestamp(redemptionSecs),
	}
	return &AnyAuthCredentialPresentation{
		Version:      PresentationVersion4,
		Presentation: pres,
	}, nil
}

// SerializeAuthCredentialWithPniZkcPresentation encodes an
// AuthCredentialWithPniZkcPresentation to its Rust bincode wire-format bytes.
//
// This is the inverse of DeserializeAnyAuthCredentialPresentation and produces
// byte-identical output to bincode::serialize on the corresponding Rust
// AuthCredentialWithPniZkcPresentation struct.
//
// Wire layout:
//
//	[0]                  version byte (PresentationVersion4 == 0x03)
//	[1..]                PresentationProof in Rust bincode format
//	[proof+0..proof+64]  aci_ciphertext (EA1 ∥ EA2)
//	[proof+64..proof+128] pni_ciphertext (EA1 ∥ EA2)
//	[proof+128..proof+136] redemption_time (8-byte LE u64, seconds since epoch)
//
// Matches Rust bincode::serialize(&AuthCredentialWithPniZkcPresentation).
func SerializeAuthCredentialWithPniZkcPresentation(
	p *AuthCredentialWithPniZkcPresentation,
) []byte {
	proofBytes := zkcredential.EncodePresentationProofBincode(p.Proof)

	out := make([]byte, 0, 1+len(proofBytes)+presentationCiphertextSize*2+8)
	out = append(out, PresentationVersion4)
	out = append(out, proofBytes...)
	out = append(out, zkcredential.EncodeCiphertext(p.ACICiphertext.Ciphertext)...)
	out = append(out, zkcredential.EncodeCiphertext(p.PNICiphertext.Ciphertext)...)

	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], p.RedemptionTimeSecs.EpochSeconds())
	out = append(out, tsBuf[:]...)

	return out
}
