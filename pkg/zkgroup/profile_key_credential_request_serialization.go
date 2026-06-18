package zkgroup

import (
	"encoding/binary"

	"github.com/gtank/ristretto255"
)

// profileKeyCredentialRequestFixedSize is the fixed-length prefix of a
// serialized ProfileKeyCredentialRequest: a reserved byte followed by five
// 32-byte ristretto points (the blinding public key Y and the ciphertext
// elements D1, D2, E1, E2). The poksho proof bytes follow and are
// variable-length.
const profileKeyCredentialRequestFixedSize = 1 + 5*32 // 161

// SerializeProfileKeyCredentialRequest serializes a ProfileKeyCredentialRequest
// to the Rust bincode wire format, producing byte-for-byte identical output to
// Rust's bincode::serialize on the same struct.
//
// Wire layout (matches Rust ProfileKeyCredentialRequest at
// rust/zkgroup/src/api/profiles/profile_key_credential_request.rs):
//
//	[0x00]      reserved byte (ReservedByte)
//	[32]        public_key  (PublicKey: blinding key Y)
//	[32]        ciphertext.D1
//	[32]        ciphertext.D2
//	[32]        ciphertext.E1
//	[32]        ciphertext.E2
//	[variable]  proof (ProfileKeyCredentialRequestProof poksho bytes)
//
// The ristretto point encoding (Element.Bytes) and the proof bytes are the
// same Rust-compatible encodings used by the request-proof generation and the
// presentation serializer, so the result matches the client-produced bytes.
func SerializeProfileKeyCredentialRequest(r *ProfileKeyCredentialRequest) []byte {
	out := make([]byte, 0, profileKeyCredentialRequestFixedSize+len(r.Proof))
	out = append(out, 0x00) // reserved
	out = append(out, r.PublicKey.Bytes()...)
	out = append(out, r.Ciphertext.D1.Bytes()...)
	out = append(out, r.Ciphertext.D2.Bytes()...)
	out = append(out, r.Ciphertext.E1.Bytes()...)
	out = append(out, r.Ciphertext.E2.Bytes()...)
	out = append(out, r.Proof...)
	return out
}

// DeserializeProfileKeyCredentialRequest decodes a ProfileKeyCredentialRequest
// from the Rust bincode wire format produced by the client's
// CreateProfileKeyCredentialRequestContext().GetRequest(). The trailing bytes
// after the five fixed points are the poksho proof, which is preserved opaque
// and validated by the server during IssueExpiringProfileKeyCredential — so a
// malformed request fails closed at proof verification rather than yielding a
// bad credential.
func DeserializeProfileKeyCredentialRequest(data []byte) (*ProfileKeyCredentialRequest, error) {
	if len(data) < profileKeyCredentialRequestFixedSize {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ProfileKeyCredentialRequest"}
	}
	if data[0] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[0]}
	}

	decode := func(b []byte) (*ristretto255.Element, error) {
		el := new(ristretto255.Element)
		if _, err := el.SetCanonicalBytes(b); err != nil {
			return nil, &ZkGroupDeserializationFailure{TypeName: "ProfileKeyCredentialRequest"}
		}
		return el, nil
	}

	publicKey, err := decode(data[1:33])
	if err != nil {
		return nil, err
	}
	d1, err := decode(data[33:65])
	if err != nil {
		return nil, err
	}
	d2, err := decode(data[65:97])
	if err != nil {
		return nil, err
	}
	e1, err := decode(data[97:129])
	if err != nil {
		return nil, err
	}
	e2, err := decode(data[129:161])
	if err != nil {
		return nil, err
	}

	proof := make([]byte, len(data)-profileKeyCredentialRequestFixedSize)
	copy(proof, data[profileKeyCredentialRequestFixedSize:])

	return &ProfileKeyCredentialRequest{
		PublicKey: publicKey,
		Ciphertext: &profileKeyCredentialRequestCiphertext{
			D1: d1,
			D2: d2,
			E1: e1,
			E2: e2,
		},
		Proof: proof,
	}, nil
}

// profileKeyCommitmentSize is the fixed serialized length of a
// ProfileKeyCommitment: a reserved byte plus three 32-byte ristretto points
// (J1, J2, J3). It equals ProfileKeyCommitmentLen.
const profileKeyCommitmentSize = 1 + 3*32 // 97

// SerializeProfileKeyCommitment serializes a ProfileKeyCommitment to the Rust
// bincode wire format: reserved byte followed by J1, J2, J3.
func SerializeProfileKeyCommitment(c *ProfileKeyCommitment) []byte {
	out := make([]byte, 0, profileKeyCommitmentSize)
	out = append(out, 0x00) // reserved
	out = append(out, c.Commitment.J1.Bytes()...)
	out = append(out, c.Commitment.J2.Bytes()...)
	out = append(out, c.Commitment.J3.Bytes()...)
	return out
}

// DeserializeProfileKeyCommitment decodes the 97-byte client-uploaded profile
// key commitment (Rust bincode wire format) into a ProfileKeyCommitment. The
// server uses it to verify a profile-key-credential request during issuance.
func DeserializeProfileKeyCommitment(data []byte) (*ProfileKeyCommitment, error) {
	if len(data) != profileKeyCommitmentSize {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ProfileKeyCommitment"}
	}
	if data[0] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[0]}
	}

	decode := func(b []byte) (*ristretto255.Element, error) {
		el := new(ristretto255.Element)
		if _, err := el.SetCanonicalBytes(b); err != nil {
			return nil, &ZkGroupDeserializationFailure{TypeName: "ProfileKeyCommitment"}
		}
		return el, nil
	}

	j1, err := decode(data[1:33])
	if err != nil {
		return nil, err
	}
	j2, err := decode(data[33:65])
	if err != nil {
		return nil, err
	}
	j3, err := decode(data[65:97])
	if err != nil {
		return nil, err
	}

	return &ProfileKeyCommitment{
		Commitment: &ProfileKeyCommitmentInternal{J1: j1, J2: j2, J3: j3},
	}, nil
}

// expiringProfileKeyCredentialResponseFixedSize is the fixed-length prefix of a
// serialized ExpiringProfileKeyCredentialResponse: a reserved byte, the
// 128-byte blinded credential (t, U, S1, S2), and an 8-byte expiration. The
// poksho issuance proof follows and is variable-length.
const expiringProfileKeyCredentialResponseFixedSize = 1 + 4*32 + 8 // 137

// SerializeExpiringProfileKeyCredentialResponse serializes the server's
// credential issuance response to the Rust bincode wire format the client
// expects in ReceiveExpiringProfileKeyCredential.
//
// Wire layout (matches Rust ExpiringProfileKeyCredentialResponse at
// rust/zkgroup/src/api/profiles/expiring_profile_key_credential_response.rs:13-18
// and crypto/credentials.rs BlindedExpiringProfileKeyCredential):
//
//	[0x00]      reserved byte
//	[32]        blinded_credential.t  (Scalar)
//	[32]        blinded_credential.U  (RistrettoPoint)
//	[32]        blinded_credential.S1 (RistrettoPoint)
//	[32]        blinded_credential.S2 (RistrettoPoint)
//	[8 LE u64]  credential_expiration_time (Timestamp)
//	[variable]  proof (ExpiringProfileKeyCredentialIssuanceProof poksho bytes)
func SerializeExpiringProfileKeyCredentialResponse(r *ExpiringProfileKeyCredentialResponse) []byte {
	out := make([]byte, 0, expiringProfileKeyCredentialResponseFixedSize+len(r.Proof))
	out = append(out, 0x00) // reserved
	out = append(out, r.BlindedCredential.t.Bytes()...)
	out = append(out, r.BlindedCredential.U.Bytes()...)
	out = append(out, r.BlindedCredential.S1.Bytes()...)
	out = append(out, r.BlindedCredential.S2.Bytes()...)
	le := r.CredentialExpirationTime.ToLeBytes()
	out = append(out, le[:]...)
	out = append(out, r.Proof...)
	return out
}

// DeserializeExpiringProfileKeyCredentialResponse decodes the wire format
// produced by SerializeExpiringProfileKeyCredentialResponse.
func DeserializeExpiringProfileKeyCredentialResponse(data []byte) (*ExpiringProfileKeyCredentialResponse, error) {
	if len(data) < expiringProfileKeyCredentialResponseFixedSize {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ExpiringProfileKeyCredentialResponse"}
	}
	if data[0] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[0]}
	}

	decodeEl := func(b []byte) (*ristretto255.Element, error) {
		el := new(ristretto255.Element)
		if _, err := el.SetCanonicalBytes(b); err != nil {
			return nil, &ZkGroupDeserializationFailure{TypeName: "ExpiringProfileKeyCredentialResponse"}
		}
		return el, nil
	}

	tScalar := new(ristretto255.Scalar)
	if _, err := tScalar.SetCanonicalBytes(data[1:33]); err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ExpiringProfileKeyCredentialResponse"}
	}
	u, err := decodeEl(data[33:65])
	if err != nil {
		return nil, err
	}
	s1, err := decodeEl(data[65:97])
	if err != nil {
		return nil, err
	}
	s2, err := decodeEl(data[97:129])
	if err != nil {
		return nil, err
	}
	expiration := NewTimestamp(binary.LittleEndian.Uint64(data[129:137]))

	proof := make([]byte, len(data)-expiringProfileKeyCredentialResponseFixedSize)
	copy(proof, data[expiringProfileKeyCredentialResponseFixedSize:])

	return &ExpiringProfileKeyCredentialResponse{
		BlindedCredential: &blindedExpiringProfileKeyCredential{
			t:  tScalar,
			U:  u,
			S1: s1,
			S2: s2,
		},
		CredentialExpirationTime: expiration,
		Proof:                    proof,
	}, nil
}
