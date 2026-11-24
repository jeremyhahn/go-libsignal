package zkgroup

import (
	"encoding/binary"

	"github.com/gtank/ristretto255"
)

// profileKeyCredentialRequestFixedSize is a reserved byte plus five 32-byte points, before the variable proof.
const profileKeyCredentialRequestFixedSize = 1 + 5*32 // 161

// SerializeProfileKeyCredentialRequest encodes r as Rust bincode: reserved byte, public key, D1, D2, E1, E2, proof.
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

// DeserializeProfileKeyCredentialRequest decodes a client request; the proof stays opaque and is verified at issuance.
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

// expiringProfileKeyCredentialResponseFixedSize is a reserved byte, the 128-byte credential and an 8-byte expiration, before the proof.
const expiringProfileKeyCredentialResponseFixedSize = 1 + 4*32 + 8 // 137

// SerializeExpiringProfileKeyCredentialResponse encodes r as Rust bincode: reserved byte, t, U, S1, S2, u64 LE expiration, proof.
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
