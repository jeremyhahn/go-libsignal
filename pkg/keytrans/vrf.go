// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

import (
	"crypto/sha512"
	"crypto/subtle"
	"math/big"

	"filippo.io/edwards25519"
)

// VRF constants for ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381).
const (
	vrfSuiteID                  = 0x03
	vrfDomainSeparatorEncode    = 0x01
	vrfDomainSeparatorChallenge = 0x02
	vrfDomainSeparatorProof     = 0x03
	vrfDomainSeparatorBack      = 0x00
)

// VRFPublicKey holds a VRF public key.
type VRFPublicKey struct {
	compressed   [32]byte
	decompressed *edwards25519.Point
}

// NewVRFPublicKey creates a VRFPublicKey from a 32-byte compressed point.
func NewVRFPublicKey(publicKey [32]byte) (*VRFPublicKey, error) {
	pt, err := new(edwards25519.Point).SetBytes(publicKey[:])
	if err != nil {
		return nil, ErrInvalidCurvePoint
	}
	// Check for small order point.
	// Multiply by the cofactor (8) and check if identity.
	cofactored := cofactorMultiply(pt)
	if cofactored.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, ErrInvalidCurvePoint
	}
	return &VRFPublicKey{
		compressed:   publicKey,
		decompressed: pt,
	}, nil
}

// AsBytes returns the 32-byte compressed representation of the public key.
func (pk *VRFPublicKey) AsBytes() *[32]byte {
	return &pk.compressed
}

// ProofToHash checks that proof is the correct VRF proof for message m,
// and outputs the VRF hash if so.
func (pk *VRFPublicKey) ProofToHash(m []byte, proof *[80]byte) ([32]byte, error) {
	// Decode proof into its component parts: gamma, c, and s.
	gammaBytes := proof[:32]
	cLowerBytes := proof[32:48]
	sBytes := proof[48:80]

	gamma, err := new(edwards25519.Point).SetBytes(gammaBytes)
	if err != nil {
		return [32]byte{}, ErrInvalidVRFProof
	}

	// Build c scalar (negate it for the verification equation).
	var cFullBytes [32]byte
	copy(cFullBytes[:16], cLowerBytes)
	cScalar, err := new(edwards25519.Scalar).SetCanonicalBytes(cFullBytes[:])
	if err != nil {
		return [32]byte{}, ErrInvalidVRFProof
	}
	negC := new(edwards25519.Scalar).Negate(cScalar)

	sScalar, err := new(edwards25519.Scalar).SetCanonicalBytes(sBytes)
	if err != nil {
		return [32]byte{}, ErrInvalidVRFProof
	}

	// H = encode_to_curve_try_and_increment(pk, m)
	h, err := encodeToCurveTryAndIncrement(pk.compressed[:], m)
	if err != nil {
		return [32]byte{}, err
	}

	// U = [s]B - [c]Y = [s]B + [-c]Y
	u := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negC, pk.decompressed, sScalar)

	// V = [s]H - [c]Gamma = [s]H + [-c]Gamma
	v := new(edwards25519.Point).VarTimeMultiScalarMult([]*edwards25519.Scalar{sScalar, negC}, []*edwards25519.Point{h, gamma})

	// Check challenge.
	var hCompressed, uCompressed, vCompressed [32]byte
	copy(hCompressed[:], h.Bytes())
	copy(uCompressed[:], u.Bytes())
	copy(vCompressed[:], v.Bytes())

	var gammaCompressed [32]byte
	copy(gammaCompressed[:], gammaBytes)

	cPrime := generateChallenge([5]*[32]byte{
		&pk.compressed,
		&hCompressed,
		&gammaCompressed,
		&uCompressed,
		&vCompressed,
	})

	if subtle.ConstantTimeCompare(cLowerBytes[:16], cPrime[:16]) != 1 {
		return [32]byte{}, ErrInvalidVRFProof
	}

	return vrfProofToHash(gamma), nil
}

// encodeToCurveTryAndIncrement implements the try-and-increment method for
// encoding to the curve. Returns ErrTryAndIncrementFailed if all 256 attempts fail.
func encodeToCurveTryAndIncrement(salt, data []byte) (*edwards25519.Point, error) {
	for i := 0; i <= 255; i++ {
		h := sha512.New()
		h.Write([]byte{vrfSuiteID, vrfDomainSeparatorEncode})
		h.Write(salt)
		h.Write(data)
		h.Write([]byte{byte(i), vrfDomainSeparatorBack})

		r := h.Sum(nil)

		// Try to decompress the first 32 bytes as an Edwards point.
		pt, err := new(edwards25519.Point).SetBytes(r[:32])
		if err != nil {
			continue
		}

		// Multiply by cofactor.
		result := cofactorMultiply(pt)
		if result.Equal(edwards25519.NewIdentityPoint()) != 1 {
			return result, nil
		}
	}
	return nil, ErrTryAndIncrementFailed
}

// cofactorMultiply multiplies a point by the cofactor (8).
func cofactorMultiply(p *edwards25519.Point) *edwards25519.Point {
	return new(edwards25519.Point).MultByCofactor(p)
}

// scalarFromUint64 creates an edwards25519.Scalar from a uint64 value.
func scalarFromUint64(v uint64) *edwards25519.Scalar {
	b := new(big.Int).SetUint64(v)
	var buf [32]byte
	bBytes := b.Bytes()
	// little-endian encoding for Scalar.SetCanonicalBytes
	for i, j := 0, len(bBytes)-1; i < j; i, j = i+1, j-1 {
		bBytes[i], bBytes[j] = bBytes[j], bBytes[i]
	}
	copy(buf[:], bBytes)
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(buf[:])
	if err != nil {
		panic("failed to create scalar from uint64")
	}
	return s
}

// generateChallenge generates the VRF challenge from 5 points.
func generateChallenge(pts [5]*[32]byte) [16]byte {
	h := sha512.New()
	h.Write([]byte{vrfSuiteID, vrfDomainSeparatorChallenge})
	for _, pt := range pts {
		h.Write(pt[:])
	}
	h.Write([]byte{vrfDomainSeparatorBack})
	c := h.Sum(nil)

	var result [16]byte
	copy(result[:], c[:16])
	return result
}

// vrfProofToHash converts a VRF gamma point to its hash output.
func vrfProofToHash(gamma *edwards25519.Point) [32]byte {
	cofactored := cofactorMultiply(gamma)

	h := sha512.New()
	h.Write([]byte{vrfSuiteID, vrfDomainSeparatorProof})
	h.Write(cofactored.Bytes())
	h.Write([]byte{vrfDomainSeparatorBack})
	index := h.Sum(nil)

	var result [32]byte
	copy(result[:], index[:32])
	return result
}
