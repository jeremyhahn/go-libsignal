package poksho

import (
	"crypto/subtle"
	"fmt"

	"github.com/gtank/ristretto255"
)

// Statement defines a zero-knowledge proof statement consisting of linear
// equations over Ristretto255 points. Each equation asserts that a linear
// combination of generators weighted by secret scalars equals a target point.
//
// Equations use named string identifiers for scalars and points, matching
// the Rust poksho::Statement system. Point index 0 is pre-assigned to "G",
// the Ristretto basepoint.
//
// The statement is serialized into a compact binary description that is
// absorbed into the SHO transcript, ensuring that different statements
// produce different challenges even with the same inputs.
type Statement struct {
	equations []equation
	scalarMap map[string]uint8
	scalarVec []string
	pointMap  map[string]uint8
	pointVec  []string
}

type equation struct {
	lhs uint8
	rhs []term
}

type term struct {
	scalar uint8
	point  uint8
}

// NewStatement creates a new empty proof statement with the Ristretto
// basepoint pre-assigned as point index 0 with name "G".
func NewStatement() *Statement {
	return &Statement{
		scalarMap: make(map[string]uint8),
		pointMap:  map[string]uint8{"G": 0},
		pointVec:  []string{"G"},
	}
}

// Add adds an equation to the statement. lhs is the name of the left-hand
// side point. rhsPairs is a list of (scalar_name, point_name) pairs for
// the right-hand side terms.
//
// Panics if input is invalid (empty lhs, empty pairs, >255 equations or terms).
func (s *Statement) Add(lhs string, rhsPairs [][2]string) {
	if lhs == "" || len(rhsPairs) == 0 || len(rhsPairs) > 255 || len(s.equations) >= 255 {
		panic("poksho: unexpected input sizes to Add")
	}

	lhsIdx := s.addPoint(lhs)
	rhs := make([]term, len(rhsPairs))
	for i, pair := range rhsPairs {
		if pair[0] == "" || pair[1] == "" {
			panic("poksho: unexpected pair size")
		}
		scalarIdx := s.addScalar(pair[0])
		pointIdx := s.addPoint(pair[1])
		rhs[i] = term{scalar: scalarIdx, point: pointIdx}
	}
	s.equations = append(s.equations, equation{lhs: lhsIdx, rhs: rhs})
}

func (s *Statement) addScalar(name string) uint8 {
	if idx, ok := s.scalarMap[name]; ok {
		return idx
	}
	if len(s.scalarMap) >= 256 {
		panic("poksho: too many scalars")
	}
	idx := uint8(len(s.scalarMap))
	s.scalarMap[name] = idx
	s.scalarVec = append(s.scalarVec, name)
	return idx
}

func (s *Statement) addPoint(name string) uint8 {
	if idx, ok := s.pointMap[name]; ok {
		return idx
	}
	if len(s.pointMap) >= 256 {
		panic("poksho: too many points")
	}
	idx := uint8(len(s.pointMap))
	s.pointMap[name] = idx
	s.pointVec = append(s.pointVec, name)
	return idx
}

// toBytes serializes the statement description into the compact binary
// format that gets absorbed into the SHO transcript.
//
// Format:
//
//	Ne : number of equations (1 byte)
//	for each equation:
//	  point_index : LHS point index (1 byte)
//	  Nt : number of terms (1 byte)
//	  for each term:
//	    scalar_index : (1 byte)
//	    point_index : (1 byte)
func (s *Statement) toBytes() []byte {
	eqCount := uint8(len(s.equations))
	v := []byte{eqCount}
	for _, eq := range s.equations {
		v = append(v, eq.lhs)
		termCount := uint8(len(eq.rhs))
		v = append(v, termCount)
		for _, t := range eq.rhs {
			v = append(v, t.scalar, t.point)
		}
	}
	return v
}

// sortScalars arranges the scalar arguments in the order defined by the
// statement's scalar_vec, validating that all required scalars are present.
func (s *Statement) sortScalars(args *ScalarArgs) ([]*ristretto255.Scalar, error) {
	if len(args.values) != len(s.scalarVec) {
		return nil, &ProofError{
			Kind:    ErrBadArgsWrongNumberOfScalarArgs,
			Context: fmt.Sprintf("expected %d scalars, got %d", len(s.scalarVec), len(args.values)),
		}
	}
	result := make([]*ristretto255.Scalar, len(s.scalarVec))
	for i, name := range s.scalarVec {
		sc, ok := args.values[name]
		if !ok {
			return nil, &ProofError{
				Kind:    ErrBadArgsMissingScalarArg,
				Context: fmt.Sprintf("missing scalar %q", name),
			}
		}
		result[i] = sc
	}
	return result, nil
}

// sortPoints arranges the point arguments in the order defined by the
// statement's point_vec, with the basepoint at index 0.
func (s *Statement) sortPoints(args *PointArgs) ([]*ristretto255.Element, error) {
	// point_vec includes "G" at index 0, args should not include "G"
	if len(args.values) != len(s.pointVec)-1 {
		return nil, &ProofError{
			Kind:    ErrBadArgsWrongNumberOfPointArgs,
			Context: fmt.Sprintf("expected %d points (excluding G), got %d", len(s.pointVec)-1, len(args.values)),
		}
	}
	result := make([]*ristretto255.Element, len(s.pointVec))
	result[0] = ristretto255.NewGeneratorElement()
	for i := 1; i < len(s.pointVec); i++ {
		name := s.pointVec[i]
		pt, ok := args.values[name]
		if !ok {
			return nil, &ProofError{
				Kind:    ErrBadArgsMissingPointArg,
				Context: fmt.Sprintf("missing point %q", name),
			}
		}
		result[i] = pt
	}
	return result, nil
}

// homomorphismWithSubtraction applies the group homomorphism from G1 -> G2.
// If challenge is non-nil, it also subtracts challenge*LHS for efficient
// recovery of the Schnorr commitment during verification.
func (s *Statement) homomorphismWithSubtraction(
	g1 []*ristretto255.Scalar,
	allPoints []*ristretto255.Element,
	challenge *ristretto255.Scalar,
) []*ristretto255.Element {
	result := make([]*ristretto255.Element, len(s.equations))
	for i, eq := range s.equations {
		// Collect scalars and points for multiscalar multiplication
		scalars := make([]*ristretto255.Scalar, 0, len(eq.rhs)+1)
		points := make([]*ristretto255.Element, 0, len(eq.rhs)+1)

		for _, t := range eq.rhs {
			scalars = append(scalars, g1[t.scalar])
			points = append(points, allPoints[t.point])
		}

		if challenge != nil {
			negH := new(ristretto255.Scalar).Negate(challenge)
			scalars = append(scalars, negH)
			points = append(points, allPoints[eq.lhs])
		}

		result[i] = new(ristretto255.Element).MultiScalarMult(scalars, points)
	}
	return result
}

// Prove creates a Schnorr-style zero-knowledge proof for the given statement.
//
// The proof process:
//  1. SHO absorbs label "POKSHO_Ristretto_SHOHMACSHA256"
//  2. SHO absorbs statement description D and point arguments A, then ratchets
//  3. A cloned SHO absorbs randomness Z and witness scalars a, then ratchets
//  4. The clone absorbs message M, then ratchets and squeezes nonce scalars
//  5. Nonce scalars are applied through the homomorphism to create commitments R
//  6. The original SHO absorbs R and message M, then squeezes the challenge
//  7. Responses are computed as nonce + challenge * witness
//  8. The proof is self-verified before being returned
func (s *Statement) Prove(
	scalarArgs *ScalarArgs,
	pointArgs *PointArgs,
	message []byte,
	randomness []byte,
) ([]byte, error) {
	if len(randomness) != 32 {
		return nil, &ProofError{Kind: ErrBadArgs, Context: "randomness must be 32 bytes"}
	}

	g1, err := s.sortScalars(scalarArgs)
	if err != nil {
		return nil, err
	}
	allPoints, err := s.sortPoints(pointArgs)
	if err != nil {
		return nil, err
	}

	// Absorb label L, statement description D, and point values A
	sho := NewShoHmacSha256("POKSHO_Ristretto_SHOHMACSHA256")
	sho.Absorb(s.toBytes()) // D
	for _, pt := range allPoints {
		sho.Absorb(pt.Bytes()) // A
	}
	sho.Ratchet()

	// Synthetic nonce: hash randomness + witness + message
	sho2 := sho.Clone()
	sho2.Absorb(randomness) // Z
	for _, sc := range g1 {
		sho2.Absorb(sc.Bytes()) // a
	}
	sho2.Ratchet()
	sho2.AbsorbAndRatchet(message) // M
	blindingBytes := sho2.SqueezeAndRatchet(len(g1) * 64)

	// Derive nonce scalars from blinding bytes (64 bytes per scalar, reduced mod order)
	nonce := make([]*ristretto255.Scalar, len(g1))
	for i := range nonce {
		var wide [64]byte
		copy(wide[:], blindingBytes[i*64:(i+1)*64])
		sc := ristretto255.NewScalar()
		if _, err := sc.SetUniformBytes(wide[:]); err != nil {
			return nil, &ProofError{Kind: ErrBadArgs, Context: fmt.Sprintf("failed to create nonce scalar %d", i)}
		}
		nonce[i] = sc
	}

	// Commitment: R = F(nonce)
	commitment := s.homomorphismWithSubtraction(nonce, allPoints, nil)

	// Challenge from commitment and message
	for _, pt := range commitment {
		sho.Absorb(pt.Bytes()) // R
	}
	sho.AbsorbAndRatchet(message) // M
	challengeBytes := sho.SqueezeAndRatchet(64)
	var challengeWide [64]byte
	copy(challengeWide[:], challengeBytes)
	challenge := ristretto255.NewScalar()
	if _, err := challenge.SetUniformBytes(challengeWide[:]); err != nil {
		return nil, &ProofError{Kind: ErrBadArgs, Context: "failed to create challenge scalar"}
	}

	// Response: response_i = nonce_i + g1_i * challenge
	response := make([]*ristretto255.Scalar, len(g1))
	for i := range response {
		g1c := new(ristretto255.Scalar).Multiply(g1[i], challenge)
		response[i] = new(ristretto255.Scalar).Add(nonce[i], g1c)
	}

	// Encode proof: challenge || response_0 || response_1 || ...
	proofBytes := make([]byte, 0, 32*(1+len(response)))
	proofBytes = append(proofBytes, challenge.Bytes()...)
	for _, r := range response {
		proofBytes = append(proofBytes, r.Bytes()...)
	}

	// Self-verify before returning
	if err := s.VerifyProof(proofBytes, pointArgs, message); err != nil {
		return nil, &ProofError{
			Kind:    ErrProofCreationVerificationFailure,
			Context: "proof self-verification failed after creation",
		}
	}

	return proofBytes, nil
}

// VerifyProof verifies a zero-knowledge proof against the statement.
//
// The verification process:
//  1. Parse proof into challenge and response scalars
//  2. Reconstruct the SHO transcript with label, statement, and points
//  3. Reconstruct commitments: R = F(response) - challenge * A
//  4. Recompute the challenge from the reconstructed commitments and message
//  5. Check that the recomputed challenge equals the proof's challenge
func (s *Statement) VerifyProof(
	proofBytes []byte,
	pointArgs *PointArgs,
	message []byte,
) error {
	// Parse proof
	if len(proofBytes) < 64 || len(proofBytes)%32 != 0 {
		return &ProofError{Kind: ErrVerificationFailure, Context: "invalid proof length"}
	}
	numResponseScalars := (len(proofBytes) / 32) - 1
	if numResponseScalars > 256 {
		return &ProofError{Kind: ErrVerificationFailure, Context: "too many response scalars"}
	}
	if numResponseScalars != len(s.scalarVec) {
		return &ProofError{Kind: ErrVerificationFailure, Context: "wrong number of response scalars"}
	}

	challenge := ristretto255.NewScalar()
	if _, err := challenge.SetCanonicalBytes(proofBytes[:32]); err != nil {
		return &ProofError{Kind: ErrVerificationFailure, Context: "invalid challenge scalar"}
	}

	response := make([]*ristretto255.Scalar, numResponseScalars)
	for i := range response {
		sc := ristretto255.NewScalar()
		offset := 32 * (1 + i)
		if _, err := sc.SetCanonicalBytes(proofBytes[offset : offset+32]); err != nil {
			return &ProofError{Kind: ErrVerificationFailure, Context: fmt.Sprintf("invalid response scalar %d", i)}
		}
		response[i] = sc
	}

	allPoints, err := s.sortPoints(pointArgs)
	if err != nil {
		return err
	}

	// Reconstruct SHO transcript
	sho := NewShoHmacSha256("POKSHO_Ristretto_SHOHMACSHA256")
	sho.Absorb(s.toBytes()) // D
	for _, pt := range allPoints {
		sho.Absorb(pt.Bytes()) // A
	}
	sho.Ratchet()

	// Reconstruct commitment: R = F(response) - challenge * A
	commitment := s.homomorphismWithSubtraction(response, allPoints, challenge)

	// Recompute challenge
	for _, pt := range commitment {
		sho.Absorb(pt.Bytes()) // R
	}
	sho.AbsorbAndRatchet(message) // M
	recomputedBytes := sho.SqueezeAndRatchet(64)
	var recomputedWide [64]byte
	copy(recomputedWide[:], recomputedBytes)
	recomputed := ristretto255.NewScalar()
	if _, err := recomputed.SetUniformBytes(recomputedWide[:]); err != nil {
		return &ProofError{Kind: ErrVerificationFailure, Context: "failed to create recomputed challenge"}
	}

	// Constant-time comparison
	if subtle.ConstantTimeCompare(challenge.Bytes(), recomputed.Bytes()) != 1 {
		return &ProofError{Kind: ErrVerificationFailure}
	}

	return nil
}

// ScalarArgs holds named scalar arguments for proof generation/verification.
type ScalarArgs struct {
	values map[string]*ristretto255.Scalar
}

// NewScalarArgs creates a new empty ScalarArgs.
func NewScalarArgs() *ScalarArgs {
	return &ScalarArgs{values: make(map[string]*ristretto255.Scalar)}
}

// Add adds a named scalar argument.
func (sa *ScalarArgs) Add(name string, val *ristretto255.Scalar) {
	sa.values[name] = val
}

// PointArgs holds named point arguments for proof generation/verification.
type PointArgs struct {
	values map[string]*ristretto255.Element
}

// NewPointArgs creates a new empty PointArgs.
func NewPointArgs() *PointArgs {
	return &PointArgs{values: make(map[string]*ristretto255.Element)}
}

// Add adds a named point argument.
func (pa *PointArgs) Add(name string, val *ristretto255.Element) {
	pa.values[name] = val
}
