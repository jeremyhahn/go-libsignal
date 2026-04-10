package zkcredential

import (
	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
)

// ShoExt wraps a poksho.SHO and provides convenience methods for generating
// ristretto255 group elements (points and scalars) from the SHO state.
//
// This mirrors the Rust ShoExt trait which extends ShoApi with get_point and
// get_scalar methods.
type ShoExt struct {
	*poksho.SHO
}

// NewShoExt wraps an existing SHO in a ShoExt.
func NewShoExt(sho *poksho.SHO) *ShoExt {
	return &ShoExt{SHO: sho}
}

// NewShoHmacSha256Ext creates a new HMAC-SHA-256 based ShoExt with the given label.
func NewShoHmacSha256Ext(label string) *ShoExt {
	return &ShoExt{SHO: poksho.NewShoHmacSha256(label)}
}

// NewShoSha256Ext creates a new SHA-256 based ShoExt with the given label.
func NewShoSha256Ext(label string) *ShoExt {
	return &ShoExt{SHO: poksho.NewShoSha256(label)}
}

// SqueezeAndRatchet squeezes outputLen bytes from the SHO and ratchets
// the state atomically. This matches the Rust squeeze_and_ratchet method.
func (s *ShoExt) SqueezeAndRatchet(outputLen int) []byte {
	return s.SHO.SqueezeAndRatchet(outputLen)
}

// AbsorbAndRatchet absorbs data into the SHO state and then ratchets.
// This matches the Rust absorb_and_ratchet method.
func (s *ShoExt) AbsorbAndRatchet(data []byte) {
	s.SHO.AbsorbAndRatchet(data)
}

// GetPoint uses SqueezeAndRatchet to generate a pseudorandom ristretto255 point.
// Squeezes 64 bytes and maps them to a point via SetUniformBytes.
func (s *ShoExt) GetPoint() (*ristretto255.Element, error) {
	pointBytes := s.SqueezeAndRatchet(64)
	e := ristretto255.NewIdentityElement()
	_, err := e.SetUniformBytes(pointBytes)
	if err != nil {
		return nil, &ErrSHODerivePoint{Err: err}
	}
	return e, nil
}

// MustGetPoint is like GetPoint but panics on error.
// This is safe to use for deterministic derivations where the SHO state
// is known to produce valid output.
func (s *ShoExt) MustGetPoint() *ristretto255.Element {
	p, err := s.GetPoint()
	if err != nil {
		panic(err)
	}
	return p
}

// PointFromSingleElligator maps 32 bytes to a ristretto255 point using a single
// Elligator map. This matches Rust's RistrettoPoint::from_uniform_bytes_single_elligator.
//
// The implementation uses SetUniformBytes(data || zeros) which computes
// MAP(data) + MAP(zeros) = MAP(data) + identity = MAP(data), achieving
// a single Elligator map without requiring a dedicated library function.
func PointFromSingleElligator(input []byte) (*ristretto255.Element, error) {
	if len(input) != 32 {
		return nil, &ErrSingleElligatorInputSize{Got: len(input)}
	}
	var uniform [64]byte
	copy(uniform[:32], input)
	// Second 32 bytes remain zero: MAP(zeros) = identity element.
	e := ristretto255.NewIdentityElement()
	if _, err := e.SetUniformBytes(uniform[:]); err != nil {
		return nil, &ErrSingleElligatorMap{Err: err}
	}
	return e, nil
}

// GetPointSingleElligator uses SqueezeAndRatchet to generate a pseudorandom
// ristretto255 point using a single Elligator map. Squeezes 32 bytes and maps
// them to a point. This matches Rust's Sho::get_point_single_elligator.
func (s *ShoExt) GetPointSingleElligator() (*ristretto255.Element, error) {
	pointBytes := s.SqueezeAndRatchet(32)
	return PointFromSingleElligator(pointBytes)
}

// MustGetPointSingleElligator is like GetPointSingleElligator but panics on error.
func (s *ShoExt) MustGetPointSingleElligator() *ristretto255.Element {
	p, err := s.GetPointSingleElligator()
	if err != nil {
		panic(err)
	}
	return p
}

// GetScalar uses SqueezeAndRatchet to generate a pseudorandom ristretto255 scalar.
// Squeezes 64 bytes and reduces them modulo the group order via SetUniformBytes.
func (s *ShoExt) GetScalar() (*ristretto255.Scalar, error) {
	scalarBytes := s.SqueezeAndRatchet(64)
	sc := ristretto255.NewScalar()
	_, err := sc.SetUniformBytes(scalarBytes)
	if err != nil {
		return nil, &ErrSHODeriveScalar{Err: err}
	}
	return sc, nil
}

// MustGetScalar is like GetScalar but panics on error.
func (s *ShoExt) MustGetScalar() *ristretto255.Scalar {
	sc, err := s.GetScalar()
	if err != nil {
		panic(err)
	}
	return sc
}

// Clone returns a deep copy of this ShoExt.
func (s *ShoExt) Clone() *ShoExt {
	return &ShoExt{SHO: s.SHO.Clone()}
}
