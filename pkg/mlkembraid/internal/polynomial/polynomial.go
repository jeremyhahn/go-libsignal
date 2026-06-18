// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package polynomial implements Lagrange interpolation over GF(2^16) for
// Reed-Solomon-like chunk redundancy in the Signal SPQR (Sparse Post-Quantum
// Ratchet) protocol. It is a direct port of the Rust sparsepostquantumratchet
// crate at commit f2589fef, providing byte-level parity with the reference.
//
// This package is an internal implementation detail of pkg/mlkembraid and must
// not be imported outside that module.
package polynomial

import (
	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/gf"
)

// Protocol constants — must match the Rust reference exactly.
const (
	// NumPolys is the number of parallel polynomial channels per 32-byte chunk.
	// Equals ChunkSize / 2 because each GF(2^16) element occupies 2 bytes.
	NumPolys = 16

	// ChunkSize is the fixed data payload size in bytes for each chunk.
	ChunkSize = 32

	// MaxStoredPolynomialDegreeV1 is the highest polynomial degree stored in
	// Protocol V1. Used for capacity bounds.
	MaxStoredPolynomialDegreeV1 = 35

	// MaxIntermediatePolynomialDegreeV1 is the highest degree constructed
	// during intermediate Lagrange calculations in Protocol V1.
	MaxIntermediatePolynomialDegreeV1 = 36
)

// Errors are defined as concrete types to satisfy the project convention of
// typed errors with no use of fmt.Errorf in the API surface.

// ErrMessageLengthEven is returned when the message length is not divisible
// by 2 (required because each GF(2^16) element is 2 bytes).
type ErrMessageLengthEven struct{}

// Error implements the error interface.
func (ErrMessageLengthEven) Error() string {
	return "polynomial: message length must be divisible by 2"
}

// ErrMessageLengthTooLong is returned when the message length exceeds the
// maximum encodable size for Protocol V1.
type ErrMessageLengthTooLong struct{}

// Error implements the error interface.
func (ErrMessageLengthTooLong) Error() string {
	return "polynomial: message length is too long"
}

// ErrSerializationInvalid is returned when deserializing malformed data.
type ErrSerializationInvalid struct{}

// Error implements the error interface.
func (ErrSerializationInvalid) Error() string {
	return "polynomial: serialization invalid"
}

// Chunk is the unit of data produced by PolyEncoder and consumed by
// PolyDecoder. It matches Rust's encoding::Chunk { index: u16, data: [u8; 32] }.
type Chunk struct {
	// Index is the sequential chunk number (u16).
	Index uint16
	// Data is the fixed 32-byte payload.
	Data [ChunkSize]byte
}

// pt is an internal Cartesian point (x, y) in GF(2^16) space.
// Ordering and equality are defined only by the x coordinate, matching
// Rust's Pt implementation (which uses x.value for Ord/PartialEq).
type pt struct {
	x gf.GF16
	y gf.GF16
}

// Poly is a polynomial with coefficients in GF(2^16), stored in
// little-endian order (coefficients[0] is the constant term).
// It mirrors Rust's Poly struct (polynomial.rs).
type Poly struct {
	// Coefficients holds the polynomial coefficients in little-endian order.
	// len(Coefficients) <= MaxIntermediatePolynomialDegreeV1 + 1 in Protocol V1.
	Coefficients []gf.GF16
}

// polyZero returns a zero polynomial pre-allocated to the given capacity.
// Mirrors Rust's Poly::zero(capacity).
func polyZero(capacity int) Poly {
	return Poly{Coefficients: make([]gf.GF16, 0, capacity)}
}

// lagrangeInterpolate returns the unique polynomial passing through all pts,
// given that each pt has a distinct x value.
// This is O(N^2) time and O(N) space. Mirrors Rust's Poly::lagrange_interpolate.
func lagrangeInterpolate(pts []pt) Poly {
	out := polyZero(len(pts))
	if len(pts) == 0 {
		return out
	}

	template := lagrangeInterpolatePrepare(pts)
	working := clonePoly(template)

	// Unroll the first iteration to skip unnecessary work.
	lagrangeInterpolateComplete(&working, pts, 0)
	// working is x * <the polynomial we need>; skip coefficients[0] (divide by x).
	out.Coefficients = append(out.Coefficients, working.Coefficients[1:]...)

	for i := 1; i < len(pts); i++ {
		copy(working.Coefficients, template.Coefficients)
		lagrangeInterpolateComplete(&working, pts, i)
		// Add working[j+1] to out[j] to skip working[0] (effectively divide by x).
		for j := range out.Coefficients {
			out.Coefficients[j].AddAssign(working.Coefficients[j+1])
		}
	}
	return out
}

// lagrangeInterpolatePrepare computes PRODUCT(x - pts[i].x) as part of
// Lagrange interpolation. Mirrors Rust's Poly::lagrange_interpolate_prepare.
func lagrangeInterpolatePrepare(pts []pt) Poly {
	p := polyZero(len(pts) + 1)
	p.Coefficients = p.Coefficients[:len(pts)+1] // resize to len+1
	offset := len(pts)
	p.Coefficients[offset] = gf.One

	for i := 0; i < offset; i++ {
		multXdiffAssignTrailing(&p, offset-i, pts[i].x)
	}
	return p
}

// multXdiffAssignTrailing computes self[start..] *= (x - difference).
// Interprets the trailing coefficients as a sub-polynomial and multiplies it
// by (x - difference), with carry into self[start-1].
// Mirrors Rust's Poly::mult_xdiff_assign_trailing.
func multXdiffAssignTrailing(p *Poly, start int, difference gf.GF16) {
	l := len(p.Coefficients)
	for i := start; i < l; i++ {
		delta := p.Coefficients[i].Mul(difference)
		p.Coefficients[i-1].SubAssign(delta)
	}
}

// lagrangeInterpolateComplete modifies working in place so that it represents
// the Lagrange basis polynomial for pts[i], scaled by x.
// After this call, working[0] should be zero (clean division).
// Mirrors Rust's Poly::lagrange_interpolate_complete.
func lagrangeInterpolateComplete(working *Poly, pts []pt, i int) {
	pi := pts[i]

	// Compute the scaling factor: pi.y / PRODUCT(pi.x - pj.x) for j != i.
	denominator := gf.One
	for _, pj := range pts {
		if pi.x.Value == pj.x.Value {
			continue
		}
		denominator.MulAssign(pi.x.Sub(pj.x))
	}
	scale, _ := pi.y.Div(denominator) // denominator is non-zero because x values are distinct

	// Long-divide by (x - pi.x) while scaling, starting from the high end.
	// The coefficients are in little-endian order, so we start from the end.
	for j := 1; j < len(working.Coefficients); j++ {
		idx := len(working.Coefficients) - j
		negativeDelta := working.Coefficients[idx].Mul(pi.x)
		working.Coefficients[idx].MulAssign(scale)
		working.Coefficients[idx-1].AddAssign(negativeDelta)
	}
}

// lagrangeInterpolatePt returns the Lagrange basis polynomial for pts[i]:
// it evaluates to pts[i].y at pts[i].x and to 0 at all other pts[j].x.
// This is the fallback used when no precomputed table is available.
// Mirrors Rust's Poly::lagrange_interpolate_pt.
func lagrangeInterpolatePt(pts []pt, i int) Poly {
	result := lagrangeInterpolatePrepare(pts)
	lagrangeInterpolateComplete(&result, pts, i)
	// Remove the first coefficient (the x factor introduced by the prepare step).
	result.Coefficients = result.Coefficients[1:]
	return result
}

// addAssign adds other to p element-wise in GF(2^16), extending p as needed.
// Mirrors Rust's Poly::add_assign.
func addAssign(p *Poly, other *Poly) {
	for i, v := range other.Coefficients {
		if i < len(p.Coefficients) {
			p.Coefficients[i].AddAssign(v)
		} else {
			p.Coefficients = append(p.Coefficients, v)
		}
	}
}

// multAssign multiplies all coefficients of p by m in GF(2^16).
// Mirrors Rust's Poly::mult_assign.
func multAssign(p *Poly, m gf.GF16) {
	gf.ParallelMult(m, p.Coefficients)
}

// ComputeAt evaluates p at the point x using Horner-like expansion via powers of x.
// Mirrors Rust's Poly::compute_at.
func (p *Poly) ComputeAt(x gf.GF16) gf.GF16 {
	n := len(p.Coefficients)
	if n == 0 {
		return gf.Zero
	}

	// Build x^0, x^1, x^2, ... x^(n-1) using the same squaring trick as Rust.
	xs := make([]gf.GF16, n)
	xs[0] = gf.One
	if n > 1 {
		xs[1] = x
	}
	for i := 2; i < n; i++ {
		a := xs[i/2]
		b := xs[i/2+(i%2)]
		xs[i] = a.Mul(b)
	}

	// Dot product of coefficients and powers.
	var out gf.GF16
	for i, c := range p.Coefficients {
		out.AddAssign(c.Mul(xs[i]))
	}
	return out
}

// lagrangeSum computes SUM(pt.y * poly) over (pt, poly) pairs.
// Mirrors Rust's Poly::lagrange_sum.
func lagrangeSum(pts []pt, polys []Poly) Poly {
	out := polyZero(len(pts))
	for i, pp := range pts {
		p := clonePoly(polys[i])
		multAssign(&p, pp.y)
		addAssign(&out, &p)
	}
	return out
}

// fromCompletePoints constructs a polynomial passing through all pts, where
// pts[i].x == i for i in 0..len(pts) (a "complete" point set). It uses
// precomputed Lagrange basis polynomials from the init-time tables for the
// allowed sizes (0, 1, 3, 5, 30, 34, 36). Other sizes fall back to the
// generic lagrangeInterpolatePt path.
// Mirrors Rust's Poly::from_complete_points.
func fromCompletePoints(pts []pt) (Poly, error) {
	for i, p := range pts {
		if p.x.Value != uint16(i) {
			return Poly{}, ErrSerializationInvalid{}
		}
	}

	var polys []Poly
	switch len(pts) {
	case 0:
		return polyZero(0), nil
	case 1:
		p := completePointsPolys1
		polys = p[:]
	case 3:
		p := completePointsPolys3
		polys = p[:]
	case 5:
		p := completePointsPolys5
		polys = p[:]
	case 30:
		p := completePointsPolys30
		polys = p[:]
	case 34:
		p := completePointsPolys34
		polys = p[:]
	case 36:
		p := completePointsPolys36
		polys = p[:]
	default:
		// Fallback path: compute basis polynomials on-the-fly.
		// Build pts with all y=1 to get the basis shape.
		ones := make([]pt, len(pts))
		for i, p := range pts {
			ones[i] = pt{x: p.x, y: gf.One}
		}
		polys = make([]Poly, len(pts))
		for i := range pts {
			polys[i] = lagrangeInterpolatePt(ones, i)
		}
	}

	return lagrangeSum(pts, polys), nil
}

// Serialize returns the byte encoding of p as a concatenation of each
// coefficient serialized as a big-endian uint16. This is byte-for-byte
// compatible with Rust's Poly::serialize (polynomial.rs:326).
func (p *Poly) Serialize() []byte {
	out := make([]byte, 0, len(p.Coefficients)*2)
	for _, c := range p.Coefficients {
		b := c.ToBytes()
		out = append(out, b[0], b[1])
	}
	return out
}

// DeserializePoly decodes a polynomial from its byte encoding produced by
// Serialize. The length of b must be a positive multiple of 2.
// Mirrors Rust's Poly::deserialize.
func DeserializePoly(b []byte) (Poly, error) {
	if len(b) == 0 || len(b)%2 != 0 {
		return Poly{}, ErrSerializationInvalid{}
	}
	coeffs := make([]gf.GF16, len(b)/2)
	for i := range coeffs {
		coeffs[i] = gf.FromBytes([2]byte{b[2*i], b[2*i+1]})
	}
	return Poly{Coefficients: coeffs}, nil
}

// clonePoly returns a deep copy of p.
func clonePoly(p Poly) Poly {
	c := make([]gf.GF16, len(p.Coefficients), cap(p.Coefficients))
	copy(c, p.Coefficients)
	return Poly{Coefficients: c}
}

// Point holds the y-values of a single polynomial channel during the
// accumulation phase before interpolation. Each element is a GF(2^16) point.
// Mirrors Rust's Point { value: Vec<GF16> }.
type Point struct {
	// Value holds the y-values at x=0, x=1, ... for one polynomial channel.
	Value []gf.GF16
}

// EncoderStateKind distinguishes the two internal states of PolyEncoder.
type EncoderStateKind int

const (
	// EncoderStatePoints means the encoder is still accumulating raw points.
	EncoderStatePoints EncoderStateKind = iota
	// EncoderStatePolys means the encoder has interpolated polynomials.
	EncoderStatePolys
)

// PolyEncoder encodes a message into an infinite stream of 32-byte chunks
// using Lagrange interpolation over GF(2^16). The first N chunks reproduce
// the original data; subsequent chunks are interpolated redundancy.
//
// PolyEncoder mirrors Rust's PolyEncoder { idx: u32, s: EncoderState }.
type PolyEncoder struct {
	idx    uint32
	points [NumPolys]Point
	polys  [NumPolys]Poly
	state  EncoderStateKind
}

// NewPolyEncoder creates a PolyEncoder for the given message.
// The message length must be a non-zero even number not exceeding
// (1<<16)*NumPolys bytes.
// Mirrors Rust's Encoder::encode_bytes.
func NewPolyEncoder(msg []byte) (*PolyEncoder, error) {
	if len(msg)%2 != 0 {
		return nil, ErrMessageLengthEven{}
	}
	if len(msg) > (1<<16)*NumPolys {
		return nil, ErrMessageLengthTooLong{}
	}

	e := &PolyEncoder{
		idx:   0,
		state: EncoderStatePoints,
	}
	// Pre-allocate each point channel.
	for i := range e.points {
		e.points[i] = Point{Value: make([]gf.GF16, 0, len(msg)/2)}
	}

	// Distribute 2-byte chunks from msg into the 16 poly channels.
	// Chunk i goes to poly channel i%16 at poly_idx i/16.
	// Mirrors Rust's encode_bytes_base loop.
	for i, c := range byteChunks2(msg) {
		polyIdx := i % NumPolys
		e.points[polyIdx].Value = append(e.points[polyIdx].Value,
			gf.GF16{Value: uint16(c[0])<<8 | uint16(c[1])})
	}
	return e, nil
}

// byteChunks2 returns successive 2-byte slices from b.
// len(b) must be even (callers guarantee this).
func byteChunks2(b []byte) [][2]byte {
	out := make([][2]byte, len(b)/2)
	for i := range out {
		out[i] = [2]byte{b[2*i], b[2*i+1]}
	}
	return out
}

// pointAt returns the y-value of the poly-th polynomial channel at poly_idx.
// If poly_idx is beyond the stored points, it triggers a transition from
// Points state to Polys state and then evaluates the interpolated polynomial.
// Mirrors Rust's PolyEncoder::point_at.
func (e *PolyEncoder) pointAt(poly, polyIdx int) gf.GF16 {
	if e.state == EncoderStatePoints {
		if polyIdx < len(e.points[poly].Value) {
			return e.points[poly].Value[polyIdx]
		}
		// Transition: interpolate polynomials from the accumulated points.
		for i := 0; i < NumPolys; i++ {
			ptVec := make([]pt, len(e.points[i].Value))
			for x, y := range e.points[i].Value {
				ptVec[x] = pt{x: gf.GF16{Value: uint16(x)}, y: y}
			}
			result, _ := fromCompletePoints(ptVec)
			e.polys[i] = result
		}
		e.state = EncoderStatePolys
	}
	return e.polys[poly].ComputeAt(gf.GF16{Value: uint16(polyIdx)})
}

// ChunkAt returns the chunk at the given index.
// Mirrors Rust's PolyEncoder::chunk_at.
func (e *PolyEncoder) ChunkAt(idx uint16) Chunk {
	var data [ChunkSize]byte
	for i := 0; i < NumPolys; i++ {
		totalIdx := int(idx)*NumPolys + i
		poly := totalIdx % NumPolys
		polyIdx := totalIdx / NumPolys
		p := e.pointAt(poly, polyIdx).Value
		data[i*2] = byte(p >> 8)
		data[i*2+1] = byte(p)
	}
	return Chunk{Index: idx, Data: data}
}

// NextChunk returns the next chunk in sequence and advances the internal
// counter. Mirrors Rust's Encoder::next_chunk.
func (e *PolyEncoder) NextChunk() Chunk {
	out := e.ChunkAt(uint16(e.idx))
	e.idx++
	return out
}

// Idx returns the current chunk index counter.
func (e *PolyEncoder) Idx() uint32 {
	return e.idx
}

// StateKind returns whether the encoder is in Points or Polys state.
func (e *PolyEncoder) StateKind() EncoderStateKind {
	return e.state
}

// Points returns the raw point arrays (valid only in EncoderStatePoints).
func (e *PolyEncoder) Points() *[NumPolys]Point {
	return &e.points
}

// Polys returns the interpolated polynomial arrays (valid only in EncoderStatePolys).
func (e *PolyEncoder) Polys() *[NumPolys]Poly {
	return &e.polys
}

// PolyDecoder collects chunks and reconstructs the original message once
// enough points have been gathered per polynomial channel.
//
// PolyDecoder mirrors Rust's PolyDecoder { pts_needed, pts: [SortedSet<Pt>; 16], is_complete }.
type PolyDecoder struct {
	// PtsNeeded is the total number of GF(2^16) elements in the message
	// (= len_bytes / 2). Exported for proto marshaling.
	PtsNeeded int

	// pts holds the received (x, y) points for each of the 16 polynomial
	// channels, sorted and deduplicated by x-value.
	pts [NumPolys]sortedPtSet

	// IsComplete is set to true after the message has been successfully decoded
	// once, preventing decoded_message from returning a second time.
	IsComplete bool
}

// sortedPtSet is a sorted, x-deduplicated set of pt values.
// It mirrors Rust's SortedSet<Pt> (ordered and equality-checked by x).
type sortedPtSet struct {
	pts []pt
}

// push inserts p into the set in sorted order by x. If a point with the same
// x already exists, the new point is discarded (Rust's SortedSet behavior).
func (s *sortedPtSet) push(p pt) {
	idx := s.search(p.x.Value)
	if idx < len(s.pts) && s.pts[idx].x.Value == p.x.Value {
		return // duplicate x: discard
	}
	// Insert at idx to maintain sorted order.
	s.pts = append(s.pts, pt{})
	copy(s.pts[idx+1:], s.pts[idx:])
	s.pts[idx] = p
}

// search returns the first index where pts[i].x.Value >= xVal (binary search).
func (s *sortedPtSet) search(xVal uint16) int {
	lo, hi := 0, len(s.pts)
	for lo < hi {
		mid := (lo + hi) / 2
		if s.pts[mid].x.Value < xVal {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// find returns (index, true) if a point with x.Value == xVal exists.
func (s *sortedPtSet) find(xVal uint16) (int, bool) {
	idx := s.search(xVal)
	if idx < len(s.pts) && s.pts[idx].x.Value == xVal {
		return idx, true
	}
	return 0, false
}

// len returns the number of points in the set.
func (s *sortedPtSet) len() int {
	return len(s.pts)
}

// NewPolyDecoder creates a PolyDecoder that expects a message of lenBytes bytes.
// lenBytes must be a positive even number.
// Mirrors Rust's Decoder::new.
func NewPolyDecoder(lenBytes int) (*PolyDecoder, error) {
	if lenBytes%2 != 0 {
		return nil, ErrMessageLengthEven{}
	}
	return &PolyDecoder{
		PtsNeeded: lenBytes / 2,
	}, nil
}

// necessaryPoints returns the number of points required for polynomial channel
// poly to fully determine the message. Mirrors Rust's necessary_points.
func (d *PolyDecoder) necessaryPoints(poly int) int {
	pointsPerPoly := d.PtsNeeded / NumPolys
	pointsRemaining := d.PtsNeeded % NumPolys
	if poly < pointsRemaining {
		return pointsPerPoly + 1
	}
	return pointsPerPoly
}

// AddChunk incorporates the data from c into the decoder.
// Points are only accepted if they are needed (either within the polynomial
// degree range or when we haven't reached the necessary count yet).
// Mirrors Rust's Decoder::add_chunk.
func (d *PolyDecoder) AddChunk(c Chunk) {
	for i := 0; i < NumPolys; i++ {
		totalIdx := int(c.Index)*NumPolys + i
		poly := totalIdx % NumPolys
		polyIdx := totalIdx / NumPolys
		x := gf.GF16{Value: uint16(polyIdx)}
		y1 := uint16(c.Data[i*2])
		y2 := uint16(c.Data[i*2+1])
		y := gf.GF16{Value: y1<<8 | y2}
		necessary := d.necessaryPoints(i)
		// Accept the point if its x-index is within the necessary range,
		// or if we haven't collected enough points yet.
		if polyIdx < necessary || d.pts[poly].len() < necessary {
			d.pts[poly].push(pt{x: x, y: y})
		}
	}
}

// DecodedMessage attempts to reconstruct and return the original message.
// Returns (msg, true) when sufficient points have been collected, or
// (nil, false) otherwise. Once the decoder returns a message, subsequent
// calls always return (nil, false) (is_complete semantics from Rust).
// Mirrors Rust's Decoder::decoded_message.
func (d *PolyDecoder) DecodedMessage() ([]byte, bool) {
	if d.IsComplete {
		return nil, false
	}

	// Check that each channel has enough points; collect slices for interpolation.
	pointsVecs := make([][]pt, 0, NumPolys)
	for i := 0; i < NumPolys; i++ {
		needed := d.necessaryPoints(i)
		if d.pts[i].len() < needed {
			return nil, false
		}
		pointsVecs = append(pointsVecs, d.pts[i].pts[:needed])
	}

	// Lazily interpolate polynomials only when a direct lookup fails.
	var interpPolys [NumPolys]*Poly

	out := make([]byte, 0, d.PtsNeeded*2)
	for i := 0; i < d.PtsNeeded; i++ {
		poly := i % NumPolys
		polyIdx := i / NumPolys
		searchX := uint16(polyIdx)

		var y gf.GF16
		if idx, found := d.pts[poly].find(searchX); found {
			y = d.pts[poly].pts[idx].y
		} else {
			// Need interpolation.
			if interpPolys[poly] == nil {
				p := lagrangeInterpolate(pointsVecs[poly])
				interpPolys[poly] = &p
			}
			y = interpPolys[poly].ComputeAt(gf.GF16{Value: searchX})
		}
		out = append(out, byte(y.Value>>8), byte(y.Value))
	}
	return out, true
}

// PtsLen returns the number of points received per channel (for debugging / proto).
func (d *PolyDecoder) PtsLen(poly int) int {
	return d.pts[poly].len()
}

// PtsForChannel returns the raw point slice for the given polynomial channel.
// Used by proto marshaling (Phase D). The returned slice must not be modified.
func (d *PolyDecoder) PtsForChannel(poly int) []pt {
	return d.pts[poly].pts
}

// SetPtsForChannel sets the points for the given channel. Used during
// deserialization from protobuf (Phase D).
func (d *PolyDecoder) SetPtsForChannel(poly int, points []pt) {
	d.pts[poly].pts = points
}

// Pt is the exported alias for the internal pt type, needed by the proto
// marshaling layer in Phase D. It mirrors Rust's Pt { x, y }.
type Pt = pt

// MakePt creates a Pt from explicit x and y values. Used by the proto codec
// (Phase D) to reconstruct decoder point sets from serialized protobuf data.
func MakePt(xVal, yVal uint16) Pt {
	return pt{
		x: gf.GF16{Value: xVal},
		y: gf.GF16{Value: yVal},
	}
}

// X returns the x coordinate value of the point as a uint16.
func (p Pt) X() uint16 {
	return p.x.Value
}

// Y returns the y coordinate value of the point as a uint16.
func (p Pt) Y() uint16 {
	return p.y.Value
}

// SerializePt serializes the point as [x_hi, x_lo, y_hi, y_lo] (4 bytes BE).
// Matches Rust's Pt::serialize().
func SerializePt(p Pt) [4]byte {
	return [4]byte{
		byte(p.x.Value >> 8), byte(p.x.Value),
		byte(p.y.Value >> 8), byte(p.y.Value),
	}
}

// NewPolyEncoderFromPolys creates a PolyEncoder in Polys state with the given
// interpolated polynomials and chunk index counter. Used by the proto codec
// (Phase D) to reconstruct an encoder that has already transitioned past the
// first-pass boundary.
func NewPolyEncoderFromPolys(polys []Poly, idx uint32) (*PolyEncoder, error) {
	if len(polys) != NumPolys {
		return nil, ErrSerializationInvalid{}
	}
	e := &PolyEncoder{
		idx:   idx,
		state: EncoderStatePolys,
	}
	copy(e.polys[:], polys)
	return e, nil
}
