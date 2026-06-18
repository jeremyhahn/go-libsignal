// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package gf

import (
	"math/rand/v2"
	"testing"
)

// TestFieldAxioms verifies that GF16 satisfies the field axioms over a large
// random sample. All axioms are required for a correct GF(2^16) implementation.
func TestFieldAxioms(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xdeadbeef, 0xcafebabe))
	const samples = 10_000

	randGF := func() GF16 {
		return New(uint16(rng.Uint32()))
	}

	t.Run("add_commutative", func(t *testing.T) {
		for range samples {
			a, b := randGF(), randGF()
			if a.Add(b) != b.Add(a) {
				t.Fatalf("add not commutative: a=%04x b=%04x", a.Value, b.Value)
			}
		}
	})

	t.Run("add_associative", func(t *testing.T) {
		for range samples {
			a, b, c := randGF(), randGF(), randGF()
			lhs := a.Add(b).Add(c)
			rhs := a.Add(b.Add(c))
			if lhs != rhs {
				t.Fatalf("add not associative: a=%04x b=%04x c=%04x", a.Value, b.Value, c.Value)
			}
		}
	})

	t.Run("add_zero_identity", func(t *testing.T) {
		for range samples {
			a := randGF()
			if a.Add(Zero) != a {
				t.Fatalf("zero not additive identity: a=%04x", a.Value)
			}
			if Zero.Add(a) != a {
				t.Fatalf("zero not additive identity (right): a=%04x", a.Value)
			}
		}
	})

	t.Run("add_self_is_zero", func(t *testing.T) {
		// In GF(2^n), a + a = 0 for all a.
		for range samples {
			a := randGF()
			if a.Add(a) != Zero {
				t.Fatalf("a + a != 0: a=%04x", a.Value)
			}
		}
	})

	t.Run("sub_equals_add", func(t *testing.T) {
		// In GF(2), subtraction == addition.
		for range samples {
			a, b := randGF(), randGF()
			if a.Sub(b) != a.Add(b) {
				t.Fatalf("sub != add: a=%04x b=%04x", a.Value, b.Value)
			}
		}
	})

	t.Run("mul_commutative", func(t *testing.T) {
		for range samples {
			a, b := randGF(), randGF()
			if a.Mul(b) != b.Mul(a) {
				t.Fatalf("mul not commutative: a=%04x b=%04x", a.Value, b.Value)
			}
		}
	})

	t.Run("mul_associative", func(t *testing.T) {
		for range samples {
			a, b, c := randGF(), randGF(), randGF()
			lhs := a.Mul(b).Mul(c)
			rhs := a.Mul(b.Mul(c))
			if lhs != rhs {
				t.Fatalf("mul not associative: a=%04x b=%04x c=%04x", a.Value, b.Value, c.Value)
			}
		}
	})

	t.Run("mul_one_identity", func(t *testing.T) {
		for range samples {
			a := randGF()
			if a.Mul(One) != a {
				t.Fatalf("one not multiplicative identity: a=%04x", a.Value)
			}
			if One.Mul(a) != a {
				t.Fatalf("one not multiplicative identity (right): a=%04x", a.Value)
			}
		}
	})

	t.Run("mul_zero_annihilates", func(t *testing.T) {
		for range samples {
			a := randGF()
			if a.Mul(Zero) != Zero {
				t.Fatalf("a * 0 != 0: a=%04x", a.Value)
			}
		}
	})

	t.Run("mul_distributes_over_add", func(t *testing.T) {
		for range samples {
			a, b, c := randGF(), randGF(), randGF()
			lhs := a.Mul(b.Add(c))
			rhs := a.Mul(b).Add(a.Mul(c))
			if lhs != rhs {
				t.Fatalf("distributive law failed: a=%04x b=%04x c=%04x", a.Value, b.Value, c.Value)
			}
		}
	})
}

// TestInverseLaw verifies that a * inv(a) == 1 for all non-zero a sampled.
func TestInverseLaw(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x12345678, 0xabcdef01))
	const samples = 10_000

	for range samples {
		v := uint16(rng.Uint32())
		if v == 0 {
			v = 1 // skip zero; tested separately
		}
		a := New(v)
		inv, err := a.Inv()
		if err != nil {
			t.Fatalf("Inv(%04x) unexpected error: %v", a.Value, err)
		}
		if got := a.Mul(inv); got != One {
			t.Fatalf("a * inv(a) != 1: a=%04x inv=%04x got=%04x", a.Value, inv.Value, got.Value)
		}
	}
}

// mulVec is a known-correct multiplication triple (a * b == product) derived
// from the Rust sparsepostquantumratchet reference implementation.
type mulVec struct{ a, b, product uint16 }

// TestKnownMulVectors validates multiplication against 25 reference triples
// generated from the Rust reference implementation using POLY = 0x1100b.
// These vectors serve as the byte-for-byte parity proof against the Rust side.
func TestKnownMulVectors(t *testing.T) {
	vectors := []mulVec{
		{0x0000, 0x0000, 0x0000},
		{0x0001, 0x0001, 0x0001},
		{0x0001, 0xffff, 0xffff},
		{0x0002, 0x0003, 0x0006},
		{0x0002, 0x0002, 0x0004},
		{0x000f, 0x000f, 0x0055},
		{0x00ff, 0x00ff, 0x5555},
		// 0x0100^2 = x^16 mod poly = x^12+x^3+x+1 = 0x100b
		{0x0100, 0x0100, 0x100b},
		{0xffff, 0xffff, 0x0733},
		{0x1234, 0x5678, 0x6324},
		{0xabcd, 0xef01, 0xc9ef},
		{0x8000, 0x8000, 0x8efa},
		{0x0010, 0x0010, 0x0100},
		{0x0003, 0x0007, 0x0009},
		{0x1000, 0x1000, 0x1bbb},
		{0xdead, 0xbeef, 0xa837},
		{0x7fff, 0x7fff, 0x89c9},
		{0x0080, 0x0080, 0x4000},
		{0x4000, 0x2000, 0xddd8},
		{0x5555, 0xaaaa, 0x5349},
		{0x1111, 0x1111, 0x0ab1},
		{0x1001, 0x1001, 0x1bba},
		{0x000b, 0x000b, 0x0045},
		{0x1100, 0x0011, 0x110b},
		{0x8001, 0x8001, 0x8efb},
	}

	for _, v := range vectors {
		a, b := New(v.a), New(v.b)
		got := a.Mul(b)
		if got.Value != v.product {
			t.Errorf("Mul(%04x, %04x): got %04x, want %04x", v.a, v.b, got.Value, v.product)
		}
	}
}

// TestKnownDivVectors validates division against 8 reference triples.
func TestKnownDivVectors(t *testing.T) {
	type divVec struct{ num, denom, quot uint16 }
	vectors := []divVec{
		{0x0001, 0x0001, 0x0001},
		{0x0002, 0x0002, 0x0001},
		{0xffff, 0xffff, 0x0001},
		{0x1234, 0x5678, 0x18f2},
		{0xabcd, 0xef01, 0xd9bd},
		{0x0006, 0x0002, 0x0003},
		{0x000a, 0x0005, 0x0002},
		{0xdead, 0xbeef, 0x3d1b},
	}

	for _, v := range vectors {
		a, b := New(v.num), New(v.denom)
		got, err := a.Div(b)
		if err != nil {
			t.Errorf("Div(%04x, %04x) unexpected error: %v", v.num, v.denom, err)
			continue
		}
		if got.Value != v.quot {
			t.Errorf("Div(%04x, %04x): got %04x, want %04x", v.num, v.denom, got.Value, v.quot)
		}
	}
}

// TestKnownInvVectors validates multiplicative inverse against 10 reference
// values generated from the Rust reference.
func TestKnownInvVectors(t *testing.T) {
	type invVec struct{ a, inv uint16 }
	vectors := []invVec{
		{0x0001, 0x0001},
		{0x0002, 0x8805},
		{0x0003, 0xf006},
		{0x000f, 0xc007},
		{0x00ff, 0x1ccc},
		{0xffff, 0x0894},
		{0x1234, 0x2ce9},
		{0x8000, 0x345d},
		{0xabcd, 0x0e12},
		{0x5555, 0x19bc},
	}

	for _, v := range vectors {
		a := New(v.a)
		got, err := a.Inv()
		if err != nil {
			t.Errorf("Inv(%04x) unexpected error: %v", v.a, err)
			continue
		}
		if got.Value != v.inv {
			t.Errorf("Inv(%04x): got %04x, want %04x", v.a, got.Value, v.inv)
		}
		// Also verify a * inv(a) == 1.
		if product := a.Mul(got); product != One {
			t.Errorf("Inv(%04x): a*inv(a) = %04x, want 0x0001", v.a, product.Value)
		}
	}
}

// TestInvZeroError verifies that computing the inverse of zero returns a typed
// ErrInvalidInverse and does not panic.
func TestInvZeroError(t *testing.T) {
	_, err := Zero.Inv()
	if err == nil {
		t.Fatal("Inv(0) should return error, got nil")
	}
	var typed ErrInvalidInverse
	if err != typed {
		t.Fatalf("Inv(0) returned wrong error type: %T %v", err, err)
	}
	if err.Error() != "gf: zero has no multiplicative inverse" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

// TestDivZeroError verifies that dividing by zero returns ErrInvalidInverse.
func TestDivZeroError(t *testing.T) {
	a := New(0x1234)
	_, err := a.Div(Zero)
	if err == nil {
		t.Fatal("Div(x, 0) should return error, got nil")
	}
	var typed ErrInvalidInverse
	if err != typed {
		t.Fatalf("Div(x, 0) returned wrong error type: %T %v", err, err)
	}
}

// TestDivAssign verifies DivAssign for both the success and zero-divisor paths.
func TestDivAssign(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// 0x0006 / 0x0002 == 0x0003 (from known div vectors)
		a := New(0x0006)
		err := a.DivAssign(New(0x0002))
		if err != nil {
			t.Fatalf("DivAssign unexpected error: %v", err)
		}
		if a.Value != 0x0003 {
			t.Fatalf("DivAssign(0x0006, 0x0002): got %04x, want 0x0003", a.Value)
		}
	})

	t.Run("zero_divisor", func(t *testing.T) {
		a := New(0x1234)
		err := a.DivAssign(Zero)
		if err == nil {
			t.Fatal("DivAssign(0) should return error, got nil")
		}
		var typed ErrInvalidInverse
		if err != typed {
			t.Fatalf("DivAssign(0) returned wrong error type: %T %v", err, err)
		}
		// a.Value should be unchanged on error.
		if a.Value != 0x1234 {
			t.Fatalf("DivAssign(0) mutated receiver on error: got %04x", a.Value)
		}
	})
}

// TestSerializationRoundTrip verifies that ToBytes followed by FromBytes is
// the identity for all sampled values.
func TestSerializationRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xfeedface, 0xc0ffee00))
	const samples = 10_000

	// Fixed boundary cases.
	for _, v := range []uint16{0x0000, 0x0001, 0x00ff, 0x0100, 0x7fff, 0x8000, 0xffff} {
		g := New(v)
		if got := FromBytes(g.ToBytes()); got != g {
			t.Errorf("round-trip(%04x): got %04x", v, got.Value)
		}
	}

	for range samples {
		v := uint16(rng.Uint32())
		g := New(v)
		if got := FromBytes(g.ToBytes()); got != g {
			t.Errorf("round-trip(%04x): got %04x", v, got.Value)
		}
	}
}

// TestSerializationBigEndian verifies that ToBytes encodes the value in
// big-endian byte order (high byte first), matching Rust's serialization.
func TestSerializationBigEndian(t *testing.T) {
	cases := []struct {
		v    uint16
		want [2]byte
	}{
		{0x0000, [2]byte{0x00, 0x00}},
		{0x0001, [2]byte{0x00, 0x01}},
		{0x0100, [2]byte{0x01, 0x00}},
		{0xffff, [2]byte{0xff, 0xff}},
		{0x1234, [2]byte{0x12, 0x34}},
		{0xabcd, [2]byte{0xab, 0xcd}},
	}
	for _, c := range cases {
		got := New(c.v).ToBytes()
		if got != c.want {
			t.Errorf("ToBytes(%04x): got %v, want %v", c.v, got, c.want)
		}
	}
}

// TestParallelMultCorrectness verifies that ParallelMult is equivalent to
// per-element Mul, for slices of various lengths (including odd and even).
func TestParallelMultCorrectness(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xbaadf00d, 0xdeadc0de))

	makeSlice := func(n int) []GF16 {
		s := make([]GF16, n)
		for i := range s {
			s[i] = New(uint16(rng.Uint32()))
		}
		return s
	}

	for _, n := range []int{0, 1, 2, 3, 7, 8, 100, 101} {
		m := New(uint16(rng.Uint32()))
		orig := makeSlice(n)

		// Expected: element-wise mul.
		want := make([]GF16, n)
		for i, x := range orig {
			want[i] = x.Mul(m)
		}

		// Actual: ParallelMult.
		got := make([]GF16, n)
		copy(got, orig)
		ParallelMult(m, got)

		for i := range got {
			if got[i] != want[i] {
				t.Errorf("ParallelMult(n=%d, i=%d): got %04x, want %04x", n, i, got[i].Value, want[i].Value)
			}
		}
	}
}

// TestParallelMultByZero verifies that multiplying by zero zeroes all elements.
func TestParallelMultByZero(t *testing.T) {
	coeffs := []GF16{New(0x1234), New(0x5678), New(0xabcd), New(0xffff), New(0x0001)}
	ParallelMult(Zero, coeffs)
	for i, c := range coeffs {
		if c != Zero {
			t.Errorf("ParallelMult(0, ...)[%d] = %04x, want 0", i, c.Value)
		}
	}
}

// TestParallelMultByOne verifies that multiplying by one is the identity.
func TestParallelMultByOne(t *testing.T) {
	original := []GF16{New(0x1234), New(0x5678), New(0xabcd), New(0xffff), New(0x0001)}
	coeffs := make([]GF16, len(original))
	copy(coeffs, original)
	ParallelMult(One, coeffs)
	for i, c := range coeffs {
		if c != original[i] {
			t.Errorf("ParallelMult(1, ...)[%d] = %04x, want %04x", i, c.Value, original[i].Value)
		}
	}
}

// TestAddSubAssign verifies the in-place Add/Sub assign methods.
func TestAddSubAssign(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x11223344, 0x55667788))
	const samples = 1_000

	for range samples {
		a := New(uint16(rng.Uint32()))
		b := New(uint16(rng.Uint32()))

		// AddAssign
		ac := a
		ac.AddAssign(b)
		if ac != a.Add(b) {
			t.Fatalf("AddAssign mismatch: a=%04x b=%04x", a.Value, b.Value)
		}

		// SubAssign
		as := a
		as.SubAssign(b)
		if as != a.Sub(b) {
			t.Fatalf("SubAssign mismatch: a=%04x b=%04x", a.Value, b.Value)
		}
	}
}

// TestMulAssign verifies the in-place MulAssign method.
func TestMulAssign(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xaabbccdd, 0xeeff0011))
	const samples = 1_000

	for range samples {
		a := New(uint16(rng.Uint32()))
		b := New(uint16(rng.Uint32()))
		want := a.Mul(b)
		a.MulAssign(b)
		if a != want {
			t.Fatalf("MulAssign mismatch: got %04x, want %04x", a.Value, want.Value)
		}
	}
}

// TestNewConstructor verifies that New sets the Value field correctly.
func TestNewConstructor(t *testing.T) {
	for _, v := range []uint16{0, 1, 0x7fff, 0x8000, 0xffff} {
		g := New(v)
		if g.Value != v {
			t.Errorf("New(%04x).Value = %04x", v, g.Value)
		}
	}
}

// TestConstants verifies the exported Zero and One constants.
func TestConstants(t *testing.T) {
	if Zero.Value != 0 {
		t.Errorf("Zero.Value = %04x, want 0x0000", Zero.Value)
	}
	if One.Value != 1 {
		t.Errorf("One.Value = %04x, want 0x0001", One.Value)
	}
	if Poly != 0x1100b {
		t.Errorf("Poly = %05x, want 0x1100b", Poly)
	}
}

// TestReduceTableConsistency verifies the first 16 entries of the internal
// REDUCE_BYTES table against the values computed by the standalone Rust
// reference generator, confirming that init() produces a byte-for-byte
// identical table.
func TestReduceTableConsistency(t *testing.T) {
	expected := [16]uint16{
		0x0000, 0x100b, 0x2016, 0x301d,
		0x402c, 0x5027, 0x603a, 0x7031,
		0x8058, 0x9053, 0xa04e, 0xb045,
		0xc074, 0xd07f, 0xe062, 0xf069,
	}
	for i, want := range expected {
		if got := reduceBytes[i]; got != want {
			t.Errorf("reduceBytes[%d] = %04x, want %04x", i, got, want)
		}
	}
}

// BenchmarkMul measures the throughput of GF16 multiplication.
func BenchmarkMul(b *testing.B) {
	x, y := New(0x1234), New(0x5678)
	b.ResetTimer()
	for b.Loop() {
		x = x.Mul(y)
	}
}

// BenchmarkInv measures the throughput of GF16 inversion.
func BenchmarkInv(b *testing.B) {
	x := New(0xABCD)
	b.ResetTimer()
	for b.Loop() {
		var err error
		x, err = x.Inv()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParallelMult measures ParallelMult over 1024 elements.
func BenchmarkParallelMult(b *testing.B) {
	m := New(0x1234)
	coeffs := make([]GF16, 1024)
	for i := range coeffs {
		coeffs[i] = New(uint16(i + 1))
	}
	b.ResetTimer()
	for b.Loop() {
		ParallelMult(m, coeffs)
	}
}
