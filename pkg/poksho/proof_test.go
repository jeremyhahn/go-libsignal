package poksho

import (
	"errors"
	"testing"

	"github.com/gtank/ristretto255"
)

// generateTestScalar creates a deterministic scalar from a seed for testing.
func generateTestScalar(seed byte) *ristretto255.Scalar {
	var wide [64]byte
	for i := range wide {
		wide[i] = seed + byte(i)
	}
	sc := ristretto255.NewScalar()
	if _, err := sc.SetUniformBytes(wide[:]); err != nil {
		panic(err)
	}
	return sc
}

// generateTestPoint creates a point by multiplying the basepoint by a scalar.
func generateTestPoint(sc *ristretto255.Scalar) *ristretto255.Element {
	return new(ristretto255.Element).ScalarBaseMult(sc)
}

func TestStatementEncoding(t *testing.T) {
	// Test 1: A = a*G
	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})
	got := st.toBytes()
	expected := []byte{1, 1, 1, 0, 0}
	if !bytesEqual(got, expected) {
		t.Errorf("encoding mismatch: got %v, want %v", got, expected)
	}

	// Test 2: A = a*G; B = a*H
	st = NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})
	st.Add("B", [][2]string{{"a", "H"}})
	got = st.toBytes()
	expected = []byte{2, 1, 1, 0, 0, 2, 1, 0, 3}
	if !bytesEqual(got, expected) {
		t.Errorf("encoding mismatch: got %v, want %v", got, expected)
	}

	// Test 3: A = a*G + b*H
	st = NewStatement()
	st.Add("A", [][2]string{{"a", "G"}, {"b", "H"}})
	got = st.toBytes()
	expected = []byte{1, 1, 2, 0, 0, 1, 2}
	if !bytesEqual(got, expected) {
		t.Errorf("encoding mismatch: got %v, want %v", got, expected)
	}
}

func TestComplexStatement(t *testing.T) {
	// Matches the Rust test_complex_statement test vector
	var block32 [32]byte
	var block64a, block64b, block64c, block64d, block64h, block64i [64]byte

	for i := 0; i < 32; i++ {
		block32[i] = byte(i)
	}
	for i := 0; i < 64; i++ {
		block64a[i] = 10 + byte(i)
		block64b[i] = 20 + byte(i)
		block64c[i] = 30 + byte(i)
		block64d[i] = 40 + byte(i)
		block64h[i] = 50 + byte(i)
		block64i[i] = 60 + byte(i)
	}

	randomness := block32[:]
	message := []byte{}

	a := ristretto255.NewScalar()
	if _, err := a.SetUniformBytes(block64a[:]); err != nil {
		t.Fatal(err)
	}
	b := ristretto255.NewScalar()
	if _, err := b.SetUniformBytes(block64b[:]); err != nil {
		t.Fatal(err)
	}
	c := ristretto255.NewScalar()
	if _, err := c.SetUniformBytes(block64c[:]); err != nil {
		t.Fatal(err)
	}
	d := ristretto255.NewScalar()
	if _, err := d.SetUniformBytes(block64d[:]); err != nil {
		t.Fatal(err)
	}

	hScalar := ristretto255.NewScalar()
	if _, err := hScalar.SetUniformBytes(block64h[:]); err != nil {
		t.Fatal(err)
	}
	H := new(ristretto255.Element).ScalarBaseMult(hScalar)

	iScalar := ristretto255.NewScalar()
	if _, err := iScalar.SetUniformBytes(block64i[:]); err != nil {
		t.Fatal(err)
	}
	I := new(ristretto255.Element).ScalarBaseMult(iScalar)

	// A = a*G + b*H + c*I
	aG := new(ristretto255.Element).ScalarBaseMult(a)
	bH := new(ristretto255.Element).ScalarMult(b, H)
	cI := new(ristretto255.Element).ScalarMult(c, I)
	A := new(ristretto255.Element).Add(aG, bH)
	A = A.Add(A, cI)

	// B = c*H + d*I
	cH := new(ristretto255.Element).ScalarMult(c, H)
	dI := new(ristretto255.Element).ScalarMult(d, I)
	B := new(ristretto255.Element).Add(cH, dI)

	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}, {"b", "H"}, {"c", "I"}})
	st.Add("B", [][2]string{{"c", "H"}, {"d", "I"}})

	// Verify encoding
	encoding := st.toBytes()
	expectedEncoding := []byte{2, 1, 3, 0, 0, 1, 2, 2, 3, 4, 2, 2, 2, 3, 3}
	if !bytesEqual(encoding, expectedEncoding) {
		t.Fatalf("encoding mismatch: got %v, want %v", encoding, expectedEncoding)
	}

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", a)
	scalarArgs.Add("b", b)
	scalarArgs.Add("c", c)
	scalarArgs.Add("d", d)

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)
	pointArgs.Add("B", B)
	pointArgs.Add("H", H)
	pointArgs.Add("I", I)

	// Test bad args - extra scalar
	scalarArgs2 := NewScalarArgs()
	scalarArgs2.Add("a", a)
	scalarArgs2.Add("b", b)
	scalarArgs2.Add("c", c)
	scalarArgs2.Add("d", d)
	scalarArgs2.Add("abc", a)
	_, err := st.Prove(scalarArgs2, pointArgs, message, randomness)
	if err == nil {
		t.Fatal("expected error for extra scalar args")
	}
	if !errors.Is(err, ErrBadArgsWrongNumberOfScalarArgs) {
		t.Fatalf("expected ErrBadArgsWrongNumberOfScalarArgs, got %v", err)
	}

	// Good proof
	proof, err := st.Prove(scalarArgs, pointArgs, message, randomness)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Verify the proof
	if err := st.VerifyProof(proof, pointArgs, message); err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	// Verify the proof bytes match the Rust test vector
	expectedProof := []byte{
		0x8e, 0xfc, 0x67, 0x6c, 0x33, 0xe6, 0xb2, 0xd0, 0x67, 0x0e, 0xd5, 0x46, 0x1a,
		0x50, 0x7f, 0x6a, 0x4b, 0xc9, 0x15, 0x3e, 0x26, 0x1d, 0xb8, 0x0f, 0xa4, 0x38,
		0xf3, 0xcd, 0x80, 0xa5, 0xc9, 0x09, 0xb1, 0x13, 0xcc, 0x0d, 0x79, 0x90, 0xad,
		0x61, 0x6d, 0x0a, 0x2f, 0xc4, 0xb8, 0x31, 0xd0, 0x63, 0x57, 0xa5, 0xee, 0x5d,
		0x36, 0xd4, 0x4b, 0x34, 0x27, 0xc7, 0x90, 0x10, 0x61, 0x18, 0x0c, 0x0f, 0xb1,
		0x79, 0x8c, 0x51, 0x68, 0x0f, 0xe2, 0x1b, 0x9f, 0x98, 0xe9, 0x79, 0x55, 0xb1,
		0x59, 0x7c, 0x49, 0x31, 0x47, 0x25, 0xc1, 0x54, 0x6a, 0x36, 0x93, 0x28, 0xcf,
		0x54, 0xda, 0xae, 0x71, 0x0b, 0xfc, 0x4a, 0x99, 0x11, 0x42, 0x2a, 0xa7, 0x7e,
		0xd6, 0xd7, 0x23, 0x1d, 0xe3, 0x00, 0x3b, 0xa5, 0xae, 0x9d, 0x9f, 0xd0, 0xc5,
		0x3c, 0xed, 0x7a, 0xd7, 0x82, 0xe2, 0x9b, 0x04, 0x68, 0x4a, 0x07, 0x22, 0x1a,
		0x6e, 0xf4, 0x7c, 0xe6, 0x1d, 0x81, 0x7f, 0x01, 0x11, 0x7c, 0xf5, 0x9d, 0xf6,
		0x9a, 0xc3, 0x5b, 0x5b, 0xb5, 0x90, 0xf1, 0xf7, 0xb6, 0xd0, 0x29, 0x71, 0x7b,
		0xc1, 0xa6, 0x25, 0x01,
	}
	if !bytesEqual(proof, expectedProof) {
		t.Errorf("proof bytes do not match Rust test vector")
		t.Errorf("got length %d, want %d", len(proof), len(expectedProof))
		for i := range expectedProof {
			if i < len(proof) && proof[i] != expectedProof[i] {
				t.Errorf("first difference at byte %d: got 0x%02x, want 0x%02x", i, proof[i], expectedProof[i])
				break
			}
		}
	}

	// Test bad args - extra point
	pointArgs2 := NewPointArgs()
	pointArgs2.Add("A", A)
	pointArgs2.Add("B", B)
	pointArgs2.Add("H", H)
	pointArgs2.Add("I", I)
	pointArgs2.Add("xyz", A)
	err = st.VerifyProof(proof, pointArgs2, message)
	if err == nil {
		t.Fatal("expected error for extra point args")
	}
	if !errors.Is(err, ErrBadArgsWrongNumberOfPointArgs) {
		t.Fatalf("expected ErrBadArgsWrongNumberOfPointArgs, got %v", err)
	}

	// Test bad message
	err = st.VerifyProof(proof, pointArgs, block32[:])
	if err == nil {
		t.Fatal("expected error for bad message")
	}
	if !errors.Is(err, ErrVerificationFailure) {
		t.Fatalf("expected ErrVerificationFailure, got %v", err)
	}

	// Test bad proof #1 - extra byte at end
	proof2 := make([]byte, len(proof)+1)
	copy(proof2, proof)
	err = st.VerifyProof(proof2, pointArgs, message)
	if err == nil {
		t.Fatal("expected error for proof with extra byte")
	}
	if !errors.Is(err, ErrVerificationFailure) {
		t.Fatalf("expected ErrVerificationFailure, got %v", err)
	}

	// Test bad proof #2 - last byte changed
	proof3 := make([]byte, len(proof))
	copy(proof3, proof)
	proof3[len(proof3)-1] += 1
	err = st.VerifyProof(proof3, pointArgs, message)
	if err == nil {
		t.Fatal("expected error for modified proof")
	}

	// Test bad proof #3 - truncated (one fewer scalar)
	proof4 := make([]byte, len(proof)-32)
	copy(proof4, proof)
	err = st.VerifyProof(proof4, pointArgs, message)
	if err == nil {
		t.Fatal("expected error for truncated proof")
	}
	if !errors.Is(err, ErrVerificationFailure) {
		t.Fatalf("expected ErrVerificationFailure, got %v", err)
	}
}

func TestProveSignVerifySingleEquation(t *testing.T) {
	// Prove knowledge of a such that A = a*G
	a := generateTestScalar(42)
	A := generateTestPoint(a)

	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", a)

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)

	randomness := make([]byte, 32)
	for i := range randomness {
		randomness[i] = byte(i)
	}

	proof, err := st.Prove(scalarArgs, pointArgs, []byte{}, randomness)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	if err := st.VerifyProof(proof, pointArgs, []byte{}); err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
}

func TestProveFailsWithWrongScalar(t *testing.T) {
	a := generateTestScalar(42)
	wrongA := generateTestScalar(99)
	A := generateTestPoint(a)

	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", wrongA) // wrong scalar

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)

	randomness := make([]byte, 32)
	for i := range randomness {
		randomness[i] = byte(i)
	}

	// The proof creation should fail during self-verification
	_, err := st.Prove(scalarArgs, pointArgs, []byte{}, randomness)
	if err == nil {
		t.Fatal("Prove should fail with wrong scalar (self-verification)")
	}
	if !errors.Is(err, ErrProofCreationVerificationFailure) {
		t.Fatalf("expected ErrProofCreationVerificationFailure, got %v", err)
	}
}

func TestProveDLOGEquality(t *testing.T) {
	// Prove knowledge of a such that A = a*G and B = a*H
	a := generateTestScalar(42)
	hScalar := generateTestScalar(77)
	H := generateTestPoint(hScalar)

	A := generateTestPoint(a)
	B := new(ristretto255.Element).ScalarMult(a, H)

	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})
	st.Add("B", [][2]string{{"a", "H"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", a)

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)
	pointArgs.Add("B", B)
	pointArgs.Add("H", H)

	randomness := make([]byte, 32)
	for i := range randomness {
		randomness[i] = byte(i + 10)
	}

	proof, err := st.Prove(scalarArgs, pointArgs, []byte("test message"), randomness)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	if err := st.VerifyProof(proof, pointArgs, []byte("test message")); err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	// Wrong message should fail
	if err := st.VerifyProof(proof, pointArgs, []byte("wrong message")); err == nil {
		t.Fatal("expected failure with wrong message")
	}
}

func TestProofBadRandomnessLength(t *testing.T) {
	a := generateTestScalar(42)
	A := generateTestPoint(a)

	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", a)

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)

	_, err := st.Prove(scalarArgs, pointArgs, []byte{}, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for bad randomness length")
	}
	if !errors.Is(err, ErrBadArgs) {
		t.Fatalf("expected ErrBadArgs, got %v", err)
	}
}

func TestVerifyProofRejectsTooManyScalars(t *testing.T) {
	// A malformed proof with >256 response scalars must be rejected early
	// before any expensive computation occurs.
	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	pointArgs := NewPointArgs()
	a := generateTestScalar(42)
	A := generateTestPoint(a)
	pointArgs.Add("A", A)

	// Construct a proof with 257 response scalars: challenge (32 bytes) + 257*32 bytes
	numScalars := 257
	proofBytes := make([]byte, 32*(1+numScalars))
	err := st.VerifyProof(proofBytes, pointArgs, []byte{})
	if err == nil {
		t.Fatal("expected error for proof with >256 response scalars")
	}
	var proofErr *ProofError
	if !errors.As(err, &proofErr) {
		t.Fatalf("expected *ProofError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrVerificationFailure) {
		t.Fatalf("expected ErrVerificationFailure, got %v", err)
	}
	if proofErr.Context != "too many response scalars" {
		t.Fatalf("expected context %q, got %q", "too many response scalars", proofErr.Context)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
