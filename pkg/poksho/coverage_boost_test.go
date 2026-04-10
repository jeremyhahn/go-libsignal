package poksho

import (
	"errors"
	"testing"

	"github.com/gtank/ristretto255"
)

// --- Statement Add validation ---

func TestAdd_PanicOnEmptyLHS(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty lhs")
		}
	}()
	st := NewStatement()
	st.Add("", [][2]string{{"a", "G"}})
}

func TestAdd_PanicOnEmptyPairs(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty pairs")
		}
	}()
	st := NewStatement()
	st.Add("A", [][2]string{})
}

func TestAdd_PanicOnEmptyScalarName(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty scalar name")
		}
	}()
	st := NewStatement()
	st.Add("A", [][2]string{{"", "G"}})
}

func TestAdd_PanicOnEmptyPointName(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty point name")
		}
	}()
	st := NewStatement()
	st.Add("A", [][2]string{{"a", ""}})
}

// --- Prove with zero scalar (edge case) ---

func TestProve_ZeroScalar(t *testing.T) {
	zero := ristretto255.NewScalar().Zero()
	identity := ristretto255.NewIdentityElement()

	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", zero)

	pointArgs := NewPointArgs()
	pointArgs.Add("A", identity)

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

// --- VerifyProof with non-canonical challenge ---

func TestVerifyProof_NonCanonicalChallenge(t *testing.T) {
	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	A := generateTestPoint(generateTestScalar(42))
	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)

	// Proof with non-canonical challenge (all 0xFF)
	proofData := make([]byte, 64)
	for i := 0; i < 32; i++ {
		proofData[i] = 0xFF
	}

	err := st.VerifyProof(proofData, pointArgs, []byte{})
	if err == nil {
		t.Fatal("expected error for non-canonical challenge scalar")
	}
	if !errors.Is(err, ErrVerificationFailure) {
		t.Fatalf("expected ErrVerificationFailure, got %v", err)
	}
}

// --- VerifyProof with non-canonical response ---

func TestVerifyProof_NonCanonicalResponse(t *testing.T) {
	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	A := generateTestPoint(generateTestScalar(42))
	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)

	// Valid challenge (zeros), non-canonical response
	proofData := make([]byte, 64)
	for i := 32; i < 64; i++ {
		proofData[i] = 0xFF
	}

	err := st.VerifyProof(proofData, pointArgs, []byte{})
	if err == nil {
		t.Fatal("expected error for non-canonical response scalar")
	}
}

// --- Shared scalar across equations (DLOG equality) ---

func TestProve_SharedScalarAcrossEquations(t *testing.T) {
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
		randomness[i] = byte(i + 50)
	}

	proof, err := st.Prove(scalarArgs, pointArgs, []byte{}, randomness)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	if err := st.VerifyProof(proof, pointArgs, []byte{}); err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
}

// --- Verify with wrong point args ---

func TestVerifyProof_RejectsWrongPointArgs(t *testing.T) {
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

	// Verify with a different point
	wrongA := generateTestPoint(generateTestScalar(99))
	wrongArgs := NewPointArgs()
	wrongArgs.Add("A", wrongA)

	if err := st.VerifyProof(proof, wrongArgs, []byte{}); err == nil {
		t.Fatal("expected verification to fail with wrong point args")
	}
}

// --- Three-scalar proof ---

func TestProve_ThreeScalars(t *testing.T) {
	x := generateTestScalar(10)
	y := generateTestScalar(20)
	z := generateTestScalar(30)

	X := generateTestPoint(x)
	Y := generateTestPoint(y)
	Z := generateTestPoint(z)

	st := NewStatement()
	st.Add("X", [][2]string{{"x", "G"}})
	st.Add("Y", [][2]string{{"y", "G"}})
	st.Add("Z", [][2]string{{"z", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("x", x)
	scalarArgs.Add("y", y)
	scalarArgs.Add("z", z)

	pointArgs := NewPointArgs()
	pointArgs.Add("X", X)
	pointArgs.Add("Y", Y)
	pointArgs.Add("Z", Z)

	randomness := make([]byte, 32)
	for i := range randomness {
		randomness[i] = byte(i + 7)
	}

	proof, err := st.Prove(scalarArgs, pointArgs, []byte{}, randomness)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	if err := st.VerifyProof(proof, pointArgs, []byte{}); err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	// Proof: 1 challenge + 3 responses = 128 bytes
	if len(proof) != 128 {
		t.Errorf("expected proof size 128, got %d", len(proof))
	}
}

// --- Missing scalar argument ---

func TestProve_MissingScalarArg(t *testing.T) {
	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}, {"b", "H"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", generateTestScalar(42))
	// Missing "b"

	H := generateTestPoint(generateTestScalar(77))
	pointArgs := NewPointArgs()
	pointArgs.Add("A", generateTestPoint(generateTestScalar(42)))
	pointArgs.Add("H", H)

	_, err := st.Prove(scalarArgs, pointArgs, []byte{}, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for missing scalar arg")
	}
	if !errors.Is(err, ErrBadArgsWrongNumberOfScalarArgs) {
		t.Fatalf("expected ErrBadArgsWrongNumberOfScalarArgs, got %v", err)
	}
}

// --- Missing point argument ---

func TestProve_MissingPointArg(t *testing.T) {
	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", generateTestScalar(42))

	pointArgs := NewPointArgs()
	// Missing "A"

	_, err := st.Prove(scalarArgs, pointArgs, []byte{}, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for missing point arg")
	}
	if !errors.Is(err, ErrBadArgsWrongNumberOfPointArgs) {
		t.Fatalf("expected ErrBadArgsWrongNumberOfPointArgs, got %v", err)
	}
}

// --- Proof with message ---

func TestProve_WithMessage(t *testing.T) {
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
		randomness[i] = byte(i + 1)
	}

	message := []byte("authenticated message")
	proof, err := st.Prove(scalarArgs, pointArgs, message, randomness)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Correct message verifies
	if err := st.VerifyProof(proof, pointArgs, message); err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}

	// Wrong message fails
	if err := st.VerifyProof(proof, pointArgs, []byte("wrong")); err == nil {
		t.Fatal("expected verification to fail with wrong message")
	}

	// Empty message fails
	if err := st.VerifyProof(proof, pointArgs, []byte{}); err == nil {
		t.Fatal("expected verification to fail with empty message")
	}
}

// --- ScalarArgs and PointArgs API ---

func TestScalarArgs_Add(t *testing.T) {
	args := NewScalarArgs()
	args.Add("x", generateTestScalar(1))
	args.Add("y", generateTestScalar(2))
	if len(args.values) != 2 {
		t.Errorf("expected 2 scalars, got %d", len(args.values))
	}
}

func TestPointArgs_Add(t *testing.T) {
	args := NewPointArgs()
	args.Add("A", generateTestPoint(generateTestScalar(1)))
	args.Add("B", generateTestPoint(generateTestScalar(2)))
	if len(args.values) != 2 {
		t.Errorf("expected 2 points, got %d", len(args.values))
	}
}

// --- ProofError ---

func TestProofError_WithContext(t *testing.T) {
	err := &ProofError{Kind: ErrBadArgs, Context: "test context"}
	if err.Error() != "poksho: bad arguments: test context" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
	if !errors.Is(err, ErrBadArgs) {
		t.Error("expected Unwrap to return ErrBadArgs")
	}
}

func TestProofError_WithoutContext(t *testing.T) {
	err := &ProofError{Kind: ErrVerificationFailure}
	if err.Error() != "poksho: verification failure" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}
