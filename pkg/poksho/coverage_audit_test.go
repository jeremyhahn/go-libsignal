package poksho

import (
	"bytes"
	"errors"
	"testing"
)

// TestErrorMessages verifies that each typed error returns the correct message
// string. This covers all Error() methods that were at 0% coverage.

func TestErrPokshoBadArgsWrongNumberOfScalarArgs_Error(t *testing.T) {
	// Trigger via Prove with wrong scalar count: statement expects 2 scalars,
	// but only 1 is provided. sortScalars returns ErrBadArgsWrongNumberOfScalarArgs.
	st := NewStatement()
	st.Add("A", [][2]string{{"x", "G"}, {"y", "H"}})

	H := generateTestPoint(generateTestScalar(5))
	A := generateTestPoint(generateTestScalar(6))

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("x", generateTestScalar(1)) // missing "y"

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)
	pointArgs.Add("H", H)

	_, err := st.Prove(scalarArgs, pointArgs, nil, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for wrong number of scalar args")
	}

	var target *ErrPokshoBadArgsWrongNumberOfScalarArgs
	if !errors.As(err, &target) {
		// The error is wrapped in ProofError whose Kind IS the sentinel.
		// Confirm errors.Is works.
		if !errors.Is(err, ErrBadArgsWrongNumberOfScalarArgs) {
			t.Fatalf("expected ErrBadArgsWrongNumberOfScalarArgs, got: %v", err)
		}
	}

	// Directly exercise the Error() method on the type.
	e := &ErrPokshoBadArgsWrongNumberOfScalarArgs{}
	if e.Error() != "poksho: wrong number of scalar arguments" {
		t.Errorf("unexpected error message: %q", e.Error())
	}
}

func TestErrPokshoBadArgsWrongNumberOfPointArgs_Error(t *testing.T) {
	// Trigger via VerifyProof with wrong point count: statement expects 1
	// non-G point ("A"), but no point is provided.
	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	// Build a valid proof first, then verify with wrong point count.
	a := generateTestScalar(42)
	A := generateTestPoint(a)

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", a)

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)

	proof, err := st.Prove(scalarArgs, pointArgs, nil, make([]byte, 32))
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Verify with empty point args (0 points, expected 1).
	emptyPointArgs := NewPointArgs()
	err = st.VerifyProof(proof, emptyPointArgs, nil)
	if err == nil {
		t.Fatal("expected error for wrong number of point args")
	}
	if !errors.Is(err, ErrBadArgsWrongNumberOfPointArgs) {
		t.Fatalf("expected ErrBadArgsWrongNumberOfPointArgs, got: %v", err)
	}

	// Directly exercise the Error() method.
	e := &ErrPokshoBadArgsWrongNumberOfPointArgs{}
	if e.Error() != "poksho: wrong number of point arguments" {
		t.Errorf("unexpected error message: %q", e.Error())
	}
}

func TestErrPokshoBadArgsMissingScalarArg_Error(t *testing.T) {
	// The missing scalar path in sortScalars is reached when the count matches
	// but a named scalar is absent. Build a statement with scalars "x" and "y",
	// but provide args with "x" and "z" (count=2 but "y" is missing).
	st := NewStatement()
	st.Add("A", [][2]string{{"x", "G"}})
	st.Add("B", [][2]string{{"y", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("x", generateTestScalar(1))
	scalarArgs.Add("z", generateTestScalar(2)) // "z" != "y"

	A := generateTestPoint(generateTestScalar(1))
	B := generateTestPoint(generateTestScalar(2))
	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)
	pointArgs.Add("B", B)

	_, err := st.Prove(scalarArgs, pointArgs, nil, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for missing scalar arg")
	}
	if !errors.Is(err, ErrBadArgsMissingScalarArg) {
		t.Fatalf("expected ErrBadArgsMissingScalarArg, got: %v", err)
	}

	// Directly exercise the Error() method.
	e := &ErrPokshoBadArgsMissingScalarArg{}
	if e.Error() != "poksho: missing scalar argument" {
		t.Errorf("unexpected error message: %q", e.Error())
	}
}

func TestErrPokshoBadArgsMissingPointArg_Error(t *testing.T) {
	// Statement uses points "A" and "H". Provide the right count (2) but use
	// "A" and "X" — "H" is missing, triggering ErrBadArgsMissingPointArg.
	// Single equation A = a*G + b*H requires points "A" and "H" (excluding G).
	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}, {"b", "H"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", generateTestScalar(1))
	scalarArgs.Add("b", generateTestScalar(2))

	Apt := generateTestPoint(generateTestScalar(3))
	// Provide "A" and "X" instead of "A" and "H" — count is 2 but "H" absent.
	pointArgs := NewPointArgs()
	pointArgs.Add("A", Apt)
	pointArgs.Add("X", generateTestPoint(generateTestScalar(4))) // wrong name

	_, err := st.Prove(scalarArgs, pointArgs, nil, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for missing point arg")
	}
	if !errors.Is(err, ErrBadArgsMissingPointArg) {
		t.Fatalf("expected ErrBadArgsMissingPointArg, got: %v", err)
	}

	// Directly exercise the Error() method.
	e := &ErrPokshoBadArgsMissingPointArg{}
	if e.Error() != "poksho: missing point argument" {
		t.Errorf("unexpected error message: %q", e.Error())
	}
}

func TestErrPokshoVerificationFailure_Error(t *testing.T) {
	// Build a valid proof, then corrupt the challenge bytes so VerifyProof
	// reaches the constant-time comparison and fails.
	a := generateTestScalar(99)
	A := generateTestPoint(a)

	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", a)

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)

	proof, err := st.Prove(scalarArgs, pointArgs, nil, make([]byte, 32))
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Flip the last byte of the challenge to produce a valid scalar but wrong
	// challenge, forcing a mismatch at the constant-time comparison.
	corrupted := make([]byte, len(proof))
	copy(corrupted, proof)
	corrupted[0] ^= 0x01

	err = st.VerifyProof(corrupted, pointArgs, nil)
	if err == nil {
		t.Fatal("expected verification failure for corrupted proof")
	}
	if !errors.Is(err, ErrVerificationFailure) {
		t.Fatalf("expected ErrVerificationFailure, got: %v", err)
	}

	// Directly exercise the Error() method.
	e := &ErrPokshoVerificationFailure{}
	if e.Error() != "poksho: verification failure" {
		t.Errorf("unexpected error message: %q", e.Error())
	}
}

func TestErrPokshoProofCreationVerificationFailure_Error(t *testing.T) {
	// Build a proof with a scalar that doesn't match the point to trigger
	// self-verification failure inside Prove.
	a := generateTestScalar(1)
	wrongA := generateTestScalar(2) // A computed from wrong scalar
	A := generateTestPoint(a)

	st := NewStatement()
	st.Add("A", [][2]string{{"a", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("a", wrongA) // scalar doesn't correspond to A

	pointArgs := NewPointArgs()
	pointArgs.Add("A", A)

	_, err := st.Prove(scalarArgs, pointArgs, nil, make([]byte, 32))
	if err == nil {
		t.Fatal("expected ErrProofCreationVerificationFailure")
	}
	if !errors.Is(err, ErrProofCreationVerificationFailure) {
		t.Fatalf("expected ErrProofCreationVerificationFailure, got: %v", err)
	}

	// Directly exercise the Error() method.
	e := &ErrPokshoProofCreationVerificationFailure{}
	if e.Error() != "poksho: proof creation verification failure" {
		t.Errorf("unexpected error message: %q", e.Error())
	}
}

func TestErrPokshoInvalidInput_Error(t *testing.T) {
	// ErrPokshoInvalidInput is exposed through InvalidInputError and as a
	// sentinel. Exercise the Error() method directly.
	e := &ErrPokshoInvalidInput{}
	if e.Error() != "poksho: invalid input" {
		t.Errorf("unexpected error message: %q", e.Error())
	}

	// Verify the sentinel variable wraps the same type.
	var target *ErrPokshoInvalidInput
	if !errors.As(ErrInvalidInput, &target) {
		t.Error("ErrInvalidInput sentinel should be *ErrPokshoInvalidInput")
	}
}

// TestInvalidInputError covers InvalidInputError.Error() and Unwrap().
func TestInvalidInputError(t *testing.T) {
	// With context.
	e := &InvalidInputError{Context: "bad bytes"}
	want := "poksho: invalid input: bad bytes"
	if e.Error() != want {
		t.Errorf("got %q, want %q", e.Error(), want)
	}
	if !errors.Is(e, ErrInvalidInput) {
		t.Error("expected Unwrap to return ErrInvalidInput")
	}

	// Without context — should fall back to the sentinel message.
	e2 := &InvalidInputError{}
	if e2.Error() != "poksho: invalid input" {
		t.Errorf("got %q, want %q", e2.Error(), "poksho: invalid input")
	}
}

// TestScalarSizeError covers ScalarSizeError.Error() and the itoa helper.
func TestScalarSizeError(t *testing.T) {
	// ScalarFromSliceWide with wrong length triggers ScalarSizeError{64, actual}.
	_, err := ScalarFromSliceWide(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for wrong-length wide scalar input")
	}
	var sse *ScalarSizeError
	if !errors.As(err, &sse) {
		t.Fatalf("expected *ScalarSizeError, got %T: %v", err, err)
	}
	if sse.Expected != 64 || sse.Actual != 16 {
		t.Errorf("wrong size fields: Expected=%d Actual=%d", sse.Expected, sse.Actual)
	}
	if sse.Error() != "poksho: scalar input must be 64 bytes" {
		t.Errorf("unexpected message: %q", sse.Error())
	}

	// ScalarFromSliceCanonical with wrong length triggers ScalarSizeError{32, actual}.
	_, err = ScalarFromSliceCanonical(make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for wrong-length canonical scalar input")
	}
	var sse2 *ScalarSizeError
	if !errors.As(err, &sse2) {
		t.Fatalf("expected *ScalarSizeError, got %T: %v", err, err)
	}
	if sse2.Expected != 32 || sse2.Actual != 5 {
		t.Errorf("wrong size fields: Expected=%d Actual=%d", sse2.Expected, sse2.Actual)
	}
	if sse2.Error() != "poksho: scalar input must be 32 bytes" {
		t.Errorf("unexpected message: %q", sse2.Error())
	}
}

// TestScalarNotCanonicalError covers ScalarNotCanonicalError.Error().
func TestScalarNotCanonicalError(t *testing.T) {
	// The group order L in little-endian starts with 0xed. A value >= L triggers
	// ScalarNotCanonicalError. Use all 0xFF bytes which is >> L.
	input := bytes.Repeat([]byte{0xFF}, 32)
	_, err := ScalarFromSliceCanonical(input)
	if err == nil {
		t.Fatal("expected error for non-canonical scalar")
	}
	var target *ScalarNotCanonicalError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ScalarNotCanonicalError, got %T: %v", err, err)
	}
	want := "poksho: scalar is not in canonical form (>= group order)"
	if target.Error() != want {
		t.Errorf("got %q, want %q", target.Error(), want)
	}
}

// TestSHO_Zeroize verifies that Zeroize() clears the chaining value and
// resets the SHO's internal state.
func TestSHO_Zeroize(t *testing.T) {
	// Build a SHO with non-zero state by absorbing and squeezing.
	sho := NewShoHmacSha256("zeroize-test")
	sho.AbsorbAndRatchet([]byte("sensitive key material"))
	out1 := sho.SqueezeAndRatchet(32)

	// Verify output is non-zero (sanity check).
	allZero := true
	for _, b := range out1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("SHO produced all-zero output before Zeroize (unexpected)")
	}

	// Zeroize and confirm the chaining value is cleared.
	sho.Zeroize()

	zeroCV := [hashLen]byte{}
	if sho.cv != zeroCV {
		t.Error("Zeroize() did not clear the chaining value")
	}
	if sho.hasher != nil {
		t.Error("Zeroize() did not nil the hasher")
	}
	if sho.absorbed != nil {
		t.Error("Zeroize() did not nil the absorbed buffer")
	}
}

// TestSHO_Zeroize_AbsorbingMode ensures that Zeroize() clears state even
// when the SHO is in ABSORBING mode (hasher and absorbed buffer are active).
func TestSHO_Zeroize_AbsorbingMode(t *testing.T) {
	sho := NewShoHmacSha256("zeroize-absorbing")
	sho.Absorb([]byte("partial data not yet ratcheted"))

	// Confirm we are in absorbing mode.
	if sho.mode != modeAbsorbing {
		t.Fatal("SHO should be in absorbing mode")
	}
	if sho.hasher == nil {
		t.Fatal("SHO should have a live hasher in absorbing mode")
	}
	if len(sho.absorbed) == 0 {
		t.Fatal("SHO should have absorbed data")
	}

	sho.Zeroize()

	zeroCV := [hashLen]byte{}
	if sho.cv != zeroCV {
		t.Error("Zeroize() did not clear the chaining value")
	}
	if sho.hasher != nil {
		t.Error("Zeroize() did not nil the hasher")
	}
	if sho.absorbed != nil {
		t.Error("Zeroize() did not nil the absorbed buffer")
	}
}

// TestItoa exercises the private itoa helper via ScalarSizeError.Error() to
// cover the unknown-size branch (returns "?").
func TestItoa_UnknownSize(t *testing.T) {
	// Construct a ScalarSizeError with a size that itoa doesn't recognise.
	e := &ScalarSizeError{Expected: 16, Actual: 8}
	// itoa(16) returns "?" since only 32 and 64 are handled.
	got := e.Error()
	want := "poksho: scalar input must be ? bytes"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
