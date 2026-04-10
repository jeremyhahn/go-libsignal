package poksho

// ErrPokshoBadArgs indicates bad arguments were passed to the function.
type ErrPokshoBadArgs struct{}

func (e *ErrPokshoBadArgs) Error() string { return "poksho: bad arguments" }

// ErrPokshoBadArgsWrongNumberOfScalarArgs indicates wrong number of scalar arguments.
type ErrPokshoBadArgsWrongNumberOfScalarArgs struct{}

func (e *ErrPokshoBadArgsWrongNumberOfScalarArgs) Error() string {
	return "poksho: wrong number of scalar arguments"
}

// ErrPokshoBadArgsWrongNumberOfPointArgs indicates wrong number of point arguments.
type ErrPokshoBadArgsWrongNumberOfPointArgs struct{}

func (e *ErrPokshoBadArgsWrongNumberOfPointArgs) Error() string {
	return "poksho: wrong number of point arguments"
}

// ErrPokshoBadArgsMissingScalarArg indicates a required scalar argument is missing.
type ErrPokshoBadArgsMissingScalarArg struct{}

func (e *ErrPokshoBadArgsMissingScalarArg) Error() string {
	return "poksho: missing scalar argument"
}

// ErrPokshoBadArgsMissingPointArg indicates a required point argument is missing.
type ErrPokshoBadArgsMissingPointArg struct{}

func (e *ErrPokshoBadArgsMissingPointArg) Error() string {
	return "poksho: missing point argument"
}

// ErrPokshoVerificationFailure indicates proof verification failed.
type ErrPokshoVerificationFailure struct{}

func (e *ErrPokshoVerificationFailure) Error() string { return "poksho: verification failure" }

// ErrPokshoProofCreationVerificationFailure indicates proof self-verification
// failed during creation, suggesting bad inputs or faulty computation.
type ErrPokshoProofCreationVerificationFailure struct{}

func (e *ErrPokshoProofCreationVerificationFailure) Error() string {
	return "poksho: proof creation verification failure"
}

// ErrPokshoInvalidInput indicates that invalid input was provided.
type ErrPokshoInvalidInput struct{}

func (e *ErrPokshoInvalidInput) Error() string { return "poksho: invalid input" }

// Sentinel variables for backward-compatible errors.Is matching.
var (
	// ErrBadArgs indicates bad arguments were passed to the function.
	ErrBadArgs error = &ErrPokshoBadArgs{}

	// ErrBadArgsWrongNumberOfScalarArgs indicates wrong number of scalar arguments.
	ErrBadArgsWrongNumberOfScalarArgs error = &ErrPokshoBadArgsWrongNumberOfScalarArgs{}

	// ErrBadArgsWrongNumberOfPointArgs indicates wrong number of point arguments.
	ErrBadArgsWrongNumberOfPointArgs error = &ErrPokshoBadArgsWrongNumberOfPointArgs{}

	// ErrBadArgsMissingScalarArg indicates a required scalar argument is missing.
	ErrBadArgsMissingScalarArg error = &ErrPokshoBadArgsMissingScalarArg{}

	// ErrBadArgsMissingPointArg indicates a required point argument is missing.
	ErrBadArgsMissingPointArg error = &ErrPokshoBadArgsMissingPointArg{}

	// ErrVerificationFailure indicates proof verification failed.
	ErrVerificationFailure error = &ErrPokshoVerificationFailure{}

	// ErrProofCreationVerificationFailure indicates proof self-verification
	// failed during creation, suggesting bad inputs or faulty computation.
	ErrProofCreationVerificationFailure error = &ErrPokshoProofCreationVerificationFailure{}

	// ErrInvalidInput indicates that invalid input was provided.
	ErrInvalidInput error = &ErrPokshoInvalidInput{}
)

// ProofError wraps a sentinel error with optional context.
type ProofError struct {
	Kind    error
	Context string
}

// Error implements the error interface.
func (e *ProofError) Error() string {
	if e.Context != "" {
		return e.Kind.Error() + ": " + e.Context
	}
	return e.Kind.Error()
}

// Unwrap returns the underlying sentinel error.
func (e *ProofError) Unwrap() error {
	return e.Kind
}

// InvalidInputError wraps ErrInvalidInput with context about the specific
// validation failure.
type InvalidInputError struct {
	Context string
}

// Error implements the error interface.
func (e *InvalidInputError) Error() string {
	if e.Context != "" {
		return "poksho: invalid input: " + e.Context
	}
	return ErrInvalidInput.Error()
}

// Unwrap returns the underlying sentinel error.
func (e *InvalidInputError) Unwrap() error {
	return ErrInvalidInput
}

// ScalarSizeError indicates a scalar input has the wrong byte length.
type ScalarSizeError struct {
	Expected int
	Actual   int
}

func (e *ScalarSizeError) Error() string {
	return "poksho: scalar input must be " + itoa(e.Expected) + " bytes"
}

// ScalarNotCanonicalError indicates a scalar value is not in canonical form.
type ScalarNotCanonicalError struct{}

func (e *ScalarNotCanonicalError) Error() string {
	return "poksho: scalar is not in canonical form (>= group order)"
}

func itoa(n int) string {
	if n == 32 {
		return "32"
	}
	if n == 64 {
		return "64"
	}
	return "?"
}
