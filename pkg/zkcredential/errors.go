package zkcredential

import "fmt"

// ErrDerivingScalar indicates a failure deriving a scalar from the SHO state.
type ErrDerivingScalar struct {
	Label string
	Err   error
}

func (e *ErrDerivingScalar) Error() string {
	return fmt.Sprintf("zkcredential: failed to derive %s: %v", e.Label, e.Err)
}

func (e *ErrDerivingScalar) Unwrap() error {
	return e.Err
}

// ErrDerivingPoint indicates a failure deriving a point from the SHO state.
type ErrDerivingPoint struct {
	Label string
	Err   error
}

func (e *ErrDerivingPoint) Error() string {
	return fmt.Sprintf("zkcredential: failed to derive %s: %v", e.Label, e.Err)
}

func (e *ErrDerivingPoint) Unwrap() error {
	return e.Err
}

// ErrTooManyAttributes indicates more attributes were provided than supported.
type ErrTooManyAttributes struct {
	Max int
}

func (e *ErrTooManyAttributes) Error() string {
	return fmt.Sprintf("zkcredential: more than %d attributes not supported", e.Max)
}

// ErrMissingInverseDomain indicates that a new domain was not provided
// for an inverse key.
type ErrMissingInverseDomain struct{}

func (e *ErrMissingInverseDomain) Error() string {
	return "zkcredential: must provide a new domain for an inverse key"
}

// ErrCiphertextSize indicates the ciphertext has the wrong byte length.
type ErrCiphertextSize struct {
	Got int
}

func (e *ErrCiphertextSize) Error() string {
	return fmt.Sprintf("zkcredential: ciphertext must be 64 bytes, got %d", e.Got)
}

// ErrInvalidEncoding indicates a point or scalar encoding is invalid.
type ErrInvalidEncoding struct {
	Field string
	Err   error
}

func (e *ErrInvalidEncoding) Error() string {
	return fmt.Sprintf("zkcredential: invalid %s encoding: %v", e.Field, e.Err)
}

func (e *ErrInvalidEncoding) Unwrap() error {
	return e.Err
}

// ErrCredentialSize indicates the credential has the wrong byte length.
type ErrCredentialSize struct {
	Got int
}

func (e *ErrCredentialSize) Error() string {
	return fmt.Sprintf("zkcredential: credential must be 96 bytes, got %d", e.Got)
}

// ErrProofCreation indicates a failure creating a ZK proof.
type ErrProofCreation struct {
	ProofType string
	Err       error
}

func (e *ErrProofCreation) Error() string {
	return fmt.Sprintf("zkcredential: failed to create %s proof: %v", e.ProofType, e.Err)
}

func (e *ErrProofCreation) Unwrap() error {
	return e.Err
}

// ErrComputingCredential indicates a failure in credential computation.
type ErrComputingCredential struct {
	Err error
}

func (e *ErrComputingCredential) Error() string {
	return fmt.Sprintf("zkcredential: failed to compute credential: %v", e.Err)
}

func (e *ErrComputingCredential) Unwrap() error {
	return e.Err
}

// ErrMissingHiddenAttributes indicates no hidden attributes were provided
// when at least one is required.
type ErrMissingHiddenAttributes struct{}

func (e *ErrMissingHiddenAttributes) Error() string {
	return "zkcredential: at least one hidden attribute is required"
}

// ErrTooManyHiddenAttributes indicates more hidden attribute points were
// provided than supported.
type ErrTooManyHiddenAttributes struct {
	Max int
}

func (e *ErrTooManyHiddenAttributes) Error() string {
	return fmt.Sprintf("zkcredential: more than %d hidden attribute points not supported", e.Max)
}

// ErrGeneratingBlindingKey indicates a failure generating a blinding key.
type ErrGeneratingBlindingKey struct {
	Err error
}

func (e *ErrGeneratingBlindingKey) Error() string {
	return fmt.Sprintf("zkcredential: failed to generate blinding key: %v", e.Err)
}

func (e *ErrGeneratingBlindingKey) Unwrap() error {
	return e.Err
}

// ErrGeneratingBlindingNonce indicates a failure generating a blinding nonce.
type ErrGeneratingBlindingNonce struct {
	Err error
}

func (e *ErrGeneratingBlindingNonce) Error() string {
	return fmt.Sprintf("zkcredential: failed to generate blinding nonce: %v", e.Err)
}

func (e *ErrGeneratingBlindingNonce) Unwrap() error {
	return e.Err
}

// ErrComputingBaseCredential indicates a failure computing the base credential.
type ErrComputingBaseCredential struct {
	Err error
}

func (e *ErrComputingBaseCredential) Error() string {
	return fmt.Sprintf("zkcredential: failed to compute base credential: %v", e.Err)
}

func (e *ErrComputingBaseCredential) Unwrap() error {
	return e.Err
}

// ErrGeneratingRootKey indicates a failure generating a root key.
type ErrGeneratingRootKey struct {
	Err error
}

func (e *ErrGeneratingRootKey) Error() string {
	return fmt.Sprintf("zkcredential: failed to generate root key: %v", e.Err)
}

func (e *ErrGeneratingRootKey) Unwrap() error {
	return e.Err
}

// ErrDerivingTagScalar indicates a failure deriving a tag scalar.
type ErrDerivingTagScalar struct {
	Err error
}

func (e *ErrDerivingTagScalar) Error() string {
	return fmt.Sprintf("zkcredential: failed to derive tag scalar: %v", e.Err)
}

func (e *ErrDerivingTagScalar) Unwrap() error {
	return e.Err
}

// ErrMissingHiddenPoints indicates no hidden points were provided
// when at least one is required.
type ErrMissingHiddenPoints struct{}

func (e *ErrMissingHiddenPoints) Error() string {
	return "zkcredential: no hidden points provided"
}

// ErrSHODerivePoint indicates a failure deriving a point from the SHO.
type ErrSHODerivePoint struct {
	Err error
}

func (e *ErrSHODerivePoint) Error() string {
	return fmt.Sprintf("zkcredential: failed to derive point from SHO: %v", e.Err)
}

func (e *ErrSHODerivePoint) Unwrap() error {
	return e.Err
}

// ErrSingleElligatorInputSize indicates the single Elligator input
// has the wrong size.
type ErrSingleElligatorInputSize struct {
	Got int
}

func (e *ErrSingleElligatorInputSize) Error() string {
	return fmt.Sprintf("zkcredential: single elligator input must be 32 bytes, got %d", e.Got)
}

// ErrSingleElligatorMap indicates the single Elligator map operation failed.
type ErrSingleElligatorMap struct {
	Err error
}

func (e *ErrSingleElligatorMap) Error() string {
	return fmt.Sprintf("zkcredential: single elligator map failed: %v", e.Err)
}

func (e *ErrSingleElligatorMap) Unwrap() error {
	return e.Err
}

// ErrSHODeriveScalar indicates a failure deriving a scalar from the SHO.
type ErrSHODeriveScalar struct {
	Err error
}

func (e *ErrSHODeriveScalar) Error() string {
	return fmt.Sprintf("zkcredential: failed to derive scalar from SHO: %v", e.Err)
}

func (e *ErrSHODeriveScalar) Unwrap() error {
	return e.Err
}

// ErrKeyPairTypeAssertion indicates that a key value could not be asserted to
// the expected *anyKeyPair concrete type.
type ErrKeyPairTypeAssertion struct {
	Got interface{}
}

func (e *ErrKeyPairTypeAssertion) Error() string {
	return fmt.Sprintf("zkcredential: expected *anyKeyPair, got %T", e.Got)
}

// ErrEndorsementResponseTruncated indicates the serialized EndorsementResponse
// is too short to contain the expected fields.
type ErrEndorsementResponseTruncated struct {
	Need int
	Got  int
}

func (e *ErrEndorsementResponseTruncated) Error() string {
	return fmt.Sprintf("zkcredential: endorsement response truncated: need %d bytes, got %d", e.Need, e.Got)
}

// ErrEndorsementResponsePointLength indicates a compressed point within an
// EndorsementResponse has an unexpected length (must be 32 bytes).
type ErrEndorsementResponsePointLength struct {
	Index int
	Got   int
}

func (e *ErrEndorsementResponsePointLength) Error() string {
	return fmt.Sprintf("zkcredential: endorsement response point[%d] has wrong length: got %d, want 32", e.Index, e.Got)
}

// ErrEndorsementResponseTrailingBytes indicates that unexpected bytes follow
// the EndorsementResponse payload; bincode rejects trailing bytes.
type ErrEndorsementResponseTrailingBytes struct {
	Count int
}

func (e *ErrEndorsementResponseTrailingBytes) Error() string {
	return fmt.Sprintf("zkcredential: endorsement response has %d unexpected trailing bytes", e.Count)
}

// ErrLengthOverflow indicates that a u64 length prefix read from the wire
// exceeds math.MaxInt and cannot be safely represented as a Go int.
// This prevents integer-overflow / unbounded-alloc on 64-bit wire lengths.
type ErrLengthOverflow struct {
	Field string
	Value uint64
}

func (e *ErrLengthOverflow) Error() string {
	return fmt.Sprintf("zkcredential: %s length %d overflows int", e.Field, e.Value)
}

// ErrLengthExceedsInput indicates that a u64 length prefix claims more bytes
// than are available in the remaining input, matching Rust bincode's behavior
// of failing immediately on lengths that exceed the buffer.
type ErrLengthExceedsInput struct {
	Field     string
	Value     uint64
	Remaining uint64
}

func (e *ErrLengthExceedsInput) Error() string {
	return fmt.Sprintf("zkcredential: %s length %d exceeds remaining input %d", e.Field, e.Value, e.Remaining)
}

// ErrTrailingBytes indicates that bytes remain unconsumed after a public
// Deserialize* function completes. Rust's bincode with reject_trailing_bytes()
// treats this as a decode error; Go matches that behavior.
type ErrTrailingBytes struct {
	Count int
}

func (e *ErrTrailingBytes) Error() string {
	return fmt.Sprintf("zkcredential: %d unexpected trailing bytes", e.Count)
}

// ErrSizeConstraint indicates the input is shorter than the minimum required.
// Used as the Err field of ErrInvalidEncoding for length-prefix validation.
type ErrSizeConstraint struct {
	Min int
	Got int
}

func (e *ErrSizeConstraint) Error() string {
	return fmt.Sprintf("too short: need %d bytes, got %d", e.Min, e.Got)
}

// ErrTruncated indicates the data ends unexpectedly with no known required
// count. Used as the Err field of ErrInvalidEncoding when data is truncated
// at a field boundary.
type ErrTruncated struct{}

func (e *ErrTruncated) Error() string {
	return "truncated"
}

// ErrTruncatedNeed indicates the data is truncated and specifies how many
// additional bytes are needed. Used as the Err field of ErrInvalidEncoding.
type ErrTruncatedNeed struct {
	Need int
}

func (e *ErrTruncatedNeed) Error() string {
	return fmt.Sprintf("truncated: need %d bytes", e.Need)
}
