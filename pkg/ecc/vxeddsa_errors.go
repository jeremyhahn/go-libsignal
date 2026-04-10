package ecc

import "fmt"

// ErrVXEdDSAInvalidSignatureLength is returned when a VXEdDSA signature is not 96 bytes.
type ErrVXEdDSAInvalidSignatureLength struct {
	Got int
}

func (e *ErrVXEdDSAInvalidSignatureLength) Error() string {
	return fmt.Sprintf("vxeddsa: signature must be 96 bytes, got %d", e.Got)
}

// Is implements errors.Is matching by type, ignoring the Got field so that
// errors.Is(err, ErrInvalidVXEdDSASignatureLength) returns true for any
// instance of this error type.
func (e *ErrVXEdDSAInvalidSignatureLength) Is(target error) bool {
	_, ok := target.(*ErrVXEdDSAInvalidSignatureLength)
	return ok
}

// ErrVXEdDSAHashToPointFailed is returned when the Elligator 2 hash-to-point operation fails.
type ErrVXEdDSAHashToPointFailed struct{}

func (e *ErrVXEdDSAHashToPointFailed) Error() string {
	return "vxeddsa: hash to point failed"
}

// ErrVXEdDSAInvalidVRFPoint is returned when a VRF point V_v cannot be decoded from the signature.
type ErrVXEdDSAInvalidVRFPoint struct{}

func (e *ErrVXEdDSAInvalidVRFPoint) Error() string {
	return "vxeddsa: invalid VRF point in signature"
}

// ErrVXEdDSANilPrivateKey is returned when a nil private key is provided.
type ErrVXEdDSANilPrivateKey struct{}

func (e *ErrVXEdDSANilPrivateKey) Error() string {
	return "vxeddsa: nil private key"
}

// ErrVXEdDSANilPublicKey is returned when a nil public key is provided.
type ErrVXEdDSANilPublicKey struct{}

func (e *ErrVXEdDSANilPublicKey) Error() string {
	return "vxeddsa: nil public key"
}

// Sentinel variables for backward-compatible errors.Is matching.
var (
	// ErrInvalidVXEdDSASignatureLength is returned when a VXEdDSA signature is not 96 bytes.
	ErrInvalidVXEdDSASignatureLength error = &ErrVXEdDSAInvalidSignatureLength{}

	// ErrHashToPointFailed is returned when the Elligator 2 hash-to-point operation fails.
	ErrHashToPointFailed error = &ErrVXEdDSAHashToPointFailed{}

	// ErrInvalidVRFPoint is returned when a VRF point V_v cannot be decoded from the signature.
	ErrInvalidVRFPoint error = &ErrVXEdDSAInvalidVRFPoint{}

	// ErrNilPrivateKey is returned when a nil private key is provided.
	ErrNilPrivateKey error = &ErrVXEdDSANilPrivateKey{}

	// ErrNilPublicKey is returned when a nil public key is provided.
	ErrNilPublicKey error = &ErrVXEdDSANilPublicKey{}
)
