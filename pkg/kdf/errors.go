package kdf

import "fmt"

// ErrLowOrderPoint is returned when curve25519.X25519 rejects the input
// because it is a low-order point, which would produce an all-zero shared secret.
type ErrLowOrderPoint struct {
	Err error
}

func (e *ErrLowOrderPoint) Error() string {
	return fmt.Sprintf("kdf: low-order point rejected by X25519: %v", e.Err)
}

func (e *ErrLowOrderPoint) Unwrap() error {
	return e.Err
}

// ErrAllZeroSharedSecret is returned when a Diffie-Hellman key agreement
// produces an all-zero shared secret, indicating a low-order or malicious
// peer public key. This matches the Rust reference CurveError::InvalidKeyAgreement.
type ErrAllZeroSharedSecret struct{}

func (e *ErrAllZeroSharedSecret) Error() string {
	return "kdf: key agreement produced invalid all-zero shared secret"
}

// ErrHKDFReadFull is returned when io.ReadFull fails to read the requested
// number of bytes from the HKDF reader.
type ErrHKDFReadFull struct {
	Err error
}

func (e *ErrHKDFReadFull) Error() string {
	return fmt.Sprintf("kdf: HKDF read failed: %v", e.Err)
}

func (e *ErrHKDFReadFull) Unwrap() error {
	return e.Err
}

// ErrShortRead is returned when HKDF produces fewer bytes than requested.
type ErrShortRead struct {
	Expected int
	Got      int
}

func (e *ErrShortRead) Error() string {
	return fmt.Sprintf("kdf: short read from HKDF: expected %d bytes, got %d", e.Expected, e.Got)
}
