package accountkeys

import "fmt"

// ErrInvalidACILength indicates the ACI input has an unexpected byte length.
// The ACI must be exactly 16 bytes (raw UUID without version prefix).
type ErrInvalidACILength struct {
	Length int
}

func (e *ErrInvalidACILength) Error() string {
	return fmt.Sprintf("accountkeys: ACI must be exactly 16 bytes, got %d", e.Length)
}

// ErrGeneratingRandomEntropy indicates a failure generating cryptographically
// secure random bytes for entropy pool generation.
type ErrGeneratingRandomEntropy struct {
	Err error
}

func (e *ErrGeneratingRandomEntropy) Error() string {
	return fmt.Sprintf("accountkeys: generating random entropy: %v", e.Err)
}

func (e *ErrGeneratingRandomEntropy) Unwrap() error {
	return e.Err
}

// ErrEntropyPoolLength indicates the entropy pool has the wrong number of characters.
type ErrEntropyPoolLength struct {
	Expected int
	Got      int
}

func (e *ErrEntropyPoolLength) Error() string {
	return fmt.Sprintf("accountkeys: entropy pool must be %d characters, got %d", e.Expected, e.Got)
}

// ErrEntropyPoolInvalidChar indicates the entropy pool contains an invalid character.
type ErrEntropyPoolInvalidChar struct {
	Position int
}

func (e *ErrEntropyPoolInvalidChar) Error() string {
	return fmt.Sprintf("accountkeys: invalid character at position %d; only [0-9a-z] allowed", e.Position)
}

// ErrSecuringSecret indicates a failure protecting derived key material
// in guarded memory.
type ErrSecuringSecret struct {
	Operation string
	Err       error
}

func (e *ErrSecuringSecret) Error() string {
	return fmt.Sprintf("accountkeys: securing %s: %v", e.Operation, e.Err)
}

func (e *ErrSecuringSecret) Unwrap() error {
	return e.Err
}

// ErrInvalidSaltLength indicates the salt has the wrong byte length.
type ErrInvalidSaltLength struct {
	Expected int
	Got      int
}

func (e *ErrInvalidSaltLength) Error() string {
	return fmt.Sprintf("accountkeys: salt must be %d bytes, got %d", e.Expected, e.Got)
}

// ErrInvalidBackupKey is returned when a backup key holds no root key of
// the expected length (a zero-value BackupKey), so nothing is derived from
// public inputs alone.
type ErrInvalidBackupKey struct {
	Expected int
	Got      int
}

func (e *ErrInvalidBackupKey) Error() string {
	return fmt.Sprintf("accountkeys: backup key must be %d bytes, got %d", e.Expected, e.Got)
}

// ErrEmptyPIN indicates the PIN is empty after normalization.
type ErrEmptyPIN struct{}

func (e *ErrEmptyPIN) Error() string {
	return "accountkeys: PIN must not be empty after normalization"
}

// ErrGeneratingSalt indicates a failure generating a random salt.
type ErrGeneratingSalt struct {
	Err error
}

func (e *ErrGeneratingSalt) Error() string {
	return fmt.Sprintf("accountkeys: generating salt: %v", e.Err)
}

func (e *ErrGeneratingSalt) Unwrap() error {
	return e.Err
}

// ErrInvalidPHCString indicates a failure parsing a PHC-formatted hash string.
type ErrInvalidPHCString struct {
	Err error
}

func (e *ErrInvalidPHCString) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("accountkeys: invalid PHC string: %v", e.Err)
	}
	return "accountkeys: invalid PHC string format"
}

func (e *ErrInvalidPHCString) Unwrap() error {
	return e.Err
}

// ErrPHCInvalidSaltEncoding indicates the salt in a PHC string could not be decoded.
type ErrPHCInvalidSaltEncoding struct {
	Err error
}

func (e *ErrPHCInvalidSaltEncoding) Error() string {
	return fmt.Sprintf("accountkeys: invalid salt encoding in PHC string: %v", e.Err)
}

func (e *ErrPHCInvalidSaltEncoding) Unwrap() error {
	return e.Err
}

// ErrPHCInvalidHashEncoding indicates the hash in a PHC string could not be decoded.
type ErrPHCInvalidHashEncoding struct {
	Err error
}

func (e *ErrPHCInvalidHashEncoding) Error() string {
	return fmt.Sprintf("accountkeys: invalid hash encoding in PHC string: %v", e.Err)
}

func (e *ErrPHCInvalidHashEncoding) Unwrap() error {
	return e.Err
}

// ErrPHCInvalidFormat indicates the PHC string has an invalid structure.
type ErrPHCInvalidFormat struct{}

func (e *ErrPHCInvalidFormat) Error() string {
	return "accountkeys: invalid PHC string format"
}
