// Package zkcredential implements attribute-based anonymous credentials between a client, an issuing server and a verifying server, after Chase, Perrin and Zaverucha, "The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption".
package zkcredential

// RandomnessLen is the standard size of entropy for operations.
// zkcredential uses explicit arrays of randomness rather than random number
// generators because it makes it easier to write expected-output tests.
const RandomnessLen = 32

// ErrVerificationType is the typed error for a failed zkcredential verification.
type ErrVerificationType struct{}

func (e *ErrVerificationType) Error() string {
	return "zkcredential: verification failed"
}

// ErrVerification indicates that a zkcredential operation failed to verify.
var ErrVerification error = &ErrVerificationType{}
