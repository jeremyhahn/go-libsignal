// Package usernames implements Signal username hashing, zero-knowledge proofs,
// and username link encryption/decryption.
package usernames

import "fmt"

// UsernameError represents errors that can occur during username validation.
type UsernameError int

const (
	ErrMissingSeparator UsernameError = iota
	ErrNicknameCannotBeEmpty
	ErrNicknameCannotStartWithDigit
	ErrBadNicknameCharacter
	ErrNicknameTooShort
	ErrNicknameTooLong
	ErrDiscriminatorCannotBeEmpty
	ErrDiscriminatorCannotBeZero
	ErrDiscriminatorCannotBeSingleDigit
	ErrDiscriminatorCannotHaveLeadingZeros
	ErrBadDiscriminatorCharacter
	ErrDiscriminatorTooLarge
)

var usernameErrorMessages = [...]string{
	ErrMissingSeparator:                    "username must contain a '.'",
	ErrNicknameCannotBeEmpty:               "name cannot be empty",
	ErrNicknameCannotStartWithDigit:        "name cannot start with a digit",
	ErrBadNicknameCharacter:                "nickname contains disallowed character",
	ErrNicknameTooShort:                    "nickname is too short",
	ErrNicknameTooLong:                     "nickname is too long",
	ErrDiscriminatorCannotBeEmpty:          "discriminator cannot be empty",
	ErrDiscriminatorCannotBeZero:           "discriminator cannot be zero",
	ErrDiscriminatorCannotBeSingleDigit:    "discriminator cannot be a single digit",
	ErrDiscriminatorCannotHaveLeadingZeros: "discriminator cannot have leading zeros unless it would otherwise be a single digit",
	ErrBadDiscriminatorCharacter:           "discriminator must only be made up of digits",
	ErrDiscriminatorTooLarge:               "value is too large to be a username discriminator",
}

func (e UsernameError) Error() string {
	if int(e) < len(usernameErrorMessages) {
		return usernameErrorMessages[e]
	}
	return fmt.Sprintf("unknown username error: %d", int(e))
}

// ProofVerificationFailure indicates a username proof could not be verified.
type ProofVerificationFailure struct{}

func (e ProofVerificationFailure) Error() string {
	return "username could not be verified"
}

// UsernameLinkError represents errors that can occur during username link operations.
type UsernameLinkError int

const (
	ErrInputDataTooLong UsernameLinkError = iota
	ErrInvalidEntropyDataLength
	ErrUsernameLinkDataTooShort
	ErrHmacMismatch
	ErrBadCiphertext
	ErrInvalidDecryptedDataStructure
)

var usernameLinkErrorMessages = [...]string{
	ErrInputDataTooLong:              "the combined length of all input data is too long",
	ErrInvalidEntropyDataLength:      "invalid size of the entropy data",
	ErrUsernameLinkDataTooShort:      "username link data size is too short: must contain IV, ciphertext, and HMAC",
	ErrHmacMismatch:                  "HMAC on username link doesn't match the one calculated with the given entropy input",
	ErrBadCiphertext:                 "ciphertext in the username link can't be decrypted",
	ErrInvalidDecryptedDataStructure: "data decrypted from the username link is of invalid structure",
}

func (e UsernameLinkError) Error() string {
	if int(e) < len(usernameLinkErrorMessages) {
		return usernameLinkErrorMessages[e]
	}
	return fmt.Sprintf("unknown username link error: %d", int(e))
}

// CryptoError indicates a cryptographic operation failure in username processing.
type CryptoError struct {
	Operation string
	Err       error
}

func (e *CryptoError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("usernames: %s: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("usernames: %s", e.Operation)
}

func (e *CryptoError) Unwrap() error {
	return e.Err
}

// CBCDecryptError indicates a CBC decryption validation failure.
type CBCDecryptError struct {
	Detail string
}

func (e *CBCDecryptError) Error() string {
	return "usernames: " + e.Detail
}

// PKCS7Error indicates a PKCS#7 padding validation failure.
type PKCS7Error struct {
	Detail string
}

func (e *PKCS7Error) Error() string {
	return "usernames: pkcs7 unpad: " + e.Detail
}

// ProtobufError indicates a protobuf encoding/decoding failure.
type ProtobufError struct {
	Detail string
}

func (e *ProtobufError) Error() string {
	return "usernames: protobuf: " + e.Detail
}
