package cipher

import "fmt"

// ErrCipherInvalidKeySize indicates the key is not exactly 32 bytes (AES-256).
type ErrCipherInvalidKeySize struct {
	Got int
}

func (e *ErrCipherInvalidKeySize) Error() string {
	return fmt.Sprintf("cipher: key must be exactly 32 bytes (AES-256), got %d", e.Got)
}

// Is implements errors.Is matching by type, ignoring the Got field.
func (e *ErrCipherInvalidKeySize) Is(target error) bool {
	_, ok := target.(*ErrCipherInvalidKeySize)
	return ok
}

// ErrCipherCiphertextTooShort indicates the ciphertext is shorter than the AES block size.
type ErrCipherCiphertextTooShort struct{}

func (e *ErrCipherCiphertextTooShort) Error() string {
	return "cipher: ciphertext too short"
}

// ErrCipherInvalidBlockSize indicates a block size <= 0 was provided to PKCS7 padding.
type ErrCipherInvalidBlockSize struct {
	Got int
}

func (e *ErrCipherInvalidBlockSize) Error() string {
	return fmt.Sprintf("cipher: invalid block size %d", e.Got)
}

// Is implements errors.Is matching by type, ignoring the Got field.
func (e *ErrCipherInvalidBlockSize) Is(target error) bool {
	_, ok := target.(*ErrCipherInvalidBlockSize)
	return ok
}

// ErrCipherInvalidPKCS7Data indicates empty or unpadded input to PKCS7 pad/unpad.
type ErrCipherInvalidPKCS7Data struct{}

func (e *ErrCipherInvalidPKCS7Data) Error() string {
	return "cipher: invalid PKCS7 data (empty or not padded)"
}

// ErrCipherInvalidPKCS7Padding indicates the PKCS7 padding bytes are malformed.
type ErrCipherInvalidPKCS7Padding struct{}

func (e *ErrCipherInvalidPKCS7Padding) Error() string {
	return "cipher: invalid padding on input"
}

// Sentinel variables for backward-compatible errors.Is matching.
var (
	// ErrInvalidKeySize is returned when the key is not exactly 32 bytes (AES-256).
	ErrInvalidKeySize error = &ErrCipherInvalidKeySize{}

	// ErrCiphertextTooShort is returned when the ciphertext is shorter than the AES block size.
	ErrCiphertextTooShort error = &ErrCipherCiphertextTooShort{}

	// ErrInvalidBlockSize is returned when a block size <= 0 is provided to PKCS7 functions.
	ErrInvalidBlockSize error = &ErrCipherInvalidBlockSize{}

	// ErrInvalidPKCS7Data is returned for empty or unpadded input to PKCS7 functions.
	ErrInvalidPKCS7Data error = &ErrCipherInvalidPKCS7Data{}

	// ErrInvalidPKCS7Padding is returned when PKCS7 padding bytes are malformed.
	ErrInvalidPKCS7Padding error = &ErrCipherInvalidPKCS7Padding{}
)

// ErrAESGCMSIVKeySize indicates the key is not the required size for AES-GCM-SIV.
type ErrAESGCMSIVKeySize struct {
	Expected int
	Got      int
}

func (e *ErrAESGCMSIVKeySize) Error() string {
	return fmt.Sprintf("aesgcmsiv: key must be %d bytes, got %d", e.Expected, e.Got)
}

// ErrAESGCMSIVNonceSize indicates the nonce is not the required size for AES-GCM-SIV.
type ErrAESGCMSIVNonceSize struct {
	Expected int
	Got      int
}

func (e *ErrAESGCMSIVNonceSize) Error() string {
	return fmt.Sprintf("aesgcmsiv: nonce must be %d bytes, got %d", e.Expected, e.Got)
}

// ErrAESGCMSIVProtectKey indicates a failure protecting the key in guarded memory.
type ErrAESGCMSIVProtectKey struct {
	Err error
}

func (e *ErrAESGCMSIVProtectKey) Error() string {
	return fmt.Sprintf("aesgcmsiv: failed to protect key: %v", e.Err)
}

func (e *ErrAESGCMSIVProtectKey) Unwrap() error {
	return e.Err
}

// ErrAESGCMSIVIncorrectNonce indicates the nonce length is incorrect for Open.
type ErrAESGCMSIVIncorrectNonce struct{}

func (e *ErrAESGCMSIVIncorrectNonce) Error() string {
	return "aesgcmsiv: incorrect nonce length"
}

// ErrAESGCMSIVCiphertextTooShort indicates the ciphertext is too short
// to contain the authentication tag.
type ErrAESGCMSIVCiphertextTooShort struct{}

func (e *ErrAESGCMSIVCiphertextTooShort) Error() string {
	return "aesgcmsiv: ciphertext too short"
}

// ErrAESGCMSIVKeyDerivation indicates a failure during per-message key derivation.
type ErrAESGCMSIVKeyDerivation struct {
	Err error
}

func (e *ErrAESGCMSIVKeyDerivation) Error() string {
	return fmt.Sprintf("aesgcmsiv: key derivation failed: %v", e.Err)
}

func (e *ErrAESGCMSIVKeyDerivation) Unwrap() error {
	return e.Err
}

// ErrAESGCMSIVTagComputation indicates a failure computing the authentication tag.
type ErrAESGCMSIVTagComputation struct {
	Err error
}

func (e *ErrAESGCMSIVTagComputation) Error() string {
	return fmt.Sprintf("aesgcmsiv: tag computation failed: %v", e.Err)
}

func (e *ErrAESGCMSIVTagComputation) Unwrap() error {
	return e.Err
}

// ErrAESGCMSIVAuthFailed indicates the authentication tag did not match
// during decryption.
type ErrAESGCMSIVAuthFailed struct{}

func (e *ErrAESGCMSIVAuthFailed) Error() string {
	return "aesgcmsiv: authentication failed"
}

// ErrAESCTRKeySize indicates the AES-CTR key is not 32 bytes.
type ErrAESCTRKeySize struct{}

func (e *ErrAESCTRKeySize) Error() string {
	return "cipher: AES-CTR key must be 32 bytes"
}

// ErrInvalidKeyLength indicates the provided key is not the required length.
// Mirrors Rust signal_crypto::Error::InvalidKeySize.
type ErrInvalidKeyLength struct {
	Got      int
	Expected int
}

func (e *ErrInvalidKeyLength) Error() string {
	return fmt.Sprintf("cipher: key must be %d bytes, got %d", e.Expected, e.Got)
}

// Is implements errors.Is matching by type, ignoring field values.
func (e *ErrInvalidKeyLength) Is(target error) bool {
	_, ok := target.(*ErrInvalidKeyLength)
	return ok
}

// ErrInvalidNonceLength indicates the provided nonce is not the required length.
// Mirrors Rust signal_crypto::Error::InvalidNonceSize.
type ErrInvalidNonceLength struct {
	Got      int
	Expected int
}

func (e *ErrInvalidNonceLength) Error() string {
	return fmt.Sprintf("cipher: nonce must be %d bytes, got %d", e.Expected, e.Got)
}

// Is implements errors.Is matching by type, ignoring field values.
func (e *ErrInvalidNonceLength) Is(target error) bool {
	_, ok := target.(*ErrInvalidNonceLength)
	return ok
}

// ErrAESCTRInputTooLong indicates the input exceeds the maximum safe length
// for AES-CTR with a 32-bit counter ((2^32 - 1) * 16 bytes).
type ErrAESCTRInputTooLong struct {
	Length int64
	Max    int64
}

func (e *ErrAESCTRInputTooLong) Error() string {
	return fmt.Sprintf("cipher: AES-CTR input length %d exceeds maximum %d for 32-bit counter", e.Length, e.Max)
}

// ErrAESCBCInvalidKey indicates the key length is not 32 bytes (AES-256).
// Only AES-256 is supported to match the Rust libsignal reference.
type ErrAESCBCInvalidKey struct {
	Got int
}

func (e *ErrAESCBCInvalidKey) Error() string {
	return fmt.Sprintf("aescbc: key must be 32 bytes (AES-256), got %d", e.Got)
}

// ErrAESCBCInvalidIVSize indicates the IV is not the correct size for AES-CBC.
type ErrAESCBCInvalidIVSize struct {
	Got int
}

func (e *ErrAESCBCInvalidIVSize) Error() string {
	return fmt.Sprintf("aescbc: IV must be 16 bytes, got %d", e.Got)
}

// ErrAESCBCCiphertextNotAligned indicates the ciphertext length is not a
// multiple of the AES block size.
type ErrAESCBCCiphertextNotAligned struct {
	Length    int
	BlockSize int
}

func (e *ErrAESCBCCiphertextNotAligned) Error() string {
	return fmt.Sprintf("aescbc: ciphertext length %d is not a multiple of block size %d", e.Length, e.BlockSize)
}

// ErrAESCBCCiphertextEmpty indicates the ciphertext is empty.
type ErrAESCBCCiphertextEmpty struct{}

func (e *ErrAESCBCCiphertextEmpty) Error() string {
	return "aescbc: ciphertext is empty"
}

// ErrAESGCMSIVPlaintextTooLong indicates the plaintext exceeds the RFC 8452
// maximum of 2^36 - 32 bytes for AES-GCM-SIV.
// Rust source: aes-gcm-siv crate enforces this limit per RFC 8452 §6.
type ErrAESGCMSIVPlaintextTooLong struct {
	Length int
}

func (e *ErrAESGCMSIVPlaintextTooLong) Error() string {
	return fmt.Sprintf("aesgcmsiv: plaintext length %d exceeds RFC 8452 §6 maximum of %d bytes",
		e.Length, aesGCMSIVMaxPlaintextLen)
}
