package backup

import (
	"bytes"
	"fmt"
	"io"
)

const (
	// MagicNumber is the 8-byte magic number that identifies a backup file
	// using the forward secrecy format. It consists of "SBACKUP" followed
	// by a version byte (0x01).
	MagicNumber = "SBACKUP\x01"

	// MagicNumberLen is the byte length of the magic number.
	MagicNumberLen = 8

	// BackupForwardSecrecyTokenLen is the byte length of the forward
	// secrecy token used for backup key derivation. Matches
	// BACKUP_FORWARD_SECRECY_TOKEN_LEN from Rust libsignal.
	BackupForwardSecrecyTokenLen = 32

	// ctMACLen is the truncated HMAC-SHA256 length appended to the
	// encrypted forward secrecy token ciphertext.
	ctMACLen = 16

	// backupMetadataIVLen is the expected length of the metadata IV.
	backupMetadataIVLen = 12

	// expectedCTLen is the expected length of the ciphertext field in a
	// forward secrecy pair: token + MAC.
	expectedCTLen = BackupForwardSecrecyTokenLen + ctMACLen

	// expectedPWSaltLen is the expected length of the password salt field,
	// matching SHA-256 output size.
	expectedPWSaltLen = 32

	// maxForwardSecrecyPairs is the maximum number of forward secrecy
	// pairs allowed in the metadata.
	maxForwardSecrecyPairs = 2
)

// ForwardSecrecyError represents an error encountered during forward
// secrecy metadata validation.
type ForwardSecrecyError struct {
	Kind    ForwardSecrecyErrorKind
	Message string
}

// ForwardSecrecyErrorKind categorizes forward secrecy errors.
type ForwardSecrecyErrorKind int

const (
	// ForwardSecrecyErrorMissingField indicates a required field is absent
	// from the metadata.
	ForwardSecrecyErrorMissingField ForwardSecrecyErrorKind = iota

	// ForwardSecrecyErrorInvalidLength indicates a field has an unexpected
	// byte length.
	ForwardSecrecyErrorInvalidLength

	// ForwardSecrecyErrorTooManyPairs indicates too many forward secrecy
	// pairs were found in the metadata.
	ForwardSecrecyErrorTooManyPairs

	// ForwardSecrecyErrorIO indicates an I/O error during reading.
	ForwardSecrecyErrorIO

	// ForwardSecrecyErrorInvalidData indicates malformed metadata.
	ForwardSecrecyErrorInvalidData
)

func (e *ForwardSecrecyError) Error() string {
	return fmt.Sprintf("backup: forward secrecy: %s", e.Message)
}

// ForwardSecrecyPair represents a single forward secrecy key pair in
// the backup metadata. Each pair contains an encrypted token (ciphertext
// with appended MAC) and a password salt used for key derivation.
type ForwardSecrecyPair struct {
	// CT is the encrypted forward secrecy token with appended MAC.
	// Its length must be BackupForwardSecrecyTokenLen + ctMACLen (48 bytes).
	CT []byte

	// PWSalt is the password salt used for HKDF key derivation.
	// Its length must be 32 bytes (SHA-256 output size).
	PWSalt []byte
}

// BackupMetadata represents the unencrypted metadata blob in a forward
// secrecy backup file. It appears after the magic number and before the
// encrypted backup data.
type BackupMetadata struct {
	// IV is the initialization vector for the metadata encryption.
	// Its length must be backupMetadataIVLen (12 bytes).
	IV []byte

	// Pairs contains the forward secrecy key pairs. There must be
	// 1 or 2 pairs: 2 is the common case (current key + replacement),
	// 1 occurs when there is no key currently on the service.
	Pairs []ForwardSecrecyPair
}

// ValidateMetadata validates a BackupMetadata according to the Signal
// backup specification. It checks that all required fields are present
// and have the correct lengths.
func ValidateMetadata(m *BackupMetadata) error {
	if len(m.Pairs) == 0 {
		return &ForwardSecrecyError{
			Kind:    ForwardSecrecyErrorMissingField,
			Message: "missing field 'pair' in unencrypted metadata",
		}
	}
	if len(m.Pairs) > maxForwardSecrecyPairs {
		return &ForwardSecrecyError{
			Kind: ForwardSecrecyErrorTooManyPairs,
			Message: fmt.Sprintf(
				"unencrypted metadata contains %d forward secrecy pairs",
				len(m.Pairs)),
		}
	}

	for _, pair := range m.Pairs {
		if len(pair.CT) == 0 {
			return &ForwardSecrecyError{
				Kind:    ForwardSecrecyErrorMissingField,
				Message: "missing field 'pair.ct' in unencrypted metadata",
			}
		}
		if len(pair.CT) != expectedCTLen {
			return &ForwardSecrecyError{
				Kind: ForwardSecrecyErrorInvalidLength,
				Message: fmt.Sprintf(
					"unencrypted metadata field 'pair.ct' was %d bytes long (expected %d)",
					len(pair.CT), expectedCTLen),
			}
		}
		if len(pair.PWSalt) == 0 {
			return &ForwardSecrecyError{
				Kind:    ForwardSecrecyErrorMissingField,
				Message: "missing field 'pair.pw_salt' in unencrypted metadata",
			}
		}
		if len(pair.PWSalt) != expectedPWSaltLen {
			return &ForwardSecrecyError{
				Kind: ForwardSecrecyErrorInvalidLength,
				Message: fmt.Sprintf(
					"unencrypted metadata field 'pair.pw_salt' was %d bytes long (expected %d)",
					len(pair.PWSalt), expectedPWSaltLen),
			}
		}
	}

	if len(m.IV) != backupMetadataIVLen {
		return &ForwardSecrecyError{
			Kind: ForwardSecrecyErrorInvalidLength,
			Message: fmt.Sprintf(
				"unencrypted metadata field 'iv' was %d bytes long (expected %d)",
				len(m.IV), backupMetadataIVLen),
		}
	}

	return nil
}

// IsMagicNumber checks whether the given data starts with the forward
// secrecy backup magic number ("SBACKUP\x01").
func IsMagicNumber(data []byte) bool {
	if len(data) < MagicNumberLen {
		return false
	}
	return bytes.Equal(data[:MagicNumberLen], []byte(MagicNumber))
}

// IsCloseToMagicNumber checks whether the given data starts with the
// "SBACKUP" prefix but has a different version byte. This is used to
// warn about potentially misidentified backup files.
func IsCloseToMagicNumber(data []byte) bool {
	if len(data) < MagicNumberLen {
		return false
	}
	prefix := []byte(MagicNumber[:MagicNumberLen-1])
	return bytes.Equal(data[:MagicNumberLen-1], prefix) && data[MagicNumberLen-1] != MagicNumber[MagicNumberLen-1]
}

// ReadMagicNumber reads exactly MagicNumberLen bytes from r and returns
// them. Returns an error if not enough bytes are available.
func ReadMagicNumber(r io.Reader) ([]byte, error) {
	magic := make([]byte, MagicNumberLen)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, &ErrReadingMagicNumber{Err: err}
	}
	return magic, nil
}

// DetectFormat reads the magic number from r and determines whether
// the backup uses the forward secrecy format (modern) or the legacy
// ciphertext-only format. It returns the magic number bytes and a
// boolean indicating whether the format is modern (true) or legacy
// (false).
func DetectFormat(r io.Reader) (magic []byte, isModern bool, err error) {
	magic, err = ReadMagicNumber(r)
	if err != nil {
		return nil, false, err
	}
	if IsMagicNumber(magic) {
		return magic, true, nil
	}
	return magic, false, nil
}

// NewBackupMetadata creates a BackupMetadata with the given IV and pairs.
// It validates the metadata before returning it.
func NewBackupMetadata(iv []byte, pairs []ForwardSecrecyPair) (*BackupMetadata, error) {
	m := &BackupMetadata{
		IV:    iv,
		Pairs: pairs,
	}
	if err := ValidateMetadata(m); err != nil {
		return nil, err
	}
	return m, nil
}

// TestMetadata creates a valid BackupMetadata suitable for testing,
// matching the Rust test_metadata() function. It contains a 12-byte
// zero IV and two pairs with predictable values.
func TestMetadata() *BackupMetadata {
	return &BackupMetadata{
		IV: make([]byte, backupMetadataIVLen),
		Pairs: []ForwardSecrecyPair{
			{
				CT:     bytes.Repeat([]byte{1}, expectedCTLen),
				PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen),
			},
			{
				CT:     bytes.Repeat([]byte{3}, expectedCTLen),
				PWSalt: bytes.Repeat([]byte{4}, expectedPWSaltLen),
			},
		},
	}
}
