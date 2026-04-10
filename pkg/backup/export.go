package backup

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	libcipher "github.com/jeremyhahn/go-libsignal/pkg/cipher"
)

// ExportError represents an error encountered during backup export operations.
type ExportError struct {
	Op  string
	Err error
}

func (e *ExportError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("backup export: %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("backup export: %s", e.Op)
}

func (e *ExportError) Unwrap() error {
	return e.Err
}

// GzipCompress compresses data using gzip encoding.
func GzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	if _, err := gzw.Write(data); err != nil {
		return nil, &ExportError{Op: "gzip compress write", Err: err}
	}
	if err := gzw.Close(); err != nil {
		return nil, &ExportError{Op: "gzip compress close", Err: err}
	}
	return buf.Bytes(), nil
}

// PadGzippedBucketed pads gzipped data to the bucketed padded length.
// The padding uses zero bytes appended to reach the target length
// determined by PaddedLength. This obscures the exact size of the backup.
func PadGzippedBucketed(data []byte) []byte {
	length := uint32(len(data))
	targetLen := PaddedLength(length)
	if uint32(len(data)) >= targetLen {
		return data
	}
	result := make([]byte, targetLen)
	copy(result, data)
	return result
}

// AESCBCEncryptExport encrypts plaintext using AES-256-CBC with PKCS7 padding
// for backup export. It delegates to the cipher package's AESCBCEncrypt.
//
// The key must be 32 bytes (AES-256). The iv must be 16 bytes.
func AESCBCEncryptExport(key, iv, plaintext []byte) ([]byte, error) {
	ciphertext, err := libcipher.AESCBCEncrypt(key, iv, plaintext)
	if err != nil {
		return nil, &ExportError{Op: "AES-CBC encrypt", Err: err}
	}
	return ciphertext, nil
}

// HMACChecksum computes an HMAC-SHA256 checksum over the IV concatenated
// with the encrypted contents. This matches the Rust hmac_checksum function
// used for backup export.
func HMACChecksum(hmacKey, iv, encryptedContents []byte) []byte {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(iv)
	mac.Write(encryptedContents)
	return mac.Sum(nil)
}
