package backup

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
)

const (
	// HMACLen is the byte length of the HMAC-SHA256 digest appended to
	// encrypted backup files.
	HMACLen = 32
	// AESIVSize is the byte length of the AES-256-CBC initialization vector.
	AESIVSize = 16
	// AESBlockSize is the AES block size in bytes.
	AESBlockSize = 16

	// maxBackupSize is the maximum number of bytes accepted from an encrypted
	// backup reader. 100 GiB is a generous upper bound that prevents a
	// malicious or corrupted stream from exhausting memory.
	maxBackupSize = 100 * 1024 * 1024 * 1024 // 100 GiB
)

// HMACMismatchError indicates that the expected HMAC did not match the
// computed HMAC over the backup ciphertext. The actual HMAC values are
// kept unexported to prevent accidental leakage through logging or
// error inspection.
type HMACMismatchError struct {
	expected [HMACLen]byte
	found    [HMACLen]byte
}

func (e *HMACMismatchError) Error() string {
	return "backup: HMAC verification failed"
}

// FrameEncryptor encrypts and writes backup frames. It writes each frame
// as gzip-compressed, AES-256-CBC encrypted, varint-length-delimited data
// with an HMAC-SHA256 appended at the end of the stream.
type FrameEncryptor struct {
	key *MessageBackupKey
}

// NewFrameEncryptor creates a new FrameEncryptor with the given key.
func NewFrameEncryptor(key *MessageBackupKey) *FrameEncryptor {
	return &FrameEncryptor{key: key}
}

// EncryptFrames encrypts a sequence of raw protobuf frame bytes and writes
// the complete encrypted backup to w. The output consists of:
//   - A random 16-byte IV
//   - AES-256-CBC encrypted gzip-compressed frames (varint-delimited)
//   - A 32-byte HMAC-SHA256 over the IV and ciphertext
//
// Each frame in the frames slice should be the raw serialized protobuf bytes
// of a backup Frame message.
func (fe *FrameEncryptor) EncryptFrames(w io.Writer, frames [][]byte) error {
	// Compress frames with varint delimiters.
	var plaintext bytes.Buffer
	gzw := gzip.NewWriter(&plaintext)
	for _, frame := range frames {
		if err := WriteVarintDelimited(gzw, frame); err != nil {
			return &ErrWritingFrame{Err: err}
		}
	}
	if err := gzw.Close(); err != nil {
		return &ErrClosingGzipWriter{Err: err}
	}

	// Generate random IV.
	var iv [AESIVSize]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return &ErrGeneratingIV{Err: err}
	}

	// PKCS#7 pad the plaintext to AES block size.
	padded := pkcs7Pad(plaintext.Bytes(), AESBlockSize)

	// Encrypt with AES-256-CBC.
	block, err := aes.NewCipher(fe.key.AESKey.Bytes())
	if err != nil {
		return &ErrCreatingAESCipher{Err: err}
	}
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv[:])
	mode.CryptBlocks(ciphertext, padded)

	// Compute HMAC over IV + ciphertext.
	mac := hmac.New(sha256.New, fe.key.HMACKey.Bytes())
	mac.Write(iv[:])
	mac.Write(ciphertext)
	hmacDigest := mac.Sum(nil)

	// Write IV + ciphertext + HMAC.
	if _, err := w.Write(iv[:]); err != nil {
		return &ErrWritingOutput{Field: "IV", Err: err}
	}
	if _, err := w.Write(ciphertext); err != nil {
		return &ErrWritingOutput{Field: "ciphertext", Err: err}
	}
	if _, err := w.Write(hmacDigest); err != nil {
		return &ErrWritingOutput{Field: "HMAC", Err: err}
	}
	return nil
}

// FrameDecryptor reads and decrypts backup frames from an encrypted backup.
type FrameDecryptor struct {
	key *MessageBackupKey
}

// NewFrameDecryptor creates a new FrameDecryptor with the given key.
func NewFrameDecryptor(key *MessageBackupKey) *FrameDecryptor {
	return &FrameDecryptor{key: key}
}

// DecryptFrames reads an encrypted backup from r and returns the decrypted
// frames. The input is expected to contain:
//   - A 16-byte IV
//   - AES-256-CBC encrypted gzip-compressed varint-delimited frames
//   - A 32-byte HMAC-SHA256 over the IV and ciphertext
//
// It verifies the HMAC before decrypting. Each returned byte slice is the
// raw serialized protobuf bytes of a backup Frame message.
//
// Reads are bounded to maxBackupSize bytes; larger streams are rejected with
// ErrBackupTooLarge to prevent memory exhaustion from malicious input.
func (fd *FrameDecryptor) DecryptFrames(r io.Reader) (_ [][]byte, err error) {
	// Read all data, bounded to prevent unbounded allocation.
	// We read one byte beyond the limit so we can distinguish "exactly at
	// the limit" from "exceeds the limit".
	limited := io.LimitReader(r, maxBackupSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, &ErrReadingEncryptedData{Err: err}
	}
	if int64(len(data)) > maxBackupSize {
		return nil, &ErrBackupTooLarge{MaxBytes: maxBackupSize}
	}

	if len(data) < AESIVSize+HMACLen {
		return nil, &ErrDataTooShort{Length: len(data), MinLen: AESIVSize + HMACLen}
	}

	// Split into content (IV + ciphertext) and HMAC.
	contentLen := len(data) - HMACLen
	content := data[:contentLen]
	expectedHMAC := data[contentLen:]

	// Verify HMAC.
	mac := hmac.New(sha256.New, fd.key.HMACKey.Bytes())
	mac.Write(content)
	computedHMAC := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expectedHMAC, computedHMAC) != 1 {
		var expected, found [HMACLen]byte
		copy(expected[:], expectedHMAC)
		copy(found[:], computedHMAC)
		return nil, &HMACMismatchError{expected: expected, found: found}
	}

	// Extract IV and ciphertext.
	iv := content[:AESIVSize]
	ciphertext := content[AESIVSize:]

	if len(ciphertext) == 0 || len(ciphertext)%AESBlockSize != 0 {
		return nil, &ErrCiphertextNotAligned{Length: len(ciphertext), BlockSize: AESBlockSize}
	}

	// Decrypt with AES-256-CBC.
	block, err := aes.NewCipher(fd.key.AESKey.Bytes())
	if err != nil {
		return nil, &ErrCreatingAESCipher{Err: err}
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding.
	plaintext, err = pkcs7Unpad(plaintext, AESBlockSize)
	if err != nil {
		return nil, &ErrRemovingPadding{Err: err}
	}

	// Decompress.
	gzr, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, &ErrCreatingGzipReader{Err: err}
	}
	defer func() {
		if cerr := gzr.Close(); cerr != nil && err == nil {
			err = &ErrClosingGzipReader{Err: cerr}
		}
	}()

	// Read varint-delimited frames.
	vr := NewVarintDelimitedReader(gzr)
	var frames [][]byte
	for {
		frame, err := vr.ReadNext()
		if err != nil {
			return nil, &ErrReadingFrame{Err: err}
		}
		if frame == nil {
			break
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// VerifyHMAC checks the HMAC of encrypted backup data without decrypting it.
// The input r should contain the full encrypted backup (IV + ciphertext + HMAC).
func VerifyHMAC(key *MessageBackupKey, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return &ErrReadingHMACData{Err: err}
	}

	if len(data) < AESIVSize+HMACLen {
		return &ErrDataTooShort{Length: len(data), MinLen: AESIVSize + HMACLen}
	}

	contentLen := len(data) - HMACLen
	content := data[:contentLen]
	expectedHMAC := data[contentLen:]

	mac := hmac.New(sha256.New, key.HMACKey.Bytes())
	mac.Write(content)
	computedHMAC := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expectedHMAC, computedHMAC) != 1 {
		var expected, found [HMACLen]byte
		copy(expected[:], expectedHMAC)
		copy(found[:], computedHMAC)
		return &HMACMismatchError{expected: expected, found: found}
	}
	return nil
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7 padding.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpad removes PKCS#7 padding from data using constant-time validation
// to prevent timing side-channels.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, &ErrEmptyUnpadData{}
	}
	if len(data)%blockSize != 0 {
		return nil, &ErrUnpadNotAligned{Length: len(data), BlockSize: blockSize}
	}

	padByte := data[len(data)-1]
	padLen := int(padByte)

	// Constant-time check: padLen must be in [1, blockSize].
	good := subtle.ConstantTimeLessOrEq(1, padLen) &
		subtle.ConstantTimeLessOrEq(padLen, blockSize)

	// Note: We iterate over blockSize bytes (not padLen) because PKCS#7
	// padding is always 1 to blockSize bytes, so blockSize is the correct
	// upper bound. This is correct for AES (blockSize=16).
	for i := 0; i < blockSize; i++ {
		isPad := subtle.ConstantTimeLessOrEq(i+1, padLen)
		match := subtle.ConstantTimeByteEq(data[len(data)-1-i], padByte)
		good &= (isPad & match) | (1 - isPad)
	}

	if good != 1 {
		return nil, &ErrInvalidPadding{}
	}
	return data[:len(data)-padLen], nil
}
