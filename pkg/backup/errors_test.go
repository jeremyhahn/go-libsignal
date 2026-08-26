package backup

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// TestBackupErrorTypes exercises the Error() and Unwrap() methods on all
// backup error types. These guards regressions in error messaging and wrapping.

func TestErrDecryptingBackup(t *testing.T) {
	inner := errors.New("aes failure")
	err := &ErrDecryptingBackup{Err: inner}
	msg := err.Error()
	if !strings.Contains(msg, "aes failure") {
		t.Errorf("ErrDecryptingBackup.Error() = %q, want to contain inner error", msg)
	}
	if !errors.Is(err, inner) {
		t.Error("ErrDecryptingBackup.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrWritingFrame(t *testing.T) {
	inner := io.ErrClosedPipe
	err := &ErrWritingFrame{Err: inner}
	if !strings.Contains(err.Error(), "compressor") {
		t.Errorf("ErrWritingFrame.Error() = %q, want to mention compressor", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrWritingFrame.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrClosingGzipWriter(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrClosingGzipWriter{Err: inner}
	if !strings.Contains(err.Error(), "gzip") {
		t.Errorf("ErrClosingGzipWriter.Error() = %q, want to mention gzip", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrClosingGzipWriter.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrGeneratingIV(t *testing.T) {
	inner := errors.New("rand failure")
	err := &ErrGeneratingIV{Err: inner}
	if !strings.Contains(err.Error(), "IV") {
		t.Errorf("ErrGeneratingIV.Error() = %q, want to mention IV", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrGeneratingIV.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrCreatingAESCipher(t *testing.T) {
	inner := errors.New("bad key")
	err := &ErrCreatingAESCipher{Err: inner}
	if !strings.Contains(err.Error(), "AES") {
		t.Errorf("ErrCreatingAESCipher.Error() = %q, want to mention AES", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrCreatingAESCipher.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrWritingOutput(t *testing.T) {
	inner := io.ErrClosedPipe
	err := &ErrWritingOutput{Field: "IV", Err: inner}
	if !strings.Contains(err.Error(), "IV") {
		t.Errorf("ErrWritingOutput.Error() = %q, want to contain field name", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrWritingOutput.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrReadingEncryptedData(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrReadingEncryptedData{Err: inner}
	if !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("ErrReadingEncryptedData.Error() = %q, want to mention encrypted", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrReadingEncryptedData.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrDataTooShort(t *testing.T) {
	err := &ErrDataTooShort{Length: 5, MinLen: 48}
	msg := err.Error()
	if !strings.Contains(msg, "5") || !strings.Contains(msg, "48") {
		t.Errorf("ErrDataTooShort.Error() = %q, want to contain length and min", msg)
	}
}

func TestErrCiphertextNotAligned(t *testing.T) {
	err := &ErrCiphertextNotAligned{Length: 17, BlockSize: 16}
	msg := err.Error()
	if !strings.Contains(msg, "17") || !strings.Contains(msg, "16") {
		t.Errorf("ErrCiphertextNotAligned.Error() = %q, want to contain length and block size", msg)
	}
}

func TestErrRemovingPadding(t *testing.T) {
	inner := errors.New("bad pad value")
	err := &ErrRemovingPadding{Err: inner}
	if !strings.Contains(err.Error(), "padding") {
		t.Errorf("ErrRemovingPadding.Error() = %q, want to mention padding", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrRemovingPadding.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrCreatingGzipReader(t *testing.T) {
	inner := errors.New("not gzip data")
	err := &ErrCreatingGzipReader{Err: inner}
	if !strings.Contains(err.Error(), "gzip") {
		t.Errorf("ErrCreatingGzipReader.Error() = %q, want to mention gzip", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrCreatingGzipReader.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrClosingGzipReader(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrClosingGzipReader{Err: inner}
	if !strings.Contains(err.Error(), "gzip") {
		t.Errorf("ErrClosingGzipReader.Error() = %q, want to mention gzip", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrClosingGzipReader.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrReadingFrame(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrReadingFrame{Err: inner}
	if !strings.Contains(err.Error(), "frame") {
		t.Errorf("ErrReadingFrame.Error() = %q, want to mention frame", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrReadingFrame.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrEmptyUnpadData(t *testing.T) {
	err := &ErrEmptyUnpadData{}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrEmptyUnpadData.Error() should not be empty")
	}
	if !strings.Contains(msg, "empty") {
		t.Errorf("ErrEmptyUnpadData.Error() = %q, want to mention empty", msg)
	}
}

func TestErrUnpadNotAligned(t *testing.T) {
	err := &ErrUnpadNotAligned{Length: 33, BlockSize: 16}
	msg := err.Error()
	if !strings.Contains(msg, "33") || !strings.Contains(msg, "16") {
		t.Errorf("ErrUnpadNotAligned.Error() = %q, want to contain 33 and 16", msg)
	}
}

func TestErrInvalidPadding(t *testing.T) {
	err := &ErrInvalidPadding{}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrInvalidPadding.Error() should not be empty")
	}
	if !strings.Contains(msg, "padding") {
		t.Errorf("ErrInvalidPadding.Error() = %q, want to mention padding", msg)
	}
}

func TestErrInvalidEntropyPool(t *testing.T) {
	inner := errors.New("pool too short")
	err := &ErrInvalidEntropyPool{Err: inner}
	if !strings.Contains(err.Error(), "entropy") {
		t.Errorf("ErrInvalidEntropyPool.Error() = %q, want to mention entropy", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrInvalidEntropyPool.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrSecuringSecret(t *testing.T) {
	inner := errors.New("locked-memory allocation error")
	err := &ErrSecuringSecret{Operation: "HMAC key", Err: inner}
	if !strings.Contains(err.Error(), "HMAC key") {
		t.Errorf("ErrSecuringSecret.Error() = %q, want to contain operation name", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrSecuringSecret.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrDerivingKey(t *testing.T) {
	inner := errors.New("hkdf failure")
	err := &ErrDerivingKey{KeyType: "backup key", Err: inner}
	if !strings.Contains(err.Error(), "backup key") {
		t.Errorf("ErrDerivingKey.Error() = %q, want to contain key type", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrDerivingKey.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrInvalidACIKind(t *testing.T) {
	err := &ErrInvalidACIKind{Kind: 0x02}
	msg := err.Error()
	if !strings.Contains(msg, "0x02") {
		t.Errorf("ErrInvalidACIKind.Error() = %q, want to contain kind 0x02", msg)
	}
}

func TestErrReadingDelimitedMessage(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrReadingDelimitedMessage{Err: inner}
	if !strings.Contains(err.Error(), "delimited") {
		t.Errorf("ErrReadingDelimitedMessage.Error() = %q, want to mention delimited", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrReadingDelimitedMessage.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrInvalidVarint(t *testing.T) {
	err := &ErrInvalidVarint{}
	msg := err.Error()
	if msg == "" {
		t.Error("ErrInvalidVarint.Error() should not be empty")
	}
	if !strings.Contains(msg, "varint") {
		t.Errorf("ErrInvalidVarint.Error() = %q, want to mention varint", msg)
	}
}

func TestErrVarintOverflow(t *testing.T) {
	err := &ErrVarintOverflow{Value: 1000, Max: 500}
	msg := err.Error()
	if !strings.Contains(msg, "1000") || !strings.Contains(msg, "500") {
		t.Errorf("ErrVarintOverflow.Error() = %q, want to contain value and max", msg)
	}
}

func TestErrReadingVarint(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrReadingVarint{Err: inner}
	if !strings.Contains(err.Error(), "varint") {
		t.Errorf("ErrReadingVarint.Error() = %q, want to mention varint", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrReadingVarint.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrWritingVarintLength(t *testing.T) {
	inner := io.ErrClosedPipe
	err := &ErrWritingVarintLength{Err: inner}
	if !strings.Contains(err.Error(), "varint") {
		t.Errorf("ErrWritingVarintLength.Error() = %q, want to mention varint", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrWritingVarintLength.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrWritingDelimitedMessage(t *testing.T) {
	inner := io.ErrClosedPipe
	err := &ErrWritingDelimitedMessage{Err: inner}
	if !strings.Contains(err.Error(), "delimited") {
		t.Errorf("ErrWritingDelimitedMessage.Error() = %q, want to mention delimited", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrWritingDelimitedMessage.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrUnknownPurpose(t *testing.T) {
	err := &ErrUnknownPurpose{Value: "bogus"}
	msg := err.Error()
	if !strings.Contains(msg, "bogus") {
		t.Errorf("ErrUnknownPurpose.Error() = %q, want to contain the value", msg)
	}
}

func TestErrReadingMagicNumber(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrReadingMagicNumber{Err: inner}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("ErrReadingMagicNumber.Error() = %q, want to mention magic", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrReadingMagicNumber.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrReadingHMACData(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrReadingHMACData{Err: inner}
	if !strings.Contains(err.Error(), "HMAC") {
		t.Errorf("ErrReadingHMACData.Error() = %q, want to mention HMAC", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrReadingHMACData.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrBackupTooLarge(t *testing.T) {
	err := &ErrBackupTooLarge{MaxBytes: 1024}
	msg := err.Error()
	if !strings.Contains(msg, "1024") {
		t.Errorf("ErrBackupTooLarge.Error() = %q, want to contain max size", msg)
	}
	if !strings.Contains(msg, "maximum") {
		t.Errorf("ErrBackupTooLarge.Error() = %q, want to mention maximum", msg)
	}
}

func TestErrBackupTooLarge_Error(t *testing.T) {
	err := &ErrInvalidBackupMagic{Got: []byte{0x53, 0x42, 0x41, 0x43}}
	msg := err.Error()
	if !strings.Contains(msg, "magic") {
		t.Errorf("ErrInvalidBackupMagic.Error() = %q, want to mention magic", msg)
	}
	if !strings.Contains(msg, "53424143") {
		t.Errorf("ErrInvalidBackupMagic.Error() = %q, want to contain got bytes hex", msg)
	}
}

func TestErrReadingMetadataLength(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrReadingMetadataLength{Err: inner}
	if !strings.Contains(err.Error(), "metadata") {
		t.Errorf("ErrReadingMetadataLength.Error() = %q, want metadata", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrReadingMetadataLength.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrReadingMetadata(t *testing.T) {
	inner := io.ErrUnexpectedEOF
	err := &ErrReadingMetadata{Err: inner}
	if !strings.Contains(err.Error(), "metadata") {
		t.Errorf("ErrReadingMetadata.Error() = %q, want metadata", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("ErrReadingMetadata.Unwrap() should expose inner via errors.Is")
	}
}

func TestErrInvalidKeyLength(t *testing.T) {
	err := &ErrInvalidKeyLength{Field: "hmac_key", Got: 16, Want: 32}
	msg := err.Error()
	if !strings.Contains(msg, "hmac_key") {
		t.Errorf("ErrInvalidKeyLength.Error() = %q, want field name", msg)
	}
	if !strings.Contains(msg, "32") {
		t.Errorf("ErrInvalidKeyLength.Error() = %q, want want-size 32", msg)
	}
	if !strings.Contains(msg, "16") {
		t.Errorf("ErrInvalidKeyLength.Error() = %q, want got-size 16", msg)
	}
}

func TestFrameTooLargeError(t *testing.T) {
	err := &FrameTooLargeError{Size: 20 * 1024 * 1024, Max: maxFrameSize}
	msg := err.Error()
	if !strings.Contains(msg, "exceeds") {
		t.Errorf("FrameTooLargeError.Error() = %q, want 'exceeds'", msg)
	}
}
