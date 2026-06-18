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
	"encoding/binary"
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
// frames. The input may be in either the legacy format or the modern format:
//
// Legacy format:
//   - A 16-byte IV
//   - AES-256-CBC encrypted gzip-compressed varint-delimited frames
//   - A 32-byte HMAC-SHA256 over the IV and ciphertext
//
// Modern format (Rust libsignal ref: rust/message-backup/src/frame.rs:92-117):
//   - "SBACKUP\x01" magic (8 bytes)
//   - varint-length-delimited MetadataPb protobuf
//   - A 16-byte IV
//   - AES-256-CBC encrypted gzip-compressed varint-delimited frames
//   - A 32-byte HMAC-SHA256 over the IV and ciphertext only (not the magic or metadata)
//
// The format is detected by peeking the first 8 bytes. If they match
// MagicNumber, the metadata is parsed and validated via ValidateMetadata
// before the payload is decrypted using the standard CBC+HMAC path.
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

	// Detect format by peeking the magic number.
	payload := data
	if IsMagicNumber(data) {
		// Modern format: parse and validate metadata, then strip the header.
		payload, err = stripModernHeader(data)
		if err != nil {
			return nil, err
		}
	} else if IsCloseToMagicNumber(data) {
		return nil, &ErrInvalidBackupMagic{Got: data[:MagicNumberLen]}
	}
	// else: legacy format, payload == data.

	if len(payload) < AESIVSize+HMACLen {
		return nil, &ErrDataTooShort{Length: len(payload), MinLen: AESIVSize + HMACLen}
	}

	// Split into content (IV + ciphertext) and HMAC.
	contentLen := len(payload) - HMACLen
	content := payload[:contentLen]
	expectedHMAC := payload[contentLen:]

	// Verify HMAC over IV + ciphertext.
	mac := hmac.New(sha256.New, fd.key.HMACKey.Bytes())
	mac.Write(content)
	computedHMAC := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expectedHMAC, computedHMAC) != 1 {
		var expected, found [HMACLen]byte
		copy(expected[:], expectedHMAC)
		copy(found[:], computedHMAC)
		return nil, &HMACMismatchError{expected: expected, found: found}
	}

	return fd.decryptPayload(content)
}

// decryptPayload decrypts the IV||ciphertext content (without HMAC) and
// returns the varint-delimited frames. This is shared between legacy and
// modern format after HMAC verification.
func (fd *FrameDecryptor) decryptPayload(content []byte) (_ [][]byte, err error) {
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
	// Rust libsignal's pad_gzipped_bucketed (rust/message-backup/src/export.rs:26)
	// appends zero bytes after the gzip stream to round the encrypted region up
	// to a bucketed length, then PKCS7-pads the result for AES-CBC. After
	// decrypt+unpad those trailing zeros remain. Disable multistream so the
	// reader returns EOF at the end of the first gzip stream rather than
	// trying to parse the trailing zeros as a second gzip header.
	gzr.Multistream(false)
	defer func() {
		if cerr := gzr.Close(); cerr != nil && err == nil {
			err = &ErrClosingGzipReader{Err: cerr}
		}
	}()

	// Read varint-delimited frames.
	vr := NewVarintDelimitedReader(gzr)
	var frames [][]byte
	for {
		frame, ferr := vr.ReadNext()
		if ferr != nil {
			return nil, &ErrReadingFrame{Err: ferr}
		}
		if frame == nil {
			break
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// stripModernHeader parses the modern SBACKUP\x01 header from data. It
// returns the payload (IV||ciphertext||HMAC) and any error. ValidateMetadata
// is called on the parsed metadata before returning.
//
// Rust libsignal ref: rust/message-backup/src/frame/forward_secrecy.rs verify_metadata
func stripModernHeader(data []byte) (payload []byte, err error) {
	// Skip the 8-byte magic; it was already verified by the caller.
	off := MagicNumberLen

	// Read the varint-encoded metadata length.
	metaLen, n := binary.Uvarint(data[off:])
	if n <= 0 {
		return nil, &ErrReadingMetadataLength{Err: &ErrInvalidVarint{}}
	}
	off += n

	// Guard against overflow: compare metaLen against the remaining bytes
	// without adding to avoid uint64 wraparound when metaLen is near 2^64-1.
	if metaLen > uint64(len(data)-off) {
		return nil, &ErrReadingMetadata{Err: &ErrDataTooShort{
			Length: len(data) - off,
			MinLen: int(metaLen),
		}}
	}

	metaBytes := data[off : off+int(metaLen)]
	off += int(metaLen)

	// Decode MetadataPb bytes into BackupMetadata and validate.
	meta, err := decodeMetadataPb(metaBytes)
	if err != nil {
		return nil, &ErrMetadataValidation{Err: err}
	}
	if err := ValidateMetadata(meta); err != nil {
		return nil, &ErrMetadataValidation{Err: err}
	}

	return data[off:], nil
}

// decodeMetadataPb decodes a MetadataPb protobuf wire-format byte slice into
// a BackupMetadata struct. It implements the minimal protobuf wire-format
// decoder needed for this specific message type without requiring a generated
// .pb.go file.
//
// MetadataPb wire format (rust/svrb/src/proto/backup_metadata.proto):
//
//	message MetadataPb {
//	  repeated Pair pair = 1; // field 1, wire type 2 (LEN)
//	  bytes iv = 2;           // field 2, wire type 2 (LEN)
//	  message Pair {
//	    bytes ct = 1;         // field 1, wire type 2 (LEN)
//	    bytes pw_salt = 2;    // field 2, wire type 2 (LEN)
//	  }
//	}
func decodeMetadataPb(b []byte) (*BackupMetadata, error) {
	var meta BackupMetadata
	for len(b) > 0 {
		// Read field tag varint.
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, &ErrInvalidVarint{}
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 7

		// All fields in MetadataPb use wire type 2 (LEN).
		if wireType != 2 {
			// Skip unknown wire types: read and discard.
			var err error
			b, err = skipProtoField(b, wireType)
			if err != nil {
				return nil, err
			}
			continue
		}

		// Read the length-delimited value.
		length, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, &ErrInvalidVarint{}
		}
		b = b[n:]
		if uint64(len(b)) < length {
			return nil, &ErrDataTooShort{Length: len(b), MinLen: int(length)}
		}
		val := b[:length]
		b = b[length:]

		switch fieldNum {
		case 1: // repeated Pair pair
			pair, err := decodeForwardSecrecyPair(val)
			if err != nil {
				return nil, err
			}
			meta.Pairs = append(meta.Pairs, *pair)
		case 2: // bytes iv
			iv := make([]byte, len(val))
			copy(iv, val)
			meta.IV = iv
		}
		// Unknown fields are silently ignored per proto3 rules.
	}
	return &meta, nil
}

// decodeForwardSecrecyPair decodes a MetadataPb.Pair submessage.
func decodeForwardSecrecyPair(b []byte) (*ForwardSecrecyPair, error) {
	var pair ForwardSecrecyPair
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, &ErrInvalidVarint{}
		}
		b = b[n:]
		fieldNum := tag >> 3
		wireType := tag & 7

		if wireType != 2 {
			var err error
			b, err = skipProtoField(b, wireType)
			if err != nil {
				return nil, err
			}
			continue
		}

		length, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, &ErrInvalidVarint{}
		}
		b = b[n:]
		if uint64(len(b)) < length {
			return nil, &ErrDataTooShort{Length: len(b), MinLen: int(length)}
		}
		val := b[:length]
		b = b[length:]

		switch fieldNum {
		case 1: // bytes ct
			ct := make([]byte, len(val))
			copy(ct, val)
			pair.CT = ct
		case 2: // bytes pw_salt
			salt := make([]byte, len(val))
			copy(salt, val)
			pair.PWSalt = salt
		}
	}
	return &pair, nil
}

// skipProtoField skips one protobuf field value of the given wire type.
// Returns the remaining bytes after the field, or an *ErrInvalidProtoWireFormat
// if the wire type is unsupported or the encoded value is truncated.
func skipProtoField(b []byte, wireType uint64) ([]byte, error) {
	switch wireType {
	case 0: // varint
		_, n := binary.Uvarint(b)
		if n <= 0 {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated varint"}
		}
		return b[n:], nil
	case 1: // 64-bit
		if len(b) < 8 {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated 64-bit field"}
		}
		return b[8:], nil
	case 2: // length-delimited
		length, n := binary.Uvarint(b)
		if n <= 0 {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated length varint"}
		}
		b = b[n:]
		if uint64(len(b)) < length {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "length-delimited field truncated"}
		}
		return b[length:], nil
	case 5: // 32-bit
		if len(b) < 4 {
			return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "truncated 32-bit field"}
		}
		return b[4:], nil
	default:
		return b, &ErrInvalidProtoWireFormat{WireType: wireType, Reason: "unsupported wire type"}
	}
}

// EncryptFramesModern encrypts a sequence of raw protobuf frame bytes and
// writes a modern-format backup to w. The output consists of:
//   - "SBACKUP\x01" magic (8 bytes)
//   - varint-length-delimited encoded BackupMetadata
//   - A random 16-byte IV
//   - AES-256-CBC encrypted gzip-compressed frames (varint-delimited)
//   - A 32-byte HMAC-SHA256 over the IV and ciphertext only
//
// The metadata is validated by ValidateMetadata before encoding. The HMAC
// covers only the post-metadata payload, matching the Rust libsignal
// modern-format specification.
//
// Rust libsignal ref: rust/message-backup/src/frame.rs:92-117
func (fe *FrameEncryptor) EncryptFramesModern(w io.Writer, frames [][]byte, meta *BackupMetadata) error {
	if err := ValidateMetadata(meta); err != nil {
		return &ErrMetadataValidation{Err: err}
	}

	// Write the magic number.
	if _, err := w.Write([]byte(MagicNumber)); err != nil {
		return &ErrWritingOutput{Field: "magic", Err: err}
	}

	// Encode BackupMetadata as a MetadataPb protobuf.
	metaBytes, err := encodeMetadataPb(meta)
	if err != nil {
		return err
	}

	// Write the varint-length-delimited metadata.
	if err := WriteVarintDelimited(w, metaBytes); err != nil {
		return &ErrWritingOutput{Field: "metadata", Err: err}
	}

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

	// PKCS#7 pad and encrypt with AES-256-CBC.
	padded := pkcs7Pad(plaintext.Bytes(), AESBlockSize)
	block, err := aes.NewCipher(fe.key.AESKey.Bytes())
	if err != nil {
		return &ErrCreatingAESCipher{Err: err}
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, padded)

	// Compute HMAC over IV + ciphertext only (not magic or metadata).
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

// encodeMetadataPb encodes a BackupMetadata into MetadataPb protobuf
// wire format bytes. This is the inverse of decodeMetadataPb.
//
// Rust libsignal ref: rust/svrb/src/proto/backup_metadata.proto
func encodeMetadataPb(meta *BackupMetadata) ([]byte, error) {
	var buf bytes.Buffer
	for _, pair := range meta.Pairs {
		// Encode each Pair submessage.
		var pairBuf bytes.Buffer
		// field 1 (ct), wire type 2
		writeProtoLenField(&pairBuf, 1, pair.CT)
		// field 2 (pw_salt), wire type 2
		writeProtoLenField(&pairBuf, 2, pair.PWSalt)
		// Write pair as field 1 of MetadataPb.
		writeProtoLenField(&buf, 1, pairBuf.Bytes())
	}
	// field 2 (iv), wire type 2
	writeProtoLenField(&buf, 2, meta.IV)
	return buf.Bytes(), nil
}

// writeProtoLenField writes a protobuf length-delimited field (wire type 2)
// to buf: varint(fieldNum<<3|2) || varint(len(val)) || val.
func writeProtoLenField(buf *bytes.Buffer, fieldNum uint64, val []byte) {
	var tagBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tagBuf[:], fieldNum<<3|2)
	buf.Write(tagBuf[:n])
	var lenBuf [binary.MaxVarintLen64]byte
	n = binary.PutUvarint(lenBuf[:], uint64(len(val)))
	buf.Write(lenBuf[:n])
	buf.Write(val)
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
