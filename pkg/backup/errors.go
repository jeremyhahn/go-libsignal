package backup

import "fmt"

// ErrInvalidProtoWireFormat indicates a protobuf field could not be skipped
// because the wire type is unsupported or the encoded value is truncated.
//
// Rust libsignal ref: rust/message-backup/src/backup.rs (proto parse helpers)
type ErrInvalidProtoWireFormat struct {
	WireType uint64
	Reason   string
}

func (e *ErrInvalidProtoWireFormat) Error() string {
	return fmt.Sprintf("backup: invalid proto wire format (wire type %d): %s", e.WireType, e.Reason)
}

// ErrUnsupportedBackupInfoVersion indicates the BackupInfo version field holds
// a value this implementation does not recognise.
type ErrUnsupportedBackupInfoVersion struct {
	Got  uint64
	Want uint64
}

func (e *ErrUnsupportedBackupInfoVersion) Error() string {
	return fmt.Sprintf("backup: unsupported BackupInfo version %d (want %d)", e.Got, e.Want)
}

// ErrUnexpectedWireType indicates a known protobuf field carried a wire type
// that does not match its declared type.
type ErrUnexpectedWireType struct {
	Field    string
	WireType uint64
}

func (e *ErrUnexpectedWireType) Error() string {
	return fmt.Sprintf("backup: %s: unexpected wire type %d", e.Field, e.WireType)
}

// ErrTruncatedField indicates a length-delimited or fixed-width protobuf field
// is shorter than its declared length.
type ErrTruncatedField struct {
	Field string
}

func (e *ErrTruncatedField) Error() string {
	return fmt.Sprintf("backup: %s: field truncated", e.Field)
}

// ErrDecryptingBackup indicates a failure during backup decryption.
type ErrDecryptingBackup struct {
	Err error
}

func (e *ErrDecryptingBackup) Error() string {
	return fmt.Sprintf("backup: decrypting backup: %v", e.Err)
}

func (e *ErrDecryptingBackup) Unwrap() error {
	return e.Err
}

// ErrWritingFrame indicates a failure writing a frame to the compressor.
type ErrWritingFrame struct {
	Err error
}

func (e *ErrWritingFrame) Error() string {
	return fmt.Sprintf("backup: writing frame to compressor: %v", e.Err)
}

func (e *ErrWritingFrame) Unwrap() error {
	return e.Err
}

// ErrClosingGzipWriter indicates a failure closing the gzip writer.
type ErrClosingGzipWriter struct {
	Err error
}

func (e *ErrClosingGzipWriter) Error() string {
	return fmt.Sprintf("backup: closing gzip writer: %v", e.Err)
}

func (e *ErrClosingGzipWriter) Unwrap() error {
	return e.Err
}

// ErrGeneratingIV indicates a failure generating a random IV.
type ErrGeneratingIV struct {
	Err error
}

func (e *ErrGeneratingIV) Error() string {
	return fmt.Sprintf("backup: generating IV: %v", e.Err)
}

func (e *ErrGeneratingIV) Unwrap() error {
	return e.Err
}

// ErrCreatingAESCipher indicates a failure creating an AES cipher block.
type ErrCreatingAESCipher struct {
	Err error
}

func (e *ErrCreatingAESCipher) Error() string {
	return fmt.Sprintf("backup: creating AES cipher: %v", e.Err)
}

func (e *ErrCreatingAESCipher) Unwrap() error {
	return e.Err
}

// ErrWritingOutput indicates a failure writing encrypted output data.
type ErrWritingOutput struct {
	Field string
	Err   error
}

func (e *ErrWritingOutput) Error() string {
	return fmt.Sprintf("backup: writing %s: %v", e.Field, e.Err)
}

func (e *ErrWritingOutput) Unwrap() error {
	return e.Err
}

// ErrReadingEncryptedData indicates a failure reading encrypted backup data.
type ErrReadingEncryptedData struct {
	Err error
}

func (e *ErrReadingEncryptedData) Error() string {
	return fmt.Sprintf("backup: reading encrypted data: %v", e.Err)
}

func (e *ErrReadingEncryptedData) Unwrap() error {
	return e.Err
}

// ErrDataTooShort indicates the encrypted data is too short to contain
// the required IV and HMAC fields.
type ErrDataTooShort struct {
	Length int
	MinLen int
}

func (e *ErrDataTooShort) Error() string {
	return fmt.Sprintf("backup: data too short (%d bytes, minimum %d)", e.Length, e.MinLen)
}

// ErrCiphertextNotAligned indicates the ciphertext length is not a multiple
// of the AES block size.
type ErrCiphertextNotAligned struct {
	Length    int
	BlockSize int
}

func (e *ErrCiphertextNotAligned) Error() string {
	return fmt.Sprintf("backup: ciphertext length %d is not a multiple of block size %d",
		e.Length, e.BlockSize)
}

// ErrRemovingPadding indicates a failure removing PKCS#7 padding.
type ErrRemovingPadding struct {
	Err error
}

func (e *ErrRemovingPadding) Error() string {
	return fmt.Sprintf("backup: removing padding: %v", e.Err)
}

func (e *ErrRemovingPadding) Unwrap() error {
	return e.Err
}

// ErrCreatingGzipReader indicates a failure creating a gzip decompressor.
type ErrCreatingGzipReader struct {
	Err error
}

func (e *ErrCreatingGzipReader) Error() string {
	return fmt.Sprintf("backup: creating gzip reader: %v", e.Err)
}

func (e *ErrCreatingGzipReader) Unwrap() error {
	return e.Err
}

// ErrClosingGzipReader indicates a failure closing the gzip reader.
type ErrClosingGzipReader struct {
	Err error
}

func (e *ErrClosingGzipReader) Error() string {
	return fmt.Sprintf("backup: closing gzip reader: %v", e.Err)
}

func (e *ErrClosingGzipReader) Unwrap() error {
	return e.Err
}

// ErrReadingFrame indicates a failure reading a decrypted frame.
type ErrReadingFrame struct {
	Err error
}

func (e *ErrReadingFrame) Error() string {
	return fmt.Sprintf("backup: reading frame: %v", e.Err)
}

func (e *ErrReadingFrame) Unwrap() error {
	return e.Err
}

// ErrEmptyUnpadData indicates empty data was provided for PKCS#7 unpadding.
type ErrEmptyUnpadData struct{}

func (e *ErrEmptyUnpadData) Error() string {
	return "backup: empty data for unpadding"
}

// ErrUnpadNotAligned indicates the data length is not a multiple of the block size
// for PKCS#7 unpadding.
type ErrUnpadNotAligned struct {
	Length    int
	BlockSize int
}

func (e *ErrUnpadNotAligned) Error() string {
	return fmt.Sprintf("backup: data length %d not a multiple of block size %d",
		e.Length, e.BlockSize)
}

// ErrInvalidPadding indicates PKCS#7 padding validation failed.
type ErrInvalidPadding struct{}

func (e *ErrInvalidPadding) Error() string {
	return "backup: invalid padding"
}

// ErrInvalidEntropyPool indicates the entropy pool failed validation.
type ErrInvalidEntropyPool struct {
	Err error
}

func (e *ErrInvalidEntropyPool) Error() string {
	return fmt.Sprintf("backup: invalid entropy pool: %v", e.Err)
}

func (e *ErrInvalidEntropyPool) Unwrap() error {
	return e.Err
}

// ErrSecuringSecret indicates a failure protecting derived key material
// in guarded memory.
type ErrSecuringSecret struct {
	Operation string
	Err       error
}

func (e *ErrSecuringSecret) Error() string {
	return fmt.Sprintf("backup: securing %s: %v", e.Operation, e.Err)
}

func (e *ErrSecuringSecret) Unwrap() error {
	return e.Err
}

// ErrDerivingKey indicates a failure in HKDF key derivation.
type ErrDerivingKey struct {
	KeyType string
	Err     error
}

func (e *ErrDerivingKey) Error() string {
	return fmt.Sprintf("backup: deriving %s: %v", e.KeyType, e.Err)
}

func (e *ErrDerivingKey) Unwrap() error {
	return e.Err
}

// ErrInvalidACIKind indicates the service ID is not an ACI.
type ErrInvalidACIKind struct {
	Kind byte
}

func (e *ErrInvalidACIKind) Error() string {
	return fmt.Sprintf("backup: expected ACI service ID, got kind 0x%02x", e.Kind)
}

// ErrReadingDelimitedMessage indicates a failure reading a varint-delimited message.
type ErrReadingDelimitedMessage struct {
	Err error
}

func (e *ErrReadingDelimitedMessage) Error() string {
	return fmt.Sprintf("backup: reading delimited message: %v", e.Err)
}

func (e *ErrReadingDelimitedMessage) Unwrap() error {
	return e.Err
}

// ErrInvalidVarint indicates an invalid varint encoding was encountered.
type ErrInvalidVarint struct{}

func (e *ErrInvalidVarint) Error() string {
	return "backup: invalid varint encoding"
}

// ErrVarintOverflow indicates a varint value exceeds the maximum allowed.
type ErrVarintOverflow struct {
	Value uint64
	Max   uint64
}

func (e *ErrVarintOverflow) Error() string {
	return fmt.Sprintf("backup: varint value %d exceeds maximum %d", e.Value, e.Max)
}

// ErrReadingVarint indicates a failure reading varint bytes from the underlying reader.
type ErrReadingVarint struct {
	Err error
}

func (e *ErrReadingVarint) Error() string {
	return fmt.Sprintf("backup: reading varint: %v", e.Err)
}

func (e *ErrReadingVarint) Unwrap() error {
	return e.Err
}

// ErrWritingVarintLength indicates a failure writing the varint length prefix.
type ErrWritingVarintLength struct {
	Err error
}

func (e *ErrWritingVarintLength) Error() string {
	return fmt.Sprintf("backup: writing varint length: %v", e.Err)
}

func (e *ErrWritingVarintLength) Unwrap() error {
	return e.Err
}

// ErrWritingDelimitedMessage indicates a failure writing the message payload
// after the varint length prefix.
type ErrWritingDelimitedMessage struct {
	Err error
}

func (e *ErrWritingDelimitedMessage) Error() string {
	return fmt.Sprintf("backup: writing delimited message: %v", e.Err)
}

func (e *ErrWritingDelimitedMessage) Unwrap() error {
	return e.Err
}

// ErrUnknownPurpose indicates an unrecognized backup purpose string.
type ErrUnknownPurpose struct {
	Value string
}

func (e *ErrUnknownPurpose) Error() string {
	return fmt.Sprintf("backup: unknown purpose %q", e.Value)
}

// ErrReadingMagicNumber indicates a failure reading the magic number from
// the backup stream.
type ErrReadingMagicNumber struct {
	Err error
}

func (e *ErrReadingMagicNumber) Error() string {
	return fmt.Sprintf("backup: reading magic number: %v", e.Err)
}

func (e *ErrReadingMagicNumber) Unwrap() error {
	return e.Err
}

// ErrReadingHMACData indicates a failure reading data for HMAC verification.
type ErrReadingHMACData struct {
	Err error
}

func (e *ErrReadingHMACData) Error() string {
	return fmt.Sprintf("backup: reading data for HMAC verification: %v", e.Err)
}

func (e *ErrReadingHMACData) Unwrap() error {
	return e.Err
}

// ErrBackupTooLarge indicates the backup data exceeds the maximum allowed size.
type ErrBackupTooLarge struct {
	MaxBytes int64
}

func (e *ErrBackupTooLarge) Error() string {
	return fmt.Sprintf("backup: data exceeds maximum allowed size of %d bytes", e.MaxBytes)
}

// ErrInvalidBackupMagic indicates the backup stream starts with a byte
// sequence that is close to but does not match the expected SBACKUP\x01
// magic number.
//
// Rust libsignal ref: rust/message-backup/src/frame/forward_secrecy.rs
type ErrInvalidBackupMagic struct {
	Got []byte
}

func (e *ErrInvalidBackupMagic) Error() string {
	return fmt.Sprintf("backup: invalid magic number %x (want %x)", e.Got, []byte(MagicNumber))
}

// ErrMetadataValidation indicates that the unencrypted metadata block
// embedded in a modern SBACKUP\x01 backup stream failed validation.
//
// Rust libsignal ref: rust/message-backup/src/frame.rs ValidationError
type ErrMetadataValidation struct {
	Err error
}

func (e *ErrMetadataValidation) Error() string {
	return fmt.Sprintf("backup: metadata validation: %v", e.Err)
}

func (e *ErrMetadataValidation) Unwrap() error {
	return e.Err
}

// ErrInvalidBackupInfo indicates the first frame of a backup cannot be
// parsed as a valid BackupInfo protobuf message.
//
// Rust libsignal ref: rust/message-backup/src/backup.rs BackupReader::read_all
type ErrInvalidBackupInfo struct {
	Err error
}

func (e *ErrInvalidBackupInfo) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("backup: invalid BackupInfo: %v", e.Err)
	}
	return "backup: invalid BackupInfo"
}

func (e *ErrInvalidBackupInfo) Unwrap() error {
	return e.Err
}

// ErrInvalidFrame indicates a backup frame cannot be parsed as a valid
// Frame protobuf message.
//
// Rust libsignal ref: rust/message-backup/src/backup.rs BackupReader::read_all
type ErrInvalidFrame struct {
	Index int
	Err   error
}

func (e *ErrInvalidFrame) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("backup: invalid frame at index %d: %v", e.Index, e.Err)
	}
	return fmt.Sprintf("backup: invalid frame at index %d", e.Index)
}

func (e *ErrInvalidFrame) Unwrap() error {
	return e.Err
}

// ErrPurposeMismatch indicates the backup Purpose declared in BackupInfo
// does not match the Purpose that was expected by the caller.
//
// Rust libsignal ref: rust/message-backup/src/backup.rs BackupReader::read_all
type ErrPurposeMismatch struct {
	Want Purpose
	Got  Purpose
}

func (e *ErrPurposeMismatch) Error() string {
	return fmt.Sprintf("backup: purpose mismatch: want %v, got %v", e.Want, e.Got)
}

// ErrReadingMetadataLength indicates a failure reading the varint-encoded
// metadata block length from a modern SBACKUP\x01 stream.
type ErrReadingMetadataLength struct {
	Err error
}

func (e *ErrReadingMetadataLength) Error() string {
	return fmt.Sprintf("backup: reading metadata length: %v", e.Err)
}

func (e *ErrReadingMetadataLength) Unwrap() error {
	return e.Err
}

// ErrReadingMetadata indicates a failure reading the metadata protobuf bytes
// from a modern SBACKUP\x01 stream.
type ErrReadingMetadata struct {
	Err error
}

func (e *ErrReadingMetadata) Error() string {
	return fmt.Sprintf("backup: reading metadata: %v", e.Err)
}

func (e *ErrReadingMetadata) Unwrap() error {
	return e.Err
}

// ErrInvalidKeyLength indicates that a raw key slice passed to NewMessageBackupKey
// has the wrong length.
type ErrInvalidKeyLength struct {
	Field string
	Got   int
	Want  int
}

func (e *ErrInvalidKeyLength) Error() string {
	return fmt.Sprintf("backup: %s must be %d bytes, got %d", e.Field, e.Want, e.Got)
}

// ErrDecompressedSizeExceeded is returned when the cumulative number of
// decompressed bytes across all frames exceeds the per-stream budget.
// An authenticated backup could legitimately trigger this only if the
// compression ratio is extreme; it guards against decompression bombs
// even after HMAC verification.
type ErrDecompressedSizeExceeded struct {
	MaxBytes int64
}

func (e *ErrDecompressedSizeExceeded) Error() string {
	return fmt.Sprintf("backup: decompressed data exceeds maximum allowed size of %d bytes", e.MaxBytes)
}
