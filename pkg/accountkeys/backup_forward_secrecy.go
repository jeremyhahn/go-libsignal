package accountkeys

import (
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// BackupKeyLength is the byte length of a BackupKey.
	BackupKeyLength = 32

	// BackupIDLength is the byte length of a BackupId.
	BackupIDLength = 16

	// LocalBackupMetadataKeyLength is the byte length of a local backup metadata key.
	LocalBackupMetadataKeyLength = 32

	// MediaIDLength is the byte length of a media ID.
	MediaIDLength = 15

	// MediaEncryptionKeyLength is the combined byte length of HMAC key + AES-CBC key.
	MediaEncryptionKeyLength = 64

	// BackupForwardSecrecyTokenLength is the byte length of a forward secrecy token.
	BackupForwardSecrecyTokenLength = 32

	// backupForwardSecrecyEncryptionKeyCipherKeySize is the AES key size.
	backupForwardSecrecyEncryptionKeyCipherKeySize = 32

	// backupForwardSecrecyEncryptionKeyHMACKeySize is the HMAC key size.
	backupForwardSecrecyEncryptionKeyHMACKeySize = 32

	// HKDF info labels matching the Rust implementation.
	backupKeyFromEntropyInfo          = "20240801_SIGNAL_BACKUP_KEY"
	backupIDInfo                      = "20241024_SIGNAL_BACKUP_ID:"
	backupECKeyInfo                   = "20241024_SIGNAL_BACKUP_ID_KEYPAIR:"
	localBackupMetadataKeyInfo        = "20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY"
	mediaIDInfo                       = "20241007_SIGNAL_BACKUP_MEDIA_ID:"
	mediaEncryptionKeyInfo            = "20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:"
	thumbnailTransitEncryptionKeyInfo = "20241030_SIGNAL_BACKUP_ENCRYPT_THUMBNAIL:"
	forwardSecrecyPasswordInfo        = "Signal Message Backup 20250627:SVR PIN"
	forwardSecrecyEncryptionKeyInfo   = "Signal Message Backup 20250627:BackupForwardSecrecyToken Encryption Key"
)

// BackupKey is the primary key for backups, used to derive other backup-related keys.
// It is derived from an AccountEntropyPool.
// Call Zeroize when the BackupKey is no longer needed.
type BackupKey struct {
	data *secret.Secret
}

// NewBackupKey creates a BackupKey from a raw 32-byte array.
// The source array is copied; the caller retains ownership of data.
func NewBackupKey(data [BackupKeyLength]byte) BackupKey {
	buf := make([]byte, BackupKeyLength)
	copy(buf, data[:])
	s, err := secretAlloc(buf)
	if err != nil {
		// secretAlloc only fails on nil input or locked-memory alloc failure.
		// A valid 32-byte slice should never trigger nil; alloc failure is fatal.
		panic("accountkeys: failed to create BackupKey secret: " + err.Error())
	}
	return BackupKey{data: s}
}

// Bytes returns the raw bytes of the BackupKey as a fixed-size array.
// The returned value is a copy; modifying it does not affect the secret.
func (k *BackupKey) Bytes() [BackupKeyLength]byte {
	var out [BackupKeyLength]byte
	if k.data != nil && !k.data.IsDestroyed() {
		_ = k.data.WithBytes(func(b []byte) error {
			copy(out[:], b)
			return nil
		})
	}
	return out
}

// expandInto fills out with HKDF-SHA256 output keyed by the backup key, read
// inside the enclave borrow. It panics if the key has been destroyed, as
// reading a destroyed key always has.
func (k *BackupKey) expandInto(out, salt, info []byte) error {
	var data *secret.Secret
	if k != nil {
		data = k.data
	}
	return data.WithBytes(func(key []byte) error {
		// A nil secret borrows as nil: refuse to derive from public
		// inputs alone.
		if len(key) != BackupKeyLength {
			return &ErrInvalidBackupKey{Expected: BackupKeyLength, Got: len(key)}
		}
		hkdfExpandInto(out, key, salt, info)
		return nil
	})
}

// Zeroize securely wipes the backup key material from memory.
func (k *BackupKey) Zeroize() {
	if k.data != nil {
		k.data.Destroy()
	}
}

// DeriveBackupKeyFromEntropyPool derives a BackupKey from an AccountEntropyPool
// using HKDF-SHA256 with the info label "20240801_SIGNAL_BACKUP_KEY".
func DeriveBackupKeyFromEntropyPool(pool AccountEntropyPool) (BackupKey, error) {
	if err := pool.Validate(); err != nil {
		return BackupKey{}, err
	}
	buf := make([]byte, BackupKeyLength)
	hkdfExpandInto(buf, []byte(pool), nil, []byte(backupKeyFromEntropyInfo))
	// secretAlloc zeroizes buf (move semantics).
	s, err := secretAlloc(buf)
	if err != nil {
		crypto.Zeroize(buf)
		return BackupKey{}, &ErrSecuringSecret{Operation: "backup key", Err: err}
	}
	return BackupKey{data: s}, nil
}

// BackupId is the per-account identifier used to store backups.
type BackupId struct {
	data [BackupIDLength]byte
}

// NewBackupId creates a BackupId from a raw byte array.
func NewBackupId(data [BackupIDLength]byte) BackupId {
	return BackupId{data: data}
}

// Bytes returns the raw bytes of the BackupId.
func (id *BackupId) Bytes() [BackupIDLength]byte {
	return id.data
}

// Zeroize securely wipes the backup ID from memory.
func (id *BackupId) Zeroize() {
	crypto.Zeroize(id.data[:])
}

// DeriveBackupId derives a BackupId from the BackupKey and an ACI (Account Identity).
// The ACI must be exactly 16 raw UUID bytes.
func (k *BackupKey) DeriveBackupId(aci []byte) (BackupId, error) {
	if len(aci) != 16 {
		return BackupId{}, &ErrInvalidACILength{Length: len(aci)}
	}
	info := append([]byte(backupIDInfo), aci...)
	var id BackupId
	if err := k.expandInto(id.data[:], nil, info); err != nil {
		return BackupId{}, err
	}
	return id, nil
}

// DeriveECKey derives a 32-byte EC private key from the BackupKey and an ACI.
// The ACI should be the 16-byte raw UUID bytes.
// The returned Secret must be destroyed by the caller when no longer needed.
func (k *BackupKey) DeriveECKey(aciServiceIdBinary []byte) (*secret.Secret, error) {
	info := append([]byte(backupECKeyInfo), aciServiceIdBinary...)
	buf := make([]byte, 32)
	if err := k.expandInto(buf, nil, info); err != nil {
		return nil, err
	}
	// secretAlloc zeroizes buf (move semantics).
	s, err := secretAlloc(buf)
	if err != nil {
		crypto.Zeroize(buf)
		return nil, &ErrSecuringSecret{Operation: "EC key", Err: err}
	}
	return s, nil
}

// DeriveLocalBackupMetadataKey derives a 32-byte metadata key for local backup encryption.
// The returned Secret must be destroyed by the caller when no longer needed.
func (k *BackupKey) DeriveLocalBackupMetadataKey() (*secret.Secret, error) {
	buf := make([]byte, LocalBackupMetadataKeyLength)
	if err := k.expandInto(buf, nil, []byte(localBackupMetadataKeyInfo)); err != nil {
		return nil, err
	}
	s, err := secretAlloc(buf)
	if err != nil {
		crypto.Zeroize(buf)
		return nil, &ErrSecuringSecret{Operation: "metadata key", Err: err}
	}
	return s, nil
}

// DeriveMediaId derives a 15-byte media ID from the BackupKey and a media name string.
func (k *BackupKey) DeriveMediaId(mediaName string) ([MediaIDLength]byte, error) {
	info := append([]byte(mediaIDInfo), []byte(mediaName)...)
	var id [MediaIDLength]byte
	if err := k.expandInto(id[:], nil, info); err != nil {
		return [MediaIDLength]byte{}, err
	}
	return id, nil
}

// DeriveMediaEncryptionKeyData derives a 64-byte encryption key (HMAC key + AES-CBC key)
// from the BackupKey and a media ID.
// The returned Secret must be destroyed by the caller when no longer needed.
func (k *BackupKey) DeriveMediaEncryptionKeyData(mediaId [MediaIDLength]byte) (*secret.Secret, error) {
	info := append([]byte(mediaEncryptionKeyInfo), mediaId[:]...)
	buf := make([]byte, MediaEncryptionKeyLength)
	if err := k.expandInto(buf, nil, info); err != nil {
		return nil, err
	}
	s, err := secretAlloc(buf)
	if err != nil {
		crypto.Zeroize(buf)
		return nil, &ErrSecuringSecret{Operation: "media encryption key", Err: err}
	}
	return s, nil
}

// DeriveThumbnailTransitEncryptionKeyData derives a 64-byte encryption key
// for thumbnail transit from the BackupKey and a media ID.
// The returned Secret must be destroyed by the caller when no longer needed.
func (k *BackupKey) DeriveThumbnailTransitEncryptionKeyData(mediaId [MediaIDLength]byte) (*secret.Secret, error) {
	info := append([]byte(thumbnailTransitEncryptionKeyInfo), mediaId[:]...)
	buf := make([]byte, MediaEncryptionKeyLength)
	if err := k.expandInto(buf, nil, info); err != nil {
		return nil, err
	}
	s, err := secretAlloc(buf)
	if err != nil {
		crypto.Zeroize(buf)
		return nil, &ErrSecuringSecret{Operation: "thumbnail encryption key", Err: err}
	}
	return s, nil
}

// BackupForwardSecrecyPassword holds a 32-byte password derived from a BackupKey
// and a salt. This password protects a forward secrecy token within secure storage.
type BackupForwardSecrecyPassword struct {
	data [32]byte
}

// Bytes returns the raw bytes of the password.
func (p *BackupForwardSecrecyPassword) Bytes() [32]byte {
	return p.data
}

// Zeroize securely wipes the password from memory.
func (p *BackupForwardSecrecyPassword) Zeroize() {
	crypto.ZeroizeArray32(&p.data)
}

// DeriveForwardSecrecyPassword derives a forward secrecy password from the BackupKey
// using HKDF-SHA256 with the provided salt and the info label
// "Signal Message Backup 20250627:SVR PIN".
func (k *BackupKey) DeriveForwardSecrecyPassword(salt []byte) (BackupForwardSecrecyPassword, error) {
	var pw BackupForwardSecrecyPassword
	if err := k.expandInto(pw.data[:], salt, []byte(forwardSecrecyPasswordInfo)); err != nil {
		crypto.Zeroize(pw.data[:])
		return BackupForwardSecrecyPassword{}, err
	}
	return pw, nil
}

// BackupForwardSecrecyEncryptionKey holds the cipher key and HMAC key needed
// to encrypt a forward secrecy token.
// Call Zeroize when the key is no longer needed.
type BackupForwardSecrecyEncryptionKey struct {
	CipherKey *secret.Secret
	HMACKey   *secret.Secret
}

// Zeroize securely wipes the cipher key and HMAC key from memory.
func (k *BackupForwardSecrecyEncryptionKey) Zeroize() {
	if k.CipherKey != nil {
		k.CipherKey.Destroy()
	}
	if k.HMACKey != nil {
		k.HMACKey.Destroy()
	}
}

// DeriveForwardSecrecyEncryptionKey derives all values necessary to encrypt a
// forward secrecy token based on the BackupKey and a salt. It produces a 32-byte
// cipher key and a 32-byte HMAC key using HKDF-SHA256 with the info label
// "Signal Message Backup 20250627:BackupForwardSecrecyToken Encryption Key".
func (k *BackupKey) DeriveForwardSecrecyEncryptionKey(salt []byte) (BackupForwardSecrecyEncryptionKey, error) {
	const totalLen = backupForwardSecrecyEncryptionKeyCipherKeySize + backupForwardSecrecyEncryptionKeyHMACKeySize

	// Derive into guarded memory, then split into two secrets.
	bufSecret, err := secretEmptyAlloc(totalLen)
	if err != nil {
		return BackupForwardSecrecyEncryptionKey{}, &ErrSecuringSecret{Operation: "HKDF output", Err: err}
	}
	defer bufSecret.Destroy()

	// Expand into the locked buffer and copy each half out, all inside the
	// enclave borrows; each half moves into its own secret below.
	cipherBuf := make([]byte, backupForwardSecrecyEncryptionKeyCipherKeySize)
	hmacBuf := make([]byte, backupForwardSecrecyEncryptionKeyHMACKeySize)
	if err := bufSecret.WithBytes(func(buf []byte) error {
		if err := k.expandInto(buf, salt, []byte(forwardSecrecyEncryptionKeyInfo)); err != nil {
			return err
		}
		copy(cipherBuf, buf[:backupForwardSecrecyEncryptionKeyCipherKeySize])
		copy(hmacBuf, buf[backupForwardSecrecyEncryptionKeyCipherKeySize:])
		return nil
	}); err != nil {
		return BackupForwardSecrecyEncryptionKey{}, &ErrSecuringSecret{Operation: "HKDF output", Err: err}
	}
	cipherSecret, err := secretAlloc(cipherBuf)
	if err != nil {
		crypto.Zeroize(cipherBuf)
		crypto.Zeroize(hmacBuf)
		return BackupForwardSecrecyEncryptionKey{}, &ErrSecuringSecret{Operation: "cipher key", Err: err}
	}

	hmacSecret, err := secretAlloc(hmacBuf)
	if err != nil {
		crypto.Zeroize(hmacBuf)
		cipherSecret.Destroy()
		return BackupForwardSecrecyEncryptionKey{}, &ErrSecuringSecret{Operation: "HMAC key", Err: err}
	}

	return BackupForwardSecrecyEncryptionKey{
		CipherKey: cipherSecret,
		HMACKey:   hmacSecret,
	}, nil
}

// BackupForwardSecrecyToken is an additional token stored in a secure enclave
// to provide forward secrecy for backups.
type BackupForwardSecrecyToken struct {
	data [BackupForwardSecrecyTokenLength]byte
}

// NewBackupForwardSecrecyToken creates a BackupForwardSecrecyToken from raw bytes.
func NewBackupForwardSecrecyToken(data [BackupForwardSecrecyTokenLength]byte) BackupForwardSecrecyToken {
	return BackupForwardSecrecyToken{data: data}
}

// Bytes returns the raw bytes of the token.
func (t *BackupForwardSecrecyToken) Bytes() [BackupForwardSecrecyTokenLength]byte {
	return t.data
}

// Zeroize securely wipes the token from memory.
func (t *BackupForwardSecrecyToken) Zeroize() {
	crypto.ZeroizeArray32(&t.data)
}
