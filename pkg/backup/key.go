package backup

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-libsignal/pkg/accountkeys"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// HMACKeyLen is the byte length of the HMAC key in a MessageBackupKey.
	HMACKeyLen = 32
	// AESKeyLen is the byte length of the AES key in a MessageBackupKey.
	AESKeyLen = 32

	// BackupKeyLen is the byte length of the intermediate backup key derived
	// from the account entropy pool.
	BackupKeyLen = 32

	// BackupIDLen is the byte length of a backup ID.
	BackupIDLen = 16

	backupKeyDerivationInfo = "20240801_SIGNAL_BACKUP_KEY"
	backupIDDerivationInfo  = "20241024_SIGNAL_BACKUP_ID:"

	messageBackupEncryptLegacyDST = "20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"
	messageBackupEncryptDST       = "20250708_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"
)

// MessageBackupKey holds the HMAC and AES keys used to encrypt and decrypt
// backup frames. It is derived from a BackupKey and BackupID.
// Call Zeroize when the MessageBackupKey is no longer needed.
type MessageBackupKey struct {
	HMACKey *secret.Secret
	AESKey  *secret.Secret
}

// NewMessageBackupKey constructs a MessageBackupKey directly from raw 32-byte
// HMAC and AES key material. Both slices must be exactly 32 bytes. The bytes
// are copied into guarded memory; the caller may zeroize its own copies after
// this call returns.
//
// This constructor is provided so interop tests and callers that hold raw key
// material can construct a MessageBackupKey without going through the full
// HKDF derivation path.
func NewMessageBackupKey(hmacKey, aesKey []byte) (*MessageBackupKey, error) {
	if len(hmacKey) != HMACKeyLen {
		return nil, &ErrInvalidKeyLength{Field: "hmacKey", Got: len(hmacKey), Want: HMACKeyLen}
	}
	if len(aesKey) != AESKeyLen {
		return nil, &ErrInvalidKeyLength{Field: "aesKey", Got: len(aesKey), Want: AESKeyLen}
	}

	hmacBuf := make([]byte, HMACKeyLen)
	copy(hmacBuf, hmacKey)
	hmacSecret, err := secret.New(hmacBuf)
	if err != nil {
		crypto.Zeroize(hmacBuf)
		return nil, &ErrSecuringSecret{Operation: "HMAC key", Err: err}
	}

	aesBuf := make([]byte, AESKeyLen)
	copy(aesBuf, aesKey)
	aesSecret, err := secret.New(aesBuf)
	if err != nil {
		crypto.Zeroize(aesBuf)
		hmacSecret.Destroy()
		return nil, &ErrSecuringSecret{Operation: "AES key", Err: err}
	}

	return &MessageBackupKey{
		HMACKey: hmacSecret,
		AESKey:  aesSecret,
	}, nil
}

// Zeroize securely wipes the HMAC and AES keys from memory.
func (mk *MessageBackupKey) Zeroize() {
	if mk.HMACKey != nil {
		mk.HMACKey.Destroy()
	}
	if mk.AESKey != nil {
		mk.AESKey.Destroy()
	}
}

// BackupKey is the intermediate key derived from an AccountEntropyPool.
// It is used to derive BackupIDs and MessageBackupKeys.
// Call Zeroize when the BackupKey is no longer needed.
type BackupKey struct {
	key *secret.Secret
}

// Zeroize securely wipes the backup key material from memory.
func (bk *BackupKey) Zeroize() {
	if bk.key != nil {
		bk.key.Destroy()
	}
}

// BackupID is a per-account identifier used for backup storage.
type BackupID struct {
	id [BackupIDLen]byte
}

// Bytes returns the raw backup ID bytes.
func (b *BackupID) Bytes() []byte {
	return b.id[:]
}

// Zeroize securely wipes the backup ID from memory.
func (b *BackupID) Zeroize() {
	crypto.Zeroize(b.id[:])
}

// DeriveBackupKey derives a BackupKey from an AccountEntropyPool using
// HKDF-SHA256 with the info string "20240801_SIGNAL_BACKUP_KEY".
func DeriveBackupKey(pool accountkeys.AccountEntropyPool) (*BackupKey, error) {
	if err := pool.Validate(); err != nil {
		return nil, &ErrInvalidEntropyPool{Err: err}
	}

	// Derive into a scratch buffer that secret.New wipes as it moves the
	// key into guarded memory (a WithBytes view is read-only).
	buf := make([]byte, BackupKeyLen)
	reader := hkdf.New(sha256.New, []byte(pool), nil, []byte(backupKeyDerivationInfo))
	if _, err := io.ReadFull(reader, buf); err != nil {
		crypto.Zeroize(buf)
		return nil, &ErrDerivingKey{KeyType: "backup key", Err: err}
	}

	keySecret, err := secret.New(buf)
	if err != nil {
		crypto.Zeroize(buf)
		return nil, &ErrSecuringSecret{Operation: "HKDF output", Err: err}
	}
	return &BackupKey{key: keySecret}, nil
}

// DeriveBackupID derives a BackupID from the BackupKey and an ACI ServiceId
// using HKDF-SHA256 with the info string "20241024_SIGNAL_BACKUP_ID:" concatenated
// with the ACI's service ID binary representation.
func (bk *BackupKey) DeriveBackupID(aci protocol.ServiceId) (*BackupID, error) {
	if aci.Kind() != protocol.ServiceIdKindACI {
		return nil, &ErrInvalidACIKind{Kind: byte(aci.Kind())}
	}

	// For ACI, service_id_binary is just the 16-byte UUID (no prefix byte).
	uuid := aci.UUID()
	info := append([]byte(backupIDDerivationInfo), uuid[:]...)

	// The backup ID is public: derive it straight into the result, with the
	// backup key borrowed for the HKDF.
	var id [BackupIDLen]byte
	if err := bk.key.WithBytes(func(key []byte) error {
		reader := hkdf.New(sha256.New, key, nil, info)
		_, rErr := io.ReadFull(reader, id[:])
		return rErr
	}); err != nil {
		return nil, &ErrDerivingKey{KeyType: "backup ID", Err: err}
	}
	return &BackupID{id: id}, nil
}

// DeriveMessageBackupKey derives a MessageBackupKey from a BackupKey and BackupID.
// If forwardSecrecyToken is non-nil, it is used as the HKDF salt with the newer
// DST; otherwise the legacy DST is used with no salt. The resulting key contains
// the HMAC key (first 32 bytes) and AES key (next 32 bytes).
func DeriveMessageBackupKey(bk *BackupKey, id *BackupID, forwardSecrecyToken []byte) (*MessageBackupKey, error) {
	var salt []byte
	var dst string
	if len(forwardSecrecyToken) > 0 {
		salt = forwardSecrecyToken
		dst = messageBackupEncryptDST
	} else {
		salt = nil
		dst = messageBackupEncryptLegacyDST
	}

	info := append([]byte(dst), id.id[:]...)

	// Derive into a scratch buffer with the backup key borrowed, then move
	// each half into its own secret; secret.New wipes the halves and the
	// deferred Zeroize wipes the scratch buffer.
	const totalLen = HMACKeyLen + AESKeyLen
	full := make([]byte, totalLen)
	defer crypto.Zeroize(full)

	if err := bk.key.WithBytes(func(key []byte) error {
		reader := hkdf.New(sha256.New, key, salt, info)
		_, rErr := io.ReadFull(reader, full)
		return rErr
	}); err != nil {
		return nil, &ErrDerivingKey{KeyType: "message backup key", Err: err}
	}

	hmacBuf := make([]byte, HMACKeyLen)
	copy(hmacBuf, full[:HMACKeyLen])
	hmacSecret, err := secret.New(hmacBuf)
	if err != nil {
		crypto.Zeroize(hmacBuf)
		return nil, &ErrSecuringSecret{Operation: "HMAC key", Err: err}
	}

	aesBuf := make([]byte, AESKeyLen)
	copy(aesBuf, full[HMACKeyLen:])
	aesSecret, err := secret.New(aesBuf)
	if err != nil {
		crypto.Zeroize(aesBuf)
		hmacSecret.Destroy()
		return nil, &ErrSecuringSecret{Operation: "AES key", Err: err}
	}

	return &MessageBackupKey{
		HMACKey: hmacSecret,
		AESKey:  aesSecret,
	}, nil
}
