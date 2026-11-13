package mlkembraid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	authKeySize = 32
)

// Authenticator provides a ratcheted MAC-based authenticator for the SCKA protocol.
// Per spec Section 2.4, it maintains a root_key and derives mac_keys via KDF_AUTH.
type Authenticator struct {
	rootKey *secret.Secret
	macKey  *secret.Secret
	epoch   uint64
}

// NewAuthenticator creates an authenticator initialized per spec Section 2.6:
// root_key = zeros(32), then Update(epoch, sharedSecret).
func NewAuthenticator(epoch uint64, sharedSecret []byte) (*Authenticator, error) {
	if len(sharedSecret) == 0 {
		return nil, &ErrInvalidInput{Field: "sharedSecret", Reason: "must not be empty"}
	}

	initialRoot, err := secret.NewEmpty(authKeySize)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "authenticator init", Err: err}
	}

	a := &Authenticator{
		rootKey: initialRoot,
		macKey:  nil,
		epoch:   epoch,
	}

	if err := a.Update(epoch, sharedSecret); err != nil {
		a.Zeroize()
		return nil, err
	}

	return a, nil
}

// Update advances the authenticator with a new key per spec Section 2.4:
// KDF_AUTH(root_key, update_key, epoch) -> (new_root_key, new_mac_key)
func (a *Authenticator) Update(epoch uint64, updateKey []byte) error {
	if len(updateKey) == 0 {
		return &ErrInvalidInput{Field: "updateKey", Reason: "must not be empty"}
	}

	var derived []byte
	err := a.rootKey.WithBytes(func(rootKey []byte) error {
		var kErr error
		derived, kErr = kdfAuth(rootKey, updateKey, epoch)
		return kErr
	})
	if err != nil {
		return &ErrKEMOperation{Op: "authenticator update", Err: err}
	}

	// Create new secrets from derived material before destroying old ones.
	newRoot, err := secret.New(derived[:authKeySize])
	if err != nil {
		return &ErrKEMOperation{Op: "authenticator update root", Err: err}
	}
	newMAC, err := secret.New(derived[authKeySize:])
	if err != nil {
		newRoot.Destroy()
		return &ErrKEMOperation{Op: "authenticator update mac", Err: err}
	}

	// Destroy old keys.
	if a.rootKey != nil {
		a.rootKey.Destroy()
	}
	if a.macKey != nil {
		a.macKey.Destroy()
	}

	a.rootKey = newRoot
	a.macKey = newMAC
	a.epoch = epoch

	return nil
}

// MacHdr computes a MAC over a header at the current epoch per spec Section 2.4:
// MAC(mac_key, PROTOCOL_INFO || ":ekheader" || ToBytes(epoch) || hdr)
func (a *Authenticator) MacHdr(epoch uint64, header []byte) ([]byte, error) {
	if a.macKey == nil {
		return nil, &ErrInvalidInput{Field: "macKey", Reason: "authenticator not initialized"}
	}
	if epoch != a.epoch {
		return nil, &ErrInvalidEpoch{Expected: a.epoch, Received: epoch}
	}
	return a.macWith([]byte(ProtocolInfo+":ekheader"), epoch, header)
}

// MacCt computes a MAC over a ciphertext at the current epoch per spec Section 2.4:
// MAC(mac_key, PROTOCOL_INFO || ":ciphertext" || ToBytes(epoch) || ct)
func (a *Authenticator) MacCt(epoch uint64, ct []byte) ([]byte, error) {
	if a.macKey == nil {
		return nil, &ErrInvalidInput{Field: "macKey", Reason: "authenticator not initialized"}
	}
	if epoch != a.epoch {
		return nil, &ErrInvalidEpoch{Expected: a.epoch, Received: epoch}
	}
	return a.macWith([]byte(ProtocolInfo+":ciphertext"), epoch, ct)
}

// VfyHdr verifies a MAC over a header at the current epoch.
func (a *Authenticator) VfyHdr(epoch uint64, header, mac []byte) (bool, error) {
	expected, err := a.MacHdr(epoch, header)
	if err != nil {
		return false, err
	}
	return hmac.Equal(expected, mac), nil
}

// VfyCt verifies a MAC over a ciphertext at the current epoch.
func (a *Authenticator) VfyCt(epoch uint64, ct, mac []byte) (bool, error) {
	expected, err := a.MacCt(epoch, ct)
	if err != nil {
		return false, err
	}
	return hmac.Equal(expected, mac), nil
}

// Clone creates an independent copy of the authenticator.
func (a *Authenticator) Clone() (*Authenticator, error) {
	rootCopy, err := a.rootKey.Clone()
	if err != nil {
		return nil, err
	}
	var macCopy *secret.Secret
	if a.macKey != nil {
		macCopy, err = a.macKey.Clone()
		if err != nil {
			rootCopy.Destroy()
			return nil, err
		}
	}
	return &Authenticator{
		rootKey: rootCopy,
		macKey:  macCopy,
		epoch:   a.epoch,
	}, nil
}

// Epoch returns the current epoch of the authenticator.
func (a *Authenticator) Epoch() uint64 {
	return a.epoch
}

// Zeroize destroys the internal key material.
func (a *Authenticator) Zeroize() {
	if a.rootKey != nil {
		a.rootKey.Destroy()
	}
	if a.macKey != nil {
		a.macKey.Destroy()
	}
}

// kdfAuth implements KDF_AUTH per the Rust reference implementation.
//
// Spec-vs-implementation divergence:
// The ML-KEM Braid spec PDF defines KDF_AUTH as:
//
//	HKDF(salt=root_key, ikm=update_key, info=..., length=64)
//
// However, the Rust reference implementation (libsignal) uses different parameters:
//
//	HKDF(salt=zeros(32), ikm=root_key||update_key, info=PROTOCOL_INFO+":Authenticator Update"+ToBytes(epoch), length=64)
//
// We follow the Rust reference for wire compatibility with existing Signal clients.
// This is a known divergence between the specification document and the authoritative
// reference implementation.
//
// Returns 64 bytes: first 32 = new root_key, second 32 = new mac_key.
func kdfAuth(rootKey, updateKey []byte, epoch uint64) ([]byte, error) {
	info := buildInfo(ProtocolInfo+":Authenticator Update", epoch)
	// Rust reference: salt = zeros(32), ikm = rootKey || updateKey (concatenated).
	salt := make([]byte, 32)
	ikm := make([]byte, len(rootKey)+len(updateKey))
	defer crypto.Zeroize(ikm)
	copy(ikm, rootKey)
	copy(ikm[len(rootKey):], updateKey)
	return kdf.DeriveSecrets(ikm, salt, info, 2*authKeySize)
}

// macWith computes computeMAC(mac_key, label, epoch, data) with the MAC key
// borrowed through WithBytes for the computation only.
func (a *Authenticator) macWith(label []byte, epoch uint64, data []byte) ([]byte, error) {
	var mac []byte
	if err := a.macKey.WithBytes(func(macKey []byte) error {
		mac = computeMAC(macKey, label, epoch, data)
		return nil
	}); err != nil {
		return nil, &ErrKEMOperation{Op: "authenticator mac", Err: err}
	}
	return mac, nil
}

// KDFOK implements KDF_OK per spec Section 2.2:
// HKDF(salt=zeros(32), ikm=shared_secret, info=PROTOCOL_INFO+":SCKA Key"+ToBytes(epoch), length=32)
func KDFOK(sharedSecret []byte, epoch uint64) ([]byte, error) {
	salt := make([]byte, 32)
	info := buildInfo(ProtocolInfo+":SCKA Key", epoch)
	return kdf.DeriveSecrets(sharedSecret, salt, info, 32)
}

// computeMAC computes HMAC-SHA256(key, label || ToBytes(epoch) || data).
func computeMAC(key, label []byte, epoch uint64, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(label)
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	mac.Write(epochBytes[:])
	mac.Write(data)
	return mac.Sum(nil)
}

// buildInfo constructs info = prefix || ToBytes(epoch) for HKDF.
func buildInfo(prefix string, epoch uint64) []byte {
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	info := make([]byte, len(prefix)+8)
	copy(info, prefix)
	copy(info[len(prefix):], epochBytes[:])
	return info
}
