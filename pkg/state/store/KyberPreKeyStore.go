package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// KyberPreKey stores Kyber pre-keys (Rust KyberPreKeyStore).
type KyberPreKey interface {
	// LoadKyberPreKey loads the Kyber pre-key with the given ID,
	// returning (nil, nil) if not found.
	LoadKyberPreKey(kyberPreKeyID uint32) (*record.KyberPreKey, error)

	// StoreKyberPreKey stores a Kyber pre-key with the given ID.
	StoreKyberPreKey(kyberPreKeyID uint32, record *record.KyberPreKey) error

	// MarkKyberPreKeyUsed deletes a one-time pre-key; for a last-resort pre-key it keeps the record but rejects a repeated (kyberPreKeyID, signedPreKeyID, baseKey) triple.
	MarkKyberPreKeyUsed(kyberPreKeyID uint32, signedPreKeyID uint32, baseKey ecc.ECPublicKeyable) error

	// ContainsKyberPreKey returns (true, nil) if the store contains a Kyber
	// pre-key with the given ID, (false, nil) if not found, or (false, err)
	// on I/O failure.
	ContainsKyberPreKey(kyberPreKeyID uint32) (bool, error)
}
