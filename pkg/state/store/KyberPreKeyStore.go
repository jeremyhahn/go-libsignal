package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// KyberPreKey is an interface for storing and managing Kyber pre-keys
// used in post-quantum key exchange.
type KyberPreKey interface {
	// LoadKyberPreKey loads the Kyber pre-key with the given ID.
	LoadKyberPreKey(kyberPreKeyID uint32) (*record.KyberPreKey, error)
	// StoreKyberPreKey stores a Kyber pre-key with the given ID.
	StoreKyberPreKey(kyberPreKeyID uint32, record *record.KyberPreKey) error
	// MarkKyberPreKeyUsed marks a Kyber pre-key as used after consumption.
	// The signedPreKeyID and baseKey parameters are provided to enable
	// last-resort key replay detection, matching the Rust reference
	// implementation's mark_kyber_pre_key_used signature.
	MarkKyberPreKeyUsed(kyberPreKeyID uint32, signedPreKeyID uint32, baseKey ecc.ECPublicKeyable) error
	// ContainsKyberPreKey returns true if the store contains a Kyber pre-key with the given ID.
	ContainsKyberPreKey(kyberPreKeyID uint32) bool
}
