package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// KyberPreKey is an interface for storing and managing Kyber pre-keys
// used in post-quantum key exchange.
//
// Mirrors the Rust libsignal trait KyberPreKeyStore at
// rust/protocol/src/storage/traits.rs.
type KyberPreKey interface {
	// LoadKyberPreKey loads the Kyber pre-key with the given ID,
	// returning (nil, nil) if not found.
	LoadKyberPreKey(kyberPreKeyID uint32) (*record.KyberPreKey, error)

	// StoreKyberPreKey stores a Kyber pre-key with the given ID.
	StoreKyberPreKey(kyberPreKeyID uint32, record *record.KyberPreKey) error

	// MarkKyberPreKeyUsed marks a Kyber pre-key as used after consumption.
	//
	// For a one-time pre-key the implementation MUST delete the record so it
	// cannot be reused. For a last-resort pre-key the record MUST NOT be
	// deleted, but the implementation MUST track the set of
	// (kyberPreKeyID, signedPreKeyID, baseKey) triples that have been seen and
	// return an error if the same triple is presented a second time. This
	// prevents a replay attacker from re-establishing a session using a
	// captured PreKeySignalMessage.
	//
	// Mirrors the Rust libsignal trait KyberPreKeyStore::mark_kyber_pre_key_used
	// at rust/protocol/src/storage/traits.rs:134-139.
	MarkKyberPreKeyUsed(kyberPreKeyID uint32, signedPreKeyID uint32, baseKey ecc.ECPublicKeyable) error

	// ContainsKyberPreKey returns (true, nil) if the store contains a Kyber
	// pre-key with the given ID, (false, nil) if not found, or (false, err)
	// on I/O failure.
	ContainsKyberPreKey(kyberPreKeyID uint32) (bool, error)
}
