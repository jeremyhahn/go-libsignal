package record

import (
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// NewPendingPreKey will return a new pending pre key object.
// The timestamp is set to the current time in seconds since epoch.
func NewPendingPreKey(preKeyID *optional.Uint32, signedPreKeyID uint32,
	baseKey ecc.ECPublicKeyable) *PendingPreKey {

	return &PendingPreKey{
		preKeyID:       preKeyID,
		signedPreKeyID: signedPreKeyID,
		baseKey:        baseKey,
		timestamp:      uint64(time.Now().Unix()),
	}
}

// NewPendingPreKeyFromStruct will return a new pending prekey object from the
// given structure.
func NewPendingPreKeyFromStruct(preKey *PendingPreKeyStructure) (*PendingPreKey, error) {
	if preKey == nil {
		return nil, nil
	}
	baseKey, err := ecc.DecodePoint(preKey.BaseKey, 0)
	if err != nil {
		return nil, err
	}

	pendingPreKey := NewPendingPreKey(
		preKey.PreKeyID,
		preKey.SignedPreKeyID,
		baseKey,
	)
	pendingPreKey.kyberPreKeyID = preKey.KyberPreKeyID
	pendingPreKey.kyberCiphertext = preKey.KyberCiphertext
	pendingPreKey.timestamp = preKey.Timestamp

	return pendingPreKey, nil
}

// PendingPreKeyStructure is a serializeable structure for pending
// prekeys.
type PendingPreKeyStructure struct {
	PreKeyID        *optional.Uint32
	SignedPreKeyID  uint32
	BaseKey         []byte
	KyberPreKeyID   *optional.Uint32 `json:"kyberPreKeyId,omitempty"`
	KyberCiphertext []byte           `json:"kyberCiphertext,omitempty"`
	Timestamp       uint64           `json:"timestamp,omitempty"`
}

// PendingPreKey is a structure for pending pre keys
// for a session state.
type PendingPreKey struct {
	preKeyID        *optional.Uint32
	signedPreKeyID  uint32
	baseKey         ecc.ECPublicKeyable
	kyberPreKeyID   *optional.Uint32
	kyberCiphertext []byte
	timestamp       uint64
}

// Timestamp returns the creation timestamp in seconds since Unix epoch.
func (p *PendingPreKey) Timestamp() uint64 {
	return p.timestamp
}

// KyberPreKeyID returns the Kyber pre-key ID, or nil if PQXDH was not used.
func (p *PendingPreKey) KyberPreKeyID() *optional.Uint32 {
	return p.kyberPreKeyID
}

// KyberCiphertext returns the Kyber ciphertext, or nil if PQXDH was not used.
func (p *PendingPreKey) KyberCiphertext() []byte {
	return p.kyberCiphertext
}

// structure will return a serializeable structure of the pending prekey.
func (p *PendingPreKey) structure() *PendingPreKeyStructure {
	return &PendingPreKeyStructure{
		PreKeyID:        p.preKeyID,
		SignedPreKeyID:  p.signedPreKeyID,
		BaseKey:         p.baseKey.Serialize(),
		KyberPreKeyID:   p.kyberPreKeyID,
		KyberCiphertext: p.kyberCiphertext,
		Timestamp:       p.timestamp,
	}
}
