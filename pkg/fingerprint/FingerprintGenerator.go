package fingerprint

import (
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
)

// FingerprintGenerator is an interface for fingerprint generators.
type FingerprintGenerator interface {
	CreateFor(version uint32, localStableID []byte, localKey *identity.Key, remoteStableID []byte, remoteKey *identity.Key) (*Fingerprint, error)
	CreateForMultiple(version uint32, localStableID []byte, localKeys []*identity.Key, remoteStableID []byte, remoteKeys []*identity.Key) (*Fingerprint, error)
}
