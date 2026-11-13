package serialize

import (
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"google.golang.org/protobuf/proto"
)

// ownedCopies records the heap buffers a serializer owns while it builds a
// protobuf message: the copies copyOut takes of secret material, and
// intermediate marshal output that embeds them. The serializer wipes them
// with wipe once proto.Marshal has run, on success and on failure.
//
// Only buffers recorded here are wiped. Fields that alias live state, such
// as public keys and signatures taken straight from the structure, are never
// recorded, so wiping cannot corrupt the caller's state.
//
// A nil *ownedCopies records nothing, so copyOut still returns a copy.
type ownedCopies struct {
	bufs [][]byte
}

// newOwnedCopies and marshalRecord are the tracker constructor and encoder
// the record serializers use. Tests replace them to observe the owned
// copies and to inject an encoding failure.
var (
	newOwnedCopies = func() *ownedCopies { return &ownedCopies{} }
	marshalRecord  = proto.Marshal
)

// copyOut copies a secret's material out of locked memory for a protobuf
// field, inside the secret's WithBytes borrow, and records the copy. A secret
// that holds no material yields nil, which proto omits. A destroyed secret is
// an error: serializing it as absent would write a record that silently
// lacks a key, and a session reloaded without its PQ ratchet state, say,
// would carry on without post-quantum protection.
func (o *ownedCopies) copyOut(s *secret.Secret) ([]byte, error) {
	beforeCopyOut(s)
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if len(b) > 0 {
			out = append([]byte(nil), b...)
		}
		return nil
	}); err != nil {
		crypto.Zeroize(out)
		return nil, err
	}
	return o.keep(out), nil
}

// beforeCopyOut runs just before copyOut borrows its source. It is a test
// seam for a source destroyed between lookup and borrow; production code
// leaves it a no-op.
var beforeCopyOut = func(*secret.Secret) {}

// keep records b as owned by the serializer and returns it.
func (o *ownedCopies) keep(b []byte) []byte {
	if o != nil && len(b) > 0 {
		o.bufs = append(o.bufs, b)
	}
	return b
}

// wipe zeroizes every recorded buffer and forgets them.
func (o *ownedCopies) wipe() {
	if o == nil {
		return
	}
	for _, b := range o.bufs {
		crypto.Zeroize(b)
	}
	o.bufs = nil
}
