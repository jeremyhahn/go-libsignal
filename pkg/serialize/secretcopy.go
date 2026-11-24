package serialize

import (
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"google.golang.org/protobuf/proto"
)

// ownedCopies records the secret copies and marshal buffers a serializer owns, which wipe clears after proto.Marshal; aliased public fields are never recorded. A nil *ownedCopies records nothing.
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

// copyOut copies a secret's material inside its WithBytes borrow and records the copy; an empty or destroyed secret yields nil.
func (o *ownedCopies) copyOut(s *secret.Secret) []byte {
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if len(b) > 0 {
			out = append([]byte(nil), b...)
		}
		return nil
	}); err != nil {
		return nil
	}
	return o.keep(out)
}

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
