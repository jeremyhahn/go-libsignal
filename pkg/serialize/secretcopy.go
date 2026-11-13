package serialize

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// copyOut copies a secret's material out of locked memory for a protobuf
// field, inside the secret's WithBytes borrow. A secret that holds no
// material, or one that has been destroyed, yields nil, which proto omits.
//
// The copy lives on the ordinary heap until the message is marshaled and
// dropped: serialization exists to move the material across the storage
// boundary, and the marshaled output holds the same bytes.
func copyOut(s *secret.Secret) []byte {
	var out []byte
	if err := s.WithBytes(func(b []byte) error {
		if len(b) > 0 {
			out = append([]byte(nil), b...)
		}
		return nil
	}); err != nil {
		return nil
	}
	return out
}
