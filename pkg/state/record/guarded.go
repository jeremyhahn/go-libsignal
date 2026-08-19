package record

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// guardECPrivateKey moves the serialized form of an EC private key into guarded
// memory for the trip through a serializer. The intermediate plaintext copy is
// zeroized before returning, so the only surviving copy is the guarded one.
//
// It returns the zero Secret when the key is absent, matching the
// zero-means-absent convention of the persisted-state structures.
func guardECPrivateKey(key ecc.ECPrivateKeyable) (secret.Secret, error) {
	if key == nil {
		return secret.Secret{}, nil
	}
	raw := key.Serialize()
	defer crypto.Zeroize(raw[:])
	return secret.NewValue(bytehelper.ArrayToSlice(raw))
}
