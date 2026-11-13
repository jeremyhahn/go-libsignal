package ecc

import (
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// GuardPrivateKey moves the serialized form of an EC private key into guarded
// memory for the trip through a serializer. The intermediate plaintext copy is
// zeroized before returning, so the only surviving copy is the guarded one.
//
// It returns the zero Secret when the key is absent, matching the
// zero-means-absent convention of the persisted-state structures.
//
// It lives here rather than beside either caller because both the 1:1 session
// records and the group sender-key records need exactly this conversion, and
// neither package can import the other. ECPrivateKeyable.Serialize returns a
// value array, which is why a plaintext copy exists at all — removing it means
// changing that interface, not this function.
func GuardPrivateKey(key ECPrivateKeyable) (secret.Secret, error) {
	if key == nil {
		return secret.Secret{}, nil
	}
	raw, err := privateKeyArray(key)
	if err != nil {
		return secret.Secret{}, err
	}
	defer crypto.Zeroize(raw[:])
	return secret.NewValue(bytehelper.ArrayToSlice(raw))
}
