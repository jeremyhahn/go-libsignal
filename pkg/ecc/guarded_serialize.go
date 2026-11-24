package ecc

import (
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// GuardPrivateKey moves a serialized EC private key into guarded memory, zeroizing the plaintext copy; an absent key gives the zero Secret.
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
