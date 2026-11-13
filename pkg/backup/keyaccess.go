package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// newAESBlock builds an AES block cipher from the key in s inside a WithBytes
// borrow. aes.NewCipher expands the key into its own schedule, so the view
// does not outlive the borrow.
func newAESBlock(s *secret.Secret) (cipher.Block, error) {
	var block cipher.Block
	err := s.WithBytes(func(key []byte) error {
		var bErr error
		block, bErr = aes.NewCipher(key)
		return bErr
	})
	return block, err
}

// newHMAC builds an HMAC-SHA256 from the key in s inside a WithBytes borrow.
// hmac.New copies the key into its own pads, so the view does not outlive
// the borrow. A nil, empty or destroyed key is refused: WithBytes calls fn
// with a nil view for a nil or zero Secret, and an HMAC under an empty key
// would let anyone forge a valid tag.
func newHMAC(s *secret.Secret) (hash.Hash, error) {
	var mac hash.Hash
	err := s.WithBytes(func(key []byte) error {
		if len(key) != HMACKeyLen {
			return &ErrInvalidKeyLength{Field: "hmacKey", Got: len(key), Want: HMACKeyLen}
		}
		mac = hmac.New(sha256.New, key)
		return nil
	})
	return mac, err
}
