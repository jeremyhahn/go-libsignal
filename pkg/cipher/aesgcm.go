// AES-256-GCM, one-shot and streaming, mirroring rust/crypto/src/aes_gcm.rs.

package cipher

import (
	"crypto/aes"
	goCipher "crypto/cipher"
	"slices"
)

// AESGCMNonceSize is the nonce size for AES-256-GCM.
// Mirrors Rust signal_crypto::Aes256GcmEncryption::NONCE_SIZE = 12.
// Rust source: rust/crypto/src/aes_gcm.rs:16
const AESGCMNonceSize = 12

// AESGCMTagSize is the authentication tag size for AES-256-GCM.
// Mirrors Rust signal_crypto::Aes256GcmEncryption::TAG_SIZE = 16.
// Rust source: rust/crypto/src/aes_gcm.rs:15
const AESGCMTagSize = 16

// AESGCMEncrypt encrypts with a 32-byte key and 12-byte nonce and returns ciphertext || tag.
func AESGCMEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrInvalidKeyLength{Got: len(key), Expected: 32}
	}
	if len(nonce) != AESGCMNonceSize {
		return nil, &ErrInvalidNonceLength{Got: len(nonce), Expected: AESGCMNonceSize}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := goCipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// AESGCMDecrypt authenticates and decrypts ciphertext with its 16-byte tag appended.
func AESGCMDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, &ErrInvalidKeyLength{Got: len(key), Expected: 32}
	}
	if len(nonce) != AESGCMNonceSize {
		return nil, &ErrInvalidNonceLength{Got: len(nonce), Expected: AESGCMNonceSize}
	}
	if len(ciphertext) < AESGCMTagSize {
		return nil, &ErrCipherCiphertextTooShort{}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := goCipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// AES256GCMEncryption is a streaming encryptor (Rust Aes256GcmEncryption); it buffers chunks and seals them in ComputeTag.
type AES256GCMEncryption struct {
	key   []byte
	nonce []byte
	aad   []byte
	buf   []byte
}

// NewAES256GCMEncryption constructs a streaming encryptor from a 32-byte key, 12-byte nonce and optional AAD.
func NewAES256GCMEncryption(key, nonce, aad []byte) (*AES256GCMEncryption, error) {
	if len(key) != 32 {
		return nil, &ErrInvalidKeyLength{Got: len(key), Expected: 32}
	}
	if len(nonce) != AESGCMNonceSize {
		return nil, &ErrInvalidNonceLength{Got: len(nonce), Expected: AESGCMNonceSize}
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	nonceCopy := make([]byte, len(nonce))
	copy(nonceCopy, nonce)
	aadCopy := make([]byte, len(aad))
	copy(aadCopy, aad)
	return &AES256GCMEncryption{
		key:   keyCopy,
		nonce: nonceCopy,
		aad:   aadCopy,
	}, nil
}

// Encrypt buffers buf; the ciphertext is ready after ComputeTag.
func (e *AES256GCMEncryption) Encrypt(buf []byte) {
	e.buf = append(e.buf, buf...)
}

// ComputeTag finishes encryption and returns the 16-byte tag; the encryptor is not reusable afterwards.
func (e *AES256GCMEncryption) ComputeTag() (ciphertext []byte, tag [AESGCMTagSize]byte, err error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, tag, err
	}
	gcm, err := goCipher.NewGCM(block)
	if err != nil {
		return nil, tag, err
	}
	// Seal appends tag to ciphertext: output = nonce || ct || tag.
	// We extract ct and tag.
	sealed := gcm.Seal(nil, e.nonce, e.buf, e.aad)
	ctLen := len(sealed) - AESGCMTagSize
	ciphertext = sealed[:ctLen]
	copy(tag[:], sealed[ctLen:])
	return ciphertext, tag, nil
}

// AES256GCMDecryption is a streaming decryptor: Decrypt chunks, then VerifyTag returns the plaintext or ErrAESGCMAuthFailed.
type AES256GCMDecryption struct {
	key   []byte
	nonce []byte
	aad   []byte
	buf   []byte
}

// NewAES256GCMDecryption constructs a streaming decryptor from a 32-byte key, 12-byte nonce and optional AAD.
func NewAES256GCMDecryption(key, nonce, aad []byte) (*AES256GCMDecryption, error) {
	if len(key) != 32 {
		return nil, &ErrInvalidKeyLength{Got: len(key), Expected: 32}
	}
	if len(nonce) != AESGCMNonceSize {
		return nil, &ErrInvalidNonceLength{Got: len(nonce), Expected: AESGCMNonceSize}
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	nonceCopy := make([]byte, len(nonce))
	copy(nonceCopy, nonce)
	aadCopy := make([]byte, len(aad))
	copy(aadCopy, aad)
	return &AES256GCMDecryption{
		key:   keyCopy,
		nonce: nonceCopy,
		aad:   aadCopy,
	}, nil
}

// Decrypt buffers ciphertext for authentication in VerifyTag.
func (d *AES256GCMDecryption) Decrypt(buf []byte) {
	d.buf = append(d.buf, buf...)
}

// VerifyTag checks the 16-byte tag and returns the plaintext; on failure it zeroes the buffer and returns ErrAESGCMAuthFailed.
func (d *AES256GCMDecryption) VerifyTag(tag []byte) ([]byte, error) {
	if len(tag) != AESGCMTagSize {
		return nil, &ErrInvalidNonceLength{Got: len(tag), Expected: AESGCMTagSize}
	}

	block, err := aes.NewCipher(d.key)
	if err != nil {
		for i := range d.buf {
			d.buf[i] = 0
		}
		return nil, err
	}
	gcm, err := goCipher.NewGCM(block)
	if err != nil {
		for i := range d.buf {
			d.buf[i] = 0
		}
		return nil, err
	}

	// Reconstruct the GCM wire format (ciphertext || tag) for Open.
	combined := slices.Concat(d.buf, tag)
	plaintext, err := gcm.Open(nil, d.nonce, combined, d.aad)
	if err != nil {
		// Zero out the internal buffer on authentication failure.
		for i := range d.buf {
			d.buf[i] = 0
		}
		return nil, &ErrAESGCMAuthFailed{}
	}
	return plaintext, nil
}

// ErrAESGCMAuthFailed is returned by AES256GCMDecryption.VerifyTag when the
// authentication tag does not match the ciphertext.
type ErrAESGCMAuthFailed struct{}

func (e *ErrAESGCMAuthFailed) Error() string {
	return "aesgcm: authentication failed"
}
