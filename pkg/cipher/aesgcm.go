// Package cipher — AES-256-GCM (AEAD, one-shot and streaming).
//
// AESGCMEncrypt and AESGCMDecrypt mirror the semantics of Rust's
// signal_crypto::Aes256GcmEncryption / Aes256GcmDecryption for the
// one-shot (non-streaming) path.
//
// AES256GCMEncryption and AES256GCMDecryption provide the streaming
// equivalents matching Rust's incremental Update/ComputeTag/VerifyTag API.
// Rust source: rust/crypto/src/aes_gcm.rs

package cipher

import (
	"crypto/aes"
	goCipher "crypto/cipher"
)

// AESGCMNonceSize is the nonce size for AES-256-GCM.
// Mirrors Rust signal_crypto::Aes256GcmEncryption::NONCE_SIZE = 12.
// Rust source: rust/crypto/src/aes_gcm.rs:16
const AESGCMNonceSize = 12

// AESGCMTagSize is the authentication tag size for AES-256-GCM.
// Mirrors Rust signal_crypto::Aes256GcmEncryption::TAG_SIZE = 16.
// Rust source: rust/crypto/src/aes_gcm.rs:15
const AESGCMTagSize = 16

// AESGCMEncrypt encrypts plaintext with AES-256-GCM using the given key,
// nonce, and additional authenticated data. Returns ciphertext || tag.
//
// key must be 32 bytes (AES-256).
// nonce must be AESGCMNonceSize (12) bytes.
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

// AESGCMDecrypt decrypts AES-256-GCM ciphertext (with appended 16-byte tag)
// and verifies authentication. Returns the plaintext on success.
//
// key must be 32 bytes (AES-256).
// nonce must be AESGCMNonceSize (12) bytes.
// ciphertext must include the 16-byte authentication tag appended at the end.
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

// AES256GCMEncryption is a streaming AES-256-GCM encryptor. It buffers
// plaintext in-place via Encrypt and produces the authentication tag via
// ComputeTag. The tag covers all data passed to Encrypt, authenticated
// against the AAD supplied to NewAES256GCMEncryption.
//
// Mirrors Rust signal_crypto::Aes256GcmEncryption.
// Rust source: rust/crypto/src/aes_gcm.rs:133-152
//
// Usage:
//
//	enc, err := NewAES256GCMEncryption(key, nonce, aad)
//	enc.Encrypt(chunk1)
//	enc.Encrypt(chunk2)
//	tag := enc.ComputeTag()
//
// AES256GCMEncryption accumulates plaintext chunks and finalises
// encryption with authentication in ComputeTag. Since crypto/cipher.GCM
// does not expose incremental GHASH, plaintext is buffered and sealed
// once at the end.
type AES256GCMEncryption struct {
	key   []byte
	nonce []byte
	aad   []byte
	buf   []byte
}

// NewAES256GCMEncryption constructs a streaming AES-256-GCM encryptor.
//
// key must be 32 bytes (AES-256).
// nonce must be AESGCMNonceSize (12) bytes.
// aad is the additional authenticated data; it may be nil.
//
// Mirrors Rust Aes256GcmEncryption::new(key, nonce, aad).
// Rust source: rust/crypto/src/aes_gcm.rs:139-151
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

// Encrypt encrypts buf in-place, appending the resulting ciphertext to the
// internal buffer. The caller should not read the result until ComputeTag.
//
// Mirrors Rust Aes256GcmEncryption::encrypt(&mut buf).
// Rust source: rust/crypto/src/aes_gcm.rs:142-148
func (e *AES256GCMEncryption) Encrypt(buf []byte) {
	e.buf = append(e.buf, buf...)
}

// ComputeTag finalises encryption, returning the 16-byte authentication tag.
// After this call the AES256GCMEncryption must not be reused.
//
// Returns the encrypted ciphertext (in-place in the internal buffer) and the
// 16-byte GCM authentication tag.
//
// Mirrors Rust Aes256GcmEncryption::compute_tag(self) -> [u8; TAG_SIZE].
// Rust source: rust/crypto/src/aes_gcm.rs:152
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

// AES256GCMDecryption is a streaming AES-256-GCM decryptor. Feed ciphertext
// chunks via Decrypt, then call VerifyTag to authenticate and obtain the
// plaintext. If the tag is invalid, VerifyTag returns ErrAESGCMAuthFailed and
// the plaintext is zeroed.
//
// Mirrors Rust signal_crypto::Aes256GcmDecryption.
// Rust source: rust/crypto/src/aes_gcm.rs:163-191
//
// Usage:
//
//	dec, err := NewAES256GCMDecryption(key, nonce, aad)
//	dec.Decrypt(chunk1)
//	dec.Decrypt(chunk2)
//	plaintext, err := dec.VerifyTag(tag)
type AES256GCMDecryption struct {
	key   []byte
	nonce []byte
	aad   []byte
	buf   []byte
}

// NewAES256GCMDecryption constructs a streaming AES-256-GCM decryptor.
//
// key must be 32 bytes (AES-256).
// nonce must be AESGCMNonceSize (12) bytes.
// aad is the additional authenticated data; it may be nil.
//
// Mirrors Rust Aes256GcmDecryption::new(key, nonce, aad).
// Rust source: rust/crypto/src/aes_gcm.rs:165-176
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

// Decrypt appends ciphertext to the internal buffer for later authentication.
//
// Mirrors Rust Aes256GcmDecryption::decrypt(&mut buf).
// Rust source: rust/crypto/src/aes_gcm.rs:178-184
func (d *AES256GCMDecryption) Decrypt(buf []byte) {
	d.buf = append(d.buf, buf...)
}

// VerifyTag authenticates all ciphertext fed via Decrypt against tag and,
// if successful, returns the decrypted plaintext. If authentication fails,
// the internal buffer is zeroed and ErrAESGCMAuthFailed is returned.
//
// tag must be exactly AESGCMTagSize (16) bytes.
//
// Mirrors Rust Aes256GcmDecryption::verify_tag(self, tag) -> Result<Vec<u8>>.
// Rust source: rust/crypto/src/aes_gcm.rs:186-191
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
	combined := append(d.buf, tag...)
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
