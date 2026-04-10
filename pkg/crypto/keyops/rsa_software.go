package keyops

import (
	"crypto"
	"crypto/rsa"
	"io"
)

// SoftwareRSASigner wraps a standard library *rsa.PrivateKey to implement
// RSASigner. Key material is zeroized on Destroy().
type SoftwareRSASigner struct {
	key       *rsa.PrivateKey
	destroyed bool
}

// Compile-time interface satisfaction check.
var _ RSASigner = (*SoftwareRSASigner)(nil)

// NewSoftwareRSASigner creates an RSASigner from an existing RSA private key.
// Returns ErrKeyDestroyed if key is nil.
func NewSoftwareRSASigner(key *rsa.PrivateKey) (RSASigner, error) {
	if key == nil {
		return nil, NewKeyDestroyedError("nil RSA private key")
	}
	return &SoftwareRSASigner{key: key}, nil
}

// Public returns the RSA public key. Returns nil if the signer has been
// destroyed.
func (s *SoftwareRSASigner) Public() crypto.PublicKey {
	if s.destroyed {
		return nil
	}
	return &s.key.PublicKey
}

// Sign performs RSA signing using the underlying private key. Returns
// ErrKeyDestroyed if the signer has been destroyed.
func (s *SoftwareRSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.destroyed {
		return nil, NewKeyDestroyedError("RSA signer destroyed")
	}
	sig, err := s.key.Sign(rand, digest, opts)
	if err != nil {
		return nil, NewSignatureError(err.Error())
	}
	return sig, nil
}

// Destroy zeroizes the private key material. This method is idempotent and
// safe to call multiple times.
func (s *SoftwareRSASigner) Destroy() {
	if s.destroyed || s.key == nil {
		return
	}
	s.key.D.SetInt64(0)
	for _, p := range s.key.Primes {
		p.SetInt64(0)
	}
	s.key.Precomputed = rsa.PrecomputedValues{}
	s.key = nil
	s.destroyed = true
}
