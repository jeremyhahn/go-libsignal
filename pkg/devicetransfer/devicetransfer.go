// Package devicetransfer provides utilities for generating RSA private keys
// and self-signed X.509 certificates used during Signal device transfer.
package devicetransfer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/crypto/keyops"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

// KeyFormat specifies the format for private key encoding.
type KeyFormat int

const (
	// KeyFormatPKCS8 encodes private keys in PKCS#8 format.
	KeyFormatPKCS8 KeyFormat = iota
	// KeyFormatPKCS1 encodes private keys in PKCS#1 (RSA-specific) format.
	KeyFormatPKCS1
)

// DefaultKeyBits is the default RSA key size used when no specific size is given.
const DefaultKeyBits = 4096

// MinKeyBits is the minimum acceptable RSA key size.
const MinKeyBits = 2048

// CreateRSAPrivateKey generates an RSA private key of the given bit size
// and returns it in the specified format as DER-encoded bytes.
//
// The caller is responsible for zeroizing the returned DER bytes when they
// are no longer needed (e.g., via crypto.Zeroize).
func CreateRSAPrivateKey(bits int, format KeyFormat) ([]byte, error) {
	if bits <= 0 {
		bits = DefaultKeyBits
	}
	if bits < MinKeyBits {
		return nil, newInvalidKeySizeError(fmt.Sprintf("%d bits requested, minimum is %d", bits, MinKeyBits))
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, newKeyGenerationError(err)
	}
	// Zeroize all RSA private key material (D, CRT parameters, and primes).
	// Use zeroizeBigInt to overwrite the backing word slice before clearing,
	// preventing sensitive data from lingering in freed memory.
	defer func() {
		zeroizeBigInt(key.D)
		zeroizeBigInt(key.Precomputed.Dp)
		zeroizeBigInt(key.Precomputed.Dq)
		zeroizeBigInt(key.Precomputed.Qinv)
		for _, prime := range key.Primes {
			zeroizeBigInt(prime)
		}
		// Note: key.Precomputed.CRTValues is deprecated since Go 1.20 and
		// is no longer populated by the Go runtime, so no zeroization is needed.
	}()

	switch format {
	case KeyFormatPKCS8:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, newKeyGenerationError(err)
		}
		return der, nil
	case KeyFormatPKCS1:
		return x509.MarshalPKCS1PrivateKey(key), nil
	default:
		return nil, newUnsupportedFormatError(fmt.Sprintf("%d", format))
	}
}

// GenerateRSASigner generates a new RSA key pair and returns it as an
// RSASigner. If bits is less than MinKeyBits, DefaultKeyBits is used.
func GenerateRSASigner(bits int) (keyops.RSASigner, error) {
	if bits < MinKeyBits {
		bits = DefaultKeyBits
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, newKeyGenerationError(err)
	}
	return keyops.NewSoftwareRSASigner(key)
}

// CreateSelfSignedCert generates a self-signed X.509 certificate using
// the given RSA private key (DER-encoded), common name, and validity period.
// It returns the certificate as DER-encoded bytes.
//
// The private key is parsed by trying PKCS#8 first and falling back to PKCS#1.
// The parsed key is wrapped in an RSASigner for signing and destroyed after use.
func CreateSelfSignedCert(privateKeyDER []byte, name string, validDays int) ([]byte, error) {
	key, err := parseRSAPrivateKey(privateKeyDER)
	if err != nil {
		return nil, err
	}

	signer, err := keyops.NewSoftwareRSASigner(key)
	if err != nil {
		return nil, newKeyGenerationError(err)
	}
	defer signer.Destroy()

	return createCertificate(signer, name, validDays)
}

// CreateSelfSignedCertWithSigner generates a self-signed X.509 certificate
// using the provided RSASigner, common name, and validity period. It returns
// the certificate as DER-encoded bytes.
//
// Unlike CreateSelfSignedCert, this function does not destroy the signer;
// lifecycle management remains the caller's responsibility.
func CreateSelfSignedCertWithSigner(signer keyops.RSASigner, name string, validDays int) ([]byte, error) {
	if signer == nil {
		return nil, ErrNilSigner
	}
	return createCertificate(signer, name, validDays)
}

// CreateRSAPrivateKeyPEM generates an RSA private key and returns it as
// PEM-encoded bytes. The PEM block type depends on the chosen format:
// "PRIVATE KEY" for PKCS#8 or "RSA PRIVATE KEY" for PKCS#1.
//
// The caller is responsible for zeroizing the returned PEM bytes when they
// are no longer needed (e.g., via crypto.Zeroize).
func CreateRSAPrivateKeyPEM(bits int, format KeyFormat) ([]byte, error) {
	der, err := CreateRSAPrivateKey(bits, format)
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(der)

	blockType := "PRIVATE KEY"
	if format == KeyFormatPKCS1 {
		blockType = "RSA PRIVATE KEY"
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: der,
	}), nil
}

// CreateSelfSignedCertPEM generates a self-signed X.509 certificate and
// returns it as PEM-encoded bytes. The privateKeyPEM must be a PEM-encoded
// RSA private key in either PKCS#8 or PKCS#1 format.
func CreateSelfSignedCertPEM(privateKeyPEM []byte, name string, validDays int) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, &Error{kind: errPEMDecode}
	}
	defer crypto.Zeroize(block.Bytes)

	certDER, err := CreateSelfSignedCert(block.Bytes, name, validDays)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), nil
}

// createCertificate is the shared certificate creation logic used by both
// CreateSelfSignedCert and CreateSelfSignedCertWithSigner.
func createCertificate(signer keyops.RSASigner, name string, validDays int) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, newCertCreationError(err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         name,
			Organization:       []string{"Signal Foundation"},
			OrganizationalUnit: []string{"Device Transfer"},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(0, 0, validDays),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, newCertCreationError(err)
	}

	return certDER, nil
}

// parseRSAPrivateKey attempts to parse a DER-encoded RSA private key,
// trying PKCS#8 first and falling back to PKCS#1.
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	// Try PKCS#8 first.
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, newKeyParsingError("PKCS#8 key is not RSA")
		}
		return key, nil
	}

	// Fall back to PKCS#1.
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, newKeyParsingErrorWrap(err)
	}

	return key, nil
}

// zeroizeBigInt overwrites the backing word slice of a big.Int with zeros
// before setting it to zero. This prevents sensitive key material from
// lingering in freed memory, unlike SetInt64(0) which merely replaces
// the value without clearing the old backing array.
func zeroizeBigInt(n *big.Int) {
	if n == nil {
		return
	}
	words := n.Bits()
	for i := range words {
		words[i] = 0
	}
	n.SetInt64(0)
}
