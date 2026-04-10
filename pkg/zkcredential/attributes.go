package zkcredential

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/gtank/ristretto255"
)

// PublicAttribute is an attribute that doesn't need to be hidden from the
// issuing server or verifying server. It can be encoded more efficiently,
// making for smaller, faster proofs.
type PublicAttribute interface {
	// HashInto mixes the attribute into the SHO hash state.
	// Implementations should call sho.AbsorbAndRatchet one or more times.
	HashInto(sho *ShoExt)
}

// PublicAttributeBytes implements PublicAttribute for a byte slice.
type PublicAttributeBytes []byte

// HashInto implements PublicAttribute.
func (p PublicAttributeBytes) HashInto(sho *ShoExt) {
	sho.AbsorbAndRatchet([]byte(p))
}

// PublicAttributeU32 implements PublicAttribute for a uint32.
type PublicAttributeU32 uint32

// HashInto implements PublicAttribute.
func (p PublicAttributeU32) HashInto(sho *ShoExt) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(p))
	PublicAttributeBytes(b).HashInto(sho)
}

// PublicAttributeU64 implements PublicAttribute for a uint64.
type PublicAttributeU64 uint64

// HashInto implements PublicAttribute.
func (p PublicAttributeU64) HashInto(sho *ShoExt) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(p))
	PublicAttributeBytes(b).HashInto(sho)
}

// Attribute represents an attribute as a pair of ristretto255 points.
// Used for credential attributes that need to take advantage of homomorphic
// encryption.
type Attribute interface {
	// AsPoints returns the attribute as a pair of ristretto255 points.
	AsPoints() [2]*ristretto255.Element
}

// PointPairAttribute is a simple Attribute implementation backed by two points.
type PointPairAttribute [2]*ristretto255.Element

// AsPoints implements Attribute.
func (p PointPairAttribute) AsPoints() [2]*ristretto255.Element {
	return [2]*ristretto255.Element(p)
}

// RevealedAttribute is an attribute that is blinded to the issuing server
// but revealed to the verifying server.
type RevealedAttribute interface {
	// AsPoint returns the attribute as a single ristretto255 point.
	AsPoint() *ristretto255.Element
}

// PointAttribute is a simple RevealedAttribute backed by a single point.
type PointAttribute struct {
	Point *ristretto255.Element
}

// AsPoint implements RevealedAttribute.
func (p *PointAttribute) AsPoint() *ristretto255.Element {
	return p.Point
}

// Domain provides separation between different encryption keys and ciphertexts.
type Domain interface {
	// ID returns a unique identifier for this encryption domain.
	ID() string
	// Ga returns the generator points for this domain.
	Ga() [2]*ristretto255.Element
}

// DeriveDefaultGeneratorPoints derives reasonable generator points for a domain
// based on its ID, using SHO with HMAC-SHA-256.
func DeriveDefaultGeneratorPoints(domainID string) [2]*ristretto255.Element {
	sho := NewShoHmacSha256Ext("Signal_ZKCredential_Domain_20231011")
	sho.AbsorbAndRatchet([]byte(domainID))
	ga1 := sho.MustGetPoint()
	ga2 := sho.MustGetPoint()
	return [2]*ristretto255.Element{ga1, ga2}
}

// KeyPair is a key used to encrypt attributes.
//
// The private key is a pair of scalars a1 and a2. Attributes are encrypted as:
//
//	E_A1 = a1 * M1
//	E_A2 = a2 * E_A1 + M2
//
// Defined in Chase-Perrin-Zaverucha section 4.1.
type KeyPair struct {
	A1        *ristretto255.Scalar
	A2        *ristretto255.Scalar
	PublicKey *PublicKey
	domain    Domain
}

// PublicKey is a key used to validate encrypted attributes.
type PublicKey struct {
	A      *ristretto255.Element
	domain Domain
}

// DomainID returns the domain ID for this public key.
func (pk *PublicKey) DomainID() string {
	if pk.domain != nil {
		return pk.domain.ID()
	}
	return ""
}

// Ga returns the domain generator points for this public key.
func (pk *PublicKey) Ga() [2]*ristretto255.Element {
	if pk.domain != nil {
		return pk.domain.Ga()
	}
	return [2]*ristretto255.Element{
		ristretto255.NewIdentityElement(),
		ristretto255.NewIdentityElement(),
	}
}

// Equal returns true if two KeyPairs have equal scalars (constant-time).
func (kp *KeyPair) Equal(other *KeyPair) bool {
	return subtle.ConstantTimeCompare(kp.A1.Bytes(), other.A1.Bytes()) == 1 &&
		subtle.ConstantTimeCompare(kp.A2.Bytes(), other.A2.Bytes()) == 1
}

// Equal returns true if two PublicKeys are equal (constant-time).
func (pk *PublicKey) Equal(other *PublicKey) bool {
	return subtle.ConstantTimeCompare(pk.A.Bytes(), other.A.Bytes()) == 1
}

// DeriveKeyPair generates a new KeyPair from the hash state in sho for
// the given domain.
func DeriveKeyPair(sho *ShoExt, domain Domain) (*KeyPair, error) {
	a1, err := sho.GetScalar()
	if err != nil {
		return nil, &ErrDerivingScalar{Label: "a1", Err: err}
	}
	a2, err := sho.GetScalar()
	if err != nil {
		return nil, &ErrDerivingScalar{Label: "a2", Err: err}
	}
	return keyPairFromScalars(a1, a2, domain), nil
}

func keyPairFromScalars(a1, a2 *ristretto255.Scalar, domain Domain) *KeyPair {
	ga := domain.Ga()
	// A = a1 * G_a1 + a2 * G_a2
	t1 := new(ristretto255.Element).ScalarMult(a1, ga[0])
	t2 := new(ristretto255.Element).ScalarMult(a2, ga[1])
	A := new(ristretto255.Element).Add(t1, t2)

	pk := &PublicKey{
		A:      A,
		domain: domain,
	}

	return &KeyPair{
		A1:        a1,
		A2:        a2,
		PublicKey:  pk,
		domain:    domain,
	}
}

// InverseKeyPair creates a KeyPair that is the inverse of other.
// That is, encrypting with the inverse and then with the original yields
// the original attribute.
//
// The domain of the result must differ from the domain of other.
func InverseKeyPair(other *KeyPair, newDomain Domain) (*KeyPair, error) {
	if other.domain != nil && newDomain.ID() == other.domain.ID() {
		return nil, &ErrMissingInverseDomain{}
	}
	a1 := new(ristretto255.Scalar).Invert(other.A1)
	// a2 = -(other.a1 * other.a2)
	a2 := new(ristretto255.Scalar).Multiply(other.A1, other.A2)
	a2 = a2.Negate(a2)
	return keyPairFromScalars(a1, a2, newDomain), nil
}

// Encrypt encrypts an attribute using this key pair.
// E_A1 = a1 * M1; E_A2 = a2 * E_A1 + M2
func (kp *KeyPair) Encrypt(attr Attribute) *Ciphertext {
	return kp.EncryptArbitrary(attr)
}

// EncryptArbitrary encrypts an arbitrary attribute, regardless of whether it
// is normally associated with this key's domain.
func (kp *KeyPair) EncryptArbitrary(attr Attribute) *Ciphertext {
	points := attr.AsPoints()
	M1 := points[0]
	M2 := points[1]
	EA1 := new(ristretto255.Element).ScalarMult(kp.A1, M1)
	t := new(ristretto255.Element).ScalarMult(kp.A2, EA1)
	EA2 := new(ristretto255.Element).Add(t, M2)
	return &Ciphertext{
		EA1: EA1,
		EA2: EA2,
	}
}

// DecryptToSecondPoint recovers M2 from a ciphertext: M2 = E_A2 - a2 * E_A1.
//
// Returns an error if E_A1 is the generator point, which would imply
// that a1 is not actually encrypting anything.
func (kp *KeyPair) DecryptToSecondPoint(ct *Ciphertext) (*ristretto255.Element, error) {
	gen := ristretto255.NewGeneratorElement()
	if ct.EA1.Equal(gen) == 1 {
		return nil, ErrVerification
	}
	t := new(ristretto255.Element).ScalarMult(kp.A2, ct.EA1)
	return new(ristretto255.Element).Subtract(ct.EA2, t), nil
}

// Ciphertext is an attribute encrypted with KeyPair.Encrypt.
type Ciphertext struct {
	EA1 *ristretto255.Element
	EA2 *ristretto255.Element
}

// AsPoints implements the Attribute interface for Ciphertext, allowing
// ciphertexts to be treated as attributes for further operations.
func (ct *Ciphertext) AsPoints() [2]*ristretto255.Element {
	return [2]*ristretto255.Element{ct.EA1, ct.EA2}
}

// Equal returns true if two Ciphertexts are equal (constant-time).
func (ct *Ciphertext) Equal(other *Ciphertext) bool {
	return subtle.ConstantTimeCompare(ct.EA1.Bytes(), other.EA1.Bytes()) == 1 &&
		subtle.ConstantTimeCompare(ct.EA2.Bytes(), other.EA2.Bytes()) == 1
}

// EncodeCiphertext encodes a Ciphertext as 64 bytes (two compressed points).
func EncodeCiphertext(ct *Ciphertext) []byte {
	out := make([]byte, 64)
	copy(out[:32], ct.EA1.Bytes())
	copy(out[32:], ct.EA2.Bytes())
	return out
}

// DecodeCiphertext decodes a Ciphertext from 64 bytes.
func DecodeCiphertext(data []byte) (*Ciphertext, error) {
	if len(data) != 64 {
		return nil, &ErrCiphertextSize{Got: len(data)}
	}
	ea1 := ristretto255.NewIdentityElement()
	if _, err := ea1.SetCanonicalBytes(data[:32]); err != nil {
		return nil, &ErrInvalidEncoding{Field: "EA1", Err: err}
	}
	ea2 := ristretto255.NewIdentityElement()
	if _, err := ea2.SetCanonicalBytes(data[32:]); err != nil {
		return nil, &ErrInvalidEncoding{Field: "EA2", Err: err}
	}
	return &Ciphertext{EA1: ea1, EA2: ea2}, nil
}
