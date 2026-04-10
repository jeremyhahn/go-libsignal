package zkcredential

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
)

// TokenLen is the length of an endorsement token in bytes.
// Small enough to minimize overhead, large enough to prevent guessing.
const TokenLen = 16

// ServerRootKeyPair is a server's secret key for issuing and verifying endorsements.
type ServerRootKeyPair struct {
	sk     *ristretto255.Scalar
	Public *ServerRootPublicKey
}

// ServerDerivedKeyPair is a specific secret key pair derived from a ServerRootKeyPair.
type ServerDerivedKeyPair struct {
	skPrime *ristretto255.Scalar
	Public  *ServerDerivedPublicKey
}

// ServerRootPublicKey is the public counterpart of ServerRootKeyPair.
type ServerRootPublicKey struct {
	PK *ristretto255.Element
}

// ServerDerivedPublicKey is the public counterpart of ServerDerivedKeyPair.
type ServerDerivedPublicKey struct {
	PKPrime *ristretto255.Element
}

// ClientDecryptionKey is used to transform endorsements of encrypted values
// to endorsements of decrypted values.
type ClientDecryptionKey struct {
	aInv *ristretto255.Scalar
}

// EndorsementResponse is a set of endorsements issued by a server, along with
// a proof of their validity.
type EndorsementResponse struct {
	R     [][]byte // compressed points
	Proof []byte
}

// Endorsement is an endorsement of a particular hidden attribute point.
type Endorsement struct {
	R *ristretto255.Element
}

// CompressedEndorsement is an endorsement stored in compressed form.
type CompressedEndorsement struct {
	R []byte // 32-byte compressed point
}

// ReceivedEndorsements contains both compressed and decompressed forms
// of endorsements extracted from an EndorsementResponse.
type ReceivedEndorsements struct {
	Compressed   []*CompressedEndorsement
	Decompressed []*Endorsement
}

// GenerateServerRootKeyPair derives a root key by hashing randomness.
func GenerateServerRootKeyPair(randomness [RandomnessLen]byte) (*ServerRootKeyPair, error) {
	sho := NewShoHmacSha256Ext(
		"Signal_ZKCredential_Endorsements_ServerRootKeyPair_generate_20240207",
	)
	sho.AbsorbAndRatchet(randomness[:])
	sk, err := sho.GetScalar()
	if err != nil {
		return nil, &ErrGeneratingRootKey{Err: err}
	}
	return ServerRootKeyPairFromRaw(sk), nil
}

// ServerRootKeyPairFromRaw creates a root key pair from an existing scalar.
func ServerRootKeyPairFromRaw(sk *ristretto255.Scalar) *ServerRootKeyPair {
	PK := new(ristretto255.Element).ScalarBaseMult(sk)
	return &ServerRootKeyPair{
		sk: sk,
		Public: &ServerRootPublicKey{
			PK: PK,
		},
	}
}

// PublicKey returns the public key.
func (rkp *ServerRootKeyPair) PublicKey() *ServerRootPublicKey {
	return rkp.Public
}

// DeriveKey derives a specific key for issuing endorsements.
func (rkp *ServerRootKeyPair) DeriveKey(tagInfo *ShoExt) (*ServerDerivedKeyPair, error) {
	t, err := tagInfo.GetScalar()
	if err != nil {
		return nil, &ErrDerivingTagScalar{Err: err}
	}
	skPlusT := new(ristretto255.Scalar).Add(rkp.sk, t)
	skPrime := new(ristretto255.Scalar).Invert(skPlusT)

	return &ServerDerivedKeyPair{
		skPrime: skPrime,
		Public:  rkp.Public.deriveKeyFromTagScalar(t),
	}, nil
}

// ServerRootPublicKeyFromRaw creates a root public key from an existing point.
func ServerRootPublicKeyFromRaw(PK *ristretto255.Element) *ServerRootPublicKey {
	return &ServerRootPublicKey{PK: PK}
}

// DeriveKey derives a specific public key used to verify endorsements.
func (rpk *ServerRootPublicKey) DeriveKey(tagInfo *ShoExt) (*ServerDerivedPublicKey, error) {
	t, err := tagInfo.GetScalar()
	if err != nil {
		return nil, &ErrDerivingTagScalar{Err: err}
	}
	return rpk.deriveKeyFromTagScalar(t), nil
}

func (rpk *ServerRootPublicKey) deriveKeyFromTagScalar(t *ristretto255.Scalar) *ServerDerivedPublicKey {
	tG := new(ristretto255.Element).ScalarBaseMult(t)
	return &ServerDerivedPublicKey{
		PKPrime: new(ristretto255.Element).Add(rpk.PK, tG),
	}
}

// NewClientDecryptionKeyFromBlinding creates a decryption key from a blinding scalar.
func NewClientDecryptionKeyFromBlinding(scalar *ristretto255.Scalar) *ClientDecryptionKey {
	return &ClientDecryptionKey{
		aInv: new(ristretto255.Scalar).Invert(scalar),
	}
}

// NewClientDecryptionKeyForFirstPoint creates a decryption key from a key pair.
func NewClientDecryptionKeyForFirstPoint(key *KeyPair) *ClientDecryptionKey {
	return NewClientDecryptionKeyFromBlinding(key.A1)
}

// endorsementProofStatement builds the poksho Statement for endorsement proofs.
func endorsementProofStatement() *poksho.Statement {
	st := poksho.NewStatement()
	st.Add("weighted_sum(R)", [][2]string{{"sk_prime", "weighted_sum(E)"}})
	st.Add("G", [][2]string{{"sk_prime", "PK_prime"}})
	return st
}

// IssueEndorsements creates endorsements for a list of hidden attribute points.
func IssueEndorsements(
	hiddenPoints []*ristretto255.Element,
	privateKey *ServerDerivedKeyPair,
	randomness [RandomnessLen]byte,
) (*EndorsementResponse, error) {
	if len(hiddenPoints) == 0 {
		return nil, &ErrMissingHiddenPoints{}
	}

	R := make([][]byte, len(hiddenPoints))
	for i, E := range hiddenPoints {
		Ri := new(ristretto255.Element).ScalarMult(privateKey.skPrime, E)
		R[i] = Ri.Bytes()
	}

	weights := generateWeightsForProof(privateKey.Public, hiddenPoints, R)

	// Compute weighted sum of E
	sumE := new(ristretto255.Element).Set(hiddenPoints[0])
	for i, w := range weights {
		wE := new(ristretto255.Element).ScalarMult(w, hiddenPoints[i+1])
		sumE = sumE.Add(sumE, wE)
	}

	sumR := new(ristretto255.Element).ScalarMult(privateKey.skPrime, sumE)

	// Build proof using poksho Statement
	statement := endorsementProofStatement()
	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("weighted_sum(E)", sumE)
	pointArgs.Add("weighted_sum(R)", sumR)
	pointArgs.Add("PK_prime", privateKey.Public.PKPrime)

	scalarArgs := poksho.NewScalarArgs()
	scalarArgs.Add("sk_prime", privateKey.skPrime)

	proof, err := statement.Prove(scalarArgs, pointArgs, []byte{}, randomness[:])
	if err != nil {
		return nil, &ErrProofCreation{ProofType: "endorsement", Err: err}
	}

	return &EndorsementResponse{
		R:     R,
		Proof: proof,
	}, nil
}

func generateWeightsForProof(
	publicKey *ServerDerivedPublicKey,
	E []*ristretto255.Element,
	R [][]byte,
) []*ristretto255.Scalar {
	hasher := NewShoHmacSha256Ext(
		"Signal_ZKCredential_Endorsements_EndorsementResponse_ProofWeights_20240207",
	)

	hasher.Absorb(publicKey.PKPrime.Bytes())

	// Absorb doubled-and-compressed E values
	for _, Ei := range E {
		doubled := new(ristretto255.Element).Add(Ei, Ei)
		hasher.Absorb(doubled.Bytes())
	}

	for _, Ri := range R {
		hasher.Absorb(Ri)
	}
	hasher.Ratchet()

	// Generate scalars < 2^127 for efficiency
	const smallScalarBytes = 16
	randomness := hasher.SqueezeAndRatchet((len(E) - 1) * smallScalarBytes)

	weights := make([]*ristretto255.Scalar, len(E)-1)
	for i := range weights {
		var scalarBytes [32]byte
		copy(scalarBytes[:16], randomness[i*smallScalarBytes:(i+1)*smallScalarBytes])
		scalarBytes[15] &= 0b0111_1111
		sc := ristretto255.NewScalar()
		if _, err := sc.SetCanonicalBytes(scalarBytes[:]); err != nil {
			panic(fmt.Sprintf("zkcredential: unexpected error creating weight scalar: %v", err))
		}
		weights[i] = sc
	}

	return weights
}

// Receive validates and retrieves the endorsements from a response.
func (er *EndorsementResponse) Receive(
	hiddenPoints []*ristretto255.Element,
	serverPublicKey *ServerDerivedPublicKey,
) (*ReceivedEndorsements, error) {
	if len(hiddenPoints) != len(er.R) {
		return nil, ErrVerification
	}

	// Decompress all R points
	Rpoints := make([]*ristretto255.Element, len(er.R))
	for i, compressed := range er.R {
		p := ristretto255.NewIdentityElement()
		if _, err := p.SetCanonicalBytes(compressed); err != nil {
			return nil, ErrVerification
		}
		Rpoints[i] = p
	}

	weights := generateWeightsForProof(serverPublicKey, hiddenPoints, er.R)

	// Compute weighted sums
	sumR := new(ristretto255.Element).Set(Rpoints[0])
	for i, w := range weights {
		wR := new(ristretto255.Element).ScalarMult(w, Rpoints[i+1])
		sumR = sumR.Add(sumR, wR)
	}

	sumE := new(ristretto255.Element).Set(hiddenPoints[0])
	for i, w := range weights {
		wE := new(ristretto255.Element).ScalarMult(w, hiddenPoints[i+1])
		sumE = sumE.Add(sumE, wE)
	}

	// Verify proof using poksho Statement
	statement := endorsementProofStatement()
	pointArgs := poksho.NewPointArgs()
	pointArgs.Add("weighted_sum(E)", sumE)
	pointArgs.Add("weighted_sum(R)", sumR)
	pointArgs.Add("PK_prime", serverPublicKey.PKPrime)

	if err := statement.VerifyProof(er.Proof, pointArgs, []byte{}); err != nil {
		return nil, ErrVerification
	}

	compressed := make([]*CompressedEndorsement, len(er.R))
	decompressed := make([]*Endorsement, len(Rpoints))
	for i := range Rpoints {
		compressed[i] = &CompressedEndorsement{R: er.R[i]}
		decompressed[i] = &Endorsement{R: Rpoints[i]}
	}

	return &ReceivedEndorsements{
		Compressed:   compressed,
		Decompressed: decompressed,
	}, nil
}

// Compress compresses an Endorsement.
func (e *Endorsement) Compress() *CompressedEndorsement {
	return &CompressedEndorsement{R: e.R.Bytes()}
}

// Decompress decompresses a CompressedEndorsement.
func (ce *CompressedEndorsement) Decompress() (*Endorsement, error) {
	p := ristretto255.NewIdentityElement()
	if _, err := p.SetCanonicalBytes(ce.R); err != nil {
		return nil, ErrVerification
	}
	return &Endorsement{R: p}, nil
}

// CombineEndorsements combines multiple endorsements into one.
func CombineEndorsements(endorsements []*Endorsement) *Endorsement {
	if len(endorsements) == 0 {
		return &Endorsement{R: ristretto255.NewIdentityElement()}
	}
	result := new(ristretto255.Element).Set(endorsements[0].R)
	for i := 1; i < len(endorsements); i++ {
		result = result.Add(result, endorsements[i].R)
	}
	return &Endorsement{R: result}
}

// CombineWith combines this endorsement with another.
func (e *Endorsement) CombineWith(other *Endorsement) *Endorsement {
	return &Endorsement{
		R: new(ristretto255.Element).Add(e.R, other.R),
	}
}

// Remove creates an endorsement with other removed from this one.
func (e *Endorsement) Remove(other *Endorsement) *Endorsement {
	return &Endorsement{
		R: new(ristretto255.Element).Subtract(e.R, other.R),
	}
}

// ToToken generates a token from this endorsement for sending to the
// verifying server.
func (e *Endorsement) ToToken(clientKey *ClientDecryptionKey) []byte {
	P := new(ristretto255.Element).ScalarMult(clientKey.aInv, e.R)
	return endorsementToTokenRaw(P)
}

func endorsementToTokenRaw(unblindedEndorsement *ristretto255.Element) []byte {
	h := sha256.Sum256(unblindedEndorsement.Bytes())
	token := make([]byte, TokenLen)
	copy(token, h[:TokenLen])
	return token
}

// Verify verifies that a token is valid for a point according to this key.
func (dk *ServerDerivedKeyPair) Verify(
	point *ristretto255.Element,
	token []byte,
) error {
	P := new(ristretto255.Element).ScalarMult(dk.skPrime, point)
	expected := endorsementToTokenRaw(P)
	if subtle.ConstantTimeCompare(token, expected) != 1 {
		return ErrVerification
	}
	return nil
}

// DefaultEndorsement returns the identity endorsement.
func DefaultEndorsement() *Endorsement {
	return &Endorsement{R: ristretto255.NewIdentityElement()}
}
