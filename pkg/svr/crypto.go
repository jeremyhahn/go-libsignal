package svr

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"runtime"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/hkdf"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// zeroScalar overwrites a ristretto255.Scalar with the zero value.
// runtime.KeepAlive prevents the compiler from eliminating the zeroing as dead writes.
func zeroScalar(s *ristretto255.Scalar) {
	if s != nil {
		s.Zero()
		runtime.KeepAlive(s)
	}
}

// arrXOR computes into ^= from. Both slices must have equal length.
func arrXOR(from, into []byte) {
	if len(from) != len(into) {
		panic("svr: arrXOR called with mismatched lengths")
	}
	for i := range from {
		into[i] ^= from[i]
	}
}

// kdf derives a key of the given length using HKDF-SHA256 with the
// concatenation of input1 and input2 as IKM and info as the info parameter.
// No salt is used. The intermediate concatenation buffer is protected in
// guarded memory and destroyed after use.
func kdf(info, input1, input2 []byte, out []byte) {
	concat := make([]byte, 0, len(input1)+len(input2))
	concat = append(concat, input1...)
	concat = append(concat, input2...)
	concatSecret, err := secret.New(concat)
	if err != nil {
		panic("svr: failed to protect IKM: " + err.Error())
	}
	defer concatSecret.Destroy()
	if err := concatSecret.WithBytes(func(ikm []byte) error {
		_, rErr := io.ReadFull(hkdf.New(sha256.New, ikm, nil, info), out)
		return rErr
	}); err != nil {
		panic("svr: HKDF expansion failed: " + err.Error())
	}
}

// kdf32 derives a 32-byte key.
func kdf32(info, input1, input2 []byte) [32]byte {
	var out [32]byte
	kdf(info, input1, input2, out[:])
	return out
}

// kdf64 derives a 64-byte key.
func kdf64(info, input1, input2 []byte) [64]byte {
	var out [64]byte
	kdf(info, input1, input2, out[:])
	return out
}

// randomScalar generates a cryptographically random ristretto255 scalar.
// The entropy buffer is protected in guarded memory and destroyed after
// the scalar is derived.
func randomScalar() *ristretto255.Scalar {
	entropy, err := secret.NewRandom(64)
	if err != nil {
		panic("svr: failed to allocate guarded entropy: " + err.Error())
	}
	defer entropy.Destroy()
	s := ristretto255.NewScalar()
	if err2 := entropy.WithBytes(func(b []byte) error {
		_, sErr := s.SetUniformBytes(b)
		return sErr
	}); err2 != nil {
		panic("svr: failed to derive scalar from uniform bytes: " + err2.Error())
	}
	return s
}

// scalarssummingTo returns n scalars that sum to s. The first n-1 are random;
// the last is computed so the total equals s.
func scalarsSummingTo(n int, s *ristretto255.Scalar) []*ristretto255.Scalar {
	if n <= 0 {
		panic("svr: scalarsSummingTo called with n <= 0")
	}
	result := make([]*ristretto255.Scalar, n)
	sum := ristretto255.NewScalar()
	for i := 0; i < n-1; i++ {
		result[i] = randomScalar()
		sum.Add(sum, result[i])
	}
	// last = s - sum = s + (-sum)
	negSum := ristretto255.NewScalar().Negate(sum)
	result[n-1] = ristretto255.NewScalar().Add(negSum, s)
	return result
}

// bytesXORingTo returns n byte slices that XOR together to produce b.
// The first n-1 are random; the last is computed so the XOR equals b.
// All intermediate random buffers used during computation are zeroized
// after being copied into the result slices.
func bytesXORingTo(n int, b []byte) [][]byte {
	if n <= 0 {
		panic("svr: bytesXORingTo called with n <= 0")
	}
	result := make([][]byte, n)
	// Accumulator for XOR shares — zeroized after computing the final share.
	xor := make([]byte, len(b))
	copy(xor, b)
	// buf is reused for generating random bytes. After each iteration the
	// random material is copied into the result and the buffer XOR'd into
	// the accumulator. We zeroize buf after the loop to prevent the last
	// intermediate share from lingering in memory.
	buf := make([]byte, len(b))
	for i := 0; i < n-1; i++ {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			crypto.Zeroize(buf)
			panic("svr: failed to read random bytes: " + err.Error())
		}
		share := make([]byte, len(b))
		copy(share, buf)
		result[i] = share
		arrXOR(buf, xor)
	}
	crypto.Zeroize(buf)
	result[n-1] = xor
	return result
}

// passwordToUniformInput derives a deterministic 64-byte input from a password
// using HKDF.
func passwordToUniformInput(password []byte) [64]byte {
	return kdf64([]byte("Signal_SVR_InputFromPassword_20240823"), password, nil)
}

// inputHashPt creates a ristretto255 point from the 64-byte uniform input.
func inputHashPt(input *[64]byte) *ristretto255.Element {
	e, err := ristretto255.NewIdentityElement().SetUniformBytes(input[:])
	if err != nil {
		panic("svr: failed to derive element from uniform bytes: " + err.Error())
	}
	return e
}

// authPt computes the authentication point: inputHashPt(input) * kOprf.
func authPt(input *[64]byte, kOprf *ristretto255.Scalar) *ristretto255.Element {
	return ristretto255.NewIdentityElement().ScalarMult(kOprf, inputHashPt(input))
}

// authSecret derives the master authorization key from the input and the
// authentication point. The returned secret is in guarded memory and must
// be destroyed by the caller when no longer needed.
func authSecret(input *[64]byte, authPoint *ristretto255.Element) *secret.Secret {
	raw := kdf32(
		[]byte("Signal_SVR_MasterAuthorizationKey_20240823"),
		input[:],
		authPoint.Bytes(),
	)
	defer crypto.ZeroizeArray32(&raw)
	s, err := secret.New(raw[:])
	if err != nil {
		panic("svr: failed to protect auth secret: " + err.Error())
	}
	return s
}

// authCommitments computes per-server (scalar, point) pairs used for
// Schnorr-like authentication in the restore protocol. The master auth
// key and per-server derivation keys are protected in guarded memory.
func authCommitments(serverIDs []uint64, input *[64]byte, authPoint *ristretto255.Element) []authCommitment {
	kAuth := authSecret(input, authPoint)
	defer kAuth.Destroy()
	result := make([]authCommitment, len(serverIDs))
	if err := kAuth.WithBytes(func(kAuthBytes []byte) error {
		for i, id := range serverIDs {
			idBytes := uint64ToBeBytes(id)
			k := kdf64(
				[]byte("Signal_SVR_ServerAuthorizationKey_20240823"),
				kAuthBytes,
				idBytes[:],
			)
			// The Rust reference uses Scalar::hash_from_bytes::<Sha512>(&k),
			// which computes SHA-512(k) and then calls
			// from_bytes_mod_order_wide on the 64-byte hash output. We must
			// replicate this: SHA-512 first, then SetUniformBytes (which
			// performs mod-order reduction on 64 bytes).
			h := sha512.Sum512(k[:])
			crypto.ZeroizeArray64(&k)
			s, serr := ristretto255.NewScalar().SetUniformBytes(h[:])
			crypto.Zeroize(h[:])
			if serr != nil {
				panic("svr: failed to derive server auth scalar: " + serr.Error())
			}
			pt := ristretto255.NewIdentityElement().ScalarBaseMult(s)
			result[i] = authCommitment{scalar: s, point: pt}
		}
		return nil
	}); err != nil {
		panic("svr: failed to access auth secret: " + err.Error())
	}
	return result
}

type authCommitment struct {
	scalar *ristretto255.Scalar
	point  *ristretto255.Element
}

// zeroize overwrites the authorization scalar so it does not linger in memory.
func (c *authCommitment) zeroize() {
	zeroScalar(c.scalar)
}

// zeroizeCommitments zeroes the scalar in every authCommitment in the slice.
func zeroizeCommitments(cs []authCommitment) {
	for i := range cs {
		cs[i].zeroize()
	}
}

// zeroizeScalars zeroes every scalar in the slice.
func zeroizeScalars(scalars []*ristretto255.Scalar) {
	for _, s := range scalars {
		zeroScalar(s)
	}
}

// encryptionKey derives the output encryption key from the encryption secret
// share and the auth key. The returned secret is in guarded memory and must
// be destroyed by the caller when no longer needed.
func encryptionKey(sEnc []byte, kAuth []byte) *secret.Secret {
	raw := kdf32([]byte("Signal_SVR_EncryptionKey_20240823"), sEnc, kAuth)
	defer crypto.ZeroizeArray32(&raw)
	s, err := secret.New(raw[:])
	if err != nil {
		panic("svr: failed to protect encryption key: " + err.Error())
	}
	return s
}

// errEmptyKeyMaterial is returned when a borrowed secret that keys the
// encryption key derivation holds no material.
var errEmptyKeyMaterial = errors.New("svr: key material is empty")

// encryptionKeyFromSecrets derives the encryption key from sEnc and kAuth,
// each borrowed through WithBytes for the derivation only.
func encryptionKeyFromSecrets(sEnc, kAuth *secret.Secret) *secret.Secret {
	var out *secret.Secret
	if err := sEnc.WithBytes(func(sEncBytes []byte) error {
		return kAuth.WithBytes(func(kAuthBytes []byte) error {
			// WithBytes borrows a nil or zero Secret as nil; refuse it.
			if len(sEncBytes) == 0 || len(kAuthBytes) == 0 {
				return errEmptyKeyMaterial
			}
			out = encryptionKey(sEncBytes, kAuthBytes)
			return nil
		})
	}); err != nil {
		panic("svr: failed to access encryption key inputs: " + err.Error())
	}
	return out
}

// withInput calls fn with the 64-byte input held in s, borrowed through
// WithBytes. fn must not retain the pointer.
func withInput(s *secret.Secret, fn func(input *[64]byte) error) error {
	return s.WithBytes(func(b []byte) error {
		if len(b) != 64 {
			return &Error{kind: errBadData}
		}
		return fn((*[64]byte)(b))
	})
}

// uint64ToBeBytes converts a uint64 to a big-endian byte array.
func uint64ToBeBytes(v uint64) [8]byte {
	return [8]byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

// decodeElement decodes a compressed ristretto255 element from bytes.
func decodeElement(b []byte) (*ristretto255.Element, error) {
	e := ristretto255.NewIdentityElement()
	if _, err := e.SetCanonicalBytes(b); err != nil {
		return nil, err
	}
	return e, nil
}

// decodeScalar decodes a canonical ristretto255 scalar from bytes.
func decodeScalar(b []byte) (*ristretto255.Scalar, error) {
	s := ristretto255.NewScalar()
	if _, err := s.SetCanonicalBytes(b); err != nil {
		return nil, err
	}
	return s, nil
}
