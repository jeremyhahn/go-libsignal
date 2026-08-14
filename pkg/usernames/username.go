package usernames

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/gtank/ristretto255"

	"github.com/jeremyhahn/go-libsignal/pkg/poksho"
)

// NicknameLimits defines the allowed nickname length range.
type NicknameLimits struct {
	minLen int
	maxLen int
}

// NewNicknameLimits creates a NicknameLimits with the given bounds.
// Panics if maxLen > MaxNicknameLength or minLen >= maxLen.
func NewNicknameLimits(minLen, maxLen int) NicknameLimits {
	if maxLen > MaxNicknameLength {
		panic(fmt.Sprintf("usernames: long nicknames are not supported. The maximum supported length is %d", MaxNicknameLength))
	}
	if minLen >= maxLen {
		panic(fmt.Sprintf("usernames: invalid nickname size limits: %d..%d", minLen, maxLen))
	}
	return NicknameLimits{minLen: minLen, maxLen: maxLen}
}

// DefaultNicknameLimits returns the default NicknameLimits of 3..32.
func DefaultNicknameLimits() NicknameLimits {
	return NewNicknameLimits(3, 32)
}

func (l NicknameLimits) validate(n int) error {
	if n < l.minLen {
		return ErrNicknameTooShort
	}
	if n > l.maxLen {
		return ErrNicknameTooLong
	}
	return nil
}

// Username represents a parsed Signal username consisting of a nickname and discriminator.
type Username struct {
	nickname      string
	discriminator uint64
	scalars       [3]*ristretto255.Scalar
}

// String returns the username in "nickname.DD" format (discriminator is zero-padded to at least 2 digits).
func (u *Username) String() string {
	return formatParts(u.nickname, u.discriminator)
}

// New parses a username string of the form "nickname.discriminator".
func New(s string) (*Username, error) {
	idx := strings.LastIndex(s, ".")
	if idx < 0 {
		return nil, ErrMissingSeparator
	}
	nickname := s[:idx]
	discriminator := s[idx+1:]
	return fromPartsWithoutSoftLimit(nickname, discriminator)
}

// FromParts creates a Username from a nickname and discriminator string,
// validating against the provided NicknameLimits.
func FromParts(nickname, discriminator string, limits NicknameLimits) (*Username, error) {
	result, err := fromPartsWithoutSoftLimit(nickname, discriminator)
	if err != nil {
		return nil, err
	}
	// Check soft limit on nickname length.
	if err := limits.validate(len(nickname)); err != nil {
		return nil, err
	}
	return result, nil
}

func fromPartsWithoutSoftLimit(nickname, discriminator string) (*Username, error) {
	if err := validatePrefix(nickname); err != nil {
		return nil, err
	}
	d, err := validateDiscriminator(discriminator)
	if err != nil {
		return nil, err
	}
	scalars, err := makeScalars(strings.ToLower(nickname), d)
	if err != nil {
		return nil, err
	}
	return &Username{
		nickname:      nickname,
		discriminator: d,
		scalars:       scalars,
	}, nil
}

// Hash computes the username hash as a 32-byte compressed ristretto point.
func (u *Username) Hash() [32]byte {
	point := hashFromScalars(u.scalars)
	var out [32]byte
	copy(out[:], point.Bytes())
	return out
}

// Proof generates a zero-knowledge proof of knowledge of the username scalars.
func (u *Username) Proof(randomness [32]byte) ([]byte, error) {
	hashPoint := hashFromScalars(u.scalars)
	var message [32]byte
	copy(message[:], hashPoint.Bytes())
	return createProof(u.scalars, hashPoint, message[:], randomness)
}

// VerifyProof verifies a zero-knowledge proof for the given username hash.
func VerifyProof(proof []byte, hash [32]byte) error {
	hashPoint := ristretto255.NewIdentityElement()
	if _, err := hashPoint.SetCanonicalBytes(hash[:]); err != nil {
		return ProofVerificationFailure{}
	}
	return verifyProof(proof, hashPoint, hash[:])
}

// CandidatesFrom generates username candidates for a given nickname by picking
// distinct random discriminators from predefined ranges (sample without
// replacement per range, matching the Rust libsignal implementation).
func CandidatesFrom(nickname string, limits NicknameLimits) ([]string, error) {
	if err := validateNickname(nickname, limits); err != nil {
		return nil, err
	}

	var candidates []string
	for i, count := range candidatesPerRange {
		r := discriminatorRanges[i]
		discriminators, err := sampleDistinct(r.Start, r.End, count)
		if err != nil {
			return nil, &CryptoError{Operation: "random generation failed", Err: err}
		}
		for _, d := range discriminators {
			candidates = append(candidates, formatParts(nickname, uint64(d)))
		}
	}
	return candidates, nil
}

// sampleDistinct draws count distinct integers from [lo, hi) without
// replacement using rejection sampling. It terminates quickly in practice
// because count is always much smaller than the range size.
func sampleDistinct(lo, hi, count int) ([]int, error) {
	seen := make(map[int]struct{}, count)
	results := make([]int, 0, count)
	for len(results) < count {
		d, err := randInRange(lo, hi)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[d]; !exists {
			seen[d] = struct{}{}
			results = append(results, d)
		}
	}
	return results, nil
}

func formatParts(nickname string, discriminator uint64) string {
	return fmt.Sprintf("%s.%02d", nickname, discriminator)
}

// randInRange returns a random int in [lo, hi).
func randInRange(lo, hi int) (int, error) {
	length := hi - lo
	n, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
	if err != nil {
		return 0, err
	}
	return lo + int(n.Int64()), nil
}

// --- Scalar construction ---

func usernameSHAScalar(nickname string, discriminator uint64) *ristretto255.Scalar {
	h := sha512.New()
	h.Write([]byte(nickname))
	h.Write([]byte{0x00})
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], discriminator)
	h.Write(buf[:])
	var wide [64]byte
	copy(wide[:], h.Sum(nil))
	s := ristretto255.NewScalar()
	if _, err := s.SetUniformBytes(wide[:]); err != nil {
		panic("usernames: failed to derive SHA scalar from uniform bytes: " + err.Error())
	}
	return s
}

func nicknameScalar(nickname string) (*ristretto255.Scalar, error) {
	if len(nickname) == 0 {
		panic("usernames: nickname_scalar called with empty nickname")
	}
	bytes := make([]byte, 0, len(nickname))
	for _, c := range nickname {
		b, ok := charToByte(c)
		if !ok {
			return nil, ErrBadNicknameCharacter
		}
		bytes = append(bytes, b)
	}
	if len(bytes) > MaxNicknameLength {
		return nil, ErrNicknameTooLong
	}
	return toBase37Scalar(bytes), nil
}

func discriminatorScalar(discriminator uint64) *ristretto255.Scalar {
	return scalarFromUint64(discriminator)
}

func makeScalars(nickname string, discriminator uint64) ([3]*ristretto255.Scalar, error) {
	ns, err := nicknameScalar(nickname)
	if err != nil {
		return [3]*ristretto255.Scalar{}, err
	}
	return [3]*ristretto255.Scalar{
		usernameSHAScalar(nickname, discriminator),
		ns,
		discriminatorScalar(discriminator),
	}, nil
}

// --- Character mapping ---

func charToByte(c rune) (byte, bool) {
	switch {
	case c == '_':
		return 1, true
	case c >= 'a' && c <= 'z':
		return byte(c) - 'a' + 2, true
	case c >= '0' && c <= '9':
		return byte(c) - '0' + 28, true
	default:
		return 0, false
	}
}

// toBase37Scalar encodes nickname bytes in base-37.
// Process bytes[1:] in reverse, multiply by 37 and add. Then multiply result by 27 and add bytes[0].
func toBase37Scalar(bytes []byte) *ristretto255.Scalar {
	if len(bytes) > MaxNicknameLength {
		panic("usernames: nickname too long for scalar")
	}

	thirtySeven := scalarFromUint64(37)
	result := ristretto255.NewScalar()
	// Process bytes[1:] in reverse
	for i := len(bytes) - 1; i >= 1; i-- {
		result.Multiply(result, thirtySeven)
		result.Add(result, scalarFromUint64(uint64(bytes[i])))
	}
	// Multiply by 27 and add bytes[0]
	result.Multiply(result, scalarFromUint64(27))
	result.Add(result, scalarFromUint64(uint64(bytes[0])))
	return result
}

func scalarFromUint64(v uint64) *ristretto255.Scalar {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:8], v)
	s := ristretto255.NewScalar()
	if _, err := s.SetCanonicalBytes(buf[:]); err != nil {
		panic("usernames: failed to decode scalar from uint64: " + err.Error())
	}
	return s
}

// --- Validation ---

func validatePrefix(s string) error {
	if len(s) == 0 {
		return ErrNicknameCannotBeEmpty
	}
	first := rune(s[0])
	if first >= '0' && first <= '9' {
		return ErrNicknameCannotStartWithDigit
	}
	return nil
}

func validateDiscriminator(discriminator string) (uint64, error) {
	if len(discriminator) == 0 {
		return 0, ErrDiscriminatorCannotBeEmpty
	}
	firstByte := discriminator[0]
	if firstByte < '0' || firstByte > '9' {
		return 0, ErrBadDiscriminatorCharacter
	}

	// Check all characters are digits and parse.
	var n uint64
	for _, c := range discriminator {
		if c < '0' || c > '9' {
			return 0, ErrBadDiscriminatorCharacter
		}
		digit := uint64(c - '0')
		// Two-condition overflow check: handles all 64-bit wrap-around cases,
		// not just the common wrap (n < prev).
		if n > math.MaxUint64/10 || (n == math.MaxUint64/10 && digit > math.MaxUint64%10) {
			return 0, ErrDiscriminatorTooLarge
		}
		n = n*10 + digit
	}

	if n == 0 {
		return 0, ErrDiscriminatorCannotBeZero
	}

	switch {
	case len(discriminator) == 1:
		return 0, ErrDiscriminatorCannotBeSingleDigit
	case len(discriminator) == 2:
		return n, nil
	case firstByte >= '1' && firstByte <= '9':
		return n, nil
	default:
		return 0, ErrDiscriminatorCannotHaveLeadingZeros
	}
}

func validateNickname(nickname string, limits NicknameLimits) error {
	if err := validatePrefix(nickname); err != nil {
		return err
	}
	lower := strings.ToLower(nickname)
	for _, c := range lower {
		if _, ok := charToByte(c); !ok {
			return ErrBadNicknameCharacter
		}
	}
	return limits.validate(len(nickname))
}

// --- Hash computation ---

func hashFromScalars(scalars [3]*ristretto255.Scalar) *ristretto255.Element {
	ss := make([]*ristretto255.Scalar, 3)
	pp := make([]*ristretto255.Element, 3)
	for i := 0; i < 3; i++ {
		ss[i] = ristretto255.NewScalar().Set(scalars[i])
		pp[i] = ristretto255.NewIdentityElement().Set(basePoints[i])
	}
	return ristretto255.NewIdentityElement().MultiScalarMult(ss, pp)
}

// --- Proof system using poksho Statement ---
//
// The proof demonstrates knowledge of 3 scalars such that:
//   username_hash = username_sha_scalar*G1 + nickname_scalar*G2 + discriminator_scalar*G3
//
// Uses the poksho Statement system matching the Rust reference implementation.

// usernameProofStatement returns the poksho Statement for username proofs.
// This matches Rust's PROOF_STATEMENT exactly.
func usernameProofStatement() *poksho.Statement {
	st := poksho.NewStatement()
	st.Add("username_hash", [][2]string{
		{"username_sha_scalar", "G1"},
		{"nickname_scalar", "G2"},
		{"discriminator_scalar", "G3"},
	})
	return st
}

// makeScalarArgs builds the scalar arguments for the proof.
func makeScalarArgs(scalars [3]*ristretto255.Scalar) *poksho.ScalarArgs {
	args := poksho.NewScalarArgs()
	args.Add("username_sha_scalar", scalars[0])
	args.Add("nickname_scalar", scalars[1])
	args.Add("discriminator_scalar", scalars[2])
	return args
}

// makePointArgs builds the point arguments for the proof.
func makePointArgs(hashPoint *ristretto255.Element) *poksho.PointArgs {
	args := poksho.NewPointArgs()
	args.Add("G1", basePoints[0])
	args.Add("G2", basePoints[1])
	args.Add("G3", basePoints[2])
	args.Add("username_hash", hashPoint)
	return args
}

func createProof(scalars [3]*ristretto255.Scalar, hashPoint *ristretto255.Element, message []byte, randomness [32]byte) ([]byte, error) {
	st := usernameProofStatement()
	scalarArgs := makeScalarArgs(scalars)
	pointArgs := makePointArgs(hashPoint)

	proof, err := st.Prove(scalarArgs, pointArgs, message, randomness[:])
	if err != nil {
		return nil, &CryptoError{Operation: "failed to create proof", Err: err}
	}
	return proof, nil
}

func verifyProof(proof []byte, hashPoint *ristretto255.Element, message []byte) error {
	st := usernameProofStatement()
	pointArgs := makePointArgs(hashPoint)

	if err := st.VerifyProof(proof, pointArgs, message); err != nil {
		return ProofVerificationFailure{}
	}
	return nil
}
