package backup

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
)

const (
	// e164Start is the starting number for replacement E164 phone numbers.
	// Corresponds to +1-555-555-0100 from the Rust implementation.
	e164Start uint64 = 15555550100

	// replacementBodyText is the replacement text used when scrambling
	// message body content.
	replacementBodyText = "https://signal.org: Why use Signal?"

	// replacementEmoji is the replacement emoji used when scrambling emoji
	// fields.
	replacementEmoji = "\u274c" // Red X

	// replacementURL is the replacement URL used when scrambling URL fields.
	replacementURL = "https://signal.org"

	// uuidLen is the byte length of a UUID.
	uuidLen = 16
)

// ScramblerError represents an error encountered during scrambling.
type ScramblerError struct {
	Op  string
	Err error
}

func (e *ScramblerError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("scramble: %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("scramble: %s", e.Op)
}

func (e *ScramblerError) Unwrap() error {
	return e.Err
}

// Scrambler scrambles backup data for testing and anonymization purposes.
// It replaces sensitive data (phone numbers, UUIDs, strings, byte slices)
// with deterministic replacements that preserve structural properties.
//
// The Scrambler uses a seeded PRNG for deterministic output and maintains
// maps of original-to-replacement values for consistent replacement across
// the entire backup.
type Scrambler struct {
	seed      uint64
	state     uint64
	e164s     map[uint64]uint64
	uuids     map[string][]byte
	usernames uint64
}

// NewScrambler creates a new Scrambler with a constant seed of 0 for
// consistent results given the same input, matching the Rust implementation.
func NewScrambler() *Scrambler {
	return NewScramblerWithSeed(0)
}

// NewScramblerWithSeed creates a new Scrambler with the given seed.
func NewScramblerWithSeed(seed uint64) *Scrambler {
	return &Scrambler{
		seed:  seed,
		state: seed,
		e164s: make(map[uint64]uint64),
		uuids: make(map[string][]byte),
	}
}

// nextUint64 returns the next pseudorandom uint64 from the scrambler's PRNG.
// Uses a simple xoshiro256-style algorithm for determinism.
func (s *Scrambler) nextUint64() uint64 {
	s.state ^= s.state << 13
	s.state ^= s.state >> 7
	s.state ^= s.state << 17
	if s.state == 0 {
		s.state = s.seed + 1
	}
	return s.state
}

// nextUint32 returns the next pseudorandom uint32.
func (s *Scrambler) nextUint32() uint32 {
	return uint32(s.nextUint64())
}

// ReplaceE164 consistently replaces an E164 phone number across a backup.
// The same input number always maps to the same replacement number.
// Replacement numbers start at +1-555-555-0100.
func (s *Scrambler) ReplaceE164(e164 uint64) uint64 {
	if replacement, ok := s.e164s[e164]; ok {
		return replacement
	}
	replacement := uint64(len(s.e164s)) + e164Start
	s.e164s[e164] = replacement
	return replacement
}

// ReplaceServiceID consistently replaces a serialized ServiceId (or other
// UUID) across a backup. Empty fields and nil UUIDs are left unchanged.
//
// If the input is 17 bytes (non-ACI ServiceId), the first byte (type prefix)
// is preserved. If the input is 16 bytes, a random v4 UUID replaces it.
// For other lengths, the replacement is truncated or padded to preserve the
// original length, including any structural mistakes.
func (s *Scrambler) ReplaceServiceID(field []byte) []byte {
	if len(field) == 0 {
		return field
	}

	// Check for nil UUID.
	allZero := true
	for _, b := range field {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero && len(field) == uuidLen {
		return field
	}

	key := string(field)
	if replacement, ok := s.uuids[key]; ok {
		result := make([]byte, len(replacement))
		copy(result, replacement)
		return result
	}

	newUUID := s.RandomUUID()
	var replacement []byte

	if len(field) == len(newUUID)+1 {
		// Non-ACI ServiceId: preserve the type byte.
		replacement = make([]byte, len(field))
		replacement[0] = field[0]
		copy(replacement[1:], newUUID)
	} else {
		// ACI / plain UUID or invalid shape.
		replacement = make([]byte, len(field))
		copy(replacement, newUUID)
		// Pad with 0xff if field is longer than UUID.
		for i := len(newUUID); i < len(field); i++ {
			replacement[i] = 0xff
		}
	}

	s.uuids[key] = replacement
	result := make([]byte, len(replacement))
	copy(result, replacement)
	return result
}

// NextUsername generates the next sequential username in the format
// "user.XX" where XX is a zero-padded counter.
func (s *Scrambler) NextUsername() string {
	s.usernames++
	return fmt.Sprintf("user.%02d", s.usernames)
}

// RandomizeBytes replaces each byte in data with a random byte.
func (s *Scrambler) RandomizeBytes(data []byte) {
	for i := range data {
		data[i] = byte(s.nextUint64())
	}
}

// RandomizeString replaces a string with an alphanumeric string of the same
// length. If the string is empty, it remains empty.
func (s *Scrambler) RandomizeString(str string) string {
	if len(str) == 0 {
		return str
	}
	const alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, len(str))
	for i := range result {
		result[i] = alphanumeric[s.nextUint64()%uint64(len(alphanumeric))]
	}
	return string(result)
}

// RandomizeUint64 returns a random uint64 replacement value.
func (s *Scrambler) RandomizeUint64() uint64 {
	return s.nextUint64()
}

// RandomizeUint32 returns a random uint32 replacement value.
func (s *Scrambler) RandomizeUint32() uint32 {
	return s.nextUint32()
}

// RandomUUID generates a random v4 UUID as a 16-byte slice.
// The UUID has the version nibble set to 4 and the variant bits set
// to RFC 4122 (10xx).
func (s *Scrambler) RandomUUID() []byte {
	uuid := make([]byte, uuidLen)
	s.RandomizeBytes(uuid)
	// Set version to 4 (0100 in the high nibble of byte 6).
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant to RFC 4122 (10xx in the high bits of byte 8).
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return uuid
}

// ScrambleContentType scrambles a MIME content type by preserving the
// major type and replacing the subtype with "unknown". For example,
// "image/jpeg" becomes "image/unknown". If there is no "/" separator,
// the entire string is replaced with "unknown".
func ScrambleContentType(contentType string) string {
	idx := strings.Index(contentType, "/")
	if idx < 0 {
		return "unknown"
	}
	return contentType[:idx+1] + "unknown"
}

// ReplacementBodyText returns the standard replacement body text used
// for scrambling message contents.
func ReplacementBodyText() string {
	return replacementBodyText
}

// ReplacementEmoji returns the standard replacement emoji used for
// scrambling emoji fields.
func ReplacementEmoji() string {
	return replacementEmoji
}

// ReplacementURL returns the standard replacement URL used for
// scrambling URL fields.
func ReplacementURL() string {
	return replacementURL
}

// CryptoRandomUUID generates a cryptographically random v4 UUID using
// crypto/rand. This is used when true randomness is required rather
// than the deterministic PRNG of a Scrambler.
func CryptoRandomUUID() ([]byte, error) {
	uuid := make([]byte, uuidLen)
	if _, err := rand.Read(uuid); err != nil {
		return nil, &ScramblerError{Op: "generate random UUID", Err: err}
	}
	// Set version to 4.
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant to RFC 4122.
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return uuid, nil
}

// CryptoRandomizeBytes fills data with cryptographically random bytes
// using crypto/rand.
func CryptoRandomizeBytes(data []byte) error {
	if _, err := rand.Read(data); err != nil {
		return &ScramblerError{Op: "randomize bytes", Err: err}
	}
	return nil
}

// CryptoRandomUint64 returns a cryptographically random uint64 using
// crypto/rand.
func CryptoRandomUint64() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, &ScramblerError{Op: "random uint64", Err: err}
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// CryptoRandomUint32 returns a cryptographically random uint32 using
// crypto/rand.
func CryptoRandomUint32() (uint32, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 0, &ScramblerError{Op: "random uint32", Err: err}
	}
	return uint32(n.Uint64()), nil
}
