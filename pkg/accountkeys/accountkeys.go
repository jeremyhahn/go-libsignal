// Package accountkeys implements PIN hashing and entropy pool key derivation
// for the Signal protocol account keys module.
package accountkeys

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/crypto/hkdf"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// secretAlloc is the function used to move key material into guarded memory.
// It defaults to secret.New and may be replaced in tests to simulate allocation failures.
var secretAlloc = secret.New

// secretRandAlloc is the function used to allocate random guarded secrets.
// It defaults to secret.NewRandom and may be replaced in tests to simulate failures.
var secretRandAlloc = secret.NewRandom

// secretEmptyAlloc is the function used to allocate empty guarded secrets.
// It defaults to secret.NewEmpty and may be replaced in tests to simulate failures.
var secretEmptyAlloc = secret.NewEmpty

const (
	// EntropyPoolLength is the number of alphanumeric characters in an entropy pool.
	EntropyPoolLength = 64

	// SVRKeyLength is the byte length of a derived SVR key.
	SVRKeyLength = 32

	// LocalPinHashLength is the byte length of a local PIN hash.
	LocalPinHashLength = 32

	// alphabet is the set of characters used in entropy pool generation.
	alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

	// argon2Time is the number of Argon2id iterations for PIN hashing.
	argon2Time = 32

	// argon2Memory is the memory parameter (in KB) for Argon2id PIN hashing.
	argon2Memory = 16384

	// argon2Parallelism is the parallelism parameter for Argon2id PIN hashing.
	argon2Parallelism = 1

	// argon2OutputLength is the total output length from Argon2id.
	argon2OutputLength = 64

	// expectedSaltLength is the expected byte length of the salt for PIN hashing.
	expectedSaltLength = 32

	svrKeyInfo    = "20240801_SIGNAL_SVR_MASTER_KEY"
	backupKeyInfo = "20240801_SIGNAL_BACKUP_KEY"

	// localPinHash Argon2i parameters matching the Rust implementation.
	localArgon2iTime        = 64
	localArgon2iMemory      = 512 // KiB
	localArgon2iParallelism = 1
	localArgon2iOutputLen   = 32

	// localPinHashSaltLength is the salt length for local PIN hashing (PHC standard).
	localPinHashSaltLength = 16
)

// AccountEntropyPool is a 64-character lowercase alphanumeric string that serves
// as the root entropy for deriving backup and SVR keys.
type AccountEntropyPool string

// GenerateAccountEntropyPool creates a new random entropy pool consisting of
// 64 characters drawn uniformly from [0-9a-z] using cryptographically random
// bytes stored in memguard-protected memory.
func GenerateAccountEntropyPool() (AccountEntropyPool, error) {
	// Generate random bytes in guarded memory for rejection sampling.
	// We need at most ~EntropyPoolLength * 2 random bytes due to rejection,
	// but allocate a generous buffer to minimize re-allocations.
	const randomBufSize = EntropyPoolLength * 4
	randBuf, err := secretRandAlloc(randomBufSize)
	if err != nil {
		return "", &ErrGeneratingRandomEntropy{Err: err}
	}
	defer randBuf.Destroy()

	buf := make([]byte, EntropyPoolLength)
	randBytes := randBuf.Bytes()
	randIdx := 0

	for i := range buf {
		// Use rejection sampling to avoid modulo bias.
		// 256 / 36 = 7 full ranges, remainder 4. Accept bytes < 252 (36*7).
		for {
			if randIdx >= len(randBytes) {
				// Exhausted buffer; allocate more random bytes.
				randBuf.Destroy()
				randBuf, err = secretRandAlloc(randomBufSize)
				if err != nil {
					crypto.Zeroize(buf)
					return "", &ErrGeneratingRandomEntropy{Err: err}
				}
				randBytes = randBuf.Bytes()
				randIdx = 0
			}
			b := randBytes[randIdx]
			randIdx++
			if b < 252 { // 36 * 7 = 252
				buf[i] = alphabet[b%36]
				break
			}
		}
	}
	pool := AccountEntropyPool(buf)
	crypto.Zeroize(buf)
	return pool, nil
}

// hkdfExpandInto reads exactly len(out) bytes from an HKDF-SHA256 reader.
// HKDF-SHA256 can produce up to 8160 bytes; all callers request <=64 bytes,
// so this never fails.
func hkdfExpandInto(out, ikm, salt, info []byte) {
	reader := hkdf.New(sha256.New, ikm, salt, info)
	if _, err := io.ReadFull(reader, out); err != nil {
		// panic: cryptographic invariant violation -- HKDF-SHA256 supports up to
		// 255*HashLen (8160) bytes of output; all callers request <=64 bytes.
		panic("accountkeys: HKDF expand failed (impossible): " + err.Error())
	}
}

// Validate checks that the entropy pool is exactly 64 lowercase alphanumeric characters.
func (p AccountEntropyPool) Validate() error {
	if utf8.RuneCountInString(string(p)) != EntropyPoolLength {
		return &ErrEntropyPoolLength{Expected: EntropyPoolLength, Got: utf8.RuneCountInString(string(p))}
	}
	for i, r := range string(p) {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') {
			return &ErrEntropyPoolInvalidChar{Position: i}
		}
	}
	return nil
}

// DeriveSVRKey derives a 32-byte SVR key from the entropy pool using HKDF-SHA256.
// The returned Secret must be destroyed by the caller when no longer needed.
func (p AccountEntropyPool) DeriveSVRKey() (*secret.Secret, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, SVRKeyLength)
	hkdfExpandInto(buf, []byte(p), nil, []byte(svrKeyInfo))
	// secretAlloc zeroizes buf (move semantics).
	s, err := secretAlloc(buf)
	if err != nil {
		crypto.Zeroize(buf)
		return nil, &ErrSecuringSecret{Operation: "SVR key", Err: err}
	}
	return s, nil
}

// DeriveBackupKey derives a 32-byte backup key from the entropy pool using HKDF-SHA256.
// The returned Secret must be destroyed by the caller when no longer needed.
func (p AccountEntropyPool) DeriveBackupKey() (*secret.Secret, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 32)
	hkdfExpandInto(buf, []byte(p), nil, []byte(backupKeyInfo))
	// secretAlloc zeroizes buf (move semantics).
	s, err := secretAlloc(buf)
	if err != nil {
		crypto.Zeroize(buf)
		return nil, &ErrSecuringSecret{Operation: "backup key", Err: err}
	}
	return s, nil
}

// PinHash holds the derived keys from a PIN hash operation.
// The 64-byte Argon2id output is split: first 32 bytes are the encryption key,
// last 32 bytes are the access key, matching the Rust libsignal implementation.
// Call Zeroize when the PinHash is no longer needed.
type PinHash struct {
	EncryptionKey *secret.Secret // For local encryption (bytes 0-31 of Argon2id output).
	AccessKey     *secret.Secret // For SVR authentication (bytes 32-63 of Argon2id output).
}

// Zeroize securely wipes the encryption key and access key from memory.
func (h *PinHash) Zeroize() {
	if h.EncryptionKey != nil {
		h.EncryptionKey.Destroy()
	}
	if h.AccessKey != nil {
		h.AccessKey.Destroy()
	}
}

// HashPin derives access and encryption keys from a PIN string and salt using Argon2id.
// The salt is expected to be 32 bytes. The PIN is normalized by trimming whitespace.
func HashPin(pin string, salt []byte) (*PinHash, error) {
	if len(salt) != expectedSaltLength {
		return nil, &ErrInvalidSaltLength{Expected: expectedSaltLength, Got: len(salt)}
	}

	normalized := normalizePin(pin)
	if len(normalized) == 0 {
		return nil, &ErrEmptyPIN{}
	}

	derived := argon2.IDKey(
		[]byte(normalized),
		salt,
		argon2Time,
		argon2Memory,
		argon2Parallelism,
		argon2OutputLength,
	)

	// Move the Argon2 output into guarded memory and zeroize the heap copy.
	derivedSecret, err := secretAlloc(derived)
	if err != nil {
		crypto.Zeroize(derived)
		return nil, &ErrSecuringSecret{Operation: "argon2 output", Err: err}
	}
	defer derivedSecret.Destroy()

	// Copy each half into its own secret. Must copy before creating secrets
	// since the view is into derivedSecret's guarded memory.
	encBuf := make([]byte, 32)
	copy(encBuf, derivedSecret.Bytes()[:32])
	encSecret, err := secretAlloc(encBuf)
	if err != nil {
		crypto.Zeroize(encBuf)
		return nil, &ErrSecuringSecret{Operation: "encryption key", Err: err}
	}

	accBuf := make([]byte, 32)
	copy(accBuf, derivedSecret.Bytes()[32:64])
	accSecret, err := secretAlloc(accBuf)
	if err != nil {
		crypto.Zeroize(accBuf)
		encSecret.Destroy()
		return nil, &ErrSecuringSecret{Operation: "access key", Err: err}
	}

	return &PinHash{
		EncryptionKey: encSecret,
		AccessKey:     accSecret,
	}, nil
}

// VerifyPin checks if a PIN matches a previously derived access key by hashing
// the PIN with the same salt and performing a constant-time comparison.
func VerifyPin(pin string, salt []byte, expectedAccessKey []byte) (bool, error) {
	h, err := HashPin(pin, salt)
	if err != nil {
		return false, err
	}
	defer h.Zeroize()
	return subtle.ConstantTimeCompare(h.AccessKey.Bytes(), expectedAccessKey) == 1, nil
}

// LocalPinHash creates a PHC-string encoded Argon2i hash of the PIN for local
// screen lock verification. Uses a random 16-byte salt and Argon2i with
// memory=512KiB, time=64, parallelism=1, output=32 bytes.
// Returns a PHC-string like "$argon2i$v=19$m=512,t=64,p=1$<salt>$<hash>".
// This matches the Rust libsignal local_pin_hash implementation.
func LocalPinHash(pin string) (string, error) {
	normalized := normalizePin(pin)
	if len(normalized) == 0 {
		return "", &ErrEmptyPIN{}
	}
	saltSecret, err := secretRandAlloc(localPinHashSaltLength)
	if err != nil {
		return "", &ErrGeneratingSalt{Err: err}
	}
	defer saltSecret.Destroy()

	// Copy salt out for use with Argon2 (which requires a plain slice).
	salt := make([]byte, localPinHashSaltLength)
	copy(salt, saltSecret.Bytes())
	defer crypto.Zeroize(salt)

	return localPinHashWithSalt([]byte(normalized), salt)
}

// localPinHashWithSalt computes an Argon2i hash and returns the PHC-string encoding.
func localPinHashWithSalt(pin, salt []byte) (string, error) {
	derived := argon2.Key(
		pin,
		salt,
		localArgon2iTime,
		localArgon2iMemory,
		localArgon2iParallelism,
		localArgon2iOutputLen,
	)

	// Move the Argon2 hash into guarded memory and zeroize the heap copy.
	derivedSecret, err := secretAlloc(derived)
	if err != nil {
		crypto.Zeroize(derived)
		return "", &ErrSecuringSecret{Operation: "argon2i output", Err: err}
	}
	defer derivedSecret.Destroy()

	// Format as PHC-string: $argon2i$v=19$m=512,t=64,p=1$<b64salt>$<b64hash>
	encodedSalt := base64RawEncode(salt)
	encodedHash := base64RawEncode(derivedSecret.Bytes())
	phc := fmt.Sprintf("$argon2i$v=19$m=%d,t=%d,p=%d$%s$%s",
		localArgon2iMemory, localArgon2iTime, localArgon2iParallelism,
		encodedSalt, encodedHash)
	return phc, nil
}

// VerifyLocalPinHash verifies a PIN against a PHC-string encoded local hash.
// The PHC-string format is "$argon2i$v=19$m=512,t=64,p=1$<salt>$<hash>".
func VerifyLocalPinHash(pin string, encodedHash string) (bool, error) {
	normalized := normalizePin(pin)
	if len(normalized) == 0 {
		return false, &ErrEmptyPIN{}
	}
	// Parse PHC string to extract salt and expected hash.
	salt, expectedHash, err := parsePHCString(encodedHash)
	if err != nil {
		return false, &ErrInvalidPHCString{Err: err}
	}
	derived := argon2.Key(
		[]byte(normalized),
		salt,
		localArgon2iTime,
		localArgon2iMemory,
		localArgon2iParallelism,
		localArgon2iOutputLen,
	)

	// Move the Argon2 output into guarded memory and zeroize the heap copy.
	derivedSecret, err := secretAlloc(derived)
	if err != nil {
		crypto.Zeroize(derived)
		return false, &ErrSecuringSecret{Operation: "argon2i output", Err: err}
	}
	defer derivedSecret.Destroy()

	return subtle.ConstantTimeCompare(derivedSecret.Bytes(), expectedHash) == 1, nil
}

// MakeSalt generates a 32-byte salt for PIN hashing from a username and group ID.
// Uses HKDF-SHA256 with username as IKM, group_id (big-endian) as salt, and empty info.
// This matches the Rust PinHash::make_salt implementation.
func MakeSalt(username string, groupID uint64) [expectedSaltLength]byte {
	ikm := []byte(username)
	salt := make([]byte, 8)
	salt[0] = byte(groupID >> 56)
	salt[1] = byte(groupID >> 48)
	salt[2] = byte(groupID >> 40)
	salt[3] = byte(groupID >> 32)
	salt[4] = byte(groupID >> 24)
	salt[5] = byte(groupID >> 16)
	salt[6] = byte(groupID >> 8)
	salt[7] = byte(groupID)
	var result [expectedSaltLength]byte
	hkdfExpandInto(result[:], ikm, salt, nil)
	return result
}

// base64RawEncode encodes bytes to base64 without padding (standard encoding).
func base64RawEncode(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

// parsePHCString extracts salt and hash from a PHC-formatted Argon2i string.
func parsePHCString(phc string) (salt, hash []byte, err error) {
	// Format: $argon2i$v=19$m=512,t=64,p=1$<salt>$<hash>
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2i" {
		return nil, nil, &ErrPHCInvalidFormat{}
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, &ErrPHCInvalidSaltEncoding{Err: err}
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, &ErrPHCInvalidHashEncoding{Err: err}
	}
	return salt, hash, nil
}

// normalizePin normalizes a PIN string following the Rust reference implementation:
// 1. Trim leading and trailing whitespace
// 2. Transliterate non-ASCII decimal digits to ASCII (e.g., Arabic-Indic, Devanagari)
// 3. Apply Unicode NFKD normalization
func normalizePin(pin string) string {
	trimmed := strings.TrimSpace(pin)
	transliterated := transliterateDigits(trimmed)
	return norm.NFKD.String(transliterated)
}

// transliterateDigits converts non-ASCII Unicode decimal digits to their ASCII
// equivalents. For any digit rune where unicode.IsDigit returns true but the
// rune is outside ASCII 0-9, it finds the zero digit of that Unicode block
// (decimal digit blocks are contiguous runs of 10) and maps it to '0' + offset.
func transliterateDigits(s string) string {
	var result []rune
	for _, r := range s {
		if r >= '0' && r <= '9' {
			result = append(result, r)
		} else if unicode.IsDigit(r) {
			// Find the zero digit of this block by walking back to the
			// start of the contiguous digit range.
			zero := r
			for unicode.IsDigit(zero - 1) {
				zero--
			}
			result = append(result, '0'+(r-zero))
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}
