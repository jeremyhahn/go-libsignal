package usernames

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"golang.org/x/crypto/hkdf"
)

// CreateForUsername encrypts a username into a username link.
//
// If entropy is nil, random entropy is generated. The entropy used and the
// encrypted buffer are returned. The encrypted buffer can be decrypted with
// DecryptUsername using the same entropy.
func CreateForUsername(username string, entropy []byte) ([UsernameLinkEntropySize]byte, []byte, error) {
	const aesBlockSize = 16

	// Encode username data: simple length-prefixed format.
	// We use a minimal protobuf-compatible encoding:
	// field 1 (string): tag=0x0a, then varint length, then bytes
	// field 2 (bytes): tag=0x12, then varint length, then padding bytes
	paddingLen := (aesBlockSize * 3) - len(username)
	if paddingLen < 0 {
		paddingLen = 0
	}
	ptext := encodeUsernameData(username, paddingLen)

	if len(ptext) >= aesBlockSize*4 {
		return [UsernameLinkEntropySize]byte{}, nil, ErrInputDataTooLong
	}

	var ent [UsernameLinkEntropySize]byte
	if entropy != nil {
		if len(entropy) != UsernameLinkEntropySize {
			return [UsernameLinkEntropySize]byte{}, nil, ErrInvalidEntropyDataLength
		}
		copy(ent[:], entropy)
	} else {
		if _, err := io.ReadFull(rand.Reader, ent[:]); err != nil {
			return [UsernameLinkEntropySize]byte{}, nil, err
		}
	}

	var iv [usernameLinkIVSize]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		return [UsernameLinkEntropySize]byte{}, nil, err
	}

	aesKey := hkdfDeriveKey(ent[:], usernameLinkLabelEncryptionKey)
	defer crypto.ZeroizeArray32(&aesKey)
	macKey := hkdfDeriveKey(ent[:], usernameLinkLabelAuthenticationKey)
	defer crypto.ZeroizeArray32(&macKey)

	ctext, err := aes256CBCEncrypt(ptext, aesKey[:], iv[:])
	if err != nil {
		return [UsernameLinkEntropySize]byte{}, nil, err
	}

	buf := make([]byte, 0, usernameLinkIVSize+len(ctext)+usernameLinkHMACLen)
	buf = append(buf, iv[:]...)
	buf = append(buf, ctext...)
	mac := computeHMAC(macKey[:], buf)
	buf = append(buf, mac...)

	return ent, buf, nil
}

// DecryptUsername decrypts an encrypted username link.
func DecryptUsername(entropy [UsernameLinkEntropySize]byte, encryptedUsername []byte) (string, error) {
	if len(encryptedUsername) <= usernameLinkIVSize+usernameLinkHMACLen {
		return "", ErrUsernameLinkDataTooShort
	}

	macKey := hkdfDeriveKey(entropy[:], usernameLinkLabelAuthenticationKey)
	defer crypto.ZeroizeArray32(&macKey)

	macOffset := len(encryptedUsername) - usernameLinkHMACLen
	ivAndCtext := encryptedUsername[:macOffset]
	expectedMAC := encryptedUsername[macOffset:]
	actualMAC := computeHMAC(macKey[:], ivAndCtext)

	if subtle.ConstantTimeCompare(expectedMAC, actualMAC) != 1 {
		return "", ErrHmacMismatch
	}

	iv := ivAndCtext[:usernameLinkIVSize]
	ctext := ivAndCtext[usernameLinkIVSize:]

	aesKey := hkdfDeriveKey(entropy[:], usernameLinkLabelEncryptionKey)
	defer crypto.ZeroizeArray32(&aesKey)

	ptext, err := aes256CBCDecrypt(ctext, aesKey[:], iv)
	if err != nil {
		return "", ErrBadCiphertext
	}

	username, err := decodeUsernameData(ptext)
	if err != nil {
		return "", ErrInvalidDecryptedDataStructure
	}

	return username, nil
}

// --- HKDF key derivation ---

func hkdfDeriveKey(entropy, label []byte) [usernameLinkKeySize]byte {
	var result [usernameLinkKeySize]byte
	reader := hkdf.New(sha256.New, entropy, nil, label)
	if _, err := io.ReadFull(reader, result[:]); err != nil {
		panic("usernames: HKDF expand failed: " + err.Error())
	}
	return result
}

// --- HMAC ---

func computeHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// --- AES-256-CBC ---

func aes256CBCEncrypt(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func aes256CBCDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, &CBCDecryptError{Detail: "ciphertext is not a multiple of block size"}
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext)
}

// --- PKCS7 padding ---

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

// pkcs7Unpad validates and removes PKCS#7 padding in constant time.
// All padding bytes are checked without early return to prevent timing
// side-channels that could leak information about the plaintext length.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, &PKCS7Error{Detail: "empty data"}
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, &PKCS7Error{Detail: "data not block-aligned"}
	}

	padByte := data[len(data)-1]
	padLen := int(padByte)

	// Constant-time check: padLen must be in [1, aes.BlockSize].
	good := subtle.ConstantTimeLessOrEq(1, padLen) &
		subtle.ConstantTimeLessOrEq(padLen, aes.BlockSize)

	// Check all padding bytes match padByte in constant time.
	// Always iterate over the last aes.BlockSize bytes to avoid
	// leaking padLen through loop count.
	for i := 0; i < aes.BlockSize; i++ {
		// isPad is 1 if position (len(data)-1-i) is in the padding region.
		isPad := subtle.ConstantTimeLessOrEq(i+1, padLen)
		// match is 1 if data[len(data)-1-i] == padByte.
		match := subtle.ConstantTimeByteEq(data[len(data)-1-i], padByte)
		// If isPad is 1 and match is 0, this is bad padding.
		good &= (isPad & match) | (1 - isPad)
	}

	if good != 1 {
		return nil, &PKCS7Error{Detail: "invalid padding"}
	}
	return data[:len(data)-padLen], nil
}

// --- Simple protobuf-like encoding for UsernameData ---
// UsernameData has two fields:
//   field 1 (string): username
//   field 2 (bytes): padding
// We use standard protobuf encoding.

func encodeUsernameData(username string, paddingLen int) []byte {
	var buf []byte

	// Field 1: username (string), wire type 2 (length-delimited), field number 1
	// Tag = (1 << 3) | 2 = 0x0a
	if len(username) > 0 {
		buf = append(buf, 0x0a)
		buf = appendVarint(buf, uint64(len(username)))
		buf = append(buf, []byte(username)...)
	}

	// Field 2: padding (bytes), wire type 2 (length-delimited), field number 2
	// Tag = (2 << 3) | 2 = 0x12
	if paddingLen > 0 {
		buf = append(buf, 0x12)
		buf = appendVarint(buf, uint64(paddingLen))
		buf = append(buf, make([]byte, paddingLen)...)
	}

	return buf
}

func decodeUsernameData(data []byte) (string, error) {
	var username string
	i := 0
	for i < len(data) {
		if i >= len(data) {
			break
		}
		tag := data[i]
		i++

		fieldNum := tag >> 3
		wireType := tag & 0x07

		switch wireType {
		case 0: // varint
			_, n, err := readVarint(data[i:])
			if err != nil {
				return "", err
			}
			i += n
		case 2: // length-delimited
			length, n, err := readVarint(data[i:])
			if err != nil {
				return "", err
			}
			i += n
			if i+int(length) > len(data) {
				return "", &ProtobufError{Detail: "field extends past end of data"}
			}
			if fieldNum == 1 {
				username = string(data[i : i+int(length)])
			}
			// field 2 (padding) and unknown fields are skipped
			i += int(length)
		default:
			return "", &ProtobufError{Detail: "unsupported wire type"}
		}
	}

	return username, nil
}

func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}

func readVarint(data []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(data); i++ {
		b := data[i]
		v |= uint64(b&0x7f) << (uint(i) * 7)
		if b < 0x80 {
			return v, i + 1, nil
		}
		if i >= binary.MaxVarintLen64-1 {
			return 0, 0, &ProtobufError{Detail: "varint too long"}
		}
	}
	return 0, 0, &ProtobufError{Detail: "unexpected end of varint"}
}
