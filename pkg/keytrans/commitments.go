// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package keytrans

import (
	"crypto/hmac"
	"crypto/sha256"
)

var fixedKey = []byte{
	0xd8, 0x21, 0xf8, 0x79, 0x0d, 0x97, 0x70, 0x97,
	0x96, 0xb4, 0xd7, 0x90, 0x33, 0x57, 0xc3, 0xf5,
}

// Commit computes an HMAC-SHA256 commitment.
func Commit(searchKey, data []byte, nonce *[16]byte) []byte {
	keyLen := uint16(len(searchKey))
	dataLen := uint32(len(data))

	mac := hmac.New(sha256.New, fixedKey)
	mac.Write(nonce[:])
	mac.Write(uint16ToBeBytes(keyLen))
	mac.Write(searchKey)
	mac.Write(uint32ToBeBytes(dataLen))
	mac.Write(data)

	return mac.Sum(nil)
}

// VerifyCommitment verifies an HMAC-SHA256 commitment.
func VerifyCommitment(searchKey, commitment, data []byte, nonce *[16]byte) bool {
	expected := Commit(searchKey, data, nonce)
	return hmac.Equal(expected, commitment)
}
