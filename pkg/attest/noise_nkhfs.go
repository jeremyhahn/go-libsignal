// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

// Package-level implementation of the Noise NKhfs handshake pattern.
//
// Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 extends the standard NK
// pattern with a KEM-based hybrid forward secrecy (HFS) step, as defined
// in the Noise HFS extension specification.
//
// NK pre-message: <- s (responder's static key is known to initiator)
//
// Message pattern:
//
//	-> e, es, e1    (initiator sends ephemeral DH key + encrypted KEM encapsulation key)
//	<- e, ee, ekem1 (responder sends ephemeral DH key + encrypted KEM ciphertext)
//
// Both sides mix the KEM shared secret into the handshake state alongside
// the standard DH operations, providing forward secrecy even if discrete-log
// is broken by a quantum adversary.
//
// Wire format (both messages are 1632 bytes):
//
//	e.pub(32) + EncryptAndHash(e1.pub or ekem1.ct)(1568+16) + EncryptAndHash(nil)(16) = 1632
//
// This matches Rust libsignal's NOISE_HANDSHAKE_OVERHEAD = 1632.

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"math"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// NoisePatternHFS is the Noise protocol name for the NKhfs pattern.
const NoisePatternHFS = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256"

// NoiseHandshakeOverheadHFS is the total wire size of each NKhfs handshake message:
// e.pub(32) + EncryptAndHash(KEM key/ct)(1568+16) + EncryptAndHash(nil)(16) = 1632.
const NoiseHandshakeOverheadHFS = 32 + 1568 + 16 + 16

// NKhfsCipherState manages symmetric encryption for the Noise transport phase.
// It holds a ChaCha20-Poly1305 key and a monotonically increasing nonce counter.
type NKhfsCipherState struct {
	key   [chacha20poly1305.KeySize]byte
	nonce uint64
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305 with the current nonce,
// using ad as additional data. The nonce is incremented after each call.
// Returns NKhfsNonceExhaustedError if the nonce counter would overflow.
func (cs *NKhfsCipherState) Encrypt(ad, plaintext []byte) ([]byte, error) {
	if cs.nonce == math.MaxUint64 {
		return nil, &NKhfsNonceExhaustedError{}
	}
	aead, err := chacha20poly1305.New(cs.key[:])
	if err != nil {
		return nil, &ClientConnectionError{Err: err}
	}
	nonce := buildChachaPolyNonce(cs.nonce)
	cs.nonce++
	return aead.Seal(nil, nonce[:], plaintext, ad), nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 with the current nonce,
// using ad as additional data. The nonce is incremented after each successful call.
// Returns NKhfsNonceExhaustedError if the nonce counter would overflow.
func (cs *NKhfsCipherState) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	if cs.nonce == math.MaxUint64 {
		return nil, &NKhfsNonceExhaustedError{}
	}
	aead, err := chacha20poly1305.New(cs.key[:])
	if err != nil {
		return nil, &ClientConnectionError{Err: err}
	}
	nonce := buildChachaPolyNonce(cs.nonce)
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, &ClientConnectionError{Err: err}
	}
	cs.nonce++
	return plaintext, nil
}

// Destroy zeroizes the cipher key to prevent sensitive data from lingering in memory.
func (cs *NKhfsCipherState) Destroy() {
	crypto.ZeroizeArray32(&cs.key)
}

// buildChachaPolyNonce builds a 12-byte nonce from a 64-bit counter.
// The counter is encoded as little-endian in bytes [4:12], matching the
// Noise protocol specification and Rust chacha20poly1305 behavior.
func buildChachaPolyNonce(n uint64) [12]byte {
	var nonce [12]byte
	nonce[4] = byte(n)
	nonce[5] = byte(n >> 8)
	nonce[6] = byte(n >> 16)
	nonce[7] = byte(n >> 24)
	nonce[8] = byte(n >> 32)
	nonce[9] = byte(n >> 40)
	nonce[10] = byte(n >> 48)
	nonce[11] = byte(n >> 56)
	return nonce
}

// nkhfsSymmetricState holds the Noise symmetric state (ck, h, k) for NKhfs.
type nkhfsSymmetricState struct {
	ck     [32]byte // chaining key
	h      [32]byte // handshake hash
	k      [32]byte // current symmetric key (zero if not yet set)
	hasKey bool     // whether k is valid
	n      uint64   // nonce counter for the handshake symmetric key
}

// initializeSymmetric initializes the symmetric state from the protocol name.
// Per the Noise spec: if len(name) <= 32, h = name padded with zeros;
// otherwise h = HASH(name). In our case the name is >32 bytes, so h = SHA256(name).
func newNKhfsSymmetricState() *nkhfsSymmetricState {
	name := []byte(NoisePatternHFS)
	h := sha256.Sum256(name)
	ss := &nkhfsSymmetricState{}
	ss.h = h
	ss.ck = h
	return ss
}

// mixHash absorbs data into the handshake hash: h = SHA256(h || data).
func (ss *nkhfsSymmetricState) mixHash(data []byte) {
	h := sha256.New()
	h.Write(ss.h[:])
	h.Write(data)
	copy(ss.h[:], h.Sum(nil))
}

// mixKey performs the HKDF-based key mixing step defined in the Noise spec:
// HKDF(ck, ikm) -> ck, temp_k. Sets k = temp_k and resets the nonce.
func (ss *nkhfsSymmetricState) mixKey(ikm []byte) error {
	out, err := noiseHKDF2(ss.ck[:], ikm)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(out)
	copy(ss.ck[:], out[:32])
	copy(ss.k[:], out[32:])
	ss.hasKey = true
	ss.n = 0
	return nil
}

// encryptAndHash encrypts plaintext (if key is set) with the current handshake key,
// mixes the ciphertext into h, and returns the ciphertext.
// If hasKey is false (pre-key phase), it just mixes plaintext into h and returns it unchanged.
func (ss *nkhfsSymmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	if !ss.hasKey {
		ss.mixHash(plaintext)
		return plaintext, nil
	}
	aead, err := chacha20poly1305.New(ss.k[:])
	if err != nil {
		return nil, err
	}
	nonce := buildChachaPolyNonce(ss.n)
	ss.n++
	ciphertext := aead.Seal(nil, nonce[:], plaintext, ss.h[:])
	ss.mixHash(ciphertext)
	return ciphertext, nil
}

// decryptAndHash decrypts ciphertext (if key is set), mixes ciphertext into h,
// and returns the plaintext. Per the Noise spec, the ciphertext is mixed into h
// BEFORE decryption, using the pre-mix h value as AEAD additional data.
func (ss *nkhfsSymmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if !ss.hasKey {
		ss.mixHash(ciphertext)
		return ciphertext, nil
	}
	// Snapshot h before mixing (used as AEAD additional data).
	hSnapshot := ss.h
	defer crypto.ZeroizeArray32(&hSnapshot)

	// Mix ciphertext into h BEFORE decrypting (per Noise spec).
	ss.mixHash(ciphertext)

	aead, err := chacha20poly1305.New(ss.k[:])
	if err != nil {
		return nil, err
	}
	nonce := buildChachaPolyNonce(ss.n)
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, hSnapshot[:])
	if err != nil {
		return nil, &NKhfsDecryptError{}
	}
	ss.n++
	return plaintext, nil
}

// split derives two CipherStates for the transport phase.
// Returns (sendCipher, recvCipher) as seen from the initiator.
// The intermediate HKDF output is zeroized after the keys are copied.
func (ss *nkhfsSymmetricState) split() (*NKhfsCipherState, *NKhfsCipherState, []byte, error) {
	out, err := noiseHKDF2(ss.ck[:], nil)
	if err != nil {
		return nil, nil, nil, err
	}
	defer crypto.Zeroize(out)

	var cs0, cs1 NKhfsCipherState
	copy(cs0.key[:], out[:32])
	copy(cs1.key[:], out[32:])

	// Return a copy of h as the handshake hash (channel binding).
	hCopy := make([]byte, 32)
	copy(hCopy, ss.h[:])

	// Zeroize ck and k after splitting (handshake is complete).
	crypto.ZeroizeArray32(&ss.ck)
	crypto.ZeroizeArray32(&ss.k)

	return &cs0, &cs1, hCopy, nil
}

// noiseHKDF2 performs HKDF with the given ck as the salt and ikm as the input
// key material, producing a 64-byte output (two 32-byte keys) per the Noise spec.
// The caller is responsible for zeroizing the returned slice after use.
func noiseHKDF2(ck, ikm []byte) ([]byte, error) {
	// The Noise spec uses HKDF with 2 outputs, each of HASHLEN (32) bytes.
	// HKDF(salt=ck, ikm=ikm, info="") -> 64 bytes split into two 32-byte keys.
	r := hkdf.New(sha256.New, ikm, ck, nil)
	out := make([]byte, 64)
	if _, err := r.Read(out); err != nil {
		crypto.Zeroize(out)
		return nil, err
	}
	return out, nil
}

// x25519DH performs a Diffie-Hellman key exchange using Curve25519.
// Returns NKhfsDHError if the result is the all-zero point (low-order point attack).
func x25519DH(privateKey, publicKey []byte) ([]byte, error) {
	result, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, err
	}
	var allZero [32]byte
	if subtle.ConstantTimeCompare(result, allZero[:]) == 1 {
		crypto.Zeroize(result)
		return nil, &NKhfsDHError{Detail: "DH produced all-zero shared secret (low-order point)"}
	}
	return result, nil
}

// nkhfsHandshakeState manages the NKhfs initiator handshake state machine.
type nkhfsHandshakeState struct {
	ss               *nkhfsSymmetricState
	localEphPriv     []byte                     // ephemeral X25519 private key
	localEphPub      []byte                     // ephemeral X25519 public key
	remoteStatic     []byte                     // peer's static X25519 public key (pre-shared)
	kemDecapKey      *mlkem.DecapsulationKey1024 // local KEM decapsulation key
	kemEncapKeyBytes []byte                     // local KEM encapsulation key bytes (sent to peer)
}

// destroy zeroizes sensitive key material in the handshake state.
// Called after the handshake is complete to prevent key material from lingering.
func (hs *nkhfsHandshakeState) destroy() {
	crypto.Zeroize(hs.localEphPriv)
}

// newNKhfsHandshakeState creates and initializes a new NKhfs initiator handshake.
// remoteStaticPub is the responder's static X25519 public key (32 bytes).
func newNKhfsHandshakeState(remoteStaticPub []byte) (*nkhfsHandshakeState, error) {
	if len(remoteStaticPub) != 32 {
		return nil, newAttestationDataError("NKhfs: remote static public key must be 32 bytes")
	}

	ss := newNKhfsSymmetricState()

	// NK pre-message: <- s. Mix the responder's static key into h.
	ss.mixHash(remoteStaticPub)

	// Generate initiator ephemeral X25519 key pair.
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		return nil, newNoiseHandshakeError(err)
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, newNoiseHandshakeError(err)
	}

	// Generate initiator KEM key pair (ML-KEM-1024).
	kemDK, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, newNoiseHandshakeError(err)
	}

	return &nkhfsHandshakeState{
		ss:               ss,
		localEphPriv:     ephPriv,
		localEphPub:      ephPub,
		remoteStatic:     remoteStaticPub,
		kemDecapKey:      kemDK,
		kemEncapKeyBytes: kemDK.EncapsulationKey().Bytes(),
	}, nil
}

// writeMessage1 produces the initiator's first handshake message: -> e, es, e1.
//
// Wire format: e.public(32) || EncryptAndHash(e1.public)(1568+16) || EncryptAndHash(payload)(len+16)
//
//  1. Append e.public to message, MixHash(e.public)
//  2. MixKey(DH(e, rs)) — sets hasKey=true; X25519 DH result is zeroized after use
//  3. EncryptAndHash(e1.public) — KEM pub is AEAD-encrypted since hasKey=true; append to message
//  4. EncryptAndHash(payload) — payload encrypted and appended
func (hs *nkhfsHandshakeState) writeMessage1(payload []byte) ([]byte, error) {
	var msg []byte

	// Step 1: e — append ephemeral public key and mix into h.
	msg = append(msg, hs.localEphPub...)
	hs.ss.mixHash(hs.localEphPub)

	// Step 2: es — DH(ephemeral, remote_static) and mix key.
	// Zeroize the DH result immediately after mixing.
	dhResult, err := x25519DH(hs.localEphPriv, hs.remoteStatic)
	if err != nil {
		return nil, newNoiseHandshakeError(err)
	}
	defer crypto.Zeroize(dhResult)
	if err := hs.ss.mixKey(dhResult); err != nil {
		return nil, newNoiseHandshakeError(err)
	}

	// Step 3: e1 — EncryptAndHash the KEM encapsulation key.
	// hasKey=true after es, so encryptAndHash applies AEAD encryption (+16 byte tag).
	encryptedKemPub, err := hs.ss.encryptAndHash(hs.kemEncapKeyBytes)
	if err != nil {
		return nil, newNoiseHandshakeError(err)
	}
	msg = append(msg, encryptedKemPub...)

	// Step 4: EncryptAndHash(payload).
	encrypted, err := hs.ss.encryptAndHash(payload)
	if err != nil {
		return nil, newNoiseHandshakeError(err)
	}
	msg = append(msg, encrypted...)

	return msg, nil
}

// readMessage2 processes the responder's second handshake message: <- e, ee, ekem1.
//
// Expected wire format:
//
//	e.public(32) || DecryptAndHash(ekem1.ciphertext)(1568+16) || DecryptAndHash(payload)(len+16)
//
// Token processing order per the Noise HFS extension spec:
//
//  1. Read e.public (32 bytes), MixHash(e.public)
//  2. MixKey(DH(e_local, e_remote)) — hasKey=true; DH result zeroized after use
//  3. DecryptAndHash(encKemCt)(1584 bytes) — recover 1568-byte KEM ct using key from step 2
//  4. Decapsulate(kemCt) → kemSS; MixKey(kemSS) — KEM SS zeroized after use
//  5. DecryptAndHash(remaining payload) — using key from step 4
//  6. split() — derive transport CipherStates, destroy ephemeral private key
//
// Returns the decrypted payload and transport CipherStates.
func (hs *nkhfsHandshakeState) readMessage2(msg []byte) ([]byte, *NKhfsCipherState, *NKhfsCipherState, []byte, error) {
	const (
		dhPubLen     = 32
		kemCtLen     = 1568 // ML-KEM-1024 ciphertext size
		aeadOverhead = 16   // ChaCha20-Poly1305 tag size
		encKemCtLen  = kemCtLen + aeadOverhead // ekem1 encrypted on wire: 1584
		minMsg2Len   = dhPubLen + encKemCtLen
	)

	if len(msg) < minMsg2Len {
		return nil, nil, nil, nil, newNoiseHandshakeError(&NKhfsMsgTooShortError{
			expected: minMsg2Len,
			actual:   len(msg),
		})
	}

	// Step 1: Read remote ephemeral DH public key (sent in clear, before ee sets hasKey).
	remoteEphPub := msg[:dhPubLen]
	msg = msg[dhPubLen:]
	hs.ss.mixHash(remoteEphPub)

	// Step 2: ee — DH(local_ephemeral, remote_ephemeral) and mix key.
	// After this, hasKey=true; DH result is zeroized immediately.
	dhResult, err := x25519DH(hs.localEphPriv, remoteEphPub)
	if err != nil {
		return nil, nil, nil, nil, newNoiseHandshakeError(err)
	}
	defer crypto.Zeroize(dhResult)
	if err := hs.ss.mixKey(dhResult); err != nil {
		return nil, nil, nil, nil, newNoiseHandshakeError(err)
	}

	// Step 3: ekem1 — DecryptAndHash the encrypted KEM ciphertext (1584 bytes on wire).
	// The responder encrypted the 1568-byte KEM ct using the key from ee (step 2).
	// We must decrypt with that same key BEFORE mixing in the KEM shared secret.
	encKemCt := msg[:encKemCtLen]
	msg = msg[encKemCtLen:]
	kemCt, err := hs.ss.decryptAndHash(encKemCt)
	if err != nil {
		return nil, nil, nil, nil, newNoiseHandshakeError(err)
	}

	// Step 4: Decapsulate the KEM ciphertext to recover the shared secret, then MixKey.
	// KEM SS is zeroized immediately after mixing.
	kemSS, err := hs.kemDecapKey.Decapsulate(kemCt)
	if err != nil {
		return nil, nil, nil, nil, newNoiseHandshakeError(err)
	}
	defer crypto.Zeroize(kemSS)
	if err := hs.ss.mixKey(kemSS); err != nil {
		return nil, nil, nil, nil, newNoiseHandshakeError(err)
	}

	// Step 5: DecryptAndHash(remaining payload) using key from KEM mixKey (step 4).
	payload, err := hs.ss.decryptAndHash(msg)
	if err != nil {
		return nil, nil, nil, nil, newNoiseHandshakeError(err)
	}

	// Step 6: Split into transport cipher states and zeroize the ephemeral private key.
	cs0, cs1, handshakeHash, err := hs.ss.split()
	if err != nil {
		return nil, nil, nil, nil, newNoiseHandshakeError(err)
	}
	hs.destroy()

	return payload, cs0, cs1, handshakeHash, nil
}

// NKhfsHandshake is the post-quantum Noise NKhfs handshaker.
// It manages the two-message initiator-side handshake for
// Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256.
type NKhfsHandshake struct {
	state          *nkhfsHandshakeState
	initialRequest []byte
	claims         *Claims
}

// newNKhfsHandshakeWithClaims creates an NKhfsHandshake from verified claims,
// writes the first handshake message, and returns the UnvalidatedHandshake.
func newNKhfsHandshakeWithClaims(claims *Claims) (*UnvalidatedHandshake, error) {
	hs, err := newNKhfsHandshakeState(claims.PublicKey)
	if err != nil {
		return nil, err
	}

	// Write message 1 with empty payload (matches Rust behavior).
	msg1, err := hs.writeMessage1(nil)
	if err != nil {
		return nil, err
	}

	nkhfs := &NKhfsHandshake{
		state:          hs,
		initialRequest: msg1,
		claims:         claims,
	}

	return &UnvalidatedHandshake{
		handshake: &Handshake{
			nkhfs:          nkhfs,
			initialRequest: msg1,
			claims:         claims,
		},
	}, nil
}

// NKhfsDecryptError indicates decryption failure during the NKhfs handshake.
type NKhfsDecryptError struct{}

func (e *NKhfsDecryptError) Error() string {
	return "NKhfs: decryption failed (authentication tag mismatch)"
}

// NKhfsMsgTooShortError indicates a handshake message was shorter than expected.
// Fields are unexported to prevent accidental leakage of internal wire-format details.
type NKhfsMsgTooShortError struct {
	expected int
	actual   int
}

func (e *NKhfsMsgTooShortError) Error() string {
	return "NKhfs: message too short"
}

// NKhfsDHError indicates that a Diffie-Hellman operation produced an invalid result.
type NKhfsDHError struct {
	Detail string
}

func (e *NKhfsDHError) Error() string {
	return "NKhfs: " + e.Detail
}

// NKhfsNonceExhaustedError indicates that the nonce counter has reached its maximum value.
// The cipher state must not be used further once this error is returned.
type NKhfsNonceExhaustedError struct{}

func (e *NKhfsNonceExhaustedError) Error() string {
	return "NKhfs: nonce counter exhausted"
}
