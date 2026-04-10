// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

// Package attest provides encryption / decryption of messages for established
// Noise protocol sessions used in Signal's attestation-based enclave
// communication.
//
// Once a noise handshake has already completed (using the constant pattern
// provided below), messages can be encrypted into one or more noise transport
// messages for sending with ClientConnection.Send. Likewise a single received
// message consisting internally of one or more noise transport messages can be
// decrypted with ClientConnection.Recv.
package attest

import (
	"github.com/flynn/noise"
)

const (
	// NoisePattern is the Noise protocol pattern used for pre-quantum connections.
	NoisePattern = "Noise_NK_25519_ChaChaPoly_SHA256"

	// NoiseTransportPerPacketMax is the maximum size of a Noise transport packet.
	NoiseTransportPerPacketMax = 65535

	// noiseTransportPerPayloadOverhead is the AEAD overhead per payload chunk.
	noiseTransportPerPayloadOverhead = 16

	// NoiseTransportPerPayloadMax is the maximum plaintext payload per Noise packet.
	NoiseTransportPerPayloadMax = NoiseTransportPerPacketMax - noiseTransportPerPayloadOverhead
)

// noiseCipher is the interface satisfied by both noise.CipherState (pre-quantum)
// and NKhfsCipherState (post-quantum). It encapsulates symmetric encryption for
// Noise transport messages.
type noiseCipher interface {
	// Encrypt encrypts plaintext with ad as additional data.
	Encrypt(ad, plaintext []byte) ([]byte, error)
	// Decrypt decrypts ciphertext with ad as additional data.
	Decrypt(ad, ciphertext []byte) ([]byte, error)
}

// preQuantumCipher wraps *noise.CipherState to implement noiseCipher.
type preQuantumCipher struct {
	cs *noise.CipherState
}

func (p *preQuantumCipher) Encrypt(ad, plaintext []byte) ([]byte, error) {
	ct, err := p.cs.Encrypt(nil, ad, plaintext)
	if err != nil {
		return nil, &ClientConnectionError{Err: err}
	}
	return ct, nil
}

func (p *preQuantumCipher) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	pt, err := p.cs.Decrypt(nil, ad, ciphertext)
	if err != nil {
		return nil, &ClientConnectionError{Err: err}
	}
	return pt, nil
}

// noiseCipherSuite returns the cipher suite used for Noise_NK_25519_ChaChaPoly_SHA256.
func noiseCipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

// ClientConnection provides encrypted transport over an established Noise session.
type ClientConnection struct {
	// HandshakeHash is the handshake hash from the completed Noise handshake.
	HandshakeHash []byte

	// sendCipher encrypts outgoing messages (initiator -> responder).
	sendCipher noiseCipher

	// recvCipher decrypts incoming messages (responder -> initiator).
	recvCipher noiseCipher
}

// Send wraps a plaintext message to be sent, returning the ciphertext.
func (c *ClientConnection) Send(plaintext []byte) ([]byte, error) {
	maxCiphertextSize := len(plaintext) +
		((len(plaintext)+NoiseTransportPerPayloadMax-1)/NoiseTransportPerPayloadMax)*
			noiseTransportPerPayloadOverhead
	if len(plaintext) == 0 {
		maxCiphertextSize = noiseTransportPerPayloadOverhead
	}
	ciphertext := make([]byte, 0, maxCiphertextSize)

	for len(plaintext) > 0 {
		chunkSize := len(plaintext)
		if chunkSize > NoiseTransportPerPayloadMax {
			chunkSize = NoiseTransportPerPayloadMax
		}
		chunk := plaintext[:chunkSize]
		plaintext = plaintext[chunkSize:]

		encrypted, err := c.sendCipher.Encrypt(nil, chunk)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, encrypted...)
	}

	if len(ciphertext) == 0 {
		encrypted, err := c.sendCipher.Encrypt(nil, nil)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, encrypted...)
	}

	return ciphertext, nil
}

// destroyable is implemented by cipher states that hold zeroizable key material.
type destroyable interface {
	Destroy()
}

// Destroy zeroizes the key material held by the cipher states, if they support it.
// This should be called when the ClientConnection is no longer needed.
func (c *ClientConnection) Destroy() {
	if d, ok := c.sendCipher.(destroyable); ok {
		d.Destroy()
	}
	if d, ok := c.recvCipher.(destroyable); ok {
		d.Destroy()
	}
}

// Recv unwraps a ciphertext message that has been received, returning the plaintext.
func (c *ClientConnection) Recv(ciphertext []byte) ([]byte, error) {
	plaintext := make([]byte, 0, len(ciphertext))

	for len(ciphertext) > 0 {
		chunkSize := len(ciphertext)
		if chunkSize > NoiseTransportPerPacketMax {
			chunkSize = NoiseTransportPerPacketMax
		}
		chunk := ciphertext[:chunkSize]
		ciphertext = ciphertext[chunkSize:]

		decrypted, err := c.recvCipher.Decrypt(nil, chunk)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, decrypted...)
	}

	return plaintext, nil
}
