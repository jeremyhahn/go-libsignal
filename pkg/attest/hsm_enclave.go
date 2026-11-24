// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/subtle"

	"github.com/flynn/noise"
)

const (
	// CodeHashSize is the size in bytes of a code hash.
	CodeHashSize = 32
	// PubKeySize is the size in bytes of a public key.
	PubKeySize = 32
)

// HSMClientConnectionEstablishment wraps a connection handshake to an HSM-resident enclave.
//
// Usage:
//
//	establishment, err := NewHSMClientConnectionEstablishment(trustedPubKey, trustedCodeHashes)
//	// open websocket
//	websocket.Send(establishment.InitialRequest())
//	initialResponse := websocket.Recv()
//	conn, err := establishment.Complete(initialResponse)
type HSMClientConnectionEstablishment struct {
	hs                *noise.HandshakeState
	initialMessage    []byte
	trustedCodeHashes [][CodeHashSize]byte
}

// NewHSMClientConnectionEstablishment creates a new HSM client connection establishment.
func NewHSMClientConnectionEstablishment(
	trustedPublicKey [PubKeySize]byte,
	trustedCodeHashes [][CodeHashSize]byte,
) (*HSMClientConnectionEstablishment, error) {
	if len(trustedCodeHashes) == 0 {
		return nil, &HSMError{
			Kind: ErrInvalidCodeHash,
		}
	}

	cs := noiseCipherSuite()

	// Concatenate all code hashes as the initial payload
	payload := make([]byte, 0, len(trustedCodeHashes)*CodeHashSize)
	for _, h := range trustedCodeHashes {
		payload = append(payload, h[:]...)
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  trustedPublicKey[:],
	})
	if err != nil {
		return nil, &HSMError{Kind: ErrHSMHandshake, Err: err}
	}

	initialMessage, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, &HSMError{Kind: ErrHSMHandshake, Err: err}
	}

	return &HSMClientConnectionEstablishment{
		hs:                hs,
		initialMessage:    initialMessage,
		trustedCodeHashes: trustedCodeHashes,
	}, nil
}

// InitialRequest returns the initial message to send to server to establish connection.
func (e *HSMClientConnectionEstablishment) InitialRequest() []byte {
	return e.initialMessage
}

// Complete completes client connection initiation, returns a valid client connection.
func (e *HSMClientConnectionEstablishment) Complete(initialReceived []byte) (*ClientConnection, error) {
	payload, cs0, cs1, err := e.hs.ReadMessage(nil, initialReceived)
	if err != nil {
		return nil, &HSMError{Kind: ErrHSMHandshake, Err: err}
	}

	if len(payload) != CodeHashSize {
		return nil, &HSMError{Kind: ErrTrustedCode}
	}

	var receivedHash [CodeHashSize]byte
	copy(receivedHash[:], payload)

	// Check if the received hash matches any trusted code hash using
	// constant-time comparison to prevent timing side-channel leaks.
	found := false
	for _, trusted := range e.trustedCodeHashes {
		if subtle.ConstantTimeCompare(trusted[:], receivedHash[:]) == 1 {
			found = true
			break
		}
	}
	if !found {
		return nil, &HSMError{Kind: ErrTrustedCode}
	}

	if cs0 == nil || cs1 == nil {
		// Handshake not yet complete, shouldn't happen for NK pattern with 2 messages
		return nil, &HSMError{
			Kind:    ErrHSMHandshake,
			Message: "handshake did not complete",
			Err:     &HandshakeIncompleteError{},
		}
	}

	return &ClientConnection{
		HandshakeHash: e.hs.ChannelBinding(),
		sendCipher:    &preQuantumCipher{cs: cs0},
		recvCipher:    &preQuantumCipher{cs: cs1},
	}, nil
}
