// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/flynn/noise"
)

func TestNewHSMClientConnectionEstablishment_HappyPath(t *testing.T) {
	cs := noiseCipherSuite()
	kp, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	var pubKey [PubKeySize]byte
	copy(pubKey[:], kp.Public)

	codeHash := [CodeHashSize]byte{}
	copy(codeHash[:], sha256.New().Sum(nil)[:CodeHashSize])

	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{codeHash})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if est == nil {
		t.Fatal("establishment should not be nil")
	}
	if len(est.InitialRequest()) == 0 {
		t.Error("initial request should not be empty")
	}
}

func TestNewHSMClientConnectionEstablishment_EmptyCodeHashes(t *testing.T) {
	var pubKey [PubKeySize]byte
	_, err := NewHSMClientConnectionEstablishment(pubKey, nil)
	if err == nil {
		t.Fatal("expected error for empty code hashes")
	}
	hsmErr, ok := err.(*HSMError)
	if !ok {
		t.Fatalf("expected HSMError, got %T", err)
	}
	if hsmErr.Kind != ErrInvalidCodeHash {
		t.Errorf("Kind = %d, want %d", hsmErr.Kind, ErrInvalidCodeHash)
	}
}

func TestNewHSMClientConnectionEstablishment_EmptySliceCodeHashes(t *testing.T) {
	var pubKey [PubKeySize]byte
	_, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{})
	if err == nil {
		t.Fatal("expected error for zero-length code hashes slice")
	}
}

func TestHSMClientConnectionEstablishment_Complete_HappyPath(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, _ := cs.GenerateKeypair(nil)

	var pubKey [PubKeySize]byte
	copy(pubKey[:], responderKP.Public)

	codeHash := [CodeHashSize]byte{0x01, 0x02, 0x03}

	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{codeHash})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Set up responder
	respHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})
	if err != nil {
		t.Fatalf("responder handshake: %v", err)
	}

	// Responder reads initiator message (which contains code hashes as payload)
	payload, _, _, err := respHS.ReadMessage(nil, est.InitialRequest())
	if err != nil {
		t.Fatalf("responder ReadMessage: %v", err)
	}

	// Verify the payload contains the code hash
	if !bytes.Equal(payload, codeHash[:]) {
		t.Errorf("payload = %x, want %x", payload, codeHash[:])
	}

	// Responder writes response with one of the trusted code hashes as payload
	respMsg, _, _, err := respHS.WriteMessage(nil, codeHash[:])
	if err != nil {
		t.Fatalf("responder WriteMessage: %v", err)
	}

	// Complete the handshake
	conn, err := est.Complete(respMsg)
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if conn == nil {
		t.Fatal("connection should not be nil")
	}
	if len(conn.HandshakeHash) == 0 {
		t.Error("HandshakeHash should not be empty")
	}
}

func TestHSMClientConnectionEstablishment_Complete_WrongCodeHash(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, _ := cs.GenerateKeypair(nil)

	var pubKey [PubKeySize]byte
	copy(pubKey[:], responderKP.Public)

	trustedHash := [CodeHashSize]byte{0x01}
	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{trustedHash})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respHS, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})

	_, _, _, _ = respHS.ReadMessage(nil, est.InitialRequest())

	// Responder sends back a DIFFERENT code hash
	wrongHash := make([]byte, CodeHashSize)
	wrongHash[0] = 0xFF
	respMsg, _, _, _ := respHS.WriteMessage(nil, wrongHash)

	_, err = est.Complete(respMsg)
	if err == nil {
		t.Fatal("expected error for wrong code hash")
	}
	hsmErr, ok := err.(*HSMError)
	if !ok {
		t.Fatalf("expected HSMError, got %T", err)
	}
	if hsmErr.Kind != ErrTrustedCode {
		t.Errorf("Kind = %d, want %d", hsmErr.Kind, ErrTrustedCode)
	}
}

func TestHSMClientConnectionEstablishment_Complete_WrongPayloadSize(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, _ := cs.GenerateKeypair(nil)

	var pubKey [PubKeySize]byte
	copy(pubKey[:], responderKP.Public)

	codeHash := [CodeHashSize]byte{0x01}
	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{codeHash})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respHS, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})

	_, _, _, _ = respHS.ReadMessage(nil, est.InitialRequest())

	// Responder sends back a payload with wrong size (not CodeHashSize)
	wrongSize := make([]byte, 16) // not 32
	respMsg, _, _, _ := respHS.WriteMessage(nil, wrongSize)

	_, err = est.Complete(respMsg)
	if err == nil {
		t.Fatal("expected error for wrong payload size")
	}
	hsmErr, ok := err.(*HSMError)
	if !ok {
		t.Fatalf("expected HSMError, got %T", err)
	}
	if hsmErr.Kind != ErrTrustedCode {
		t.Errorf("Kind = %d, want %d", hsmErr.Kind, ErrTrustedCode)
	}
}

func TestHSMClientConnectionEstablishment_Complete_InvalidHandshakeData(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	var pubKey [PubKeySize]byte
	copy(pubKey[:], kp.Public)

	codeHash := [CodeHashSize]byte{0x01}
	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{codeHash})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = est.Complete([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid handshake data")
	}
}

func TestHSMClientConnectionEstablishment_MultipleCodeHashes(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, _ := cs.GenerateKeypair(nil)

	var pubKey [PubKeySize]byte
	copy(pubKey[:], responderKP.Public)

	hash1 := [CodeHashSize]byte{0x01}
	hash2 := [CodeHashSize]byte{0x02}
	hash3 := [CodeHashSize]byte{0x03}

	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{hash1, hash2, hash3})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respHS, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})

	payload, _, _, _ := respHS.ReadMessage(nil, est.InitialRequest())

	// Verify all code hashes are concatenated in the payload
	expectedLen := 3 * CodeHashSize
	if len(payload) != expectedLen {
		t.Fatalf("payload len = %d, want %d", len(payload), expectedLen)
	}

	// Respond with hash2 (the second trusted hash)
	respMsg, _, _, _ := respHS.WriteMessage(nil, hash2[:])

	conn, err := est.Complete(respMsg)
	if err != nil {
		t.Fatalf("Complete should succeed with any trusted hash: %v", err)
	}
	if conn == nil {
		t.Fatal("connection should not be nil")
	}
}
