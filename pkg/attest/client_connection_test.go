// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"bytes"
	"testing"

	"github.com/flynn/noise"
)

// setupClientConnection creates a completed Noise NK handshake and returns both
// the initiator's ClientConnection and the responder's cipher states, so we can
// test round-trip encryption/decryption.
func setupClientConnection(t *testing.T) (*ClientConnection, *noise.CipherState, *noise.CipherState) {
	t.Helper()

	cs := noiseCipherSuite()
	responderKP, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// Initiator
	initHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  responderKP.Public,
	})
	if err != nil {
		t.Fatalf("init handshake state: %v", err)
	}

	// Responder
	respHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:        noise.HandshakeNK,
		Initiator:      false,
		StaticKeypair:  responderKP,
	})
	if err != nil {
		t.Fatalf("resp handshake state: %v", err)
	}

	// Message 1: initiator -> responder
	msg1, _, _, err := initHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("init WriteMessage: %v", err)
	}
	_, _, _, err = respHS.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("resp ReadMessage: %v", err)
	}

	// Message 2: responder -> initiator
	msg2, respCS0, respCS1, err := respHS.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("resp WriteMessage: %v", err)
	}
	_, initCS0, initCS1, err := initHS.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("init ReadMessage: %v", err)
	}

	conn := &ClientConnection{
		HandshakeHash: initHS.ChannelBinding(),
		sendCipher:    &preQuantumCipher{cs: initCS0},
		recvCipher:    &preQuantumCipher{cs: initCS1},
	}

	// In Noise NK: initiator's cs0 = responder's cs0 (initiator->responder direction).
	// The responder decrypts with cs0 and encrypts with cs1.
	return conn, respCS0, respCS1
}

func TestClientConnection_SendRecv_SmallMessage(t *testing.T) {
	conn, respRecvCS, respSendCS := setupClientConnection(t)

	plaintext := []byte("hello, enclave!")
	ciphertext, err := conn.Send(plaintext)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// Responder decrypts
	decrypted, err := respRecvCS.Decrypt(nil, nil, ciphertext)
	if err != nil {
		t.Fatalf("responder Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}

	// Responder sends back
	reply := []byte("hello back!")
	replyCiphertext, err := respSendCS.Encrypt(nil, nil, reply)
	if err != nil {
		t.Fatalf("responder Encrypt failed: %v", err)
	}

	decryptedReply, err := conn.Recv(replyCiphertext)
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}
	if !bytes.Equal(decryptedReply, reply) {
		t.Errorf("decrypted reply = %q, want %q", decryptedReply, reply)
	}
}

func TestClientConnection_Send_EmptyPayload(t *testing.T) {
	conn, respRecvCS, _ := setupClientConnection(t)

	ciphertext, err := conn.Send([]byte{})
	if err != nil {
		t.Fatalf("Send empty failed: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Error("ciphertext for empty payload should not be empty (AEAD overhead)")
	}

	decrypted, err := respRecvCS.Decrypt(nil, nil, ciphertext)
	if err != nil {
		t.Fatalf("responder Decrypt failed: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("decrypted empty payload should be empty, got %d bytes", len(decrypted))
	}
}

func TestClientConnection_Send_NilPayload(t *testing.T) {
	conn, _, _ := setupClientConnection(t)

	ciphertext, err := conn.Send(nil)
	if err != nil {
		t.Fatalf("Send nil failed: %v", err)
	}
	// nil is treated as empty; should produce AEAD tag
	if len(ciphertext) == 0 {
		t.Error("expected AEAD overhead for nil payload")
	}
}

func TestClientConnection_Recv_InvalidCiphertext(t *testing.T) {
	conn, _, _ := setupClientConnection(t)

	// Invalid ciphertext should fail decryption
	_, err := conn.Recv([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	if err == nil {
		t.Fatal("expected error for invalid ciphertext")
	}
	var connErr *ClientConnectionError
	if ok := isClientConnectionError(err, &connErr); !ok {
		t.Errorf("expected ClientConnectionError, got %T", err)
	}
}

func isClientConnectionError(err error, target **ClientConnectionError) bool {
	e, ok := err.(*ClientConnectionError)
	if ok {
		*target = e
	}
	return ok
}

func TestClientConnection_Recv_EmptyCiphertext(t *testing.T) {
	conn, _, _ := setupClientConnection(t)

	result, err := conn.Recv([]byte{})
	if err != nil {
		t.Fatalf("Recv empty should succeed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(result))
	}
}

func TestNoiseCipherSuite(t *testing.T) {
	cs := noiseCipherSuite()
	if cs == nil {
		t.Fatal("noiseCipherSuite returned nil")
	}
	// Verify it returns the expected cipher suite by name
	if string(cs.Name()) != "25519_ChaChaPoly_SHA256" {
		t.Errorf("unexpected cipher suite name: %s", cs.Name())
	}
}

func TestNoiseConstants(t *testing.T) {
	if NoiseTransportPerPacketMax != 65535 {
		t.Errorf("NoiseTransportPerPacketMax = %d, want 65535", NoiseTransportPerPacketMax)
	}
	if NoiseTransportPerPayloadMax != 65535-16 {
		t.Errorf("NoiseTransportPerPayloadMax = %d, want %d", NoiseTransportPerPayloadMax, 65535-16)
	}
}

func TestClientConnection_SendRecv_LargeMessage(t *testing.T) {
	conn, respRecvCS, _ := setupClientConnection(t)

	// Create a message larger than NoiseTransportPerPayloadMax to test chunking
	plaintext := make([]byte, NoiseTransportPerPayloadMax+100)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := conn.Send(plaintext)
	if err != nil {
		t.Fatalf("Send large message failed: %v", err)
	}

	// Large messages should be split into chunks. The ciphertext should be larger
	// than the plaintext due to per-chunk AEAD overhead on at least 2 chunks.
	expectedOverhead := 2 * noiseTransportPerPayloadOverhead
	if len(ciphertext) < len(plaintext)+expectedOverhead {
		t.Errorf("ciphertext too short for chunked message: %d bytes", len(ciphertext))
	}

	// Decrypt chunk by chunk (responder side)
	var decrypted []byte
	remaining := ciphertext
	for len(remaining) > 0 {
		chunkSize := len(remaining)
		if chunkSize > NoiseTransportPerPacketMax {
			chunkSize = NoiseTransportPerPacketMax
		}
		chunk := remaining[:chunkSize]
		remaining = remaining[chunkSize:]

		dec, err := respRecvCS.Decrypt(nil, nil, chunk)
		if err != nil {
			t.Fatalf("responder Decrypt chunk failed: %v", err)
		}
		decrypted = append(decrypted, dec...)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large message round-trip failed")
	}
}
