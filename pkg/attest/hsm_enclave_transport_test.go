// HSM enclave transport round-trip tests.
//
// Ports the message-transport portion of Rust's test_hsm_enclave_happy_path
// (rust/attest/tests/hsm_enclave.rs:14-57) which establishes the Noise NK
// handshake and then verifies bidirectional message transport via the
// resulting ClientConnection (Send/Recv).
//
// The existing hsm_enclave_test.go tests establish and complete the
// handshake but do not exercise the post-handshake transport. This file
// closes that gap.
//
// Rust source: rust/attest/tests/hsm_enclave.rs:14-57
// Upstream commit: 98915c44
package attest

import (
	"bytes"
	"testing"

	"github.com/flynn/noise"
)

// TestHSMClientConnection_SendRecv_ServerToClient verifies that after completing
// a Noise NK handshake, the server can encrypt a message using its send cipher
// and the client's ClientConnection.Recv decrypts it correctly.
//
// In Noise NK, after split: c1 = responder-send = client-recv cipher.
// Rust ref: test_hsm_enclave_happy_path (server → client message, lines 37-42).
func TestHSMClientConnection_SendRecv_ServerToClient(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	var pubKey [PubKeySize]byte
	copy(pubKey[:], responderKP.Public)

	codeHash := [CodeHashSize]byte{0x01}
	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{codeHash})
	if err != nil {
		t.Fatalf("NewHSMClientConnectionEstablishment: %v", err)
	}

	// Responder (server-side) reads the initiator message.
	respHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})
	if err != nil {
		t.Fatalf("responder handshake: %v", err)
	}
	payload, _, _, err := respHS.ReadMessage(nil, est.InitialRequest())
	if err != nil {
		t.Fatalf("responder ReadMessage: %v", err)
	}
	if !bytes.Equal(payload, codeHash[:]) {
		t.Fatalf("server received unexpected payload: %x", payload)
	}

	// Responder writes its response; c0 = initiator→responder, c1 = responder→initiator.
	respMsg, _, serverSendCipher, err := respHS.WriteMessage(nil, codeHash[:])
	if err != nil {
		t.Fatalf("responder WriteMessage: %v", err)
	}

	// Client completes the handshake.
	conn, err := est.Complete(respMsg)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Server encrypts [7, 8, 9] using the responder→initiator cipher (c1 = serverSendCipher).
	plaintext := []byte{7, 8, 9}
	ciphertext, err := serverSendCipher.Encrypt(nil, nil, plaintext)
	if err != nil {
		t.Fatalf("server Encrypt: %v", err)
	}

	// Client must decrypt it via Recv (which uses recvCipher = cs1, same as serverSendCipher).
	decrypted, err := conn.Recv(ciphertext)
	if err != nil {
		t.Fatalf("ClientConnection.Recv: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Recv() = %v, want %v", decrypted, plaintext)
	}
}

// TestHSMClientConnection_SendRecv_ClientToServer verifies that
// ClientConnection.Send produces ciphertext the server-side transport can
// decrypt, completing the bidirectional round-trip.
//
// In Noise NK, after split: c0 = initiator→responder = server's receive cipher.
// Rust ref: test_hsm_enclave_happy_path (client → server message, lines 44-51).
func TestHSMClientConnection_SendRecv_ClientToServer(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	var pubKey [PubKeySize]byte
	copy(pubKey[:], responderKP.Public)

	codeHash := [CodeHashSize]byte{0x01}
	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{codeHash})
	if err != nil {
		t.Fatalf("NewHSMClientConnectionEstablishment: %v", err)
	}

	respHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})
	if err != nil {
		t.Fatalf("responder handshake: %v", err)
	}
	_, _, _, err = respHS.ReadMessage(nil, est.InitialRequest())
	if err != nil {
		t.Fatalf("responder ReadMessage: %v", err)
	}

	// c0 = initiator→responder (server receive cipher), c1 = responder→initiator.
	respMsg, serverRecvCipher, _, err := respHS.WriteMessage(nil, codeHash[:])
	if err != nil {
		t.Fatalf("responder WriteMessage: %v", err)
	}

	conn, err := est.Complete(respMsg)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Client encrypts [0x0a, 0x0b, 0x0c] using Send (sendCipher = cs0 = initiator→responder).
	plaintext := []byte{0x0a, 0x0b, 0x0c}
	ciphertext, err := conn.Send(plaintext)
	if err != nil {
		t.Fatalf("ClientConnection.Send: %v", err)
	}

	// Server decrypts with c0 = serverRecvCipher (same initiator→responder direction).
	decrypted, err := serverRecvCipher.Decrypt(nil, nil, ciphertext)
	if err != nil {
		t.Fatalf("server Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("server Decrypt() = %v, want %v", decrypted, plaintext)
	}
}

// TestHSMClientConnection_Recv_RejectsGarbage asserts that Recv rejects
// malformed ciphertext with an error, confirming the AEAD authentication tag
// is verified and spoofed server messages are rejected.
func TestHSMClientConnection_Recv_RejectsGarbage(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, err := cs.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	var pubKey [PubKeySize]byte
	copy(pubKey[:], responderKP.Public)

	codeHash := [CodeHashSize]byte{0x01}
	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{codeHash})
	if err != nil {
		t.Fatalf("NewHSMClientConnectionEstablishment: %v", err)
	}

	respHS, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})
	if err != nil {
		t.Fatalf("responder handshake: %v", err)
	}
	_, _, _, err = respHS.ReadMessage(nil, est.InitialRequest())
	if err != nil {
		t.Fatalf("responder ReadMessage: %v", err)
	}

	respMsg, _, _, err := respHS.WriteMessage(nil, codeHash[:])
	if err != nil {
		t.Fatalf("responder WriteMessage: %v", err)
	}

	conn, err := est.Complete(respMsg)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Feed random garbage as ciphertext; Recv must return an error.
	garbage := make([]byte, 32)
	for i := range garbage {
		garbage[i] = byte(i + 1)
	}
	_, err = conn.Recv(garbage)
	if err == nil {
		t.Error("Recv must reject garbage ciphertext, but returned nil")
	}
}
