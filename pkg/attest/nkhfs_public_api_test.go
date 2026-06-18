// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// newNKhfsServerKeypair derives a fresh responder static X25519 key pair.
func newNKhfsServerKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	return priv, pub
}

// TestNewNKhfsInitiator_FullRoundTrip drives the public NKhfs entry points
// (NewNKhfsInitiator on the client, NewNKhfsResponder + ProcessMessage1 on the
// server) through a complete two-message handshake and a bidirectional
// transport exchange. This exercises the exported wrappers that the unexported
// round-trip tests bypass.
func TestNewNKhfsInitiator_FullRoundTrip(t *testing.T) {
	priv, pub := newNKhfsServerKeypair(t)

	uv, err := NewNKhfsInitiator(pub)
	if err != nil {
		t.Fatalf("NewNKhfsInitiator: %v", err)
	}
	hs := uv.SkipRaftValidation()
	msg1 := hs.InitialRequest()

	responder, err := NewNKhfsResponder(priv, pub)
	if err != nil {
		t.Fatalf("NewNKhfsResponder: %v", err)
	}
	msg2, respSend, respRecv, respHash, err := responder.ProcessMessage1(msg1)
	if err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}

	conn, err := hs.Complete(msg2)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil ClientConnection")
	}
	if !bytes.Equal(conn.HandshakeHash, respHash) {
		t.Fatalf("handshake hash mismatch:\n client: %x\n server: %x", conn.HandshakeHash, respHash)
	}

	// Client -> server.
	pt := []byte("hello via public NKhfs API")
	ct, err := conn.Send(pt)
	if err != nil {
		t.Fatalf("conn.Send: %v", err)
	}
	got, err := respRecv.Decrypt(nil, ct)
	if err != nil {
		t.Fatalf("server Decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("server decrypted %q, want %q", got, pt)
	}

	// Server -> client.
	reply := []byte("reply via public NKhfs API")
	replyCt, err := respSend.Encrypt(nil, reply)
	if err != nil {
		t.Fatalf("server Encrypt: %v", err)
	}
	gotReply, err := conn.Recv(replyCt)
	if err != nil {
		t.Fatalf("conn.Recv: %v", err)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Fatalf("client decrypted %q, want %q", gotReply, reply)
	}

	// Destroy zeroizes the NKhfs cipher states, which implement the
	// destroyable interface — this exercises both branches of Destroy.
	conn.Destroy()
}

// errCipher is a noiseCipher whose Encrypt and Decrypt always fail, used to
// drive the error-propagation branches of ClientConnection.Send and Recv.
type errCipher struct{}

func (errCipher) Encrypt(ad, plaintext []byte) ([]byte, error) {
	return nil, &ClientConnectionError{Err: errCipherFailure{}}
}

func (errCipher) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	return nil, &ClientConnectionError{Err: errCipherFailure{}}
}

type errCipherFailure struct{}

func (errCipherFailure) Error() string { return "synthetic cipher failure" }

// TestClientConnection_Send_EncryptError verifies that Send propagates an
// underlying cipher Encrypt failure (client_connection.go:100).
func TestClientConnection_Send_EncryptError(t *testing.T) {
	conn := &ClientConnection{sendCipher: errCipher{}, recvCipher: errCipher{}}
	if _, err := conn.Send([]byte("non-empty payload")); err == nil {
		t.Fatal("expected error from Send when cipher fails")
	}
}

// TestClientConnection_Recv_DecryptError verifies that Recv propagates an
// underlying cipher Decrypt failure (client_connection.go:131).
func TestClientConnection_Recv_DecryptError(t *testing.T) {
	conn := &ClientConnection{sendCipher: errCipher{}, recvCipher: errCipher{}}
	if _, err := conn.Recv([]byte("non-empty ciphertext")); err == nil {
		t.Fatal("expected error from Recv when cipher fails")
	}
}

// TestClientConnection_Destroy_NonDestroyableCiphers verifies that Destroy is a
// safe no-op when the cipher states do not implement the destroyable interface.
func TestClientConnection_Destroy_NonDestroyableCiphers(t *testing.T) {
	conn := &ClientConnection{sendCipher: errCipher{}, recvCipher: errCipher{}}
	conn.Destroy() // must not panic; both type assertions fail.
}

// TestX25519DH_InvalidKeyLength exercises the error branch of x25519DH where the
// underlying curve25519.X25519 rejects a malformed (wrong-length) scalar.
func TestX25519DH_InvalidKeyLength(t *testing.T) {
	_, pub := newNKhfsServerKeypair(t)
	// A 31-byte private scalar is invalid for X25519.
	if _, err := x25519DH(make([]byte, 31), pub); err == nil {
		t.Fatal("expected error from x25519DH for wrong-length private key")
	}
}

// TestX25519DH_LowOrderPoint exercises the low-order-point rejection branch of
// x25519DH. curve25519.X25519 rejects low-order public keys that would yield an
// all-zero shared secret, so x25519DH must return a non-nil error.
func TestX25519DH_LowOrderPoint(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// All-zero public key is a canonical low-order point.
	lowOrder := make([]byte, 32)
	if _, err := x25519DH(priv, lowOrder); err == nil {
		t.Fatal("expected error from x25519DH for low-order public key")
	}
}

// TestNewNKhfsInitiator_InvalidServerKey verifies that the initiator rejects a
// server public key that is not exactly 32 bytes.
func TestNewNKhfsInitiator_InvalidServerKey(t *testing.T) {
	if _, err := NewNKhfsInitiator([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("expected error for short server public key")
	}
}

// TestNewNKhfsResponder_InvalidKeyLengths verifies that NewNKhfsResponder
// validates both the private and public key lengths.
func TestNewNKhfsResponder_InvalidKeyLengths(t *testing.T) {
	_, pub := newNKhfsServerKeypair(t)

	if _, err := NewNKhfsResponder(make([]byte, 31), pub); err == nil {
		t.Fatal("expected error for short private key")
	}
	if _, err := NewNKhfsResponder(make([]byte, 32), make([]byte, 33)); err == nil {
		t.Fatal("expected error for wrong-length public key")
	}
}

// TestNKhfsResponder_ProcessMessage1_TooShort verifies that ProcessMessage1
// rejects a message that is shorter than the minimum handshake length.
func TestNKhfsResponder_ProcessMessage1_TooShort(t *testing.T) {
	priv, pub := newNKhfsServerKeypair(t)
	responder, err := NewNKhfsResponder(priv, pub)
	if err != nil {
		t.Fatalf("NewNKhfsResponder: %v", err)
	}
	_, _, _, _, err = responder.ProcessMessage1([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for too-short message 1")
	}
	if _, ok := err.(*NKhfsMsgTooShortError); !ok {
		t.Fatalf("expected *NKhfsMsgTooShortError, got %T: %v", err, err)
	}
}
