//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 5 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 pattern requires it
// (Noise Protocol Framework rev 34), so the fips140only build tag drops this
// file from the FIPS gate. `make test` and `make coverage` still run it.

// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func newServerKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	return priv, pub
}

func TestNewNKhfsResponder_HappyPath(t *testing.T) {
	priv, pub := newServerKeypair(t)
	r, err := NewNKhfsResponder(priv, pub)
	if err != nil {
		t.Fatalf("NewNKhfsResponder: %v", err)
	}
	if r == nil {
		t.Fatal("nil responder")
	}
}

func TestNewNKhfsResponder_RejectsWrongLength(t *testing.T) {
	_, pub := newServerKeypair(t)
	if _, err := NewNKhfsResponder(make([]byte, 31), pub); err == nil {
		t.Error("expected error on short private key")
	}
	if _, err := NewNKhfsResponder(make([]byte, 32), make([]byte, 31)); err == nil {
		t.Error("expected error on short public key")
	}
}

func TestNKhfsResponder_ProcessMessage1_RoundTrip(t *testing.T) {
	priv, pub := newServerKeypair(t)
	r, err := NewNKhfsResponder(priv, pub)
	if err != nil {
		t.Fatalf("NewNKhfsResponder: %v", err)
	}

	// Initiator side: build message 1 against the same static public key.
	claims := &Claims{PublicKey: pub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims: %v", err)
	}
	msg1 := uv.handshake.InitialRequest()

	msg2, sendCS, recvCS, hash, err := r.ProcessMessage1(msg1)
	if err != nil {
		t.Fatalf("ProcessMessage1: %v", err)
	}
	if len(msg2) == 0 {
		t.Error("msg2 should not be empty")
	}
	if sendCS == nil || recvCS == nil {
		t.Error("cipher states should not be nil")
	}
	if len(hash) == 0 {
		t.Error("handshake hash should not be empty")
	}

	// Complete the handshake on the initiator side and exchange transport
	// messages in both directions.
	conn, err := uv.handshake.Complete(msg2)
	if err != nil {
		t.Fatalf("handshake.Complete: %v", err)
	}
	if !bytes.Equal(conn.HandshakeHash, hash) {
		t.Errorf("handshake hash mismatch:\n  client: %x\n  server: %x",
			conn.HandshakeHash, hash)
	}

	// Client -> server.
	cliCT, err := conn.Send([]byte("hello server"))
	if err != nil {
		t.Fatalf("conn.Send: %v", err)
	}
	gotCli, err := recvCS.Decrypt(nil, cliCT)
	if err != nil {
		t.Fatalf("recvCS.Decrypt: %v", err)
	}
	if string(gotCli) != "hello server" {
		t.Errorf("server recv = %q", gotCli)
	}

	// Server -> client.
	srvCT, err := sendCS.Encrypt(nil, []byte("hello client"))
	if err != nil {
		t.Fatalf("sendCS.Encrypt: %v", err)
	}
	gotSrv, err := conn.Recv(srvCT)
	if err != nil {
		t.Fatalf("conn.Recv: %v", err)
	}
	if string(gotSrv) != "hello client" {
		t.Errorf("client recv = %q", gotSrv)
	}
}

func TestNKhfsResponder_ProcessMessage1_RejectsTooShort(t *testing.T) {
	priv, pub := newServerKeypair(t)
	r, _ := NewNKhfsResponder(priv, pub)
	_, _, _, _, err := r.ProcessMessage1(make([]byte, 10))
	if err == nil {
		t.Error("expected error on short message")
	}
}

func TestNKhfsResponder_ProcessMessage1_RejectsTamperedMsg(t *testing.T) {
	priv, pub := newServerKeypair(t)
	r, _ := NewNKhfsResponder(priv, pub)

	claims := &Claims{PublicKey: pub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims: %v", err)
	}
	msg1 := uv.handshake.InitialRequest()
	// Flip a byte in the AEAD-protected region.
	msg1[40] ^= 0x01
	if _, _, _, _, err := r.ProcessMessage1(msg1); err == nil {
		t.Error("expected decryption failure on tampered msg1")
	}
}
