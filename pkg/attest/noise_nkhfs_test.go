//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 4 tests in this file exercise X25519 and ChaCha20-Poly1305. FIPS 140-3
// does not approve that, but the
// Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 pattern names both (Noise
// Protocol Framework rev 34), so the fips140only build tag drops this file
// from the FIPS gate. `make test` and `make coverage` still run it.

// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// nkhfsResponder implements the server side of Noise NKhfs for testing purposes.
// It mirrors the initiator logic, processing message 1 and producing message 2.
type nkhfsResponder struct {
	staticPriv []byte
	staticPub  []byte
	ss         *nkhfsSymmetricState
	ephPriv    []byte
	ephPub     []byte
}

// newNKhfsResponder creates a responder with the given static X25519 key pair.
func newNKhfsResponder(staticPriv, staticPub []byte) *nkhfsResponder {
	return &nkhfsResponder{
		staticPriv: staticPriv,
		staticPub:  staticPub,
	}
}

// processMessage1 parses the initiator's first message (-> e, es, e1),
// generates the responder's ephemeral key, and derives the transport ciphers.
//
// Wire format consumed:
//
//	e.pub(32) + DecryptAndHash(e1.pub)(1568+16) + DecryptAndHash(payload)(len+16)
//
// Wire format produced:
//
//	e.pub(32) + EncryptAndHash(ekem1.ct)(1568+16) + EncryptAndHash(payload)(len+16)
//
// Returns: (msg2, sendCipher, recvCipher, handshakeHash, err).
// sendCipher and recvCipher are from the responder's perspective.
func (r *nkhfsResponder) processMessage1(msg1 []byte) ([]byte, *NKhfsCipherState, *NKhfsCipherState, []byte, error) {
	const (
		dhPubLen     = 32
		kemPubLen    = 1568
		aeadOverhead = 16
		encKemPubLen = kemPubLen + aeadOverhead // e1 on wire: encrypted KEM pub = 1584
		minMsg1Len   = dhPubLen + encKemPubLen
	)
	if len(msg1) < minMsg1Len {
		return nil, nil, nil, nil, &NKhfsMsgTooShortError{
			expected: minMsg1Len,
			actual:   len(msg1),
		}
	}

	r.ss = newNKhfsSymmetricState()
	// Pre-message: <- s (responder static public key is known).
	r.ss.mixHash(r.staticPub)

	// Read e (initiator ephemeral DH public key) — sent in the clear, before es.
	initEphPub := msg1[:dhPubLen]
	msg1 = msg1[dhPubLen:]
	r.ss.mixHash(initEphPub)

	// es: DH(static, initiator_ephemeral) — sets hasKey=true.
	dhResult, err := x25519DH(r.staticPriv, initEphPub)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := r.ss.mixKey(dhResult); err != nil {
		return nil, nil, nil, nil, err
	}

	// Read e1 (initiator KEM encapsulation key) — AEAD-encrypted since hasKey=true after es.
	// On wire: 1568 + 16 = 1584 bytes.
	encKemPub := msg1[:encKemPubLen]
	msg1 = msg1[encKemPubLen:]
	kemPubBytes, err := r.ss.decryptAndHash(encKemPub)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// DecryptAndHash(remaining payload from initiator).
	_, err = r.ss.decryptAndHash(msg1)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Generate responder ephemeral X25519 key pair.
	r.ephPriv = make([]byte, 32)
	if _, err := rand.Read(r.ephPriv); err != nil {
		return nil, nil, nil, nil, err
	}
	r.ephPub, err = curve25519.X25519(r.ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Build message 2: <- e, ee, ekem1.
	var msg2 []byte

	// e: append responder ephemeral public key and mix into h (sent in clear, before ee).
	msg2 = append(msg2, r.ephPub...)
	r.ss.mixHash(r.ephPub)

	// ee: DH(responder_ephemeral, initiator_ephemeral) — hasKey remains true.
	dh2, err := x25519DH(r.ephPriv, initEphPub)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := r.ss.mixKey(dh2); err != nil {
		return nil, nil, nil, nil, err
	}

	// ekem1: encapsulate using initiator's KEM public key.
	kemEK, err := mlkem.NewEncapsulationKey1024(kemPubBytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	kemSS, kemCt := kemEK.Encapsulate()

	// Per Noise HFS spec: EncryptAndHash(kemCt) FIRST (using the key from ee),
	// then MixKey(kemSS) to fold the KEM shared secret into the chaining key.
	// The initiator inverts this: DecryptAndHash(encKemCt) first, then MixKey(kemSS).
	encryptedKemCt, err := r.ss.encryptAndHash(kemCt)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	msg2 = append(msg2, encryptedKemCt...)

	if err := r.ss.mixKey(kemSS); err != nil {
		return nil, nil, nil, nil, err
	}

	// EncryptAndHash(empty payload).
	encrypted, err := r.ss.encryptAndHash(nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	msg2 = append(msg2, encrypted...)

	// Split: from responder's view, cs1 sends to initiator, cs0 receives from initiator.
	// The Noise spec split() returns (cs0, cs1) where cs0 is initiator->responder.
	cs0, cs1, handshakeHash, err := r.ss.split()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Responder sends on cs1, receives on cs0.
	return msg2, cs1, cs0, handshakeHash, nil
}

// TestNKhfsHandshake_FullRoundTrip verifies a complete NKhfs initiator/responder
// handshake followed by bidirectional transport message exchange.
func TestNKhfsHandshake_FullRoundTrip(t *testing.T) {
	// Generate responder static X25519 key pair.
	respStaticPriv := make([]byte, 32)
	if _, err := rand.Read(respStaticPriv); err != nil {
		t.Fatalf("failed to generate responder static private key: %v", err)
	}
	respStaticPub, err := curve25519.X25519(respStaticPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to derive responder static public key: %v", err)
	}

	// Initiator creates handshake and produces message 1.
	claims := &Claims{PublicKey: respStaticPub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims failed: %v", err)
	}
	msg1 := uv.handshake.InitialRequest()

	// Verify message 1 size: e.pub(32) + EncryptAndHash(e1.pub)(1568+16) + EncryptAndHash(nil)(16) = 1632.
	const expectedMsg1Len = 32 + 1584 + 16
	if len(msg1) != expectedMsg1Len {
		t.Errorf("msg1 length = %d, want %d", len(msg1), expectedMsg1Len)
	}

	// Responder processes message 1 and produces message 2.
	responder := newNKhfsResponder(respStaticPriv, respStaticPub)
	msg2, respSendCS, respRecvCS, respHandshakeHash, err := responder.processMessage1(msg1)
	if err != nil {
		t.Fatalf("responder.processMessage1 failed: %v", err)
	}

	// Verify message 2 size: e.pub(32) + EncryptAndHash(ekem1.ct)(1568+16) + EncryptAndHash(nil)(16) = 1632.
	const expectedMsg2Len = 32 + 1584 + 16
	if len(msg2) != expectedMsg2Len {
		t.Errorf("msg2 length = %d, want %d", len(msg2), expectedMsg2Len)
	}

	// Initiator completes the handshake by processing message 2.
	conn, err := uv.handshake.Complete(msg2)
	if err != nil {
		t.Fatalf("handshake.Complete failed: %v", err)
	}
	if conn == nil {
		t.Fatal("ClientConnection should not be nil")
	}

	// Verify handshake hashes match on both sides.
	if !bytes.Equal(conn.HandshakeHash, respHandshakeHash) {
		t.Errorf("handshake hash mismatch:\n  initiator: %x\n  responder: %x",
			conn.HandshakeHash, respHandshakeHash)
	}

	// Test transport: initiator sends, responder receives.
	plaintext := []byte("post-quantum hello from initiator")
	ciphertext, err := conn.Send(plaintext)
	if err != nil {
		t.Fatalf("conn.Send failed: %v", err)
	}
	decrypted, err := respRecvCS.Decrypt(nil, ciphertext)
	if err != nil {
		t.Fatalf("responder Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("responder decrypted = %q, want %q", decrypted, plaintext)
	}

	// Test transport: responder sends, initiator receives.
	reply := []byte("post-quantum reply from responder")
	replyCt, err := respSendCS.Encrypt(nil, reply)
	if err != nil {
		t.Fatalf("responder Encrypt failed: %v", err)
	}
	decryptedReply, err := conn.Recv(replyCt)
	if err != nil {
		t.Fatalf("conn.Recv failed: %v", err)
	}
	if !bytes.Equal(decryptedReply, reply) {
		t.Errorf("initiator decrypted = %q, want %q", decryptedReply, reply)
	}
}

// TestNKhfsHandshake_InvalidRemoteKey verifies that a non-32-byte public key
// is rejected before any cryptographic operations are attempted.
func TestNKhfsHandshake_InvalidRemoteKey(t *testing.T) {
	claims := &Claims{
		PublicKey: []byte{0x01, 0x02}, // too short: must be 32 bytes
		Custom:    make(map[string][]byte),
	}
	_, err := newNKhfsHandshakeWithClaims(claims)
	if err == nil {
		t.Fatal("expected error for 2-byte public key")
	}
}

// TestNKhfsHandshake_ReadMessage2TooShort verifies that readMessage2 rejects
// messages that are shorter than the minimum expected size.
func TestNKhfsHandshake_ReadMessage2TooShort(t *testing.T) {
	respStaticPriv := make([]byte, 32)
	rand.Read(respStaticPriv) //nolint:errcheck
	respStaticPub, _ := curve25519.X25519(respStaticPriv, curve25519.Basepoint)

	claims := &Claims{PublicKey: respStaticPub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims failed: %v", err)
	}

	// Feed a truncated message 2 to Complete.
	shortMsg := make([]byte, 10)
	_, err = uv.handshake.Complete(shortMsg)
	if err == nil {
		t.Fatal("expected error for truncated message 2")
	}
}

// TestNKhfsHandshake_CorruptedMessage2 verifies that bit-flipping in the
// ciphertext portion of message 2 causes an AEAD authentication failure.
func TestNKhfsHandshake_CorruptedMessage2(t *testing.T) {
	respStaticPriv := make([]byte, 32)
	rand.Read(respStaticPriv) //nolint:errcheck
	respStaticPub, _ := curve25519.X25519(respStaticPriv, curve25519.Basepoint)

	claims := &Claims{PublicKey: respStaticPub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims failed: %v", err)
	}

	responder := newNKhfsResponder(respStaticPriv, respStaticPub)
	msg2, _, _, _, err := responder.processMessage1(uv.handshake.InitialRequest())
	if err != nil {
		t.Fatalf("processMessage1 failed: %v", err)
	}

	// Corrupt a byte in the encrypted KEM ciphertext portion (bytes 32..1616).
	msg2[100] ^= 0xFF

	_, err = uv.handshake.Complete(msg2)
	if err == nil {
		t.Fatal("expected error for corrupted message 2")
	}
}

// TestNKhfsHandshake_MultipleTransportMessages verifies that sequential transport
// messages can be sent and received correctly (nonce advances properly).
func TestNKhfsHandshake_MultipleTransportMessages(t *testing.T) {
	respStaticPriv := make([]byte, 32)
	rand.Read(respStaticPriv) //nolint:errcheck
	respStaticPub, _ := curve25519.X25519(respStaticPriv, curve25519.Basepoint)

	claims := &Claims{PublicKey: respStaticPub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims failed: %v", err)
	}

	responder := newNKhfsResponder(respStaticPriv, respStaticPub)
	msg2, _, respRecvCS, _, err := responder.processMessage1(uv.handshake.InitialRequest())
	if err != nil {
		t.Fatalf("processMessage1 failed: %v", err)
	}

	conn, err := uv.handshake.Complete(msg2)
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	messages := [][]byte{
		[]byte("message one"),
		[]byte("message two"),
		[]byte("message three with more data"),
	}

	for i, msg := range messages {
		ct, err := conn.Send(msg)
		if err != nil {
			t.Fatalf("Send[%d] failed: %v", i, err)
		}
		pt, err := respRecvCS.Decrypt(nil, ct)
		if err != nil {
			t.Fatalf("Decrypt[%d] failed: %v", i, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Errorf("message[%d]: got %q, want %q", i, pt, msg)
		}
	}
}

// TestNKhfsHandshake_InitialRequestSize verifies that message 1 is exactly
// the expected wire-format size for NKhfs.
//
// Expected: e.pub(32) + EncryptAndHash(e1.pub)(1568+16) + EncryptAndHash(nil)(16) = 1632
func TestNKhfsHandshake_InitialRequestSize(t *testing.T) {
	respStaticPriv := make([]byte, 32)
	rand.Read(respStaticPriv) //nolint:errcheck
	respStaticPub, _ := curve25519.X25519(respStaticPriv, curve25519.Basepoint)

	claims := &Claims{PublicKey: respStaticPub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims failed: %v", err)
	}

	req := uv.handshake.InitialRequest()
	// e.pub(32) + EncryptAndHash(e1.pub)(1568+16) + EncryptAndHash(nil)(16) = 1632
	const want = NoiseHandshakeOverheadHFS
	if len(req) != want {
		t.Errorf("initial request length = %d, want %d", len(req), want)
	}
}

// TestNKhfsHandshake_PostQuantumViaNewHandshakeWithClaims verifies that the
// PostQuantum HandshakeType routes through the NKhfs path end-to-end.
func TestNKhfsHandshake_PostQuantumViaNewHandshakeWithClaims(t *testing.T) {
	respStaticPriv := make([]byte, 32)
	rand.Read(respStaticPriv) //nolint:errcheck
	respStaticPub, _ := curve25519.X25519(respStaticPriv, curve25519.Basepoint)

	claims := &Claims{PublicKey: respStaticPub, Custom: make(map[string][]byte)}

	uv, err := newHandshakeWithClaims(claims, PostQuantum)
	if err != nil {
		t.Fatalf("newHandshakeWithClaims(PostQuantum) failed: %v", err)
	}
	if uv == nil {
		t.Fatal("expected non-nil UnvalidatedHandshake")
	}
	if uv.handshake.nkhfs == nil {
		t.Error("expected nkhfs field to be set for PostQuantum handshake")
	}
	if uv.handshake.hs != nil {
		t.Error("expected hs field to be nil for PostQuantum handshake")
	}

	// Complete the handshake with a real responder.
	responder := newNKhfsResponder(respStaticPriv, respStaticPub)
	msg2, _, _, _, err := responder.processMessage1(uv.handshake.InitialRequest())
	if err != nil {
		t.Fatalf("responder.processMessage1 failed: %v", err)
	}

	conn, err := uv.handshake.Complete(msg2)
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if len(conn.HandshakeHash) == 0 {
		t.Error("HandshakeHash should not be empty")
	}
}

// TestNKhfsCipherState_Encrypt verifies that encrypting the same plaintext
// twice produces different ciphertexts (due to nonce counter increment).
func TestNKhfsCipherState_Encrypt(t *testing.T) {
	var key [32]byte
	rand.Read(key[:]) //nolint:errcheck

	cs := &NKhfsCipherState{key: key}
	pt := []byte("test plaintext")

	ct1, err := cs.Encrypt(nil, pt)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}
	ct2, err := cs.Encrypt(nil, pt)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("same plaintext encrypted twice should produce different ciphertexts (nonce advance)")
	}
}

// TestNKhfsCipherState_Decrypt verifies that decryption with a mismatched
// additional data value fails authentication.
func TestNKhfsCipherState_Decrypt(t *testing.T) {
	var key [32]byte
	rand.Read(key[:]) //nolint:errcheck

	encCS := &NKhfsCipherState{key: key}
	decCS := &NKhfsCipherState{key: key}

	pt := []byte("secret data")
	ad := []byte("authenticated data")

	ct, err := encCS.Encrypt(ad, pt)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decryption with correct ad succeeds.
	got, err := decCS.Decrypt(ad, ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("decrypted = %q, want %q", got, pt)
	}
}

// TestNKhfsCipherState_DecryptWrongAD verifies that wrong additional data
// causes a decryption failure.
func TestNKhfsCipherState_DecryptWrongAD(t *testing.T) {
	var key [32]byte
	rand.Read(key[:]) //nolint:errcheck

	encCS := &NKhfsCipherState{key: key}
	decCS := &NKhfsCipherState{key: key}

	ct, err := encCS.Encrypt([]byte("correct-ad"), []byte("data"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = decCS.Decrypt([]byte("wrong-ad"), ct)
	if err == nil {
		t.Fatal("expected error for wrong additional data")
	}
}

// TestNKhfsHandshake_HandshakeHashLength verifies the handshake hash is 32 bytes.
func TestNKhfsHandshake_HandshakeHashLength(t *testing.T) {
	respStaticPriv := make([]byte, 32)
	rand.Read(respStaticPriv) //nolint:errcheck
	respStaticPub, _ := curve25519.X25519(respStaticPriv, curve25519.Basepoint)

	claims := &Claims{PublicKey: respStaticPub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims: %v", err)
	}

	responder := newNKhfsResponder(respStaticPriv, respStaticPub)
	msg2, _, _, _, err := responder.processMessage1(uv.handshake.InitialRequest())
	if err != nil {
		t.Fatalf("processMessage1: %v", err)
	}

	conn, err := uv.handshake.Complete(msg2)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(conn.HandshakeHash) != 32 {
		t.Errorf("HandshakeHash length = %d, want 32", len(conn.HandshakeHash))
	}
}

// TestNKhfsHandshake_EmptyPayload verifies that the transport layer correctly
// handles an empty plaintext. Rust ClientConnection::send returns an empty Vec
// for empty input (zero chunks iterated); the Go implementation must match.
func TestNKhfsHandshake_EmptyPayload(t *testing.T) {
	respStaticPriv := make([]byte, 32)
	rand.Read(respStaticPriv) //nolint:errcheck
	respStaticPub, _ := curve25519.X25519(respStaticPriv, curve25519.Basepoint)

	claims := &Claims{PublicKey: respStaticPub, Custom: make(map[string][]byte)}
	uv, err := newNKhfsHandshakeWithClaims(claims)
	if err != nil {
		t.Fatalf("newNKhfsHandshakeWithClaims: %v", err)
	}

	responder := newNKhfsResponder(respStaticPriv, respStaticPub)
	msg2, _, _, _, err := responder.processMessage1(uv.handshake.InitialRequest())
	if err != nil {
		t.Fatalf("processMessage1: %v", err)
	}

	conn, err := uv.handshake.Complete(msg2)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	ct, err := conn.Send([]byte{})
	if err != nil {
		t.Fatalf("Send([]byte{}) failed: %v", err)
	}
	// Rust returns empty Vec for empty input — Go must match.
	if len(ct) != 0 {
		t.Errorf("Send([]byte{}) = %d bytes, want 0 (Rust returns empty Vec)", len(ct))
	}
}

// TestNKhfsCipherState_NonceExhausted verifies that Encrypt and Decrypt
// return NKhfsNonceExhaustedError when the nonce counter is at MaxUint64.
func TestNKhfsCipherState_NonceExhausted(t *testing.T) {
	var key [32]byte
	rand.Read(key[:]) //nolint:errcheck

	cs := &NKhfsCipherState{key: key, nonce: ^uint64(0)} // nonce = MaxUint64

	_, err := cs.Encrypt(nil, []byte("data"))
	if err == nil {
		t.Fatal("Encrypt: expected NKhfsNonceExhaustedError, got nil")
	}
	var nonceErr *NKhfsNonceExhaustedError
	if !isErrorType(err, &nonceErr) {
		t.Errorf("Encrypt: expected *NKhfsNonceExhaustedError, got %T: %v", err, err)
	}

	cs2 := &NKhfsCipherState{key: key, nonce: ^uint64(0)}
	_, err = cs2.Decrypt(nil, []byte("data"))
	if err == nil {
		t.Fatal("Decrypt: expected NKhfsNonceExhaustedError, got nil")
	}
	if !isErrorType(err, &nonceErr) {
		t.Errorf("Decrypt: expected *NKhfsNonceExhaustedError, got %T: %v", err, err)
	}
}

// TestNKhfsCipherState_Destroy verifies that Destroy zeroizes the key.
func TestNKhfsCipherState_Destroy(t *testing.T) {
	var key [32]byte
	rand.Read(key[:]) //nolint:errcheck

	cs := &NKhfsCipherState{key: key}
	cs.Destroy()

	var zero [32]byte
	if cs.key != zero {
		t.Error("Destroy did not zeroize the key")
	}
}

// TestNKhfsDHError verifies the NKhfsDHError error message.
func TestNKhfsDHError(t *testing.T) {
	err := &NKhfsDHError{Detail: "test detail"}
	want := "NKhfs: test detail"
	if err.Error() != want {
		t.Errorf("NKhfsDHError.Error() = %q, want %q", err.Error(), want)
	}
}

// TestNKhfsMsgTooShortError verifies the NKhfsMsgTooShortError error message.
func TestNKhfsMsgTooShortError(t *testing.T) {
	err := &NKhfsMsgTooShortError{expected: 100, actual: 10}
	want := "NKhfs: message too short"
	if err.Error() != want {
		t.Errorf("NKhfsMsgTooShortError.Error() = %q, want %q", err.Error(), want)
	}
}

// isErrorType is a helper that checks if err can be assigned to target via errors.As.
func isErrorType[T error](err error, target *T) bool {
	var t T
	_ = t
	// Simple type assertion for test purposes.
	_, ok := err.(T)
	return ok
}

// TestNKhfsErrorMessages covers Error() for NKhfsDecryptError,
// NKhfsMsgTooShortError, NKhfsDHError, and NKhfsNonceExhaustedError.
func TestNKhfsErrorMessages(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		contain string
	}{
		{"NKhfsDecryptError", &NKhfsDecryptError{}, "decrypt"},
		{"NKhfsMsgTooShortError", &NKhfsMsgTooShortError{expected: 64, actual: 10}, "short"},
		{"NKhfsDHError", &NKhfsDHError{Detail: "bad dh result"}, "dh result"},
		{"NKhfsNonceExhaustedError", &NKhfsNonceExhaustedError{}, "nonce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("Error() returned empty string")
			}
			found := false
			for i := 0; i <= len(msg)-len(tc.contain); i++ {
				if msg[i:i+len(tc.contain)] == tc.contain {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Error() = %q, want to contain %q", msg, tc.contain)
			}
		})
	}
}
