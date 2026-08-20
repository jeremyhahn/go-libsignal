//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// These 10 tests were split out of dcap_coverage_test.go. They drive the
// Noise_NK_25519_ChaChaPoly_SHA256 and Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256
// handshakes Signal uses to reach its enclaves, both X25519 by construction,
// and crypto/ecdh rejects X25519 under GODEBUG=fips140=only. Keeping them
// here lets the fips140only build tag drop just these while the other 63
// tests in dcap_coverage_test.go -- DCAP quote parsing, X.509 and P-256 --
// stay inside the FIPS gate.

package attest

import (
	"testing"

	"github.com/flynn/noise"
)

func TestClientConnection_Send_ExactlyOneChunk(t *testing.T) {
	conn, respRecvCS, _ := setupClientConnection(t)

	plaintext := make([]byte, NoiseTransportPerPayloadMax)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := conn.Send(plaintext)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if len(ciphertext) != NoiseTransportPerPayloadMax+noiseTransportPerPayloadOverhead {
		t.Errorf("expected exactly one packet (%d bytes), got %d bytes",
			NoiseTransportPerPayloadMax+noiseTransportPerPayloadOverhead, len(ciphertext))
	}

	decrypted, err := respRecvCS.Decrypt(nil, nil, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if len(decrypted) != len(plaintext) {
		t.Errorf("decrypted length = %d, want %d", len(decrypted), len(plaintext))
	}
}

func TestClientConnection_SendRecv_MultipleMessages(t *testing.T) {
	conn, respRecvCS, respSendCS := setupClientConnection(t)

	// Test multiple send/receive cycles
	for i := 0; i < 5; i++ {
		msg := []byte("message " + string(rune('A'+i)))
		ct, err := conn.Send(msg)
		if err != nil {
			t.Fatalf("Send %d failed: %v", i, err)
		}

		dec, err := respRecvCS.Decrypt(nil, nil, ct)
		if err != nil {
			t.Fatalf("Decrypt %d failed: %v", i, err)
		}
		if string(dec) != string(msg) {
			t.Errorf("round-trip %d: got %q, want %q", i, dec, msg)
		}

		// Responder reply
		reply := []byte("reply " + string(rune('A'+i)))
		replyCT, err := respSendCS.Encrypt(nil, nil, reply)
		if err != nil {
			t.Fatalf("Encrypt %d failed: %v", i, err)
		}
		decReply, err := conn.Recv(replyCT)
		if err != nil {
			t.Fatalf("Recv %d failed: %v", i, err)
		}
		if string(decReply) != string(reply) {
			t.Errorf("reply round-trip %d: got %q, want %q", i, decReply, reply)
		}
	}
}

func TestUnvalidatedHandshake_Validate_MismatchConfig(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	claims := &Claims{
		PublicKey: kp.Public,
		Custom:    make(map[string][]byte),
		RaftGroupConfig: &RaftConfig{
			MinVotingReplicas: 3,
			MaxVotingReplicas: 5,
			GroupID:           42,
		},
	}
	uv, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Validate against a different config
	differentConfig := &RaftConfig{
		MinVotingReplicas: 4,
		MaxVotingReplicas: 7,
		GroupID:           99,
	}
	_, err = uv.Validate(differentConfig)
	if err == nil {
		t.Fatal("expected error for mismatching raft config")
	}
}

func TestUnvalidatedHandshake_Validate_NilRaftConfigInClaims(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	claims := &Claims{
		PublicKey:       kp.Public,
		Custom:          make(map[string][]byte),
		RaftGroupConfig: nil,
	}
	uv, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := &RaftConfig{MinVotingReplicas: 3}
	_, err = uv.Validate(config)
	if err == nil {
		t.Fatal("expected error for nil raft config in claims")
	}
}

func TestUnvalidatedHandshake_Validate_Success(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	config := &RaftConfig{
		MinVotingReplicas:  3,
		MaxVotingReplicas:  5,
		SuperMajority:      0,
		GroupID:            42,
		DBVersion:          1,
		AttestationTimeout: 30,
		Simulated:          false,
	}

	claims := &Claims{
		PublicKey:       kp.Public,
		Custom:          make(map[string][]byte),
		RaftGroupConfig: config,
	}
	uv, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hs, err := uv.Validate(config)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if hs == nil {
		t.Fatal("handshake should not be nil")
	}
}

func TestUnvalidatedHandshake_SkipRaftValidation_WithClaims(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)

	claims := &Claims{
		PublicKey:       kp.Public,
		Custom:          map[string][]byte{"key": []byte("value")},
		RaftGroupConfig: &RaftConfig{GroupID: 42},
	}
	uv, err := newHandshakeWithClaims(claims, PreQuantum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hs := uv.SkipRaftValidation()
	if hs == nil {
		t.Fatal("handshake should not be nil")
	}
	if hs.claims.RaftGroupConfig.GroupID != 42 {
		t.Error("claims should be preserved after skip validation")
	}
}

func TestHSMClientConnection_SendRecv_AfterComplete(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, _ := cs.GenerateKeypair(nil)

	var pubKey [PubKeySize]byte
	copy(pubKey[:], responderKP.Public)

	codeHash := [CodeHashSize]byte{0xAA}
	est, err := NewHSMClientConnectionEstablishment(pubKey, [][CodeHashSize]byte{codeHash})
	if err != nil {
		t.Fatalf("NewHSMClientConnectionEstablishment: %v", err)
	}

	respHS, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})

	_, _, _, _ = respHS.ReadMessage(nil, est.InitialRequest())
	respMsg, respCS0, respCS1, _ := respHS.WriteMessage(nil, codeHash[:])

	conn, err := est.Complete(respMsg)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Send message
	ct, err := conn.Send([]byte("hello HSM"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	// respCS0 decrypts initiator->responder messages
	dec, err := respCS0.Decrypt(nil, nil, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(dec) != "hello HSM" {
		t.Errorf("got %q, want %q", dec, "hello HSM")
	}

	// Recv reply from responder
	replyCT, err := respCS1.Encrypt(nil, nil, []byte("hello back"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	reply, err := conn.Recv(replyCT)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(reply) != "hello back" {
		t.Errorf("got %q, want %q", reply, "hello back")
	}
}

func TestNewHandshakeWithClaims_PostQuantum(t *testing.T) {
	cs := noiseCipherSuite()
	kp, _ := cs.GenerateKeypair(nil)
	claims := &Claims{PublicKey: kp.Public, Custom: make(map[string][]byte)}
	uv, err := newHandshakeWithClaims(claims, PostQuantum)
	if err != nil {
		t.Fatalf("PostQuantum handshake should succeed with valid key: %v", err)
	}
	if uv == nil {
		t.Fatal("expected non-nil UnvalidatedHandshake for PostQuantum")
	}
	// NKhfs msg1: e.pub(32) + EncryptAndHash(e1.pub)(1568+16) + EncryptAndHash(nil)(16) = 1632
	req := uv.handshake.InitialRequest()
	if len(req) != NoiseHandshakeOverheadHFS {
		t.Errorf("NKhfs initial request: got %d bytes, want %d", len(req), NoiseHandshakeOverheadHFS)
	}
}

func TestHandshake_Complete_FullRoundTrip(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, _ := cs.GenerateKeypair(nil)

	claims := &Claims{PublicKey: responderKP.Public, Custom: make(map[string][]byte)}
	uv, _ := newHandshakeWithClaims(claims, PreQuantum)

	respHS, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: responderKP,
	})

	_, _, _, _ = respHS.ReadMessage(nil, uv.handshake.InitialRequest())
	respMsg, _, _, _ := respHS.WriteMessage(nil, nil)

	conn, err := uv.handshake.Complete(respMsg)
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	ct, err := conn.Send([]byte("test"))
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if len(ct) == 0 {
		t.Error("ciphertext should not be empty")
	}
}

func TestHandshake_Complete_BadData(t *testing.T) {
	cs := noiseCipherSuite()
	responderKP, _ := cs.GenerateKeypair(nil)

	claims := &Claims{PublicKey: responderKP.Public, Custom: make(map[string][]byte)}
	uv, _ := newHandshakeWithClaims(claims, PreQuantum)

	// Pass garbage data to Complete
	_, err := uv.handshake.Complete([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for bad handshake data")
	}
}
