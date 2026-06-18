// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/mlkem"
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// NewNKhfsInitiator constructs a client-side NKhfs handshake against
// the supplied server static X25519 public key. Returns an
// UnvalidatedHandshake that exposes the first message via
// InitialRequest() and completes via Complete(message2).
//
// Unlike SVR2NewHandshake (which validates SGX attestation evidence
// before producing a Handshake), NewNKhfsInitiator is the unattested
// entry point: callers have already validated the server's public key
// out-of-band (software-attestation deployments, TPM-quote
// deployments, or fully-end-to-end tests). It complements the
// server-side NKhfsResponder.
func NewNKhfsInitiator(serverStaticPub []byte) (*UnvalidatedHandshake, error) {
	claims := &Claims{PublicKey: serverStaticPub, Custom: make(map[string][]byte)}
	return newNKhfsHandshakeWithClaims(claims)
}

// NKhfsResponder implements the server side of the Noise NKhfs
// (NK + Hash-Forward-Secrecy via ML-KEM-1024) handshake. The
// initiator-side counterpart is NKhfsHandshake; together they form a
// complete two-message handshake matching Signal's SVR/CDSI/SGX enclave
// transport.
//
// The server (responder) is the long-lived service. Its static X25519
// key pair is generated once at startup and surfaced in attestation
// claims so clients can mix the static key into their handshake hash.
// Each inbound client opens a fresh NKhfsResponder, calls
// ProcessMessage1 with the inbound message-1 bytes, and receives the
// outbound message-2 bytes plus the two transport cipher states.
//
// The two cipher states returned by ProcessMessage1 are FROM THE
// SERVER'S PERSPECTIVE:
//
//   - sendCipher: the server encrypts outbound frames with this.
//   - recvCipher: the server decrypts inbound frames with this.
//
// After ProcessMessage1 succeeds, the NKhfsResponder is single-use;
// callers should discard it (other than the cipher states it returned).
type NKhfsResponder struct {
	staticPriv []byte
	staticPub  []byte
}

// NewNKhfsResponder constructs a responder. staticPriv must be a 32-byte
// X25519 private scalar; staticPub must be the corresponding 32-byte
// X25519 public key. Callers typically generate this key pair once and
// expose staticPub through attestation evidence.
func NewNKhfsResponder(staticPriv, staticPub []byte) (*NKhfsResponder, error) {
	if len(staticPriv) != 32 {
		return nil, newAttestationDataError("NKhfsResponder: static private key must be 32 bytes")
	}
	if len(staticPub) != 32 {
		return nil, newAttestationDataError("NKhfsResponder: static public key must be 32 bytes")
	}
	return &NKhfsResponder{
		staticPriv: append([]byte(nil), staticPriv...),
		staticPub:  append([]byte(nil), staticPub...),
	}, nil
}

// ProcessMessage1 consumes the initiator's first handshake message
// (-> e, es, e1) and produces the responder's reply (<- e, ee, ekem1).
//
// Wire format consumed:
//
//	e.pub(32) + EncryptedKemPub(1568+16) + EncryptedPayload(plen+16)
//
// Wire format produced:
//
//	e.pub(32) + EncryptedKemCt(1568+16) + EncryptedPayload(16)
//
// Returns (msg2, sendCipher, recvCipher, handshakeHash, error). The
// handshake hash uniquely identifies the session and can be used as
// channel-binding material in higher-level protocols.
func (r *NKhfsResponder) ProcessMessage1(msg1 []byte) ([]byte, *NKhfsCipherState, *NKhfsCipherState, []byte, error) {
	const (
		dhPubLen     = 32
		kemPubLen    = 1568
		aeadOverhead = 16
		encKemPubLen = kemPubLen + aeadOverhead
		minMsg1Len   = dhPubLen + encKemPubLen
	)
	if len(msg1) < minMsg1Len {
		return nil, nil, nil, nil, &NKhfsMsgTooShortError{
			expected: minMsg1Len,
			actual:   len(msg1),
		}
	}

	ss := newNKhfsSymmetricState()
	// Pre-message: <- s (responder's static public key is known to both).
	ss.mixHash(r.staticPub)

	// Read e (initiator ephemeral DH public key) — clear, before es.
	initEphPub := msg1[:dhPubLen]
	msg1 = msg1[dhPubLen:]
	ss.mixHash(initEphPub)

	// es: DH(static, initiator_ephemeral) — sets hasKey=true.
	dhResult, err := x25519DH(r.staticPriv, initEphPub)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := ss.mixKey(dhResult); err != nil {
		return nil, nil, nil, nil, err
	}

	// Read e1 (initiator KEM encapsulation key) — AEAD encrypted since hasKey=true.
	encKemPub := msg1[:encKemPubLen]
	msg1 = msg1[encKemPubLen:]
	kemPubBytes, err := ss.decryptAndHash(encKemPub)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// DecryptAndHash any remaining payload.
	if _, err := ss.decryptAndHash(msg1); err != nil {
		return nil, nil, nil, nil, err
	}

	// Generate responder ephemeral X25519 key pair.
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		return nil, nil, nil, nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Build message 2: <- e, ee, ekem1.
	var msg2 []byte
	msg2 = append(msg2, ephPub...)
	ss.mixHash(ephPub)

	// ee: DH(responder_ephemeral, initiator_ephemeral).
	dh2, err := x25519DH(ephPriv, initEphPub)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := ss.mixKey(dh2); err != nil {
		return nil, nil, nil, nil, err
	}

	// ekem1: encapsulate using initiator's KEM public key.
	kemEK, err := mlkem.NewEncapsulationKey1024(kemPubBytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	kemSS, kemCt := kemEK.Encapsulate()

	// Per HFS spec: EncryptAndHash(kemCt) FIRST (with key from ee), then
	// MixKey(kemSS). Initiator does the inverse.
	encryptedKemCt, err := ss.encryptAndHash(kemCt)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	msg2 = append(msg2, encryptedKemCt...)

	if err := ss.mixKey(kemSS); err != nil {
		return nil, nil, nil, nil, err
	}

	// EncryptAndHash(empty payload).
	encryptedPayload, err := ss.encryptAndHash(nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	msg2 = append(msg2, encryptedPayload...)

	// Split yields (cs0, cs1) where cs0 is initiator->responder.
	// The responder reads with cs0 and writes with cs1.
	cs0, cs1, handshakeHash, err := ss.split()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return msg2, cs1, cs0, handshakeHash, nil
}
