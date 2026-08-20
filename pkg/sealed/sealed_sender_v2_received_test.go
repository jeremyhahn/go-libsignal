//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 8 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) requires it for the Sealed Sender
// ephemeral keys, so the fips140only build tag drops this file from the FIPS
// gate. `make test` and `make coverage` still run it.

package sealed

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// TestV2ParseReceivedMessageValid verifies that a well-formed v2 received
// message is parsed correctly, extracting the C, AT, E.pub, and ciphertext
// fields at their correct offsets.
func TestV2ParseReceivedMessageValid(t *testing.T) {
	tests := []struct {
		name    string
		version byte
	}{
		{"version 0x22 (UUID)", SealedSenderV2VersionUUID},
		{"version 0x23 (ServiceId)", SealedSenderV2VersionServiceId},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a synthetic received message.
			encM := make([]byte, v2EncryptedMKeySize)
			for i := range encM {
				encM[i] = byte(i)
			}
			authTag := make([]byte, v2AuthTagSize)
			for i := range authTag {
				authTag[i] = byte(0xA0 + i)
			}
			ephPub := make([]byte, 32)
			for i := range ephPub {
				ephPub[i] = byte(0xB0 + i)
			}
			payload := []byte("test encrypted payload data")

			msg := V2BuildReceivedMessage(tt.version, encM, authTag, ephPub, payload)

			parsed, err := v2ParseReceivedMessage(msg)
			if err != nil {
				t.Fatalf("v2ParseReceivedMessage error: %v", err)
			}

			// V2BuildReceivedMessage always uses SealedSenderV2VersionUUID (0x22)
			// regardless of the input version, matching the Rust reference behavior
			// where the ReceivedMessage format hasn't changed since version 0x22.
			if parsed.Version != SealedSenderV2VersionUUID {
				t.Errorf("Version = 0x%02x, want 0x%02x (always UUID version per Rust reference)", parsed.Version, SealedSenderV2VersionUUID)
			}
			if len(parsed.EncryptedMKey) != v2EncryptedMKeySize {
				t.Errorf("EncryptedMKey length = %d, want %d", len(parsed.EncryptedMKey), v2EncryptedMKeySize)
			}
			for i, b := range parsed.EncryptedMKey {
				if b != byte(i) {
					t.Errorf("EncryptedMKey[%d] = 0x%02x, want 0x%02x", i, b, byte(i))
					break
				}
			}
			if len(parsed.AuthTag) != v2AuthTagSize {
				t.Errorf("AuthTag length = %d, want %d", len(parsed.AuthTag), v2AuthTagSize)
			}
			for i, b := range parsed.AuthTag {
				if b != byte(0xA0+i) {
					t.Errorf("AuthTag[%d] = 0x%02x, want 0x%02x", i, b, byte(0xA0+i))
					break
				}
			}
			if len(parsed.EphemeralPublic) != 32 {
				t.Errorf("EphemeralPublic length = %d, want 32", len(parsed.EphemeralPublic))
			}
			for i, b := range parsed.EphemeralPublic {
				if b != byte(0xB0+i) {
					t.Errorf("EphemeralPublic[%d] = 0x%02x, want 0x%02x", i, b, byte(0xB0+i))
					break
				}
			}
			if string(parsed.EncryptedPayload) != "test encrypted payload data" {
				t.Errorf("EncryptedPayload = %q, want %q", string(parsed.EncryptedPayload), "test encrypted payload data")
			}
		})
	}
}

// TestV2ParseReceivedMessageTruncated verifies that truncated messages at
// various cutoff points are rejected with the correct error.
func TestV2ParseReceivedMessageTruncated(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"version only", []byte{SealedSenderV2VersionUUID}},
		{"partial C", func() []byte {
			buf := []byte{SealedSenderV2VersionUUID}
			buf = append(buf, make([]byte, 10)...) // only 10 of 32 bytes for C
			return buf
		}()},
		{"C complete, no AT", func() []byte {
			buf := []byte{SealedSenderV2VersionUUID}
			buf = append(buf, make([]byte, v2EncryptedMKeySize)...)
			return buf
		}()},
		{"C+AT complete, no E.pub", func() []byte {
			buf := []byte{SealedSenderV2VersionUUID}
			buf = append(buf, make([]byte, v2EncryptedMKeySize+v2AuthTagSize)...)
			return buf
		}()},
		{"C+AT+E.pub complete, no payload", func() []byte {
			buf := []byte{SealedSenderV2VersionUUID}
			buf = append(buf, make([]byte, v2EncryptedMKeySize+v2AuthTagSize+32)...)
			return buf
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v2ParseReceivedMessage(tt.data)
			if err == nil {
				t.Error("v2ParseReceivedMessage should return error for truncated data")
			}
			if !errors.Is(err, ErrV2ReceivedMessageTooShort) {
				t.Errorf("error = %v, want ErrV2ReceivedMessageTooShort", err)
			}
		})
	}
}

// TestV2ParseReceivedMessageUnsupportedVersion verifies that messages with
// version bytes whose major version is not 2 are rejected.
func TestV2ParseReceivedMessageUnsupportedVersion(t *testing.T) {
	tests := []struct {
		name    string
		version byte
	}{
		{"v1 version 0x11", 0x11},
		{"v0 version 0x00", 0x00},
		{"v3 version 0x33", 0x33},
		{"random version 0xFF", 0xFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a message with the wrong version but correct size.
			buf := []byte{tt.version}
			buf = append(buf, make([]byte, v2EncryptedMKeySize+v2AuthTagSize+32+10)...)

			_, err := v2ParseReceivedMessage(buf)
			if err == nil {
				t.Error("v2ParseReceivedMessage should return error for unsupported version")
			}
			if !errors.Is(err, ErrV2ReceivedUnsupportedVersion) {
				t.Errorf("error = %v, want ErrV2ReceivedUnsupportedVersion", err)
			}
		})
	}
}

// TestV2BuildReceivedMessage verifies the wire format construction.
func TestV2BuildReceivedMessage(t *testing.T) {
	encM := make([]byte, v2EncryptedMKeySize)
	encM[0] = 0xAA
	authTag := make([]byte, v2AuthTagSize)
	authTag[0] = 0xBB
	ephPub := make([]byte, 32)
	ephPub[0] = 0xCC
	payload := []byte("payload")

	msg := V2BuildReceivedMessage(SealedSenderV2VersionUUID, encM, authTag, ephPub, payload)

	expectedLen := 1 + v2EncryptedMKeySize + v2AuthTagSize + 32 + len(payload)
	if len(msg) != expectedLen {
		t.Fatalf("message length = %d, want %d", len(msg), expectedLen)
	}

	if msg[0] != SealedSenderV2VersionUUID {
		t.Errorf("version = 0x%02x, want 0x%02x", msg[0], SealedSenderV2VersionUUID)
	}
	if msg[1] != 0xAA {
		t.Errorf("C[0] = 0x%02x, want 0xAA", msg[1])
	}
	if msg[1+v2EncryptedMKeySize] != 0xBB {
		t.Errorf("AT[0] = 0x%02x, want 0xBB", msg[1+v2EncryptedMKeySize])
	}
	if msg[1+v2EncryptedMKeySize+v2AuthTagSize] != 0xCC {
		t.Errorf("E.pub[0] = 0x%02x, want 0xCC", msg[1+v2EncryptedMKeySize+v2AuthTagSize])
	}
}

// TestV2ReceivedEndToEndDecrypt performs a full encrypt-then-decrypt roundtrip:
// 1. Encrypt a USMC using the multi-recipient sent format
// 2. Extract the per-recipient data to build a received format message
// 3. Decrypt using SealedSenderV2DecryptReceivedToUSMC
func TestV2ReceivedEndToEndDecrypt(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate error: %v", err)
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		2, senderCert, []byte("received format test"), ContentHintDefault, nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent error: %v", err)
	}

	// Encrypt using multi-recipient sent format.
	sentCiphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil,
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	// Parse the sent format to extract per-recipient data.
	parsed, err := v2ParseMessage(sentCiphertext[1:], sentCiphertext[0])
	if err != nil {
		t.Fatalf("v2ParseMessage error: %v", err)
	}

	bobServiceId, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	if err != nil {
		t.Fatalf("ServiceIdFromString error: %v", err)
	}

	recipient, ok := parsed.Recipients[bobServiceId.String()]
	if !ok {
		t.Fatal("Bob should be in the parsed recipients")
	}

	// Build a received format message (simulating what the server does).
	// Per Rust reference, the received format always uses version 0x22.
	receivedMsg := V2BuildReceivedMessage(
		SealedSenderV2VersionUUID,
		recipient.EncryptedMKey,
		recipient.AuthTag,
		parsed.EphemeralPublic,
		parsed.EncryptedPayload,
	)

	// Decrypt using the received format.
	decryptedUSMC, err := SealedSenderV2DecryptReceivedToUSMC(receivedMsg, bobStore)
	if err != nil {
		t.Fatalf("SealedSenderV2DecryptReceivedToUSMC error: %v", err)
	}

	if decryptedUSMC.Type() != 2 {
		t.Errorf("Decrypted Type() = %d, want 2", decryptedUSMC.Type())
	}
	if string(decryptedUSMC.Contents()) != "received format test" {
		t.Errorf("Decrypted Contents() = %q, want %q", string(decryptedUSMC.Contents()), "received format test")
	}
}

// TestV2ReceivedEndToEndDecryptVersion0x23 verifies that received format
// messages constructed with version 0x23 can also be decrypted.
func TestV2ReceivedEndToEndDecryptVersion0x23(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate error: %v", err)
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		2, senderCert, []byte("version 0x23 test"), ContentHintDefault, nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent error: %v", err)
	}

	sentCiphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil,
		usmc,
		aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	parsed, err := v2ParseMessage(sentCiphertext[1:], sentCiphertext[0])
	if err != nil {
		t.Fatalf("v2ParseMessage error: %v", err)
	}

	bobServiceId, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	if err != nil {
		t.Fatalf("ServiceIdFromString error: %v", err)
	}

	recipient := parsed.Recipients[bobServiceId.String()]

	// Build received message with version 0x23.
	receivedMsg := V2BuildReceivedMessage(
		SealedSenderV2VersionServiceId,
		recipient.EncryptedMKey,
		recipient.AuthTag,
		parsed.EphemeralPublic,
		parsed.EncryptedPayload,
	)

	decryptedUSMC, err := SealedSenderV2DecryptReceivedToUSMC(receivedMsg, bobStore)
	if err != nil {
		t.Fatalf("SealedSenderV2DecryptReceivedToUSMC error: %v", err)
	}

	if string(decryptedUSMC.Contents()) != "version 0x23 test" {
		t.Errorf("Decrypted Contents() = %q, want %q", string(decryptedUSMC.Contents()), "version 0x23 test")
	}
}

// TestV2ReceivedDecryptTamperedC verifies that tampering with C (encrypted M)
// causes ephemeral key validation to fail.
func TestV2ReceivedDecryptTamperedC(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("tamper C"), ContentHintDefault, nil)

	sentCiphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	parsed, _ := v2ParseMessage(sentCiphertext[1:], sentCiphertext[0])
	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	recipient := parsed.Recipients[bobServiceId.String()]

	// Tamper with C.
	tamperedC := make([]byte, len(recipient.EncryptedMKey))
	copy(tamperedC, recipient.EncryptedMKey)
	tamperedC[0] ^= 0xFF

	receivedMsg := V2BuildReceivedMessage(
		SealedSenderV2VersionUUID,
		tamperedC,
		recipient.AuthTag,
		parsed.EphemeralPublic,
		parsed.EncryptedPayload,
	)

	_, err = SealedSenderV2DecryptReceivedToUSMC(receivedMsg, bobStore)
	if err == nil {
		t.Error("should fail with tampered C")
	}
	if !errors.Is(err, ErrV2ReceivedEphemeralKeyMismatch) {
		t.Errorf("error = %v, want ErrV2ReceivedEphemeralKeyMismatch", err)
	}
}

// TestV2ReceivedDecryptTamperedAuthTag verifies that tampering with AT
// causes the authentication tag verification to fail.
func TestV2ReceivedDecryptTamperedAuthTag(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("tamper AT"), ContentHintDefault, nil)

	sentCiphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	parsed, _ := v2ParseMessage(sentCiphertext[1:], sentCiphertext[0])
	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	recipient := parsed.Recipients[bobServiceId.String()]

	// Tamper with AT.
	tamperedAT := make([]byte, len(recipient.AuthTag))
	copy(tamperedAT, recipient.AuthTag)
	tamperedAT[0] ^= 0xFF

	receivedMsg := V2BuildReceivedMessage(
		SealedSenderV2VersionUUID,
		recipient.EncryptedMKey,
		tamperedAT,
		parsed.EphemeralPublic,
		parsed.EncryptedPayload,
	)

	_, err = SealedSenderV2DecryptReceivedToUSMC(receivedMsg, bobStore)
	if err == nil {
		t.Error("should fail with tampered AT")
	}
	if !errors.Is(err, ErrV2ReceivedAuthTagMismatch) {
		t.Errorf("error = %v, want ErrV2ReceivedAuthTagMismatch", err)
	}
}

// TestV2ReceivedDecryptTamperedPayload verifies that tampering with the
// encrypted payload causes AES-GCM-SIV decryption to fail.
func TestV2ReceivedDecryptTamperedPayload(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("tamper payload"), ContentHintDefault, nil)

	sentCiphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	parsed, _ := v2ParseMessage(sentCiphertext[1:], sentCiphertext[0])
	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	recipient := parsed.Recipients[bobServiceId.String()]

	// Tamper with payload.
	tamperedPayload := make([]byte, len(parsed.EncryptedPayload))
	copy(tamperedPayload, parsed.EncryptedPayload)
	tamperedPayload[len(tamperedPayload)-1] ^= 0xFF

	receivedMsg := V2BuildReceivedMessage(
		SealedSenderV2VersionUUID,
		recipient.EncryptedMKey,
		recipient.AuthTag,
		parsed.EphemeralPublic,
		tamperedPayload,
	)

	_, err = SealedSenderV2DecryptReceivedToUSMC(receivedMsg, bobStore)
	if err == nil {
		t.Error("should fail with tampered payload")
	}
	// Tampered payload causes either decryption failure or ephemeral key mismatch
	// (since the key derivation is correct but AEAD authentication fails).
	if !errors.Is(err, ErrV2ReceivedDecryptFailed) && !errors.Is(err, ErrV2ReceivedEphemeralKeyMismatch) {
		t.Errorf("error = %v, want ErrV2ReceivedDecryptFailed or ErrV2ReceivedEphemeralKeyMismatch", err)
	}
}

// TestV2ReceivedDecryptTamperedEphPub verifies that tampering with E.pub
// causes the decryption to fail (wrong shared secret).
func TestV2ReceivedDecryptTamperedEphPub(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("tamper eph pub"), ContentHintDefault, nil)

	sentCiphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	parsed, _ := v2ParseMessage(sentCiphertext[1:], sentCiphertext[0])
	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	recipient := parsed.Recipients[bobServiceId.String()]

	// Tamper with E.pub.
	tamperedEphPub := make([]byte, len(parsed.EphemeralPublic))
	copy(tamperedEphPub, parsed.EphemeralPublic)
	tamperedEphPub[0] ^= 0xFF

	receivedMsg := V2BuildReceivedMessage(
		SealedSenderV2VersionUUID,
		recipient.EncryptedMKey,
		recipient.AuthTag,
		tamperedEphPub,
		parsed.EncryptedPayload,
	)

	_, err = SealedSenderV2DecryptReceivedToUSMC(receivedMsg, bobStore)
	if err == nil {
		t.Error("should fail with tampered E.pub")
	}
}

// TestV2ReceivedDecryptWrongRecipient verifies that a message encrypted for
// one recipient cannot be decrypted by a different identity.
func TestV2ReceivedDecryptWrongRecipient(t *testing.T) {
	aliceStore, _, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, _ := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999, serverCert, serverKey.PrivateKey(),
	)
	usmc, _ := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("wrong recipient"), ContentHintDefault, nil)

	sentCiphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	parsed, _ := v2ParseMessage(sentCiphertext[1:], sentCiphertext[0])
	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	recipient := parsed.Recipients[bobServiceId.String()]

	receivedMsg := V2BuildReceivedMessage(
		SealedSenderV2VersionUUID,
		recipient.EncryptedMKey,
		recipient.AuthTag,
		parsed.EphemeralPublic,
		parsed.EncryptedPayload,
	)

	// Try to decrypt with a completely different identity.
	eveStore := newV2TestIdentityStore(t)
	_, err = SealedSenderV2DecryptReceivedToUSMC(receivedMsg, eveStore)
	if err == nil {
		t.Error("should fail when wrong recipient tries to decrypt")
	}
}

// TestV2ReceivedDispatchFromDecryptToUSMC verifies that SealedSenderDecryptToUSMC
// correctly dispatches to the received format handler when no ServiceId is provided.
func TestV2ReceivedDispatchFromDecryptToUSMC(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)

	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderCert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		nil,
		aliceStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate error: %v", err)
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		2, senderCert, []byte("dispatch test"), ContentHintDefault, nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent error: %v", err)
	}

	sentCiphertext, err := SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddress},
		[]*record.Session{bobSession},
		nil, usmc, aliceStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt error: %v", err)
	}

	parsed, _ := v2ParseMessage(sentCiphertext[1:], sentCiphertext[0])
	bobServiceId, _ := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	recipient := parsed.Recipients[bobServiceId.String()]

	receivedMsg := V2BuildReceivedMessage(
		SealedSenderV2VersionUUID,
		recipient.EncryptedMKey,
		recipient.AuthTag,
		parsed.EphemeralPublic,
		parsed.EncryptedPayload,
	)

	// Dispatch via SealedSenderDecryptToUSMC without providing a ServiceId.
	// This should route to SealedSenderV2DecryptReceivedToUSMC.
	decryptedUSMC, err := SealedSenderDecryptToUSMC(receivedMsg, bobStore)
	if err != nil {
		t.Fatalf("SealedSenderDecryptToUSMC error: %v", err)
	}

	if string(decryptedUSMC.Contents()) != "dispatch test" {
		t.Errorf("Contents() = %q, want %q", string(decryptedUSMC.Contents()), "dispatch test")
	}
}

// TestV2ReceivedMessageDataIsolation verifies that the parsed fields are
// independent copies of the input data (modifying input does not affect parsed output).
func TestV2ReceivedMessageDataIsolation(t *testing.T) {
	encM := make([]byte, v2EncryptedMKeySize)
	encM[0] = 0x42
	authTag := make([]byte, v2AuthTagSize)
	ephPub := make([]byte, 32)
	payload := []byte("isolation test")

	msg := V2BuildReceivedMessage(SealedSenderV2VersionUUID, encM, authTag, ephPub, payload)

	parsed, err := v2ParseReceivedMessage(msg)
	if err != nil {
		t.Fatalf("v2ParseReceivedMessage error: %v", err)
	}

	// Modify the original message buffer.
	msg[1] = 0xFF // position of C[0]

	// The parsed copy should be unaffected.
	if parsed.EncryptedMKey[0] != 0x42 {
		t.Errorf("EncryptedMKey[0] = 0x%02x, want 0x42 (data isolation violated)", parsed.EncryptedMKey[0])
	}
}

// TestV2ReceivedMinSizeConstant verifies the minimum size constant matches
// the expected layout.
func TestV2ReceivedMinSizeConstant(t *testing.T) {
	expected := v2EncryptedMKeySize + v2AuthTagSize + 32 + 1
	if v2ReceivedMinSize != expected {
		t.Errorf("v2ReceivedMinSize = %d, want %d", v2ReceivedMinSize, expected)
	}
}
