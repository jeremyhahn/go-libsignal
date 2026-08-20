//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

// Conformance test: Sealed Sender v2 received-format wire parity vs Rust libsignal.
//
// The Rust emitter produced a sealed sender v2 single-recipient received-format
// message (version byte 0x22) for Bob. When the fixture includes bob_identity_private,
// Go decrypts the Rust-emitted ciphertext end-to-end and asserts sender identity.
//
// Assertion strategy: DECRYPT-AND-MATCH when bob_identity_private is present.
//   Load the Rust-emitted received message bytes, decrypt with
//   SealedSenderDecryptToUSMC using Bob's identity key pair (via the received-
//   format path SealedSenderV2DecryptReceivedToUSMC), and assert:
//     1. The sender UUID, E164, device ID match Alice's values.
//     2. The sender certificate bytes are byte-identical to the fixture's
//        sender_cert_serialized.
//     3. The USMC contents (plaintext) match the fixture's expected plaintext.
//
// If bob_identity_private is absent from the fixture (old fixture format), the
// test fails with a clear message directing the developer to regenerate via
// `make interop-wire-emit`.
//
// Rust upstream: rust/protocol/src/sealed_sender.rs (libsignal v0.92.2)

package interop

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/sealed"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type sealedSenderV2ReceivedWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			AliceDeviceID        int    `json:"alice_device_id"`
			AliceE164            string `json:"alice_e164"`
			AliceIdentityPrivate string `json:"alice_identity_private"`
			AliceIdentityPublic  string `json:"alice_identity_public"`
			AliceUUID            string `json:"alice_uuid"`
			BobDeviceID          int    `json:"bob_device_id"`
			BobIdentityPrivate   string `json:"bob_identity_private"`
			BobIdentityPublic    string `json:"bob_identity_public"`
			BobUUID              string `json:"bob_uuid"`
			CertExpiryMs         int64  `json:"cert_expiry_ms"`
			Plaintext            string `json:"plaintext"`
			SenderCertSerialized string `json:"sender_cert_serialized"`
			TrustRootPublicKey   string `json:"trust_root_public_key"`
		} `json:"inputs"`
		Expected struct {
			BobReceivedMessage string `json:"bob_received_message"`
		} `json:"expected"`
	} `json:"vectors"`
}

// wireV2IdentityStore is a minimal store.IdentityKey for v2 wire decryption tests.
// The key pair represents the recipient (Bob). GetIdentity returns nil as it is
// not required by the v2 received-format decrypt path.
type wireV2IdentityStore struct {
	keyPair *identity.KeyPair
}

func (s *wireV2IdentityStore) GetIdentityKeyPair() *identity.KeyPair { return s.keyPair }
func (s *wireV2IdentityStore) GetLocalRegistrationId() uint32        { return 1 }
func (s *wireV2IdentityStore) SaveIdentity(_ *protocol.SignalAddress, _ *identity.Key) (store.IdentityChange, error) {
	return store.IdentityChangeNewOrUnchanged, nil
}
func (s *wireV2IdentityStore) IsTrustedIdentity(_ *protocol.SignalAddress, _ *identity.Key, _ store.Direction) (bool, error) {
	return true, nil
}
func (s *wireV2IdentityStore) GetIdentity(_ *protocol.SignalAddress) (*identity.Key, error) {
	return nil, nil
}

// buildWireV2IdentityStore constructs an identity store from both private and public key hex.
func buildWireV2IdentityStore(t *testing.T, privHex, pubHex string) *wireV2IdentityStore {
	t.Helper()
	privBytes := mustHex(t, privHex)
	pubBytes := mustHex(t, pubHex)

	privKey := ecc.NewDjbECPrivateKey(mustSliceTo32(t, privBytes))
	pubKey, err := ecc.DecodePoint(pubBytes, 0)
	if err != nil {
		t.Fatalf("DecodePoint pub: %v", err)
	}
	idKey := identity.NewKey(pubKey)
	idKeyPair := identity.NewKeyPair(idKey, privKey)
	return &wireV2IdentityStore{keyPair: idKeyPair}
}

// TestSealedSenderV2ReceivedWire decrypts the Rust-emitted v2 received-format
// message with Go's SealedSenderDecryptToUSMC (dispatched to the received path)
// and asserts that the sender identity and plaintext match the fixture values.
//
// When bob_identity_private is absent from the fixture, the test fails with a
// clear regen instruction.
func TestSealedSenderV2ReceivedWire(t *testing.T) {
	raw := loader.MustRead("wire/sealed_sender_v2_received.json")

	var fx sealedSenderV2ReceivedWireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			// Gate: bob_identity_private must be present in the committed fixture.
			if v.Inputs.BobIdentityPrivate == "" {
				t.Fatalf("fixture missing bob_identity_private — regenerate via: make interop-wire-emit")
			}

			receivedBytes := mustHex(t, v.Expected.BobReceivedMessage)

			// Version byte check.
			if len(receivedBytes) < 1 {
				t.Fatal("received message is empty")
			}
			if receivedBytes[0] != sealed.SealedSenderV2VersionUUID {
				t.Errorf("version byte: got 0x%02x, want 0x%02x (v2 UUID)",
					receivedBytes[0], sealed.SealedSenderV2VersionUUID)
			}

			// Minimum length: version(1) + C(32) + AT(16) + E.pub(32) + payload(≥1).
			const minV2ReceivedLen = 1 + 32 + 16 + 32 + 1
			if len(receivedBytes) < minV2ReceivedLen {
				t.Fatalf("received message too short: %d bytes, want >= %d",
					len(receivedBytes), minV2ReceivedLen)
			}

			// Build Bob's identity store from the fixture private + public keys.
			bobStore := buildWireV2IdentityStore(t, v.Inputs.BobIdentityPrivate, v.Inputs.BobIdentityPublic)

			// Decrypt using the v2 received-format path (SealedSenderV2DecryptReceivedToUSMC).
			usmc, err := sealed.SealedSenderDecryptToUSMC(receivedBytes, bobStore)
			if err != nil {
				t.Fatalf("SealedSenderDecryptToUSMC: %v", err)
			}

			// Assert sender identity fields match Alice's fixture values.
			senderCert := usmc.Sender()

			if got := senderCert.SenderUUID(); got != v.Inputs.AliceUUID {
				t.Errorf("SenderUUID: got %q, want %q", got, v.Inputs.AliceUUID)
			}
			if senderCert.SenderE164() == nil {
				t.Errorf("SenderE164: got nil, want %q", v.Inputs.AliceE164)
			} else if got := *senderCert.SenderE164(); got != v.Inputs.AliceE164 {
				t.Errorf("SenderE164: got %q, want %q", got, v.Inputs.AliceE164)
			}
			if got := senderCert.SenderDevice(); got != uint32(v.Inputs.AliceDeviceID) {
				t.Errorf("SenderDevice: got %d, want %d", got, v.Inputs.AliceDeviceID)
			}

			// Assert sender certificate bytes are byte-identical to the fixture.
			wantCert := mustHex(t, v.Inputs.SenderCertSerialized)
			if !bytes.Equal(senderCert.Serialize(), wantCert) {
				t.Errorf("sender cert bytes mismatch:\n  got  %x\n  want %x",
					senderCert.Serialize(), wantCert)
			}

			// Assert the decrypted USMC contents match the fixture plaintext.
			// The wire emitter uses CiphertextMessageType::Plaintext, so the
			// USMC Contents() field holds the raw plaintext bytes.
			gotContent := usmc.Contents()
			wantContent := mustHex(t, v.Inputs.Plaintext)
			if !bytes.Equal(gotContent, wantContent) {
				t.Errorf("decrypted plaintext mismatch:\n  got  %x\n  want %x",
					gotContent, wantContent)
			}

			// Validate sender certificate against trust root for completeness.
			trustRootBytes := mustHex(t, v.Inputs.TrustRootPublicKey)
			trustRootKey, err := ecc.DecodePoint(trustRootBytes, 0)
			if err != nil {
				t.Fatalf("decode trust root: %v", err)
			}
			valid, err := senderCert.Validate(trustRootKey, uint64(v.Inputs.CertExpiryMs-1000))
			if err != nil {
				t.Fatalf("Validate sender cert: %v", err)
			}
			if !valid {
				t.Error("sender certificate did not validate against trust root")
			}

			t.Logf("v2 received wire: DECRYPT-AND-MATCH passed (len=%d, sender=%s)",
				len(receivedBytes), v.Inputs.AliceUUID)
		})
	}
}
