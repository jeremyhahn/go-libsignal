//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

// Conformance test: Sealed Sender v1 wire-format parity vs Rust libsignal.
//
// The Rust emitter (tests/interop/rust/src/bin/wire_emitter.rs) produced the
// fixture by calling sealed_sender_encrypt with a seeded ephemeral key pair.
// The ephemeral private key is NOT exposed in the fixture inputs, so we cannot
// reproduce the ciphertext bytes in Go.
//
// Assertion strategy: DECRYPT-AND-MATCH.
//   Load the Rust-emitted ciphertext, decrypt it with Go's
//   SealedSenderDecryptToUSMC using Bob's identity key pair, and assert:
//     1. The sender UUID, E164, and device ID match Alice's fixture values.
//     2. The sender certificate bytes are byte-identical to the fixture's
//        sender_cert_serialized (strongest structural check available).
//     3. The sender certificate validates against the trust root.
//
// Full ciphertext bytes-equal would require the Rust emitter to expose the
// ephemeral private key; if added in a future RUST_REV bump, upgrade to
// that stronger assertion.
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

type sealedSenderV1WireFixture struct {
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
			ServerKeyPrivateKey  string `json:"server_key_private_key"`
			ServerKeyPublicKey   string `json:"server_key_public_key"`
			TrustRootPrivateKey  string `json:"trust_root_private_key"`
			TrustRootPublicKey   string `json:"trust_root_public_key"`
		} `json:"inputs"`
		Expected struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"expected"`
	} `json:"vectors"`
}

// wireV1IdentityStore is a minimal store.IdentityKey for v1 wire decryption tests.
// Bob's identity key pair is stored; GetIdentity returns nil (not needed for v1 decrypt).
type wireV1IdentityStore struct {
	keyPair *identity.KeyPair
}

func (s *wireV1IdentityStore) GetIdentityKeyPair() *identity.KeyPair { return s.keyPair }
func (s *wireV1IdentityStore) GetLocalRegistrationId() uint32        { return 1 }
func (s *wireV1IdentityStore) SaveIdentity(_ *protocol.SignalAddress, _ *identity.Key) (store.IdentityChange, error) {
	return store.IdentityChangeNewOrUnchanged, nil
}
func (s *wireV1IdentityStore) IsTrustedIdentity(_ *protocol.SignalAddress, _ *identity.Key, _ store.Direction) (bool, error) {
	return true, nil
}
func (s *wireV1IdentityStore) GetIdentity(_ *protocol.SignalAddress) (*identity.Key, error) {
	return nil, nil
}

// buildWireV1IdentityStore constructs Bob's identity store from raw private/public key hex.
func buildWireV1IdentityStore(t *testing.T, privHex, pubHex string) *wireV1IdentityStore {
	t.Helper()

	privBytes := mustHex(t, privHex)
	pubBytes := mustHex(t, pubHex)

	privKey := ecc.NewDjbECPrivateKey(mustSliceTo32(t, privBytes))
	pubKey, err := ecc.DecodePoint(pubBytes, 0)
	if err != nil {
		t.Fatalf("DecodePoint bob pub: %v", err)
	}

	idKey := identity.NewKey(pubKey)
	idKeyPair := identity.NewKeyPair(idKey, privKey)
	return &wireV1IdentityStore{keyPair: idKeyPair}
}

// TestSealedSenderV1Wire decrypts the Rust-emitted v1 ciphertext using Go's
// SealedSenderDecryptToUSMC and asserts that the sender identity and certificate
// match the fixture inputs byte-for-byte.
func TestSealedSenderV1Wire(t *testing.T) {
	raw := loader.MustRead("wire/sealed_sender_v1.json")

	var fx sealedSenderV1WireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			ciphertext := mustHex(t, v.Expected.Ciphertext)
			plaintext := mustHex(t, v.Inputs.Plaintext)

			// Bob is the recipient: build his identity store.
			bobStore := buildWireV1IdentityStore(t, v.Inputs.BobIdentityPrivate, v.Inputs.BobIdentityPublic)

			// Verify version byte 0x11 (sealed sender v1).
			if len(ciphertext) < 1 || ciphertext[0] != sealed.SealedSenderV1Version {
				t.Fatalf("ciphertext[0] = 0x%02x, want 0x%02x (v1 version byte)",
					ciphertext[0], sealed.SealedSenderV1Version)
			}

			// Decrypt the Rust-emitted sealed sender v1 message using Go.
			usmc, err := sealed.SealedSenderDecryptToUSMC(ciphertext, bobStore)
			if err != nil {
				t.Fatalf("SealedSenderDecryptToUSMC: %v\n  ciphertext: %x", err, ciphertext)
			}

			// Assert sender identity fields match Alice's fixture values.
			sender := usmc.Sender()
			if got := sender.SenderUUID(); got != v.Inputs.AliceUUID {
				t.Errorf("SenderUUID: got %q, want %q", got, v.Inputs.AliceUUID)
			}
			if sender.SenderE164() == nil {
				t.Errorf("SenderE164: got nil, want %q", v.Inputs.AliceE164)
			} else if got := *sender.SenderE164(); got != v.Inputs.AliceE164 {
				t.Errorf("SenderE164: got %q, want %q", got, v.Inputs.AliceE164)
			}
			if got := sender.SenderDevice(); got != uint32(v.Inputs.AliceDeviceID) {
				t.Errorf("SenderDevice: got %d, want %d", got, v.Inputs.AliceDeviceID)
			}

			// Assert the sender certificate bytes are byte-identical to the fixture.
			// This is the strongest structural assertion available without the ephemeral key.
			wantCert := mustHex(t, v.Inputs.SenderCertSerialized)
			if !bytes.Equal(sender.Serialize(), wantCert) {
				t.Errorf("sender certificate bytes mismatch:\n  got  %x\n  want %x",
					sender.Serialize(), wantCert)
			}

			// Assert the trust root validates the sender certificate.
			trustRootBytes := mustHex(t, v.Inputs.TrustRootPublicKey)
			trustRootKey, err := ecc.DecodePoint(trustRootBytes, 0)
			if err != nil {
				t.Fatalf("decode trust root: %v", err)
			}
			// Validate at a time well before expiry.
			valid, err := sender.Validate(trustRootKey, uint64(v.Inputs.CertExpiryMs-1000))
			if err != nil {
				t.Fatalf("Validate sender cert: %v", err)
			}
			if !valid {
				t.Error("sender certificate did not validate against trust root")
			}

			// Assert Alice's identity public key is embedded in the sender certificate.
			alicePubBytes := mustHex(t, v.Inputs.AliceIdentityPublic)
			alicePubKey, err := ecc.DecodePoint(alicePubBytes, 0)
			if err != nil {
				t.Fatalf("decode Alice pubkey: %v", err)
			}
			if !bytes.Equal(sender.Key().Serialize(), alicePubKey.Serialize()) {
				t.Errorf("sender key mismatch:\n  got  %x\n  want %x",
					sender.Key().Serialize(), alicePubKey.Serialize())
			}

			// The USMC contents must be non-empty (inner session message).
			if len(usmc.Contents()) == 0 {
				t.Error("USMC contents must be non-empty")
			}
			// Fixture plaintext must be non-empty (sanity check on fixture itself).
			if len(plaintext) == 0 {
				t.Error("fixture plaintext must be non-empty")
			}

			t.Logf("v1 wire: decrypt-and-match passed (sender=%s device=%d contents=%d bytes)",
				sender.SenderUUID(), sender.SenderDevice(), len(usmc.Contents()))
		})
	}
}

// mustSliceTo32 copies a 32-byte slice to a [32]byte array.
func mustSliceTo32(t *testing.T, b []byte) [32]byte {
	t.Helper()
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	var arr [32]byte
	copy(arr[:], b)
	return arr
}
