//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 2 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) and the Double Ratchet
// specification (section 5.2) require it, so the fips140only build tag drops
// this file from the FIPS gate. `make test` and `make coverage` still run
// it.

package session_test

// Fuzz targets for the session cipher's out-of-order / malformed message paths.
//
// These targets confirm that Decrypt and DecryptPreKeyMessage never panic on
// arbitrary byte inputs — they must either succeed (return plaintext) or return
// a typed error from pkg/session or pkg/protocol. Any panic is a bug.
//
// Seed corpus covers three representative failure modes per target:
//   1. Truncated message — too short to parse.
//   2. Plausible version byte but garbage body.
//   3. Unknown version byte — unknown major/minor version fields.
//
// Run as a CI smoke-check:
//
//	go test -run=^$ -fuzz=FuzzDecryptSignalMessage -fuzztime=10s ./pkg/session/...
//	go test -run=^$ -fuzz=FuzzDecryptPreKeyMessage -fuzztime=10s ./pkg/session/...

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// buildFuzzSession constructs two in-memory users (Alice → Bob) with a fully
// established PQXDH session. Alice's cipher is returned for use by fuzz targets
// that call Cipher.Decrypt; Bob's builder is returned for targets that call
// Cipher.DecryptPreKeyMessage. No host-side state is modified; all stores are
// in-memory only.
func buildFuzzSession() (aliceCipher *session.Cipher, bobBuilder *session.Builder,
	bobCipher *session.Cipher,
	signalSer protocol.SignalMessageSerializer,
	preKeySer protocol.PreKeySignalMessageSerializer) {

	ser := serialize.NewProtobufSerializer()

	aliceKP, _ := keyhelper.GenerateIdentityKeyPair()
	bobKP, _ := keyhelper.GenerateIdentityKeyPair()
	aliceRegID := keyhelper.GenerateRegistrationID()
	bobRegID := keyhelper.GenerateRegistrationID()

	aliceAddr := protocol.NewSignalAddress("alice-fuzz", 1)
	bobAddr := protocol.NewSignalAddress("bob-fuzz", 1)

	aliceIdentityStore := newInMemoryIdentityKey(aliceKP, aliceRegID)
	bobIdentityStore := newInMemoryIdentityKey(bobKP, bobRegID)

	aliceSessionStore := newInMemorySession(ser)
	bobSessionStore := newInMemorySession(ser)

	alicePreKeyStore := newInMemoryPreKey()
	bobPreKeyStore := newInMemoryPreKey()

	aliceSignedPKStore := newInMemorySignedPreKey()
	bobSignedPKStore := newInMemorySignedPreKey()

	aliceKyberStore := newInMemoryKyberPreKey()
	bobKyberStore := newInMemoryKyberPreKey()

	// Generate Bob's pre-key material and populate his stores.
	// start=1: GeneratePreKeys requires start >= 1 (pre-key ID 0 is invalid).
	bobPreKeyList, _ := keyhelper.GeneratePreKeys(1, 10, ser.PreKeyRecord)
	for _, pk := range bobPreKeyList {
		if err := bobPreKeyStore.StorePreKey(pk.ID().Value,
			record.NewPreKey(pk.ID().Value, pk.KeyPair(), ser.PreKeyRecord)); err != nil {
			panic("setup: StorePreKey: " + err.Error())
		}
	}
	bobSPK, _ := keyhelper.GenerateSignedPreKey(bobKP, 0, ser.SignedPreKeyRecord)
	if err := bobSignedPKStore.StoreSignedPreKey(bobSPK.ID(),
		record.NewSignedPreKey(bobSPK.ID(), bobSPK.Timestamp(), bobSPK.KeyPair(),
			bobSPK.Signature(), ser.SignedPreKeyRecord)); err != nil {
		panic("setup: StoreSignedPreKey: " + err.Error())
	}
	bobKyberPreKey, _ := keyhelper.GenerateKyberPreKey(bobKP.PrivateKey(), 42, &mockKyberPreKeySerializer{})
	_ = bobKyberStore.StoreKyberPreKey(42, bobKyberPreKey)

	// Build Alice's session toward Bob using Bob's bundle.
	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessionStore, alicePreKeyStore, aliceSignedPKStore,
		aliceIdentityStore, aliceKyberStore, bobAddr, ser,
	)
	bundle := prekey.NewBundleWithKyber(
		bobRegID,
		bobAddr.DeviceID(),
		bobPreKeyList[0].ID(),
		bobSPK.ID(),
		bobPreKeyList[0].KeyPair().PublicKey(),
		bobSPK.KeyPair().PublicKey(),
		bobSPK.Signature(),
		identity.NewKey(bobKP.PublicKey().PublicKey()),
		&optional.Uint32{Value: 42},
		bobKyberPreKey.PublicKey(),
		bobKyberPreKey.Signature(),
	)
	_ = aliceBuilder.ProcessBundle(bundle)
	aliceCipher = session.NewCipherWithIdentityAndLocalAddress(aliceBuilder, aliceAddr, bobAddr, aliceIdentityStore)

	bobBuilder = session.NewBuilderWithKyber(
		bobSessionStore, bobPreKeyStore, bobSignedPKStore,
		bobIdentityStore, bobKyberStore, aliceAddr, ser,
	)
	bobCipher = session.NewCipherWithIdentityAndLocalAddress(bobBuilder, bobAddr, aliceAddr, bobIdentityStore)

	return aliceCipher, bobBuilder, bobCipher, ser.SignalMessage, ser.PreKeySignalMessage
}

// FuzzDecryptSignalMessage feeds mutated bytes to the SignalMessage deserializer
// and then to Cipher.Decrypt. The cipher must not panic on any input.
// A typed error return is acceptable; a panic is a bug.
//
// Seed corpus covers three representative malformed inputs:
//   - Seed 0: 1-byte truncated message — too short to parse.
//   - Seed 1: 10 bytes with a plausible v3 version prefix and garbage body.
//   - Seed 2: unknown future version byte 0xFF.
func FuzzDecryptSignalMessage(f *testing.F) {
	// Seed 0: truncated — 1 byte only.
	f.Add([]byte{0x33})
	// Seed 1: plausible v3 version byte with garbage body.
	f.Add([]byte{0x33, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	// Seed 2: unknown future version byte — must be rejected before any crypto.
	f.Add([]byte{0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	cipher, _, _, signalSer, _ := buildFuzzSession()

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := protocol.NewSignalMessageFromBytes(data, signalSer)
		if err != nil {
			// Deserialization rejected the input — expected for malformed bytes.
			return
		}
		// Must not panic; a typed error is acceptable.
		_, _ = cipher.Decrypt(msg)
	})
}

// FuzzDecryptPreKeyMessage feeds mutated bytes to the PreKeySignalMessage
// deserializer and then to Cipher.DecryptPreKeyMessage. The cipher must not
// panic on any input.
//
// Seed corpus:
//   - Seed 0: 1-byte truncated message.
//   - Seed 1: 12-byte message with a plausible v4 prefix but no body.
//   - Seed 2: empty slice.
func FuzzDecryptPreKeyMessage(f *testing.F) {
	// Seed 0: truncated — 1 byte only.
	f.Add([]byte{0x44})
	// Seed 1: 12 bytes with a v4 version byte, zero counter, zero registration ID.
	f.Add([]byte{0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// Seed 2: empty slice — degenerate minimum input.
	f.Add([]byte{})

	_, builder, cipher, signalSer, preKeySer := buildFuzzSession()

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := protocol.NewPreKeySignalMessageFromBytes(data, preKeySer, signalSer)
		if err != nil {
			// Deserialization rejected the input — expected for malformed bytes.
			return
		}
		// Must not panic; a typed error is acceptable.
		_, _, _ = cipher.DecryptPreKeyMessage(builder, msg)
	})
}
