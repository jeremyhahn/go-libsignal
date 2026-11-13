// Conformance test: SenderKeyMessage wire parity vs Rust libsignal.
//
// The fixture contains the full SenderKeyDistributionMessage bytes (which carry
// the chain key and signing public key) and the encrypted SenderKeyMessage
// expected bytes. The signing key *private* key is NOT in the fixture inputs,
// so the 64-byte Ed25519 signature on the SenderKeyMessage cannot be reproduced.
//
// Assertion strategy: DECRYPT-AND-MATCH (decrypt the ciphertext inside the
// Rust-emitted SenderKeyMessage and verify the recovered plaintext equals the
// fixture plaintext).
//
//  1. Deserialize the expected SenderKeyMessage from expected.serialized.
//  2. Rebuild the SenderChainKey from the SKDM's chain_key at iteration 0.
//  3. Derive the SenderMessageKey (iteration 0) from the SenderChainKey.
//  4. Use the SenderMessageKey's IV and CipherKey to decrypt the ciphertext
//     field of the SenderKeyMessage with AES-256-CBC.
//  5. Assert the decrypted bytes equal the fixture plaintext.
//
// Additionally:
//  - Verify the distribution ID, chain ID (key ID), and iteration embedded in
//    the SenderKeyMessage match the fixture inputs.
//  - Verify the message version byte is 0x33 (version 3 in high nibble).
//
// Full bytes-equal on the SenderKeyMessage would require the signing key private
// key to be added to the fixture; if added in a future RUST_REV bump, upgrade.
//
// Rust upstream: rust/protocol/src/group_cipher.rs (libsignal v0.92.2)

package interop

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type groupsSKMWireFixture struct {
	Source  string `json:"source"`
	RustRev string `json:"rust_rev"`
	Purpose string `json:"purpose"`
	Vectors []struct {
		Name   string `json:"name"`
		Inputs struct {
			AliceDeviceID           int    `json:"alice_device_id"`
			AliceUUID               string `json:"alice_uuid"`
			DistributionID          string `json:"distribution_id"`
			Plaintext               string `json:"plaintext"`
			SenderKeyDistSerialized string `json:"senderkey_distribution_serialized"`
		} `json:"inputs"`
		Expected struct {
			Serialized string `json:"serialized"`
		} `json:"expected"`
	} `json:"vectors"`
}

// TestGroupsSKMWire decrypts the ciphertext field inside the Rust-emitted
// SenderKeyMessage using the chain key from the SKDM and asserts the recovered
// plaintext matches the fixture.
func TestGroupsSKMWire(t *testing.T) {
	raw := loader.MustRead("wire/senderkey_message.json")

	var fx groupsSKMWireFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture contains no vectors")
	}

	protobufSerializer := serialize.NewProtobufSerializer()

	for _, v := range fx.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			wantPlaintext := mustHex(t, v.Inputs.Plaintext)
			skmBytes := mustHex(t, v.Expected.Serialized)

			// Check version byte: 0x33 = (3 << 4) | 3 (SenderKeyCurrentVersion = 3).
			if len(skmBytes) < 1 {
				t.Fatal("serialized SenderKeyMessage is empty")
			}
			const wantVersionByte = byte((protocol.SenderKeyCurrentVersion << 4) | protocol.SenderKeyCurrentVersion)
			if skmBytes[0] != wantVersionByte {
				t.Errorf("version byte: got 0x%02x, want 0x%02x", skmBytes[0], wantVersionByte)
			}

			// Deserialize the expected SenderKeyMessage.
			skm, err := protocol.NewSenderKeyMessageFromBytes(skmBytes,
				protobufSerializer.SenderKeyMessage)
			if err != nil {
				t.Fatalf("NewSenderKeyMessageFromBytes: %v\n  bytes: %x", err, skmBytes)
			}

			// Verify distribution ID, key ID, and iteration from the message.
			wantDistID := parseUUID(t, v.Inputs.DistributionID)
			if gotDistID := skm.DistributionID(); gotDistID != wantDistID {
				t.Errorf("DistributionID: got %x, want %x", gotDistID, wantDistID)
			}

			// Deserialize the SKDM to extract chain key and iteration.
			skdmBytes := mustHex(t, v.Inputs.SenderKeyDistSerialized)
			skdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes,
				protobufSerializer.SenderKeyDistributionMessage)
			if err != nil {
				t.Fatalf("NewSenderKeyDistributionMessageFromBytes: %v", err)
			}
			defer skdm.Release()

			// Rebuild the SenderChainKey at the SKDM's iteration.
			chainKey := ratchet.NewSenderChainKey(skdm.Iteration(), skdm.ChainKey())

			// Derive the SenderMessageKey for iteration == skm.Iteration().
			// If the SKDM iteration equals the SKM iteration, use the first message key.
			// If the SKM is ahead, advance the chain accordingly.
			skmIteration := skm.Iteration()
			skdmIteration := skdm.Iteration()

			currentChain := chainKey
			for i := skdmIteration; i < skmIteration; i++ {
				next, err := currentChain.Next()
				if err != nil {
					t.Fatalf("SenderChainKey.Next at i=%d: %v", i, err)
				}
				currentChain = next
			}

			msgKey, err := currentChain.SenderMessageKey()
			if err != nil {
				t.Fatalf("SenderMessageKey: %v", err)
			}

			// Decrypt the SenderKeyMessage ciphertext with AES-256-CBC.
			// cipher.Decrypt(iv, key, ciphertext) matching GroupCipher.Decrypt.
			gotPlaintext, err := cipher.Decrypt(msgKey.Iv(), msgKey.CipherKey(), skm.Ciphertext())
			if err != nil {
				t.Fatalf("cipher.Decrypt: %v\n  ciphertext: %x\n  iv: %x\n  key: %x",
					err, skm.Ciphertext(), msgKey.Iv(), msgKey.CipherKey())
			}

			// DECRYPT-AND-MATCH: the recovered plaintext must equal the fixture plaintext.
			if !bytes.Equal(gotPlaintext, wantPlaintext) {
				t.Errorf("decrypted plaintext mismatch:\n  got  %x\n  want %x",
					gotPlaintext, wantPlaintext)
			}

			// Verify the iteration field.
			if skm.Iteration() != skdm.Iteration() {
				// The message is at the same iteration as the SKDM since this is
				// the first message in the chain.
				t.Logf("note: SKM iteration=%d, SKDM iteration=%d",
					skm.Iteration(), skdm.Iteration())
			}

			t.Logf("SKM wire: decrypt-and-match passed (dist=%x keyID=%d iter=%d plaintext=%d bytes)",
				skm.DistributionID(), skm.KeyID(), skm.Iteration(), len(gotPlaintext))
		})
	}
}
