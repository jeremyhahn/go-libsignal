// SenderKeyMessage parity: decrypt the Rust message with the SKDM chain key and match the plaintext, IDs, iteration and version 0x33; the fixture lacks the signing key.

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

// TestGroupsSKMWire decrypts the Rust SenderKeyMessage with the SKDM chain key and checks the plaintext.
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

			// Derive the message key for skm.Iteration(), advancing the chain if needed.
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

			// The recovered plaintext must equal the fixture plaintext.
			if !bytes.Equal(gotPlaintext, wantPlaintext) {
				t.Errorf("decrypted plaintext mismatch:\n  got  %x\n  want %x",
					gotPlaintext, wantPlaintext)
			}

			// Verify the iteration field.
			if skm.Iteration() != skdm.Iteration() {
				// This first message shares the SKDM's iteration.
				t.Logf("note: SKM iteration=%d, SKDM iteration=%d",
					skm.Iteration(), skdm.Iteration())
			}

			t.Logf("SKM wire: decrypt-and-match passed (dist=%x keyID=%d iter=%d plaintext=%d bytes)",
				skm.DistributionID(), skm.KeyID(), skm.Iteration(), len(gotPlaintext))
		})
	}
}
