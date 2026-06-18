// Keytrans end-to-end search verification against the upstream Rust fixture.
//
// The fixture tests/interop/fixtures/net/chat_search_response.dat is a
// protobuf-encoded SearchResponse (ChatSearchResponse) emitted by the Rust
// libsignal staging configuration.  This test deserialises it, builds the
// PublicConfig from the staging key material, and calls
// pkg/keytrans.VerifySearch for the ACI entry to confirm that Go produces
// the same result as Rust's staging tests:
//
//	rust/net/chat/src/api/keytrans.rs:770-816 (search_returns_data_not_requested,
//	search_does_not_return_requested_data).
//
// The parameters come directly from the Rust test constants:
//
//	KEYTRANS_SIGNING_KEY_MATERIAL_STAGING  (rust/net/src/env.rs:363)
//	KEYTRANS_VRF_KEY_MATERIAL_STAGING      (rust/net/src/env.rs:365)
//	KEYTRANS_AUDITOR_KEY_MATERIAL_STAGING  (rust/net/src/env.rs:367-371)
//	test_account::ACI                      (rust/net/chat/src/api/keytrans.rs:567)
//	CHAT_SEARCH_RESPONSE_VALID_AT          (rust/net/tests/data/chat_response_valid_at.in)
//
// Upstream commit: 98915c442d
package interop

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/jeremyhahn/go-libsignal/pkg/keytrans"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// storedAccountData681Hex is STORED_ACCOUNT_DATA_681 from
// rust/net/chat/src/api/keytrans.rs:631-633. It is a protobuf-encoded
// StoredAccountData for tree size 681.  The test extracts only the
// last_tree_head (field 4) to populate SearchContext.LastTreeHead.
const storedAccountData681Hex = "0a3e0a203901c94081c4e6321e92b3e434dcaf788f5326913e7bdcab47b4fd2ae7a6848a10131a0308ff0320012a116190c979fdeab44a08b6da69dedeab9b29123a0a2086052cc2a2689558e852d053c5ab411d8c3baef20171ec298e551574806ca95d104c1a0308ff0320012a0d6e2b31383030353535303130301a4f0a206f55ac745ebeaf39fd5b21177c7fa692876c42678ffa1f3d58ed8fbc5ef023b910a6011a0308ff0320012a2175dc711808c2cf66d5e6a33ce41f27d69d942d2e1ff4db22d39b42d2eff8d0974622e8020abc0208a90510bec5b0c4d7331a640a20bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e124000eec714425c086bcde66e5a2af2c87031eea6c485965b549ac81bc3793cf5bdd5222073f59dd4959f6e9fdb6f6d405a477a7aaeb4bc8fd89b876b59cf89bf031a640a201123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755124034a1a53ac786258ad28d79b3b9cd9a59219b1449b10e769f3934d8981bf58d47c594439a93a3bb1adc318b5b227a60257406052f4501540d06c3d01b07a35a051a640a20093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd63612402cec2570d4fc3e3063aa9c358e2fcb55ae65f25f8c82072fc8d4016ce4fe2be182adeee08d786745109a8978189791feb52d2ebe7e98d1a22ab0478ea5190e0b1220032487becda242fa353ee8654ba3a5fb7d9e9aa1d48eb42f2ea6866070a494a118c4d6b0c4d733"

// distinguishedTree677HeadHex is DISTINGUISHED_TREE_677_HEAD from
// rust/net/chat/src/api/keytrans.rs:625-627.
// It is a protobuf-encoded TreeHead at tree size 677.
const distinguishedTree677HeadHex = "08a50510f981afc4d7331a640a20bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e1240404fcd202d174fa3c1db70dd7a2af28aa7289230f16bbbabfbb0cf8ac0351ce8ddcc770a4e5ab2a2b32b4af7fba5e056f2d6f70be1039c152aeda2e7c6117a0d1a640a201123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e7551240521e691c9356343feee2e80c5355d1f257550d870542ac0b6e25d349b6223966eb0859dd0df942cd5e541b37e9028682c9c986a5c9f33ce4739e205f58cbd2061a640a20093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd636124081185aaf680e96e329dee42cdb2f1ce7bef6da769b51dabfda8db0163977d500a47d00fe60a6fe3e2562f08e5ff8c4ec4dfcf054e31a85b28d0665ff92c0f901"

// distinguishedTree677RootHex is DISTINGUISHED_TREE_677_ROOT from
// rust/net/chat/src/api/keytrans.rs:628-629.
const distinguishedTree677RootHex = "8bf5f1bdfb17a7772210f05192e4581f4b4364c9ca2efdd79244d5fc01adcde5"

// stagingSigningKey is KEYTRANS_SIGNING_KEY_MATERIAL_STAGING from
// rust/net/src/env.rs:364.
var stagingSigningKeyHex = "ac0de1fd7f33552bbeb6ebc12b9d4ea10bf5f025c45073d3fb5f5648955a749e"

// stagingVRFKey is KEYTRANS_VRF_KEY_MATERIAL_STAGING from
// rust/net/src/env.rs:366.
var stagingVRFKeyHex = "ec3a268237cf5c47115cf222405d5f90cc633ebe05caf82c0dd5acf9d341dadb"

// stagingAuditorKeys are KEYTRANS_AUDITOR_KEY_MATERIAL_STAGING from
// rust/net/src/env.rs:367-371.
var stagingAuditorKeyHexes = []string{
	"1123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755",
	"bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e",
	"093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd636",
}

// testACI is the UUID from test_account::ACI (rust/net/chat/src/api/keytrans.rs:567).
// UUID "90c979fd-eab4-4a08-b6da-69dedeab9b29" as 16 raw bytes.
var testACIUUID = [16]byte{
	0x90, 0xc9, 0x79, 0xfd, 0xea, 0xb4, 0x4a, 0x08,
	0xb6, 0xda, 0x69, 0xde, 0xde, 0xab, 0x9b, 0x29,
}

// chatSearchResponseValidAt is CHAT_SEARCH_RESPONSE_VALID_AT from
// rust/net/tests/data/chat_response_valid_at.in: Duration::from_secs(1775843959).
var chatSearchResponseValidAt = time.Unix(1775843959, 0)

// searchKeyPrefixACI is "a", the ACI prefix from SEARCH_KEY_PREFIX_ACI
// (rust/net/chat/src/api/keytrans.rs:32).
const searchKeyPrefixACI = byte('a')

// buildStagingPublicConfig returns the PublicConfig for the Signal staging
// environment, derived from rust/net/src/env.rs::From<KeyTransConfig> for PublicConfig.
// The signing_key_material is an ed25519 public key.  The vrf_key_material is a
// compressed Edwards25519 point used as the VRF public key.  The auditor keys
// use ThirdPartyAuditing mode.
func buildStagingPublicConfig(t *testing.T) keytrans.PublicConfig {
	t.Helper()

	sigKeyBytes, err := hex.DecodeString(stagingSigningKeyHex)
	if err != nil {
		t.Fatalf("decode signing key: %v", err)
	}
	if len(sigKeyBytes) != 32 {
		t.Fatalf("signing key must be 32 bytes, got %d", len(sigKeyBytes))
	}
	signatureKey := ed25519.PublicKey(sigKeyBytes)

	vrfKeyBytes, err := hex.DecodeString(stagingVRFKeyHex)
	if err != nil {
		t.Fatalf("decode VRF key: %v", err)
	}
	if len(vrfKeyBytes) != 32 {
		t.Fatalf("VRF key must be 32 bytes, got %d", len(vrfKeyBytes))
	}
	var vrfArr [32]byte
	copy(vrfArr[:], vrfKeyBytes)
	vrfKey, err := keytrans.NewVRFPublicKey(vrfArr)
	if err != nil {
		t.Fatalf("NewVRFPublicKey: %v", err)
	}

	auditorKeys := make([]ed25519.PublicKey, 0, len(stagingAuditorKeyHexes))
	for _, h := range stagingAuditorKeyHexes {
		kb, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("decode auditor key %q: %v", h, err)
		}
		auditorKeys = append(auditorKeys, ed25519.PublicKey(kb))
	}

	return keytrans.PublicConfig{
		Mode:         keytrans.ThirdPartyAuditing(auditorKeys),
		SignatureKey: signatureKey,
		VRFKey:       vrfKey,
	}
}

// buildDistinguishedLastTreeHead constructs the LastTreeHead for the
// distinguished tree at size 677 from the Rust test constants.
// Rust: DISTINGUISHED_TREE_677_HEAD (protobuf TreeHead) +
//
//	DISTINGUISHED_TREE_677_ROOT (32-byte root hash).
//
// Source: rust/net/chat/src/api/keytrans.rs:625-629.
func buildDistinguishedLastTreeHead(t *testing.T) *keytrans.LastTreeHead {
	t.Helper()

	headBytes, err := hex.DecodeString(distinguishedTree677HeadHex)
	if err != nil {
		t.Fatalf("decode distinguished head hex: %v", err)
	}
	th, err := decodeTreeHead(headBytes)
	if err != nil {
		t.Fatalf("decodeTreeHead: %v", err)
	}

	rootBytes, err := hex.DecodeString(distinguishedTree677RootHex)
	if err != nil {
		t.Fatalf("decode distinguished root hex: %v", err)
	}
	if len(rootBytes) != 32 {
		t.Fatalf("root must be 32 bytes, got %d", len(rootBytes))
	}
	var root keytrans.TreeRoot
	copy(root[:], rootBytes)

	return &keytrans.LastTreeHead{Head: *th, Root: root}
}

// aciSearchKey builds the ACI search key: "a" || ACI-UUID-bytes (16 bytes).
// Rust: Aci::as_search_key = [SEARCH_KEY_PREFIX_ACI, aci.service_id_binary()].concat()
// where service_id_binary() for an ACI is just the raw 16-byte UUID.
func aciSearchKey() []byte {
	key := make([]byte, 1+16)
	key[0] = searchKeyPrefixACI
	copy(key[1:], testACIUUID[:])
	return key
}

// decodeStoredAccountDataLastTreeHead extracts the last_tree_head (field 4)
// from a protobuf-encoded StoredAccountData message and converts it to a
// keytrans.LastTreeHead.
//
// StoredAccountData fields (store.proto):
//
//	1: StoredMonitoringData aci
//	2: StoredMonitoringData e164
//	3: StoredMonitoringData username_hash
//	4: StoredTreeHead last_tree_head
//
// StoredTreeHead fields:
//
//	1: TreeHead tree_head
//	2: bytes root
//	3: uint64 stored_at_ms
func decodeStoredAccountDataLastTreeHead(data []byte) (*keytrans.LastTreeHead, error) {
	var storedTreeHeadBytes []byte
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		if num == 4 && typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			storedTreeHeadBytes = append([]byte(nil), v...)
			data = data[n:]
		} else {
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	if storedTreeHeadBytes == nil {
		return nil, fmt.Errorf("StoredAccountData has no last_tree_head (field 4)")
	}
	return decodeStoredTreeHead(storedTreeHeadBytes)
}

// decodeStoredTreeHead decodes a StoredTreeHead message into a LastTreeHead.
func decodeStoredTreeHead(data []byte) (*keytrans.LastTreeHead, error) {
	var th *keytrans.TreeHead
	var root []byte
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			decoded, err := decodeTreeHead(v)
			if err != nil {
				return nil, err
			}
			th = decoded
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			root = append([]byte(nil), v...)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	if th == nil {
		return nil, fmt.Errorf("StoredTreeHead has no tree_head (field 1)")
	}
	if len(root) != 32 {
		return nil, fmt.Errorf("StoredTreeHead.root must be 32 bytes, got %d", len(root))
	}
	var rootArr keytrans.TreeRoot
	copy(rootArr[:], root)
	return &keytrans.LastTreeHead{Head: *th, Root: rootArr}, nil
}

// decodeChatSearchResponse parses a protobuf-encoded SearchResponse (ChatSearchResponse)
// using the field layout from rust/keytrans/src/proto/chat.proto.
//
// SearchResponse fields:
//
//	1: FullTreeHead        tree_head
//	2: CondensedTreeSearch aci
//	3: CondensedTreeSearch e164  (optional)
//	4: CondensedTreeSearch username_hash (optional)
func decodeChatSearchResponse(data []byte) (*keytrans.ChatSearchResponse, error) {
	resp := &keytrans.ChatSearchResponse{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			fth, err := decodeFullTreeHead(v)
			if err != nil {
				return nil, err
			}
			resp.TreeHead = fth
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			csr, err := decodeCondensedTreeSearchResponse(v)
			if err != nil {
				return nil, err
			}
			resp.ACI = csr
			data = data[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			csr, err := decodeCondensedTreeSearchResponse(v)
			if err != nil {
				return nil, err
			}
			resp.E164 = csr
			data = data[n:]
		case num == 4 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			csr, err := decodeCondensedTreeSearchResponse(v)
			if err != nil {
				return nil, err
			}
			resp.UsernameHash = csr
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return resp, nil
}

// decodeFullTreeHead decodes a FullTreeHead message.
//
// FullTreeHead fields (wire.proto):
//
//	1: TreeHead tree_head
//	2: repeated bytes last
//	3: repeated bytes distinguished
//	4: repeated FullAuditorTreeHead full_auditor_tree_heads
func decodeFullTreeHead(data []byte) (*keytrans.FullTreeHead, error) {
	fth := &keytrans.FullTreeHead{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			th, err := decodeTreeHead(v)
			if err != nil {
				return nil, err
			}
			fth.TreeHead = th
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			cp := make([]byte, len(v))
			copy(cp, v)
			fth.Last = append(fth.Last, cp)
			data = data[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			cp := make([]byte, len(v))
			copy(cp, v)
			fth.Distinguished = append(fth.Distinguished, cp)
			data = data[n:]
		case num == 4 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			fath, err := decodeFullAuditorTreeHead(v)
			if err != nil {
				return nil, err
			}
			fth.FullAuditorTreeHeads = append(fth.FullAuditorTreeHeads, *fath)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return fth, nil
}

// decodeTreeHead decodes a TreeHead message.
//
// TreeHead fields (wire.proto):
//
//	1: uint64 tree_size
//	2: int64 timestamp
//	3: repeated Signature signatures
func decodeTreeHead(data []byte) (*keytrans.TreeHead, error) {
	th := &keytrans.TreeHead{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			th.TreeSize = v
			data = data[n:]
		case num == 2 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			th.Timestamp = int64(v)
			data = data[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			sig, err := decodeSignature(v)
			if err != nil {
				return nil, err
			}
			th.Signatures = append(th.Signatures, *sig)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return th, nil
}

// decodeSignature decodes a Signature message.
//
// Signature fields (wire.proto):
//
//	1: bytes auditor_public_key
//	2: bytes signature
func decodeSignature(data []byte) (*keytrans.Signature, error) {
	sig := &keytrans.Signature{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			sig.AuditorPublicKey = append([]byte(nil), v...)
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			sig.SignatureBytes = append([]byte(nil), v...)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return sig, nil
}

// decodeAuditorTreeHead decodes an AuditorTreeHead message.
//
// AuditorTreeHead fields (wire.proto):
//
//	1: uint64 tree_size
//	2: int64 timestamp
//	3: bytes signature
func decodeAuditorTreeHead(data []byte) (*keytrans.AuditorTreeHead, error) {
	ath := &keytrans.AuditorTreeHead{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			ath.TreeSize = v
			data = data[n:]
		case num == 2 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			ath.Timestamp = int64(v)
			data = data[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			ath.Signature = append([]byte(nil), v...)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return ath, nil
}

// decodeFullAuditorTreeHead decodes a FullAuditorTreeHead message.
//
// FullAuditorTreeHead fields (wire.proto):
//
//	1: AuditorTreeHead tree_head
//	2: optional bytes root_value
//	3: repeated bytes consistency
//	4: bytes public_key
func decodeFullAuditorTreeHead(data []byte) (*keytrans.FullAuditorTreeHead, error) {
	fath := &keytrans.FullAuditorTreeHead{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			ath, err := decodeAuditorTreeHead(v)
			if err != nil {
				return nil, err
			}
			fath.TreeHead = ath
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			fath.RootValue = append([]byte(nil), v...)
			data = data[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			fath.Consistency = append(fath.Consistency, append([]byte(nil), v...))
			data = data[n:]
		case num == 4 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			fath.PublicKey = append([]byte(nil), v...)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return fath, nil
}

// decodeCondensedTreeSearchResponse decodes a CondensedTreeSearchResponse message.
//
// CondensedTreeSearchResponse fields (wire.proto):
//
//	1: bytes vrf_proof
//	2: SearchProof search
//	3: bytes opening
//	4: UpdateValue value
func decodeCondensedTreeSearchResponse(data []byte) (*keytrans.CondensedTreeSearchResponse, error) {
	csr := &keytrans.CondensedTreeSearchResponse{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			csr.VRFProof = append([]byte(nil), v...)
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			sp, err := decodeSearchProof(v)
			if err != nil {
				return nil, err
			}
			csr.Search = sp
			data = data[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			csr.Opening = append([]byte(nil), v...)
			data = data[n:]
		case num == 4 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			uv, err := decodeUpdateValue(v)
			if err != nil {
				return nil, err
			}
			csr.Value = uv
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return csr, nil
}

// decodeSearchProof decodes a SearchProof message.
//
// SearchProof fields (wire.proto):
//
//	1: uint64 pos
//	2: repeated ProofStep steps
//	3: repeated bytes inclusion
func decodeSearchProof(data []byte) (*keytrans.SearchProof, error) {
	sp := &keytrans.SearchProof{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			sp.Pos = v
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			step, err := decodeProofStep(v)
			if err != nil {
				return nil, err
			}
			sp.Steps = append(sp.Steps, *step)
			data = data[n:]
		case num == 3 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			sp.Inclusion = append(sp.Inclusion, append([]byte(nil), v...))
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return sp, nil
}

// decodeProofStep decodes a ProofStep message.
//
// ProofStep fields (wire.proto):
//
//	1: PrefixProof prefix
//	2: bytes commitment
func decodeProofStep(data []byte) (*keytrans.ProofStep, error) {
	ps := &keytrans.ProofStep{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			pp, err := decodePrefixProof(v)
			if err != nil {
				return nil, err
			}
			ps.Prefix = pp
			data = data[n:]
		case num == 2 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			ps.Commitment = append([]byte(nil), v...)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return ps, nil
}

// decodePrefixProof decodes a PrefixProof message.
//
// PrefixProof fields (wire.proto):
//
//	1: repeated bytes proof
//	2: uint32 counter
func decodePrefixProof(data []byte) (*keytrans.PrefixProof, error) {
	pp := &keytrans.PrefixProof{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			pp.Proof = append(pp.Proof, append([]byte(nil), v...))
			data = data[n:]
		case num == 2 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			pp.Counter = uint32(v)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return pp, nil
}

// decodeUpdateValue decodes an UpdateValue message.
//
// UpdateValue fields (wire.proto):
//
//	1: bytes value
func decodeUpdateValue(data []byte) (*keytrans.UpdateValue, error) {
	uv := &keytrans.UpdateValue{}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			uv.Value = append([]byte(nil), v...)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return uv, nil
}

// TestKeytrans_ChatSearchResponse_LoadAndDeserialize verifies that the
// chat_search_response.dat fixture can be deserialized into a ChatSearchResponse
// and that its structure is well-formed (ACI response present, tree head present).
// This catches bit-rot in the fixture and ensures the Go protowire decoder
// handles the actual Rust-emitted binary format.
//
// Rust source: rust/net/chat/src/api/keytrans.rs:770-776
func TestKeytrans_ChatSearchResponse_LoadAndDeserialize(t *testing.T) {
	raw := loader.MustRead("net/chat_search_response.dat")
	if len(raw) == 0 {
		t.Fatal("fixture is empty")
	}

	resp, err := decodeChatSearchResponse(raw)
	if err != nil {
		t.Fatalf("decodeChatSearchResponse: %v", err)
	}

	if resp.TreeHead == nil {
		t.Fatal("ChatSearchResponse.TreeHead is nil")
	}
	if resp.TreeHead.TreeHead == nil {
		t.Fatal("ChatSearchResponse.TreeHead.TreeHead is nil")
	}
	if resp.TreeHead.TreeHead.TreeSize == 0 {
		t.Fatal("tree_size is zero")
	}
	if resp.ACI == nil {
		t.Fatal("ChatSearchResponse.ACI is nil — ACI entry is mandatory")
	}
	if len(resp.ACI.VRFProof) != 80 {
		t.Fatalf("ACI VRF proof must be 80 bytes, got %d", len(resp.ACI.VRFProof))
	}
	t.Logf("tree_size=%d, has_e164=%v, has_username_hash=%v",
		resp.TreeHead.TreeHead.TreeSize,
		resp.E164 != nil,
		resp.UsernameHash != nil,
	)
}

// TestKeytrans_ChatSearchResponse_VerifyACI performs end-to-end ACI search
// verification using the staging PublicConfig and the pinned Rust fixture.
//
// This mirrors the Rust test at rust/net/chat/src/api/keytrans.rs:805-816 which
// calls verify_chat_search_response with the ACI CondensedTreeSearchResponse and
// stored_account_data=Some(test_account_data()). The Go test exercises the
// equivalent path: VerifySearch on the ACI CondensedTreeSearchResponse with
// LastTreeHead populated from STORED_ACCOUNT_DATA_681.
//
// The valid_at timestamp comes from rust/net/tests/data/chat_response_valid_at.in.
// The stored account data hex is STORED_ACCOUNT_DATA_681 from
// rust/net/chat/src/api/keytrans.rs:631-633.
func TestKeytrans_ChatSearchResponse_VerifyACI(t *testing.T) {
	raw := loader.MustRead("net/chat_search_response.dat")
	resp, err := decodeChatSearchResponse(raw)
	if err != nil {
		t.Fatalf("decodeChatSearchResponse: %v", err)
	}
	if resp.ACI == nil {
		t.Fatal("ACI search response absent from fixture")
	}
	if resp.TreeHead == nil {
		t.Fatal("tree head absent from fixture")
	}

	// Decode the stored account data to extract the last_tree_head for context.
	storedBytes, err := hex.DecodeString(storedAccountData681Hex)
	if err != nil {
		t.Fatalf("decode stored account data hex: %v", err)
	}
	lastTreeHead, err := decodeStoredAccountDataLastTreeHead(storedBytes)
	if err != nil {
		t.Fatalf("decodeStoredAccountDataLastTreeHead: %v", err)
	}

	distinguishedTreeHead := buildDistinguishedLastTreeHead(t)

	config := buildStagingPublicConfig(t)
	kt := keytrans.KeyTransparency{Config: config}

	searchKey := aciSearchKey()
	req := keytrans.NewSlimSearchRequest(searchKey)
	fullResp := keytrans.NewFullSearchResponse(resp.ACI, resp.TreeHead)
	ctx := keytrans.SearchContext{
		LastTreeHead:              lastTreeHead,
		LastDistinguishedTreeHead: distinguishedTreeHead,
	}

	_, err = kt.VerifySearch(req, fullResp, ctx, true, chatSearchResponseValidAt)
	if err != nil {
		t.Fatalf("VerifySearch for ACI: %v", err)
	}
}

// TestKeytrans_ChatSearchResponse_VerifyACI_WrongTime confirms that verification
// fails when the current time is outside the allowed window, matching Rust's
// timestamp validation behaviour (server: 24h behind / 60s ahead).
func TestKeytrans_ChatSearchResponse_VerifyACI_WrongTime(t *testing.T) {
	raw := loader.MustRead("net/chat_search_response.dat")
	resp, err := decodeChatSearchResponse(raw)
	if err != nil {
		t.Fatalf("decodeChatSearchResponse: %v", err)
	}
	if resp.ACI == nil {
		t.Fatal("ACI absent from fixture")
	}

	storedBytes, err := hex.DecodeString(storedAccountData681Hex)
	if err != nil {
		t.Fatalf("decode stored account data hex: %v", err)
	}
	lastTreeHead, err := decodeStoredAccountDataLastTreeHead(storedBytes)
	if err != nil {
		t.Fatalf("decodeStoredAccountDataLastTreeHead: %v", err)
	}

	distinguishedTreeHead := buildDistinguishedLastTreeHead(t)

	config := buildStagingPublicConfig(t)
	kt := keytrans.KeyTransparency{Config: config}

	searchKey := aciSearchKey()
	req := keytrans.NewSlimSearchRequest(searchKey)
	fullResp := keytrans.NewFullSearchResponse(resp.ACI, resp.TreeHead)
	ctx := keytrans.SearchContext{
		LastTreeHead:              lastTreeHead,
		LastDistinguishedTreeHead: distinguishedTreeHead,
	}

	// Use a time far in the future so the tree head timestamp is too old.
	wrongTime := chatSearchResponseValidAt.Add(48 * time.Hour)
	_, err = kt.VerifySearch(req, fullResp, ctx, true, wrongTime)
	if err == nil {
		t.Fatal("expected error when current time is far in the future, got nil")
	}
}
