package sealed

import (
	"encoding/hex"
	"sync"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// knownServerCertificateEntry holds a pre-provisioned server certificate
// along with its associated trust root public key. These are well-known
// certificates that can be referenced by ID in SenderCertificate protobufs
// instead of embedding the full certificate bytes.
type knownServerCertificateEntry struct {
	// trustRoot is the XEd25519 public key (33 bytes with type prefix) that
	// signed this server certificate.
	trustRoot []byte
	// certData is the serialized ServerCertificate protobuf bytes.
	certData []byte
}

// knownServerCertificateData contains the raw certificate data for well-known
// server certificates, keyed by their key ID. These values are extracted from
// the Rust reference implementation's KNOWN_SERVER_CERTIFICATES constant.
//
// Each entry contains:
//   - Key ID (uint32)
//   - Trust root public key (33 bytes, XEd25519 with 0x05 type prefix)
//   - Serialized ServerCertificate protobuf bytes
var knownServerCertificateData = map[uint32]knownServerCertificateEntry{
	// Staging trust root certificate (key ID 2).
	2: {
		trustRoot: mustDecodeHex("058854ead3e3a8fe3a286644cd1b3538be14dfd5797653c9fd7d3d85ae2b12b926"),
		certData: mustDecodeHex(
			"0a25080212210539450d63ebd0752c0fd4038b9d07a916f5e174b756d409b5ca79f4c97400631e" +
				"124064c5a38b1e927497d3d4786b101a623ab34a7da3954fae126b04dba9d7a3604ed88cdc8550950f0d4a9134ceb7e19b94139151d2c3d6e1c81e9d1128aafca806",
		),
	},
	// Production trust root certificate (key ID 3).
	3: {
		trustRoot: mustDecodeHex("054918d08fbdfa83e00c29f8f8073a22ef35df2bea903aff81af03ccbc45c6e93a"),
		certData: mustDecodeHex(
			"0a250803122105bc9d1d290be964810dfa7e94856480a3f7060d004c9762c24c575a1522353a5a" +
				"1240c11ec3c401eb0107ab38f8600e8720a63169e0e2eb8a3fae24f63099f85ea319c3c1c46d3454706ae2a679d1fee690a488adda98a2290b66c906bb60295ed781",
		),
	},
	// Test certificate (key ID 0x7357C357).
	// Uses a trust root with private key of all zeros and a server certificate
	// for a private key of all 0xFF bytes. Never used in production.
	0x7357C357: {
		trustRoot: mustDecodeHex("052fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"),
		certData: mustDecodeHex(
			"0a2908d786df9a07122105847c0d2c375234f365e660955187a3735a0f7613d1609d3a6a4d8c53aeaa5a" +
				"221240e0b9ebacdfc3aa2827f7924b697784d1c25e44ca05dd433e1a38dc6382eb2730d419ca9a250b1be9d5a9463e61efd6781777a91b83c97b844d014206e2829785",
		),
	},
}

// knownCertEntry holds a resolved (deserialized) known server certificate
// and its associated trust root public key.
type knownCertEntry struct {
	trustRoot ecc.ECPublicKeyable
	cert      *ServerCertificate
}

var (
	knownCertsOnce sync.Once
	knownCertsMap  map[uint32]knownCertEntry
)

// resolvedKnownCertificates returns the lazily-initialized map of deserialized
// known server certificates. The map is built once and reused for the lifetime
// of the process.
func resolvedKnownCertificates() map[uint32]knownCertEntry {
	knownCertsOnce.Do(func() {
		knownCertsMap = make(map[uint32]knownCertEntry, len(knownServerCertificateData))
		for id, entry := range knownServerCertificateData {
			trustRoot, err := ecc.DecodePoint(entry.trustRoot, 0)
			if err != nil {
				panic("sealed: known server certificate trust root is invalid: " + err.Error())
			}
			cert, err := DeserializeServerCertificate(entry.certData)
			if err != nil {
				panic("sealed: known server certificate data is invalid: " + err.Error())
			}
			knownCertsMap[id] = knownCertEntry{
				trustRoot: trustRoot,
				cert:      cert,
			}
		}
	})
	return knownCertsMap
}

// lookupKnownServerCertificate resolves a server certificate ID to a known
// pre-provisioned ServerCertificate. Returns an error if the ID is not found.
func lookupKnownServerCertificate(id uint32) (*ServerCertificate, error) {
	entry, ok := resolvedKnownCertificates()[id]
	if !ok {
		return nil, newUnknownServerCertificateIDError(id)
	}
	return entry.cert, nil
}

// mustDecodeHex decodes a hex string and panics on failure. Used only for
// compile-time constant certificate data initialization.
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("sealed: invalid hex in known certificate data: " + err.Error())
	}
	return b
}
