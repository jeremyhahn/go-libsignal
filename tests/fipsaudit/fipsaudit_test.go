// Package fipsaudit statically audits the repository's production Go source
// for cryptographic primitives FIPS 140-3 does not approve.
//
// It complements the runtime FIPS gate (`make fips`, docs/FIPS.md) rather than
// duplicating it. The runtime gate is the stronger check where it applies, but
// it can only observe code a *gated test* actually executes, and the tests that
// drive the Signal Protocol are necessarily exempt from it (X25519 is the DH
// function of X3DH and the Double Ratchet). That leaves a hole: a new
// non-approved call added to a production path exercised only by an exempt test
// would compile and never run under `fips140=only`.
//
// This audit closes that hole from the other side, with two registers that fail
// for different reasons.
//
// The first reads every non-test .go file in the module and fails on any
// non-approved primitive imported, or called through a package qualifier, that
// is not in `register` — regardless of which tests, if any, reach it. It is
// file-and-symbol scoped and pins a count, so widening it is a visible diff with
// a reviewer, not a silent consequence of a build tag.
//
// Counting qualified references is exact for a direct call and blind to
// indirection. Once a file holds a curve25519.X25519 call, a package that calls
// that wrapper — or a function-valued alias of it — performs an X25519 operation
// while adding no selector anywhere, so no count rises. The second register,
// `reachRegister`, holds that boundary by import closure rather than by call
// graph: naming anything in a package requires importing it, so a package that
// gains the ability to perform a non-approved operation gains an import edge to
// the package holding it, through however many wrappers. An import edge cannot
// be hidden, where a syntactic call graph has to guess at methods, interface
// dispatch, function values and reflection, and every guess is a missed call.
// Most of the module's packages are absent from that register, which asserts
// something stronger than an exemption: no non-approved primitive is reachable
// from them at all.
//
// What it does not read is arithmetic. The audit classifies packages, so a
// primitive implemented in this repository's own source — SHA-1 or ChaCha20
// written out by hand, importing nothing denied — matches no rule and produces
// no finding. The runtime gate is equally blind to it, since such code never
// enters the Go Cryptographic Module. Nothing here enforces that case; a green
// run means "no non-approved primitive reached through a package outside the
// register", not "no non-approved cryptography in this repository"
// (docs/FIPS.md, "What the runtime gate cannot see").
//
// Nor does either register count an additional call, from inside a package
// already registered for a primitive, to a local wrapper of that primitive:
// there is no new qualified reference and no new import edge. What that leaves
// unflagged is one more use of a primitive the package is already exempt for, on
// a protocol path already cited in docs/FIPS.md — and every exemption here is
// protocol-wide rather than per-call-site (X25519 is the DH function of X3DH),
// so an additional call is not a new compliance decision.
// TestRegisterViolations_DoNotCountLocalWrapperCalls pins that boundary so it
// stays reviewed rather than becoming a surprise.
//
// It also covers what the runtime gate structurally cannot: pure-Go
// implementations that never reach the Go Cryptographic Module and so can never
// trip it. Ristretto255, edwards25519, Argon2id and Round-3 Kyber are every bit
// as non-approved as X25519; they were simply invisible. Here they are not.
//
// The audit is allowlist-based, not denylist-based. Inside the policed
// namespaces -- stdlib crypto/..., golang.org/x/crypto/... and the module's
// cryptographic dependencies -- a package must be classified as approved or as
// a registered exemption. Anything else is a finding purely for being
// unclassified, so a primitive nobody thought to enumerate (BLAKE2, say) fails
// closed rather than passing silently. TestModuleDependenciesAreClassified
// extends the same rule to go.mod, so a new cryptographic dependency cannot
// arrive in a namespace the audit does not police.
//
// The audit runs in `make test`, `make integration-test` and `make fips-test`:
// it parses source and executes no cryptography, so it is unaffected by
// GODEBUG=fips140=only and carries no build tag.
package fipsaudit

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// policedNamespaces are the import-path prefixes where every package must be
// classified. An import under one of these that appears in neither
// approvedCrypto nor the denied lists is a finding on its own -- the audit
// refuses to assume an unknown cryptographic package is safe.
//
// Everything outside these prefixes is ordinary application code and is not
// the audit's business; TestModuleDependenciesAreClassified is what stops a new
// cryptographic dependency from landing outside them unnoticed.
var policedNamespaces = []string{
	"crypto",
	"golang.org/x/crypto",
	"filippo.io/edwards25519",
	"github.com/gtank/ristretto255",
	"github.com/cloudflare/circl",
	"github.com/flynn/noise",
}

// approvedCrypto are the packages inside a policed namespace whose primitives
// FIPS 140-3 approves, or which carry no primitive at all. The value is the
// reason, so a reader can check the classification rather than trust it.
//
// crypto/cipher and crypto/ecdh are approved as packages but restricted by
// deniedSelectors: each offers both approved and non-approved constructions.
var approvedCrypto = map[string]string{
	"crypto":           "the hash and signer registry; carries no primitive of its own",
	"crypto/aes":       "AES, FIPS 197",
	"crypto/cipher":    "block cipher modes; the non-approved GCM constructors are handled by deniedSelectors",
	"crypto/ecdh":      "ECDH; P-256/384/521 are SP 800-56A Rev. 3, and X25519 is handled by deniedSelectors",
	"crypto/ecdsa":     "ECDSA, FIPS 186-5",
	"crypto/ed25519":   "EdDSA, FIPS 186-5",
	"crypto/elliptic":  "NIST curve parameters, FIPS 186-5",
	"crypto/hkdf":      "HKDF, SP 800-56C Rev. 2",
	"crypto/hmac":      "HMAC, FIPS 198-1",
	"crypto/mlkem":     "ML-KEM, FIPS 203",
	"crypto/pbkdf2":    "PBKDF2, SP 800-132",
	"crypto/rand":      "the module CSPRNG, SP 800-90A",
	"crypto/rsa":       "RSA, FIPS 186-5",
	"crypto/sha256":    "SHA-2, FIPS 180-4",
	"crypto/sha3":      "SHA-3, FIPS 202",
	"crypto/sha512":    "SHA-2, FIPS 180-4",
	"crypto/subtle":    "constant-time helpers; carries no primitive",
	"crypto/tls":       "TLS; the module constrains its cipher suites under fips140=only",
	"crypto/x509":      "certificate parsing; defers to the primitives above",
	"crypto/x509/pkix": "ASN.1 structures; carries no primitive",

	"golang.org/x/crypto/hkdf":       "a thin wrapper over crypto/hkdf since Go 1.24",
	"golang.org/x/crypto/cryptobyte": "ASN.1/DER encoding; carries no primitive",
}

// deniedImports are import paths whose whole purpose is a primitive FIPS 140-3
// does not approve. Importing one is a finding on its own, and so is every
// qualified call into it: the register pins how many occurrences a file is
// authorised to make, and counting only the import would let one line stand in
// for any number of uses.
//
// The value is the primitive's name, used in the failure message.
var deniedImports = map[string]string{
	"crypto/md5":                           "MD5",
	"crypto/sha1":                          "SHA-1",
	"crypto/des":                           "DES / Triple-DES",
	"crypto/rc4":                           "RC4",
	"crypto/hpke":                          "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)",
	"golang.org/x/crypto/curve25519":       "X25519",
	"golang.org/x/crypto/chacha20poly1305": "ChaCha20-Poly1305",
	"golang.org/x/crypto/chacha20":         "ChaCha20",
	"golang.org/x/crypto/blake2b":          "BLAKE2b",
	"golang.org/x/crypto/blake2s":          "BLAKE2s",
	"golang.org/x/crypto/poly1305":         "Poly1305",
	"golang.org/x/crypto/sha3":             "SHA-3 (use stdlib crypto/sha3)",
	"golang.org/x/crypto/blowfish":         "Blowfish",
	"golang.org/x/crypto/cast5":            "CAST5",
	"golang.org/x/crypto/twofish":          "Twofish",
	"golang.org/x/crypto/ripemd160":        "RIPEMD-160",
	"golang.org/x/crypto/md4":              "MD4",
	"golang.org/x/crypto/salsa20":          "Salsa20",
	"golang.org/x/crypto/salsa20/salsa":    "Salsa20",
	"golang.org/x/crypto/tea":              "TEA",
	"golang.org/x/crypto/xtea":             "XTEA",
	"golang.org/x/crypto/nacl/box":         "NaCl box (X25519 + Salsa20-Poly1305)",
	"golang.org/x/crypto/nacl/secretbox":   "NaCl secretbox (Salsa20-Poly1305)",
	"golang.org/x/crypto/nacl/sign":        "NaCl sign",
	"golang.org/x/crypto/openpgp/elgamal":  "ElGamal",

	// The pure-Go implementations the Go Cryptographic Module never sees. They
	// do their own field arithmetic, so GODEBUG=fips140=only cannot reject
	// them however the tests are tagged, and this audit is the only place they
	// can be caught at all.
	//
	// Each is named by exact package, never by module tree. CIRCL ships dozens
	// of algorithms: a `github.com/cloudflare/circl` prefix would let pkg/kem,
	// already registered for Kyber, import an unrelated signature or cipher
	// scheme and produce the same already-allowed finding. edwards25519 is
	// smaller but the same shape -- two packages today, and nothing says the
	// third is still curve arithmetic. Every unlisted package of these modules
	// is inside a policed namespace, so it fails closed as unclassified.
	"filippo.io/edwards25519":                         "edwards25519 group and field arithmetic",
	"filippo.io/edwards25519/field":                   "edwards25519 group and field arithmetic",
	"github.com/cloudflare/circl/kem/kyber/kyber1024": "Round-3 Kyber-1024 (CIRCL)",
	"github.com/gtank/ristretto255":                   "Ristretto255",
	"github.com/flynn/noise":                          "Noise Protocol Framework (25519 + ChaChaPoly patterns)",
	"golang.org/x/crypto/argon2":                      "Argon2id",
	"golang.org/x/crypto/bcrypt":                      "bcrypt",
	"golang.org/x/crypto/scrypt":                      "scrypt",
	"golang.org/x/crypto/ed25519":                     "Ed25519 (use crypto/ed25519)",
}

// deniedSelectors are individual functions of an otherwise-approved package.
// crypto/ecdh serves both P-256 (approved) and X25519 (not), and crypto/cipher
// offers both NewGCMWithRandomNonce (approved, SP 800-38D section 8.2.2) and
// the arbitrary-IV constructors the module rejects — so these cannot be judged
// by import path.
//
// The key is "<import path>.<function>"; the value is the primitive's name.
//
// Selector analysis assumes a qualified call. A dot import erases the
// qualifier -- `import . "crypto/ecdh"` turns ecdh.X25519() into a bare
// X25519() with no SelectorExpr to match -- so dotImportFinding below refuses
// a dot import of any package named here rather than analysing past it. The
// audit fails closed on a shape it cannot read.
var deniedSelectors = map[string]string{
	"crypto/ecdh.X25519":                "X25519",
	"crypto/cipher.NewGCM":              "AES-GCM under a caller-supplied nonce",
	"crypto/cipher.NewGCMWithNonceSize": "AES-GCM under a caller-supplied nonce",
	"crypto/cipher.NewGCMWithTagSize":   "AES-GCM under a caller-supplied nonce",
}

// register is the allowlist: the production sites where a non-approved
// primitive is mandated by the Signal Protocol or an external standard. It
// mirrors the exemption register in docs/FIPS.md and must stay in step with it.
//
// Keys are module-relative file paths; values are the primitive names from the
// two maps above. An entry that no longer matches anything in the tree is a
// failure too, so the register cannot rot into a blanket permission.
var register = map[string]map[string]int{
	// The X3DH DH function and the Double Ratchet's DH ratchet (X3DH section
	// 2.1, Double Ratchet section 5.2).
	"pkg/ecc/Curve.go":               {"X25519": 2},
	"pkg/ecc/guarded_key_pair.go":    {"X25519": 2},
	"pkg/ecc/guarded_private_key.go": {"X25519": 3},
	"pkg/kdf/HKDF.go":                {"X25519": 2},
	"pkg/sealed/sealed_sender_v2.go": {"X25519": 4},

	// RFC 9180 fixes DHKEM(X25519, HKDF-SHA256) for the
	// Base_X25519_HkdfSha256_Aes256Gcm suite (rust/crypto/src/hpke.rs).
	"pkg/cipher/hpke.go": {"HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)": 17, "X25519": 1},

	// The GCM nonce is derived by the protocol and carried on the wire, so it
	// cannot be replaced by the module-generated nonce of
	// NewGCMWithRandomNonce (rust/crypto/src/aes_gcm.rs).
	"pkg/cipher/aesgcm.go": {"AES-GCM under a caller-supplied nonce": 4},

	// Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256 names both primitives;
	// Noise_NK_25519_ChaChaPoly_SHA256 names X25519 (Noise Protocol Framework
	// rev 34). Signal uses these to reach its SGX and HSM enclaves.
	"pkg/attest/noise_nkhfs.go":        {"ChaCha20-Poly1305": 6, "X25519": 4},
	"pkg/attest/noise_nkhfs_server.go": {"X25519": 3},

	// Argon2id is the PIN-hashing function of Signal's SVR / registration lock
	// (Rust PinHash, rust/account-keys/src/hash.rs). FIPS 140-3 approves no
	// memory-hard password hash; PBKDF2 would change the stored hash.
	"pkg/accountkeys/accountkeys.go": {"Argon2id": 4},

	// flynn/noise implements the Noise patterns above. Listed separately from
	// the raw X25519 and ChaCha20-Poly1305 entries because the dependency
	// itself is a non-approved construction, not just a caller of one.
	"pkg/attest/client_connection.go": {"Noise Protocol Framework (25519 + ChaChaPoly patterns)": 7},
	"pkg/attest/enclave.go":           {"Noise Protocol Framework (25519 + ChaChaPoly patterns)": 5},
	"pkg/attest/hsm_enclave.go":       {"Noise Protocol Framework (25519 + ChaChaPoly patterns)": 5},

	// Elligator-2 maps a uniform field element to a Curve25519 point; it is
	// defined over that curve and has no NIST-curve analogue.
	"pkg/crypto/elligator/elligator.go": {"edwards25519 group and field arithmetic": 90},

	// XEdDSA and VXEdDSA sign with a Curve25519 identity key by converting it
	// to Edwards form (Signal XEdDSA specification, sections 2 and 4). FIPS
	// 140-3 approves Ed25519 itself (FIPS 186-5) but not this construction,
	// and the signatures are on the wire.
	"pkg/ecc/DjbECPublicKey.go": {"edwards25519 group and field arithmetic": 15},
	"pkg/ecc/SignCurve25519.go": {"edwards25519 group and field arithmetic": 21},
	"pkg/ecc/vxeddsa.go":        {"edwards25519 group and field arithmetic": 68},

	// Round-3 Kyber-1024, retained for back-compat with peers that have not
	// migrated to ML-KEM. The FIPS 203 algorithms this repository also ships
	// use stdlib crypto/mlkem and are approved, so they are absent here.
	"pkg/kem/guarded_kem.go": {"Round-3 Kyber-1024 (CIRCL)": 2},
	"pkg/kem/kyber.go":       {"Round-3 Kyber-1024 (CIRCL)": 2},

	// ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 section 5.5) is the VRF Signal's
	// key transparency tree is built on; the ciphersuite names the curve.
	"pkg/keytrans/vrf.go": {"edwards25519 group and field arithmetic": 21},

	// Ristretto255 (draft-irtf-cfrg-ristretto255-decaf448) is the prime-order
	// group Signal's zero-knowledge credentials are defined over -- the
	// Chase-Perrin-Zaverucha system (rust/poksho, rust/zkgroup,
	// rust/zkcredential) and the SVR OPRF. FIPS 140-3 approves no
	// Ristretto255 construction, and every group element here is on the wire.
	"pkg/poksho/proof.go":                                         {"Ristretto255": 31},
	"pkg/poksho/sign.go":                                          {"Ristretto255": 4},
	"pkg/svr/backup.go":                                           {"Ristretto255": 2},
	"pkg/svr/crypto.go":                                           {"Ristretto255": 26},
	"pkg/svr/restore.go":                                          {"Ristretto255": 11},
	"pkg/usernames/constants.go":                                  {"Ristretto255": 3},
	"pkg/usernames/username.go":                                   {"Ristretto255": 26},
	"pkg/zkcredential/attributes.go":                              {"Ristretto255": 37},
	"pkg/zkcredential/credentials.go":                             {"Ristretto255": 68},
	"pkg/zkcredential/endorsements.go":                            {"Ristretto255": 44},
	"pkg/zkcredential/issuance.go":                                {"Ristretto255": 6},
	"pkg/zkcredential/issuance_blind.go":                          {"Ristretto255": 34},
	"pkg/zkcredential/presentation.go":                            {"Ristretto255": 49},
	"pkg/zkcredential/room_credential.go":                         {"Ristretto255": 2},
	"pkg/zkcredential/sho.go":                                     {"Ristretto255": 11},
	"pkg/zkgroup/backups.go":                                      {"Ristretto255": 3},
	"pkg/zkgroup/call_links.go":                                   {"Ristretto255": 5},
	"pkg/zkgroup/crypto.go":                                       {"Ristretto255": 54},
	"pkg/zkgroup/group_send_endorsement.go":                       {"Ristretto255": 10},
	"pkg/zkgroup/groups.go":                                       {"Ristretto255": 5},
	"pkg/zkgroup/presentation_serialization.go":                   {"Ristretto255": 3},
	"pkg/zkgroup/profile_credentials.go":                          {"Ristretto255": 100},
	"pkg/zkgroup/profile_key_credential_presentation.go":          {"Ristretto255": 16},
	"pkg/zkgroup/profile_key_credential_request_serialization.go": {"Ristretto255": 8},
	"pkg/zkgroup/receipts.go":                                     {"Ristretto255": 57},
	"pkg/zkgroup/zkgroup.go":                                      {"Ristretto255": 5},
}

// reachRegister is the second half of the allowlist, and the one that survives
// indirection. registerViolations above pins direct uses file by file: exact
// for a qualified call, blind to everything else. Once pkg/kdf/HKDF.go holds a
// curve25519.X25519 call, a package that calls kdf.DeriveSecrets performs an
// X25519 operation without adding a selector anywhere, and so does a caller of
// a function-valued alias (`agree := curve25519.X25519`) invoked later. Neither
// raises an occurrence count, so neither shows up in a diff.
//
// This register closes that across package boundaries, and closes it by import
// closure rather than by call graph. A call graph built from syntax cannot be
// trusted: it has to guess at methods, interface dispatch, function values and
// reflection, and every guess is a way to miss a call. An import edge cannot be
// guessed at or hidden. To name anything in package P -- a function, a method,
// a variable holding a function -- a package must import P, so a package that
// gains the ability to perform a non-approved operation gains an import edge to
// the package holding it, however many wrappers lie in between.
//
// Keys are module-relative package directories; values are the primitives
// reachable from them, transitively. A package absent from this table asserts
// something stronger than an exemption: that no non-approved primitive is
// reachable from it at all. Most of the module's packages are absent.
//
// What it does not bound is a value handed across an interface: a package that
// receives an already-constructed object can drive it without importing its
// package. The package that *constructed* it did import, and is registered, so
// the set below still bounds where a non-approved operation can be introduced
// by static reference -- it does not claim to name every frame on the stack
// when one runs. See docs/FIPS.md, "What the runtime gate cannot see".
var reachRegister = map[string][]string{
	// The examples build the full protocol, so they reach what the protocol
	// reaches. They are not shipped as library code.
	"examples/group-messaging": {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"examples/sealed-sender":   {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"examples/simple-session":  {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},

	// Argon2id and the protected-memory layer; the PIN hash does not touch the curve.
	"pkg/accountkeys": {"Argon2id"},

	// The enclave transports: Noise_NK_25519_ChaChaPoly_SHA256 and its
	// post-quantum hybrid.
	"pkg/attest":              {"ChaCha20-Poly1305", "Noise Protocol Framework (25519 + ChaChaPoly patterns)", "X25519"},
	"pkg/backup":              {"AES-GCM under a caller-supplied nonce", "Argon2id", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/cipher":              {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "X25519"},
	"pkg/crypto/elligator":    {"edwards25519 group and field arithmetic"},
	"pkg/ecc":                 {"X25519", "edwards25519 group and field arithmetic"},
	"pkg/fingerprint":         {"X25519", "edwards25519 group and field arithmetic"},
	"pkg/groups":              {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/groups/ratchet":      {"X25519"},
	"pkg/groups/state/record": {"X25519", "edwards25519 group and field arithmetic"},
	"pkg/groups/state/store":  {"X25519", "edwards25519 group and field arithmetic"},
	"pkg/kdf":                 {"X25519"},
	"pkg/kem":                 {"Round-3 Kyber-1024 (CIRCL)"},
	"pkg/keys/chain":          {"X25519"},
	"pkg/keys/identity":       {"X25519", "edwards25519 group and field arithmetic"},
	"pkg/keys/prekey":         {"Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/keys/root":           {"X25519", "edwards25519 group and field arithmetic"},
	"pkg/keys/session":        {"X25519", "edwards25519 group and field arithmetic"},
	"pkg/keytrans":            {"edwards25519 group and field arithmetic"},
	"pkg/mlkembraid":          {"Round-3 Kyber-1024 (CIRCL)", "X25519"},
	"pkg/net":                 {"AES-GCM under a caller-supplied nonce", "ChaCha20-Poly1305", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Noise Protocol Framework (25519 + ChaChaPoly patterns)", "Ristretto255", "X25519"},
	"pkg/poksho":              {"Ristretto255"},
	"pkg/protocol":            {"X25519", "edwards25519 group and field arithmetic"},
	"pkg/ratchet":             {"Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/sealed":              {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/serialize":           {"Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/sesame":              {"Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/session":             {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/sessionmanagement":   {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/spqr":                {"Round-3 Kyber-1024 (CIRCL)", "X25519"},
	"pkg/state/record":        {"Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/state/store":         {"Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/svr":                 {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Ristretto255", "X25519"},
	"pkg/tripleratchet":       {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519"},
	"pkg/usernames":           {"Ristretto255"},
	"pkg/util/keyhelper":      {"Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
	"pkg/zkcredential":        {"Ristretto255"},
	"pkg/zkgroup":             {"AES-GCM under a caller-supplied nonce", "Argon2id", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Ristretto255", "X25519", "edwards25519 group and field arithmetic"},

	// The integration suite drives the protocol end to end.
	"tests": {"AES-GCM under a caller-supplied nonce", "HPKE (DHKEM(X25519, HKDF-SHA256) in this repository)", "Round-3 Kyber-1024 (CIRCL)", "X25519", "edwards25519 group and field arithmetic"},
}

// dependencyClassification records what every module in go.mod is, so a new
// cryptographic dependency cannot arrive in a namespace policedNamespaces does
// not cover. Modules inside a policed namespace are absent here: their packages
// are classified individually by approvedCrypto and the denied lists.
//
// "No cryptography" is a claim, so each value names what the module does
// instead.
var dependencyClassification = map[string]string{
	"github.com/Eyevinn/mp4ff":        "ISO-BMFF box-tree parsing for MP4 sanitisation; no cryptography",
	"golang.org/x/text":               "Unicode normalisation and encoding; no cryptography",
	"golang.org/x/sys":                "syscall wrappers; no cryptography",
	"google.golang.org/protobuf":      "wire serialisation; no cryptography",
	"pgregory.net/rapid":              "property-based testing, test-only; no cryptography",
	"github.com/kr/pretty":            "test output formatting, indirect; no cryptography",
	"github.com/rogpeppe/go-internal": "test tooling, indirect; no cryptography",

	// memcall is the syscall layer under go-enclave (formerly under memguard,
	// which this module replaced): mlock/mprotect wrappers, no cryptography.
	"github.com/awnumar/memcall": "mlock/mprotect syscall wrappers; no cryptography",

	// go-enclave is the portfolio locked-memory primitive (mlock + guard pages
	// + canary) that replaced memguard. Unlike memguard it holds material in
	// plaintext locked memory with no at-rest cipher, so it carries no
	// non-approved cryptography; its only crypto is the FIPS-approved crypto/rand
	// (SP 800-90A) for the canary and crypto/subtle for constant-time compares.
	"github.com/jeremyhahn/go-enclave": "the portfolio locked-memory primitive (mlock, guard pages, canary); only FIPS-approved crypto/rand and crypto/subtle",
}

// skipDirs are trees the audit does not own: generated protobuf code, the
// upstream Rust reference crate, and anything vendored.
var skipDirs = map[string]bool{
	".git":   true,
	"vendor": true,
	"rust":   true,
}

// unclassified is the sentinel classify returns for a policed import that is
// in neither approvedCrypto nor the denied lists.
const unclassified = "\x00unclassified"

// unclassifiedMarker prefixes the primitive name of an unclassified-import
// finding, for the same reason dotImportMarker does.
const unclassifiedMarker = "unclassified cryptographic package "

// classify decides what an import path is. It returns (primitive, true) for a
// denied path, (unclassified, false) for a policed path nobody has classified,
// and ("", false) for anything the audit does not police.
//
// Denied beats approved: a path in both lists is a mistake in the tables, and
// failing closed is the safe way to surface it.
func classify(path string) (string, bool) {
	if primitive, denied := deniedImports[path]; denied {
		return primitive, true
	}
	if !policed(path) {
		return "", false
	}
	if _, approved := approvedCrypto[path]; approved {
		return "", false
	}
	return unclassified, false
}

// dotImportMarker prefixes the primitive name of a dot-import finding, so the
// failure can be reported in its own words rather than as "uses <primitive>".
const dotImportMarker = "dot import of "

// finding is one non-approved use at one position.
type finding struct {
	File      string // module-relative
	Line      int
	Primitive string
}

// selectorAnalysedPackages are the import paths deniedSelectors distinguishes
// approved from non-approved use within. A dot import of one of these defeats
// that analysis, so it is itself a finding.
func selectorAnalysedPackages() map[string]bool {
	out := map[string]bool{}
	for key := range deniedSelectors {
		out[key[:strings.LastIndex(key, ".")]] = true
	}
	return out
}

// policed reports whether an import path falls inside a namespace the audit
// classifies. Matching is on the tree root or a subpackage of it, so
// "crypto/sha256" is policed and a hypothetical "cryptoxyz" is not.
func policed(path string) bool {
	for _, ns := range policedNamespaces {
		if path == ns || strings.HasPrefix(path, ns+"/") {
			return true
		}
	}
	return false
}

// scanFile parses one Go source file and reports every non-approved primitive
// it uses. relPath is used only to label findings.
func scanFile(relPath string, src []byte) ([]finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, relPath, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	var out []finding
	// local name -> import path, for resolving selector expressions.
	byLocalName := map[string]string{}
	selectorAnalysed := selectorAnalysedPackages()

	for _, spec := range file.Imports {
		path, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil {
			continue
		}
		line := fset.Position(spec.Pos()).Line
		switch primitive, denied := classify(path); {
		case denied:
			out = append(out, finding{relPath, line, primitive})
		case primitive == unclassified:
			out = append(out, finding{relPath, line, unclassifiedMarker + path})
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." && (selectorAnalysed[path] || deniedImports[path] != "") {
			out = append(out, finding{relPath, fset.Position(spec.Pos()).Line, dotImportMarker + path})
		}
		byLocalName[name] = path
	}

	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		path, known := byLocalName[ident.Name]
		if !known {
			return true
		}
		if primitive, denied := deniedSelectors[path+"."+sel.Sel.Name]; denied {
			out = append(out, finding{relPath, fset.Position(sel.Pos()).Line, primitive})
			return true
		}
		// Every qualified reference into a denied package is its own
		// occurrence, not a repeat of the import. The register pins how many
		// a file is authorised to make, so counting uses -- rather than
		// counting the one import that admits them -- is what makes a second
		// use of an already-exempt primitive a visible widening.
		if primitive, denied := deniedImports[path]; denied {
			out = append(out, finding{relPath, fset.Position(sel.Pos()).Line, primitive})
		}
		return true
	})
	return out, nil
}

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test's working directory")
		}
		dir = parent
	}
}

// auditTree scans every non-test .go file under root and returns, for each
// module-relative path, how many times each non-approved primitive occurs in
// it. Occurrences are counted rather than deduplicated: the register pins the
// count, so a second use of a primitive a file is already exempt for is a
// change the register has to acknowledge.
func auditTree(t *testing.T, root string) map[string]map[string]int {
	t.Helper()
	found := map[string]map[string]int{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		findings, scanErr := scanFile(rel, src)
		if scanErr != nil {
			t.Errorf("%s: parse failed: %v", rel, scanErr)
			return nil
		}
		for _, f := range findings {
			if found[f.File] == nil {
				found[f.File] = map[string]int{}
			}
			found[f.File][f.Primitive]++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return found
}

// sortedPrimitives returns a file's primitive names in a stable order, for
// failure messages.
func sortedPrimitives(counts map[string]int) []string {
	names := make([]string, 0, len(counts))
	for p := range counts {
		names = append(names, p)
	}
	sort.Strings(names)
	return names
}

// registerViolations compares what production source actually does against
// what the register authorises, in the direction the gate cares about: a file
// nobody registered, a primitive that file is not registered for, or *more
// occurrences* of a registered primitive than the register accounts for.
//
// The count is the point. A register of file-and-primitive pairs alone would
// let a second X25519 operation land in a file already exempt for X25519
// without changing anything a reviewer sees. Pinning the number means every
// new use of an already-exempt primitive has to raise it, in a diff, with the
// same justification a new entry needs.
//
// Marker-prefixed primitives (dot imports, unclassified packages) are never
// registrable and are reported by the caller instead.
func registerViolations(found, reg map[string]map[string]int) []string {
	var out []string
	for _, file := range sortedFiles(found) {
		registrable := map[string]int{}
		for p, n := range found[file] {
			if !strings.HasPrefix(p, dotImportMarker) && !strings.HasPrefix(p, unclassifiedMarker) {
				registrable[p] = n
			}
		}
		if len(registrable) == 0 {
			continue
		}
		allowed, listed := reg[file]
		if !listed {
			out = append(out, fmt.Sprintf("%s uses %v, which FIPS 140-3 does not approve, and is "+
				"not in the register.\nFix the call site if an approved primitive will do. Only "+
				"if an external protocol or standard mandates it, add the file here and to "+
				"docs/FIPS.md with the citation.", file, sortedPrimitives(registrable)))
			continue
		}
		for _, p := range sortedPrimitives(registrable) {
			switch limit := allowed[p]; {
			case limit == 0:
				out = append(out, fmt.Sprintf("%s uses %q, which is not among its registered "+
					"primitives %v.\nWidening an existing entry needs the same justification as "+
					"a new one; see docs/FIPS.md.", file, p, sortedPrimitives(allowed)))
			case registrable[p] > limit:
				out = append(out, fmt.Sprintf("%s uses %q %d times, but the register authorises "+
					"%d.\nA new use of an already-exempt primitive is a widening like any other: "+
					"justify it, then raise the count here and in docs/FIPS.md.",
					file, p, registrable[p], limit))
			}
		}
	}
	return out
}

// sortedFiles returns the keys of a per-file map in a stable order, so failures
// read the same way on every run.
func sortedFiles(m map[string]map[string]int) []string {
	files := make([]string, 0, len(m))
	for f := range m {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

// TestFIPSAudit_ProductionCodeMatchesRegister is the gate. Every non-approved
// primitive in production code must appear in the register, no more often than
// the register authorises, and every register entry must still describe
// something the tree actually does.
func TestFIPSAudit_ProductionCodeMatchesRegister(t *testing.T) {
	root := moduleRoot(t)
	found := auditTree(t, root)

	if len(found) == 0 {
		t.Fatal("audit found nothing at all; the walk or the parser is broken, " +
			"because the register below is non-empty and its files are checked in")
	}

	for _, file := range sortedFiles(found) {
		for _, p := range sortedPrimitives(found[file]) {
			if path, ok := strings.CutPrefix(p, dotImportMarker); ok {
				t.Errorf("%s dot-imports %s. That erases the package qualifier, so this "+
					"audit can neither tell an approved call there from a non-approved one "+
					"nor count the uses it authorises, and refuses to guess. Import it "+
					"normally.", file, path)
			}
			if path, ok := strings.CutPrefix(p, unclassifiedMarker); ok {
				t.Errorf("%s imports %s, which is inside a policed namespace but classified "+
					"nowhere.\nAdd it to approvedCrypto with the standard that approves it, or "+
					"to deniedImports plus this file's register and "+
					"docs/FIPS.md. The audit does not assume an unknown cryptographic package "+
					"is safe.", file, path)
			}
		}
	}

	for _, msg := range registerViolations(found, register) {
		t.Error(msg)
	}
}

// TestFIPSAudit_RegisterHasNoStaleEntries keeps the register honest in the
// other direction: an entry whose file is gone, whose primitive is no longer
// used, or whose count is higher than the file's actual uses is a standing
// permission nobody needs. The count check is what stops a widening from
// outliving the code that justified it.
func TestFIPSAudit_RegisterHasNoStaleEntries(t *testing.T) {
	root := moduleRoot(t)
	found := auditTree(t, root)

	exists := func(file string) bool {
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(file)))
		return err == nil
	}
	for _, msg := range staleRegisterEntries(found, register, exists) {
		t.Error(msg)
	}
}

// staleRegisterEntries reports permissions the code no longer needs: an entry
// whose file is gone, whose primitive is unused, or whose count exceeds the
// file's actual uses. Together with registerViolations it pins the count
// exactly, in both directions, so the register tracks the code rather than
// drifting above it.
func staleRegisterEntries(found, reg map[string]map[string]int, exists func(string) bool) []string {
	var out []string
	for _, file := range sortedFiles(reg) {
		allowed := reg[file]
		if !exists(file) {
			out = append(out, fmt.Sprintf("register lists %s, which does not exist; drop the "+
				"entry and the matching row in docs/FIPS.md", file))
			continue
		}
		for _, p := range sortedPrimitives(allowed) {
			switch uses := found[file][p]; {
			case uses == 0:
				out = append(out, fmt.Sprintf("register allows %q in %s, but the file no longer "+
					"uses it; drop the entry and the matching row in docs/FIPS.md", p, file))
			case uses < allowed[p]:
				out = append(out, fmt.Sprintf("register authorises %d uses of %q in %s, but the "+
					"file makes %d; lower the count so the exemption stays no wider than the "+
					"code needs", allowed[p], p, file, uses))
			}
		}
	}
	return out
}

// modulePath extracts this module's own import path from go.mod, so the import
// graph below can tell an import of this module from a third-party one without
// the path being written down twice.
func modulePath(src string) string {
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if path, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(path)
		}
	}
	return ""
}

// moduleImports returns the module-relative package directories one file
// imports from this module. It parses with parser.ImportsOnly, which stops at
// the end of the import block, so building the graph costs a fraction of a full
// parse even though every file is read twice.
func moduleImports(module, relPath string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, relPath, src, parser.ImportsOnly|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, spec := range file.Imports {
		path, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil {
			continue
		}
		if dir, ok := strings.CutPrefix(path, module+"/"); ok {
			out = append(out, dir)
		}
	}
	return out, nil
}

// packageGraph is the input to reachability: which module packages each package
// imports, and which non-approved primitives each one names directly.
type packageGraph struct {
	imports map[string]map[string]bool // package dir -> imported package dirs
	direct  map[string]map[string]bool // package dir -> primitives used in its own source
}

// registrablePrimitive reports whether a finding names a primitive the register
// can authorise. Dot imports and unclassified packages are reported in their own
// words instead, and are not primitives, so they do not propagate.
func registrablePrimitive(primitive string) bool {
	return !strings.HasPrefix(primitive, dotImportMarker) &&
		!strings.HasPrefix(primitive, unclassifiedMarker)
}

// reachablePrimitives propagates each package's direct uses backwards along the
// import edges until nothing changes: the result is, for every package, every
// non-approved primitive reachable from it. Go forbids import cycles, so the
// fixed point converges in as many rounds as the graph is deep; iterating to
// quiescence rather than assuming a depth keeps it correct if that ever stops
// being true.
func reachablePrimitives(g packageGraph) map[string]map[string]bool {
	reach := map[string]map[string]bool{}
	for pkg, primitives := range g.direct {
		reach[pkg] = map[string]bool{}
		for p := range primitives {
			reach[pkg][p] = true
		}
	}
	for {
		changed := false
		for pkg, deps := range g.imports {
			for dep := range deps {
				for p := range reach[dep] {
					if reach[pkg] == nil {
						reach[pkg] = map[string]bool{}
					}
					if !reach[pkg][p] {
						reach[pkg][p] = true
						changed = true
					}
				}
			}
		}
		if !changed {
			return reach
		}
	}
}

// auditGraph walks the tree the way auditTree does and builds the import graph
// alongside each package's direct non-approved uses.
func auditGraph(t *testing.T, root, module string) packageGraph {
	t.Helper()
	g := packageGraph{
		imports: map[string]map[string]bool{},
		direct:  map[string]map[string]bool{},
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		pkg := pathDir(rel)

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if g.imports[pkg] == nil {
			g.imports[pkg] = map[string]bool{}
		}
		deps, impErr := moduleImports(module, rel, src)
		if impErr != nil {
			t.Errorf("%s: parse failed: %v", rel, impErr)
			return nil
		}
		for _, dep := range deps {
			g.imports[pkg][dep] = true
		}

		findings, scanErr := scanFile(rel, src)
		if scanErr != nil {
			t.Errorf("%s: parse failed: %v", rel, scanErr)
			return nil
		}
		for _, f := range findings {
			if !registrablePrimitive(f.Primitive) {
				continue
			}
			if g.direct[pkg] == nil {
				g.direct[pkg] = map[string]bool{}
			}
			g.direct[pkg][f.Primitive] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return g
}

// pathDir is filepath.Dir for a slash-separated module-relative path, returning
// "" for a file at the module root so the register never carries a "." key.
func pathDir(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return ""
}

// sortedSet returns a primitive set in a stable order, for comparison and for
// failure messages.
func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// reachViolations reports packages that reach a non-approved primitive the
// reachability register does not authorise: a package absent from it entirely,
// or a primitive absent from that package's list.
func reachViolations(reach map[string]map[string]bool, reg map[string][]string) []string {
	var out []string
	for _, pkg := range sortedReachPackages(reach) {
		if len(reach[pkg]) == 0 {
			continue
		}
		allowed, listed := reg[pkg]
		if !listed {
			out = append(out, fmt.Sprintf("package %s can reach %v, which FIPS 140-3 does "+
				"not approve, and is not in the reachability register.\nAn import edge into a "+
				"registered package is how a wrapper, an alias or a method value carries a "+
				"non-approved operation into new code. If the package needs that reach, add it "+
				"here and to docs/FIPS.md with the reason; if it does not, drop the import.",
				pkgLabel(pkg), sortedSet(reach[pkg])))
			continue
		}
		for _, p := range sortedSet(reach[pkg]) {
			if !containsString(allowed, p) {
				out = append(out, fmt.Sprintf("package %s can now reach %q, which is not among "+
					"its registered primitives %v.\nWidening a package's reach needs the same "+
					"justification as a new entry; see docs/FIPS.md.", pkgLabel(pkg), p, allowed))
			}
		}
	}
	return out
}

// staleReachEntries keeps the reachability register honest in the other
// direction: a package that is gone, or a primitive it can no longer reach, is
// a standing permission nobody needs.
func staleReachEntries(reach map[string]map[string]bool, reg map[string][]string, exists func(string) bool) []string {
	var out []string
	pkgs := make([]string, 0, len(reg))
	for pkg := range reg {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	for _, pkg := range pkgs {
		if !exists(pkg) {
			out = append(out, fmt.Sprintf("reachability register lists package %s, which does "+
				"not exist; drop the entry and the matching row in docs/FIPS.md", pkgLabel(pkg)))
			continue
		}
		for _, p := range reg[pkg] {
			if !reach[pkg][p] {
				out = append(out, fmt.Sprintf("reachability register allows %q in package %s, "+
					"which can no longer reach it; drop the primitive so the exemption stays no "+
					"wider than the code needs", p, pkgLabel(pkg)))
			}
		}
	}
	return out
}

// sortedReachPackages returns reachability keys in a stable order.
func sortedReachPackages(reach map[string]map[string]bool) []string {
	pkgs := make([]string, 0, len(reach))
	for pkg := range reach {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	return pkgs
}

// pkgLabel names the module root readably; every other package is its directory.
func pkgLabel(pkg string) string {
	if pkg == "" {
		return "(module root)"
	}
	return pkg
}

// TestFIPSAudit_PackageReachMatchesRegister is the gate against indirection.
// The per-file register above counts direct uses and cannot see a wrapper or a
// function-valued alias; this one holds the import closure, which no wrapper can
// step around. A package that gains an import edge to non-approved cryptography
// fails here until the register says it may have one.
func TestFIPSAudit_PackageReachMatchesRegister(t *testing.T) {
	root := moduleRoot(t)
	module := moduleImportPath(t, root)
	reach := reachablePrimitives(auditGraph(t, root, module))

	if len(reach) == 0 {
		t.Fatal("reachability found nothing at all; the walk or the parser is broken, " +
			"because the register below is non-empty and its packages are checked in")
	}

	for _, msg := range reachViolations(reach, reachRegister) {
		t.Error(msg)
	}
}

// TestFIPSAudit_ReachRegisterHasNoStaleEntries stops the reachability register
// from outliving the imports that earned it.
func TestFIPSAudit_ReachRegisterHasNoStaleEntries(t *testing.T) {
	root := moduleRoot(t)
	module := moduleImportPath(t, root)
	reach := reachablePrimitives(auditGraph(t, root, module))

	exists := func(pkg string) bool {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(pkg)))
		return err == nil && info.IsDir()
	}
	for _, msg := range staleReachEntries(reach, reachRegister, exists) {
		t.Error(msg)
	}
}

// moduleImportPath reads this module's import path from go.mod.
func moduleImportPath(t *testing.T, root string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	module := modulePath(string(src))
	if module == "" {
		t.Fatal("no module directive in go.mod; the import graph cannot tell this module's " +
			"packages from third-party ones without it")
	}
	return module
}

// TestReachablePrimitives_FollowsAWrapperAndAnAlias is the regression for the
// gap the per-file counts cannot close. Two synthetic packages: one holds the
// X25519 call and re-exports it as a function value, the other only calls into
// it. The caller names no denied package and makes no denied selector, so
// scanFile reports nothing for it -- yet reachability must find X25519 there,
// through the wrapper and through the alias alike.
func TestReachablePrimitives_FollowsAWrapperAndAnAlias(t *testing.T) {
	const module = "example.test/m"

	// The registered package: a wrapper function and a function-valued alias.
	low := []byte(`package low

import "golang.org/x/crypto/curve25519"

// Agree is the alias: taking the value, not calling it.
var Agree = curve25519.X25519

func Wrap(a, b []byte) ([]byte, error) { return curve25519.X25519(a, b) }
`)
	// The new caller: no denied import, no denied selector, two indirect uses.
	high := []byte(`package high

import "example.test/m/pkg/low"

func ViaWrapper(a, b []byte) ([]byte, error) { return low.Wrap(a, b) }

func ViaAlias(a, b []byte) ([]byte, error) { return low.Agree(a, b) }
`)

	highFindings, err := scanFile("pkg/high/high.go", high)
	if err != nil {
		t.Fatalf("scanFile(high): %v", err)
	}
	if len(highFindings) != 0 {
		t.Fatalf("scanFile reported %v for the caller; the premise of this test is that "+
			"per-file scanning cannot see indirection", highFindings)
	}

	lowFindings, err := scanFile("pkg/low/low.go", low)
	if err != nil {
		t.Fatalf("scanFile(low): %v", err)
	}
	g := packageGraph{
		imports: map[string]map[string]bool{"pkg/low": {}, "pkg/high": {}},
		direct:  map[string]map[string]bool{},
	}
	deps, err := moduleImports(module, "pkg/high/high.go", high)
	if err != nil {
		t.Fatalf("moduleImports(high): %v", err)
	}
	for _, dep := range deps {
		g.imports["pkg/high"][dep] = true
	}
	for _, f := range lowFindings {
		if !registrablePrimitive(f.Primitive) {
			continue
		}
		if g.direct["pkg/low"] == nil {
			g.direct["pkg/low"] = map[string]bool{}
		}
		g.direct["pkg/low"][f.Primitive] = true
	}

	reach := reachablePrimitives(g)
	if !reach["pkg/high"]["X25519"] {
		t.Errorf("pkg/high reaches X25519 through a wrapper and a function-valued alias, but "+
			"reachability reported %v; the audit would let a new non-approved operation land "+
			"without a register change", sortedSet(reach["pkg/high"]))
	}
	if !reach["pkg/low"]["X25519"] {
		t.Errorf("pkg/low uses X25519 directly, but reachability reported %v",
			sortedSet(reach["pkg/low"]))
	}
}

// TestReachablePrimitives_StopsWithoutAnImportEdge is the other half: taint must
// not smear across the whole module. A package with no path to a denied one
// stays clean, which is what makes the register's absences meaningful.
func TestReachablePrimitives_StopsWithoutAnImportEdge(t *testing.T) {
	g := packageGraph{
		imports: map[string]map[string]bool{
			"pkg/ecc":       {},
			"pkg/session":   {"pkg/ecc": true},
			"pkg/proto":     {},
			"pkg/unrelated": {"pkg/proto": true},
		},
		direct: map[string]map[string]bool{"pkg/ecc": {"X25519": true}},
	}
	reach := reachablePrimitives(g)

	if !reach["pkg/session"]["X25519"] {
		t.Error("pkg/session imports pkg/ecc, so X25519 must be reachable from it")
	}
	if len(reach["pkg/unrelated"]) != 0 {
		t.Errorf("pkg/unrelated has no path to a denied package, but reachability reported %v",
			sortedSet(reach["pkg/unrelated"]))
	}
	if len(reach["pkg/proto"]) != 0 {
		t.Errorf("pkg/proto has no path to a denied package, but reachability reported %v",
			sortedSet(reach["pkg/proto"]))
	}
}

// TestReachablePrimitives_PropagatesThroughAChain checks the fixed point rather
// than a single hop: a primitive three imports deep must still surface, because
// a wrapper around a wrapper is the ordinary shape of a layered protocol stack.
func TestReachablePrimitives_PropagatesThroughAChain(t *testing.T) {
	g := packageGraph{
		imports: map[string]map[string]bool{
			"pkg/a": {"pkg/b": true},
			"pkg/b": {"pkg/c": true},
			"pkg/c": {"pkg/d": true},
			"pkg/d": {},
		},
		direct: map[string]map[string]bool{"pkg/d": {"Ristretto255": true}},
	}
	reach := reachablePrimitives(g)

	for _, pkg := range []string{"pkg/a", "pkg/b", "pkg/c", "pkg/d"} {
		if !reach[pkg]["Ristretto255"] {
			t.Errorf("%s reaches Ristretto255 through the import chain, but reachability "+
				"reported %v", pkg, sortedSet(reach[pkg]))
		}
	}
}

// TestReachViolations_RejectsANewPackageAndANewPrimitive covers both failure
// directions of the reachability gate: a package nobody registered, and a
// registered package whose reach has widened to a primitive its entry does not
// list.
func TestReachViolations_RejectsANewPackageAndANewPrimitive(t *testing.T) {
	reg := map[string][]string{"pkg/ecc": {"X25519"}}
	reach := map[string]map[string]bool{
		"pkg/ecc":       {"X25519": true, "Ristretto255": true},
		"pkg/newcomer":  {"X25519": true},
		"pkg/untainted": {},
	}

	msgs := reachViolations(reach, reg)
	if len(msgs) != 2 {
		t.Fatalf("expected one violation for the unregistered package and one for the widened "+
			"entry, got %d: %v", len(msgs), msgs)
	}
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined, "pkg/newcomer") {
		t.Errorf("an unregistered package that reaches X25519 must fail; got %v", msgs)
	}
	if !strings.Contains(joined, "Ristretto255") {
		t.Errorf("a registered package that reaches a primitive its entry omits must fail; "+
			"got %v", msgs)
	}
	if strings.Contains(joined, "pkg/untainted") {
		t.Errorf("a package that reaches nothing must not be reported; got %v", msgs)
	}
}

// TestStaleReachEntries_ShrinkWithTheCode is the register's other direction: a
// package that no longer exists, and a primitive it can no longer reach, must
// both fail rather than sitting as a permission nothing needs.
func TestStaleReachEntries_ShrinkWithTheCode(t *testing.T) {
	reg := map[string][]string{
		"pkg/ecc":     {"X25519", "Ristretto255"},
		"pkg/deleted": {"X25519"},
		"pkg/kdf":     {"X25519"},
	}
	reach := map[string]map[string]bool{
		"pkg/ecc": {"X25519": true},
		"pkg/kdf": {"X25519": true},
	}
	exists := func(pkg string) bool { return pkg != "pkg/deleted" }

	msgs := staleReachEntries(reach, reg, exists)
	if len(msgs) != 2 {
		t.Fatalf("expected one stale package and one stale primitive, got %d: %v", len(msgs), msgs)
	}
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined, "pkg/deleted") {
		t.Errorf("a register entry for a package that is gone must fail; got %v", msgs)
	}
	if !strings.Contains(joined, "Ristretto255") {
		t.Errorf("a primitive a package can no longer reach must fail; got %v", msgs)
	}
}

// TestModuleImports_ReadsOnlyThisModule keeps the import graph from either
// missing an edge or inventing one: an aliased or blank import of a module
// package is still an edge, and a third-party path that merely shares a prefix
// is not.
func TestModuleImports_ReadsOnlyThisModule(t *testing.T) {
	src := []byte(`package p

import (
	"crypto/sha256"

	ecc "example.test/m/pkg/ecc"
	_ "example.test/m/pkg/proto"
	"example.test/module-lookalike/pkg/other"
	"golang.org/x/crypto/curve25519"
)

var (
	_ = sha256.New
	_ = ecc.GenerateKeyPair
	_ = other.Thing
	_ = curve25519.ScalarBaseMult
)
`)
	got, err := moduleImports("example.test/m", "pkg/p/p.go", src)
	if err != nil {
		t.Fatalf("moduleImports: %v", err)
	}
	sort.Strings(got)
	want := []string{"pkg/ecc", "pkg/proto"}
	if len(got) != len(want) {
		t.Fatalf("module imports = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("module imports = %v, want %v", got, want)
		}
	}
}

// TestModulePath_ReadsTheModuleDirective covers the one line the import graph
// depends on, and the failure the gate must not paper over: no directive means
// no way to tell this module's packages from anyone else's.
func TestModulePath_ReadsTheModuleDirective(t *testing.T) {
	if got := modulePath("module github.com/jeremyhahn/go-libsignal\n\ngo 1.26.6\n"); got != "github.com/jeremyhahn/go-libsignal" {
		t.Errorf("modulePath = %q, want the module's import path", got)
	}
	if got := modulePath("go 1.26.6\n\nrequire golang.org/x/crypto v0.52.0\n"); got != "" {
		t.Errorf("modulePath = %q for a file with no module directive, want the empty "+
			"string so the gate fails rather than guessing", got)
	}
}

// TestRegisterViolations_DoNotCountLocalWrapperCalls pins a limit rather than a
// guarantee, so it stays a reviewed boundary instead of becoming a surprise.
//
// Inside a package already registered for a primitive, a new call to a local
// wrapper of that primitive adds no occurrence, because there is no new
// qualified reference to count. reachRegister is what bounds this: the widening
// cannot leave the package without an import edge, and an edge into a new
// package fails the reachability gate. What is left unflagged is one more use of
// a primitive that package is already exempt for, on a protocol path already
// documented in docs/FIPS.md -- and for this repository those exemptions are
// protocol-wide (X25519 is the DH function of X3DH), never per-call-site, so an
// additional call is not a new compliance decision.
func TestRegisterViolations_DoNotCountLocalWrapperCalls(t *testing.T) {
	src := []byte(`package kdf

import "golang.org/x/crypto/curve25519"

func agree(a, b []byte) ([]byte, error) { return curve25519.X25519(a, b) }

// Added later: two more production paths, no new qualified reference.
func RootKey(a, b []byte) ([]byte, error)  { return agree(a, b) }
func ChainKey(a, b []byte) ([]byte, error) { return agree(a, b) }
`)
	findings, err := scanFile("pkg/kdf/HKDF.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}

	found := map[string]map[string]int{"pkg/kdf/HKDF.go": {}}
	for _, f := range findings {
		found[f.File][f.Primitive]++
	}
	// The import and the one qualified call: two occurrences, not four.
	if got := found["pkg/kdf/HKDF.go"]["X25519"]; got != 2 {
		t.Fatalf("occurrences = %d, want 2 (the import and the single qualified call); if this "+
			"changed, the limit this test documents has changed with it", got)
	}
	if msgs := registerViolations(found, map[string]map[string]int{
		"pkg/kdf/HKDF.go": {"X25519": 2},
	}); len(msgs) != 0 {
		t.Fatalf("expected the local calls to go uncounted, which is the documented limit; "+
			"got %v", msgs)
	}
}

// TestRegisterViolations_CountsPinEveryUse is the regression for the register's
// widest fail-open: a register of file-and-primitive pairs authorises a file
// once and then absorbs every later use of that primitive silently. Counting
// occurrences is what turns the second use into a failure the author has to
// justify and a reviewer can see.
func TestRegisterViolations_CountsPinEveryUse(t *testing.T) {
	reg := map[string]map[string]int{
		"pkg/ecc/Curve.go":     {"X25519": 2},
		"pkg/cipher/aesgcm.go": {"AES-GCM under a caller-supplied nonce": 4},
	}
	cases := []struct {
		name  string
		found map[string]map[string]int
		want  string // substring the violation must carry; "" means no violation
	}{
		{
			name:  "exactly the authorised uses",
			found: map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 2}},
		},
		{
			name:  "one more use of an already-exempt primitive",
			found: map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 3}},
			want:  `uses "X25519" 3 times, but the register authorises 2`,
		},
		{
			name:  "another arbitrary-nonce GCM construction in an exempt file",
			found: map[string]map[string]int{"pkg/cipher/aesgcm.go": {"AES-GCM under a caller-supplied nonce": 5}},
			want:  "5 times, but the register authorises 4",
		},
		{
			name:  "a different primitive in an exempt file",
			found: map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 2, "Ristretto255": 1}},
			want:  `uses "Ristretto255", which is not among its registered primitives`,
		},
		{
			name:  "an unregistered file",
			found: map[string]map[string]int{"pkg/new/thing.go": {"X25519": 1}},
			want:  "is not in the register",
		},
		{
			name:  "fewer uses than authorised is not a violation here",
			found: map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 1}},
		},
		{
			name: "markers are never registrable and never counted",
			found: map[string]map[string]int{
				"pkg/new/thing.go": {unclassifiedMarker + "crypto/blake3": 1, dotImportMarker + "crypto/ecdh": 1},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := registerViolations(c.found, reg)
			switch {
			case c.want == "":
				if len(got) != 0 {
					t.Errorf("expected no violation, got %v", got)
				}
			case len(got) != 1:
				t.Errorf("expected exactly one violation containing %q, got %v", c.want, got)
			case !strings.Contains(got[0], c.want):
				t.Errorf("violation %q does not mention %q", got[0], c.want)
			}
		})
	}
}

// TestStaleRegisterEntries_CountsShrinkWithTheCode is the other direction: an
// exemption must stay no wider than the code needs, so a count left above the
// file's actual uses -- or an entry whose file or primitive is gone -- fails
// just as a missing entry does.
func TestStaleRegisterEntries_CountsShrinkWithTheCode(t *testing.T) {
	reg := map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 2}}
	present := func(string) bool { return true }

	cases := []struct {
		name   string
		found  map[string]map[string]int
		exists func(string) bool
		want   string
	}{
		{
			name:   "count matches the code",
			found:  map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 2}},
			exists: present,
		},
		{
			name:   "a use was removed but the count was not lowered",
			found:  map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 1}},
			exists: present,
			want:   "authorises 2 uses",
		},
		{
			name:   "the primitive is gone entirely",
			found:  map[string]map[string]int{"pkg/ecc/Curve.go": {}},
			exists: present,
			want:   "no longer uses it",
		},
		{
			name:   "the file is gone",
			found:  map[string]map[string]int{},
			exists: func(string) bool { return false },
			want:   "which does not exist",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := staleRegisterEntries(c.found, reg, c.exists)
			switch {
			case c.want == "":
				if len(got) != 0 {
					t.Errorf("expected no stale entry, got %v", got)
				}
			case len(got) != 1:
				t.Errorf("expected exactly one stale entry containing %q, got %v", c.want, got)
			case !strings.Contains(got[0], c.want):
				t.Errorf("stale entry %q does not mention %q", got[0], c.want)
			}
		})
	}
}

// TestScanFile_CountsEveryUseOfADeniedPackage is the scanner half of the same
// rule. The register can only pin a count the scanner actually produces, so a
// second call into an already-imported denied package has to raise the finding
// count -- otherwise the import alone would stand in for any number of uses.
func TestScanFile_CountsEveryUseOfADeniedPackage(t *testing.T) {
	one := []byte(`package p

import c25519 "golang.org/x/crypto/curve25519"

func agree(a, b []byte) ([]byte, error) {
	return c25519.X25519(a, b)
}
`)
	two := []byte(`package p

import c25519 "golang.org/x/crypto/curve25519"

func agree(a, b []byte) ([]byte, error) {
	return c25519.X25519(a, b)
}

func agreeAgain(a, b []byte) ([]byte, error) {
	return c25519.X25519(a, b)
}
`)
	count := func(src []byte) int {
		t.Helper()
		findings, err := scanFile("pkg/ecc/Curve.go", src)
		if err != nil {
			t.Fatalf("scanFile: %v", err)
		}
		n := 0
		for _, f := range findings {
			if f.Primitive == "X25519" {
				n++
			}
		}
		return n
	}

	// One import plus one use, then one import plus two uses.
	if got := count(one); got != 2 {
		t.Fatalf("one use: got %d X25519 findings, want 2 (import + use)", got)
	}
	if got := count(two); got != 3 {
		t.Fatalf("two uses: got %d X25519 findings, want 3 (import + two uses); a second "+
			"use of an already-imported denied package must be visible to the register", got)
	}

	// And the second use is what the gate rejects, given the register the
	// first one justified.
	reg := map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 2}}
	if got := registerViolations(map[string]map[string]int{"pkg/ecc/Curve.go": {"X25519": 3}}, reg); len(got) != 1 {
		t.Errorf("expected the extra use to be rejected, got %v", got)
	}
}

// TestScanFile_RefusesDotImportOfDeniedPackage covers the shape that would
// defeat counting: a dot import erases the qualifier, so uses of a denied
// package become invisible and its import alone would authorise any number of
// them. The audit refuses the import rather than undercounting.
func TestScanFile_RefusesDotImportOfDeniedPackage(t *testing.T) {
	src := []byte(`package p

import . "golang.org/x/crypto/curve25519"

func agree(a, b []byte) ([]byte, error) {
	return X25519(a, b)
}
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	var marked bool
	for _, f := range findings {
		if f.Primitive == dotImportMarker+"golang.org/x/crypto/curve25519" {
			marked = true
		}
	}
	if !marked {
		t.Errorf("dot import of a denied package not refused; got %v", findings)
	}
}

// TestModuleDependenciesAreClassified extends the allowlist to go.mod. The
// per-import rules only police the namespaces they know about, so a new
// cryptographic dependency under an unfamiliar module path would be invisible
// to them. Every module must therefore be either inside a policed namespace or
// classified here with what it does instead.
func TestModuleDependenciesAreClassified(t *testing.T) {
	root := moduleRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	modules := requiredModules(string(src))
	if len(modules) == 0 {
		t.Fatal("no modules parsed from go.mod; the parser is broken, because the " +
			"file carries require blocks")
	}

	for _, mod := range modules {
		if policed(mod) {
			continue
		}
		if _, classified := dependencyClassification[mod]; !classified {
			t.Errorf("go.mod requires %s, which is neither inside a policed namespace nor "+
				"classified.\nIf it carries cryptography, add its namespace to "+
				"policedNamespaces and classify its packages. If it does not, add it to "+
				"dependencyClassification saying what it does instead.", mod)
		}
	}

	for mod := range dependencyClassification {
		if !containsString(modules, mod) {
			t.Errorf("dependencyClassification lists %s, which go.mod no longer requires; "+
				"drop the entry", mod)
		}
	}
}

// requiredModules extracts module paths from go.mod's require blocks and
// single-line require directives.
func requiredModules(src string) []string {
	var out []string
	inBlock := false
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case line == "require (":
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock && line != "":
			if path, _, ok := strings.Cut(line, " "); ok {
				out = append(out, path)
			}
		case strings.HasPrefix(line, "require "):
			if path, _, ok := strings.Cut(strings.TrimPrefix(line, "require "), " "); ok {
				out = append(out, path)
			}
		}
	}
	return out
}

// TestScanFile_FlagsUnclassifiedPolicedImports is the inversion's regression:
// a package inside a policed namespace that nobody enumerated must fail for
// being unclassified, not pass for being unknown. BLAKE2 is the worked example
// -- pure Go, not FIPS-approved, and invisible to GODEBUG=fips140=only.
func TestScanFile_FlagsUnclassifiedPolicedImports(t *testing.T) {
	src := []byte(`package p

import (
	"crypto/dsa"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/somethingnobodyhasinventedyet"
)

var (
	_ = dsa.Sign
	_ = blake2s.New256
	_ = sha3.New256
	_ = somethingnobodyhasinventedyet.Thing
)
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	// blake2s and x/crypto/sha3 are named outright -- their import and their
	// one use each are separate occurrences, because the register counts uses.
	// The other two packages are policed but unenumerated, and must fail for
	// exactly that reason; an unclassified package is a failure whatever its
	// count, so only its import is reported.
	var named, unclassifiedCount int
	for _, f := range findings {
		if strings.HasPrefix(f.Primitive, unclassifiedMarker) {
			unclassifiedCount++
		} else {
			named++
		}
	}
	if named != 4 || unclassifiedCount != 2 {
		t.Errorf("expected 4 named and 2 unclassified findings, got %d and %d: %v",
			named, unclassifiedCount, findings)
	}
}

// TestScanFile_IgnoresUnpolicedImports keeps the inversion from swallowing
// ordinary application code: outside the policed namespaces the audit has no
// opinion, and go.mod classification is what guards that boundary.
func TestScanFile_IgnoresUnpolicedImports(t *testing.T) {
	src := []byte(`package p

import (
	"fmt"
	"github.com/Eyevinn/mp4ff/mp4"
	"google.golang.org/protobuf/proto"
)

var (
	_ = fmt.Sprintf
	_ = mp4.DecodeFile
	_ = proto.Marshal
)
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("non-cryptographic imports reported: %v", findings)
	}
}

// TestClassify_DeniedBeatsApproved pins the precedence: a path in both tables
// is a mistake, and the audit must fail closed rather than silently prefer the
// approval.
func TestClassify_DeniedBeatsApproved(t *testing.T) {
	// crypto/hpke is denied; if it were ever added to approvedCrypto by
	// accident, classify must still report it.
	if _, denied := classify("crypto/hpke"); !denied {
		t.Error("classify(crypto/hpke) should be denied")
	}
	if _, denied := classify("crypto/sha256"); denied {
		t.Error("classify(crypto/sha256) should not be denied")
	}
	if prim, _ := classify("crypto/blake3"); prim != unclassified {
		t.Errorf("classify(crypto/blake3) = %q, want unclassified", prim)
	}
	if prim, denied := classify("fmt"); prim != "" || denied {
		t.Errorf("classify(fmt) = (%q, %v), want (\"\", false)", prim, denied)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestScanFile_FlagsDeniedImportsAndSelectors covers the detector itself: a
// silent scanner would make the gate above pass vacuously.
func TestScanFile_FlagsDeniedImportsAndSelectors(t *testing.T) {
	src := []byte(`package p

import (
	"crypto/cipher"
	goecdh "crypto/ecdh"
	"crypto/sha1"
	c25519 "golang.org/x/crypto/curve25519"
)

func f(b cipher.Block) {
	_, _ = cipher.NewGCM(b)
	_ = goecdh.X25519()
	_ = c25519.ScalarBaseMult
	_ = sha1.New
}
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}

	got := map[string]bool{}
	for _, f := range findings {
		got[f.Primitive] = true
		if f.Line == 0 {
			t.Errorf("finding %q carries no line number", f.Primitive)
		}
	}
	for _, want := range []string{
		"SHA-1",
		"X25519",
		"AES-GCM under a caller-supplied nonce",
	} {
		if !got[want] {
			t.Errorf("scanFile missed %q; got %v", want, keys(got))
		}
	}
	// The aliased curve25519 import and the aliased ecdh.X25519 call both
	// report X25519, so aliasing must not hide either.
	if len(findings) < 4 {
		t.Errorf("expected at least 4 findings (sha1, curve25519, ecdh.X25519, NewGCM), got %d: %v",
			len(findings), findings)
	}
}

// TestScanFile_FlagsPureGoNonApprovedDependencies covers the primitives the
// runtime gate structurally cannot reach: these packages do their own field
// arithmetic and never enter the Go Cryptographic Module, so this audit is the
// only thing standing between them and an unnoticed new use.
func TestScanFile_FlagsPureGoNonApprovedDependencies(t *testing.T) {
	src := []byte(`package p

import (
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/flynn/noise"
	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/argon2"
	ed "filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

var (
	_ = ristretto255.NewScalar
	_ = ed.NewIdentityPoint
	_ = field.Element{}
	_ = kyber1024.Scheme
	_ = noise.DH25519
	_ = argon2.IDKey
)
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Primitive] = true
	}
	for _, want := range []string{
		"Ristretto255",
		"edwards25519 group and field arithmetic",
		"Round-3 Kyber-1024 (CIRCL)",
		"Noise Protocol Framework (25519 + ChaChaPoly patterns)",
		"Argon2id",
	} {
		if !got[want] {
			t.Errorf("scanFile missed %q; got %v", want, keys(got))
		}
	}
	// edwards25519 and its /field subpackage are one tree but two imports, so
	// six imports produce six findings -- and each is used once, which is six
	// more. Uses are counted separately from the import that admits them so
	// the register can pin how many a file makes.
	if len(findings) != 12 {
		t.Errorf("expected 12 findings (6 imports + 6 uses), got %d: %v", len(findings), findings)
	}
}

// TestClassify_NamesDeniedPackagesExactly is the regression for the audit's
// scope rule: a denied primitive is bound to the exact package that implements
// it, never to the module tree around it. Registering pkg/kem for Kyber must
// not carry any other CIRCL algorithm with it -- an unregistered CIRCL package
// has to come back unclassified, which fails closed and forces a register and
// docs/FIPS.md change.
func TestClassify_NamesDeniedPackagesExactly(t *testing.T) {
	cases := []struct {
		path      string
		primitive string // "" means not denied
		policed   bool   // if not denied, whether it must come back unclassified
	}{
		// The exact packages this repository uses.
		{"github.com/cloudflare/circl/kem/kyber/kyber1024", "Round-3 Kyber-1024 (CIRCL)", false},
		{"filippo.io/edwards25519", "edwards25519 group and field arithmetic", false},
		{"filippo.io/edwards25519/field", "edwards25519 group and field arithmetic", false},
		{"github.com/gtank/ristretto255", "Ristretto255", false},
		{"github.com/flynn/noise", "Noise Protocol Framework (25519 + ChaChaPoly patterns)", false},
		{"golang.org/x/crypto/argon2", "Argon2id", false},

		// Their neighbours in the same module trees: unclassified, not
		// silently covered by the entries above.
		{"github.com/cloudflare/circl/sign/dilithium/mode3", "", true},
		{"github.com/cloudflare/circl/cipher/ascon", "", true},
		{"github.com/cloudflare/circl/kem", "", true},
		{"github.com/cloudflare/circl", "", true},
		{"filippo.io/edwards25519/somethingadded", "", true},

		// Paths that merely start with the same characters are a different
		// module and none of the audit's business.
		{"filippo.io/edwards25519x", "", false},
		{"github.com/gtank/ristretto255x/inner", "", false},
		{"crypto/sha256", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		primitive, denied := classify(c.path)
		switch {
		case c.primitive != "":
			if !denied || primitive != c.primitive {
				t.Errorf("classify(%q) = (%q, %v), want (%q, true)", c.path, primitive, denied, c.primitive)
			}
		case c.policed:
			if denied || primitive != unclassified {
				t.Errorf("classify(%q) = (%q, %v), want (unclassified, false); an "+
					"unregistered package of a module this repository uses must fail "+
					"closed rather than inherit its neighbour's exemption", c.path, primitive, denied)
			}
		default:
			if denied || primitive != "" {
				t.Errorf("classify(%q) = (%q, %v), want (\"\", false)", c.path, primitive, denied)
			}
		}
	}
}

// TestScanFile_UnregisteredCIRCLAlgorithmIsNotCoveredByKyber is the same rule
// seen through the scanner, in the shape that matters: pkg/kem is registered
// for Round-3 Kyber-1024, so the danger is a second CIRCL algorithm arriving in
// that same file and reporting the primitive the register already allows.
func TestScanFile_UnregisteredCIRCLAlgorithmIsNotCoveredByKyber(t *testing.T) {
	src := []byte(`package p

import (
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

var (
	_ = kyber1024.Scheme
	_ = mode3.Scheme
)
`)
	findings, err := scanFile("pkg/kem/kyber.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	// Two imports plus the one Kyber use; the unclassified import's use is not
	// counted, because an unclassified package fails whatever its count.
	if len(findings) != 3 {
		t.Fatalf("expected both CIRCL imports reported, got %d: %v", len(findings), findings)
	}

	var kyber, unregistered int
	for _, f := range findings {
		switch {
		case f.Primitive == "Round-3 Kyber-1024 (CIRCL)":
			kyber++
		case f.Primitive == unclassifiedMarker+"github.com/cloudflare/circl/sign/dilithium/mode3":
			unregistered++
		default:
			t.Errorf("unexpected finding %q", f.Primitive)
		}
	}
	if kyber != 2 || unregistered != 1 {
		t.Errorf("got %d Kyber and %d unclassified findings, want 2 and 1: %v",
			kyber, unregistered, findings)
	}

	// The premise, and the reason the split matters: pkg/kem/kyber.go already
	// carries the Kyber exemption. The gate strips marker-prefixed primitives
	// out of the registrable set before consulting the register, so that
	// exemption cannot absorb the second import however the register is
	// written -- the new package has to be classified.
	if register["pkg/kem/kyber.go"]["Round-3 Kyber-1024 (CIRCL)"] == 0 {
		t.Error("pkg/kem/kyber.go is no longer registered for Round-3 Kyber-1024 (CIRCL); " +
			"this test assumes the file carries that exemption")
	}
}

// TestScanFile_FlagsDotImportsThatHideSelectors is the regression for the
// shape selector analysis cannot read. `import . "crypto/ecdh"` makes
// ecdh.X25519() into a bare X25519() with no SelectorExpr, and the same for
// cipher.NewGCM, so the audit refuses the dot import itself rather than
// analysing past it and reporting nothing.
func TestScanFile_FlagsDotImportsThatHideSelectors(t *testing.T) {
	src := []byte(`package p

import (
	. "crypto/cipher"
	. "crypto/ecdh"
)

func f(b Block) {
	_, _ = NewGCM(b)
	_ = X25519()
}
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected both dot imports reported, got %d: %v", len(findings), findings)
	}
	for _, want := range []string{dotImportMarker + "crypto/ecdh", dotImportMarker + "crypto/cipher"} {
		hit := false
		for _, f := range findings {
			if f.Primitive == want {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%q not reported; got %v", want, findings)
		}
	}
}

// TestScanFile_AllowsDotImportOfApprovedPackage keeps the rule narrow: it
// exists only because selector analysis cannot see through a dot import, so a
// package the audit does not analyse by selector is not its business.
func TestScanFile_AllowsDotImportOfApprovedPackage(t *testing.T) {
	src := []byte(`package p

import . "crypto/sha256"

var _ = New
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("dot import of an unanalysed package reported: %v", findings)
	}
}

// TestScanFile_FlagsDotImportOfDeniedPackage confirms the import-path rules are
// unaffected by the import name: a denied path is denied however it is bound.
func TestScanFile_FlagsDotImportOfDeniedPackage(t *testing.T) {
	src := []byte(`package p

import (
	. "github.com/gtank/ristretto255"
	_ "crypto/sha1"
)

var _ = NewScalar
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Primitive] = true
	}
	for _, want := range []string{"Ristretto255", "SHA-1"} {
		if !got[want] {
			t.Errorf("scanFile missed %q behind a dot/blank import; got %v", want, keys(got))
		}
	}
}

// TestScanFile_IgnoresApprovedCrypto is the negative case: approved primitives,
// and the approved GCM constructor, must not be reported. Without this the
// detector could pass the gate by flagging everything.
func TestScanFile_IgnoresApprovedCrypto(t *testing.T) {
	src := []byte(`package p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha256"
	xhkdf "golang.org/x/crypto/hkdf"
)

func f(b cipher.Block) {
	_, _ = cipher.NewGCMWithRandomNonce(b)
	_ = ecdh.P256()
	_ = aes.NewCipher
	_ = hmac.New
	_ = sha256.New
	_ = hkdf.Key[any]
	_ = xhkdf.New
	_ = ed25519.Sign
	// ML-KEM is FIPS 203; only the Round-3 Kyber this repository keeps for
	// back-compat is denied.
	_ = mlkem.GenerateKey1024
}
`)
	findings, err := scanFile("fake.go", src)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("approved primitives reported as findings: %v", findings)
	}
}

// TestScanFile_ReportsParseErrors ensures malformed input fails loudly rather
// than silently scanning to zero findings.
func TestScanFile_ReportsParseErrors(t *testing.T) {
	if _, err := scanFile("bad.go", []byte("package p\nfunc (")); err == nil {
		t.Fatal("expected a parse error for malformed source")
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
