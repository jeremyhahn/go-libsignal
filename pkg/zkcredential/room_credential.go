package zkcredential

import (
	"github.com/gtank/ristretto255"
)

// RoomId is a byte-slice attribute representing a chat room identifier.
//
// It implements [RevealedAttribute]: the room ID is hidden from the issuing
// server during credential issuance (via blind issuance) but is revealed
// to the verifying server during presentation so it can enforce room access.
//
// The attribute hashes its raw bytes to a Ristretto255 point using the
// ShoSha256 Stateful Hash Object, matching the Rust convention for
// RevealedAttribute implementations that call sho.get_point_single_elligator
// or equivalent.
//
// Rust reference: this type mirrors the RoomId attribute shown in the Rust
// zkcredential benchmark (libsignal/rust/zkcredential/benches/) and
// demonstrates the RevealedAttribute flow from
// libsignal/rust/zkcredential/src/attributes.rs.
type RoomId []byte

// AsPoint converts the RoomId to a Ristretto255 point by hashing the raw
// bytes with ShoSha256.
//
// The derivation uses the label "RoomId_20231011" to domain-separate room
// identifier hashing from other credential attributes.
func (r RoomId) AsPoint() *ristretto255.Element {
	sho := NewShoSha256Ext("RoomId_20231011")
	sho.AbsorbAndRatchet([]byte(r))
	return sho.MustGetPoint()
}

// RoomCredentialLabel is the issuance label that uniquely identifies a
// RoomCredential. Passed to IssuanceProofBuilder and PresentationProofVerifier
// so both sides compute the same public-attribute hash. Mirrors the Rust
// upstream literal at rust/zkcredential/examples/room_credential.rs.
//
// #nosec G101 -- public domain-separation tag, not a secret credential value.
const RoomCredentialLabel = "RoomCredential_20231011"
