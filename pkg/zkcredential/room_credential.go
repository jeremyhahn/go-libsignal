package zkcredential

import (
	"github.com/gtank/ristretto255"
)

// RoomId is a revealed attribute: hidden at issuance, revealed at presentation, hashed to a point with ShoSha256 (Rust zkcredential benches).
type RoomId []byte

// AsPoint hashes the RoomId bytes to a point with ShoSha256 label "RoomId_20231011".
func (r RoomId) AsPoint() *ristretto255.Element {
	sho := NewShoSha256Ext("RoomId_20231011")
	sho.AbsorbAndRatchet([]byte(r))
	return sho.MustGetPoint()
}

// RoomCredentialLabel is the issuance label for RoomCredential (Rust room_credential.rs).
// #nosec G101 -- public domain-separation tag, not a secret.
const RoomCredentialLabel = "RoomCredential_20231011"
