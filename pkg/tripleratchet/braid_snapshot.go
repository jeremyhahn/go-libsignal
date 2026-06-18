package tripleratchet

import "github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"

// snapshotBraid serializes a Braid to bytes for in-process atomic rollback.
//
// This uses mlkembraid.Braid.Serialize(), which emits the Go-only binary
// format (not Rust-interop). That is intentional: snapshot/restore is a pure
// in-process operation. Cross-language serialization is handled separately
// by pkg/spqr's proto_codec.
//
// The SA1019 deprecation on Braid.Serialize refers exclusively to Rust-interop
// use cases and does not apply here.
func snapshotBraid(b *mlkembraid.Braid) ([]byte, error) {
	return b.Serialize() //nolint:staticcheck // intentional: snapshot/restore is in-process only; Rust-interop uses proto_codec.go
}

// restoreBraid deserializes a Braid from bytes previously written by snapshotBraid.
//
// Uses mlkembraid.DeserializeBraid(), which reads the Go-only binary format.
// Acceptable for snapshot/restore; not for cross-language sessions.
func restoreBraid(data []byte) (*mlkembraid.Braid, error) {
	return mlkembraid.DeserializeBraid(data) //nolint:staticcheck // intentional: snapshot/restore is in-process only; Rust-interop uses proto_codec.go
}
