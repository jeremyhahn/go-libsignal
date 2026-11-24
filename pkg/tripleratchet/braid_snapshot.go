package tripleratchet

import "github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"

// snapshotBraid serializes a Braid for in-process rollback with the Go-only format, so the Rust-interop deprecation of Braid.Serialize does not apply.
func snapshotBraid(b *mlkembraid.Braid) ([]byte, error) {
	return b.Serialize() //nolint:staticcheck // intentional: snapshot/restore is in-process only; Rust-interop uses proto_codec.go
}

// restoreBraid restores a Braid written by snapshotBraid.
func restoreBraid(data []byte) (*mlkembraid.Braid, error) {
	return mlkembraid.DeserializeBraid(data) //nolint:staticcheck // intentional: snapshot/restore is in-process only; Rust-interop uses proto_codec.go
}
