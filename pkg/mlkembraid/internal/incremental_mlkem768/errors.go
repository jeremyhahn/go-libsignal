package incremental_mlkem768

import (
	"fmt"
	"io"
)

// mustWrite calls w.Write(p) and panics if it returns an error.
// sha3 hash implementations never return write errors; a non-nil error
// would indicate a broken implementation and is a programmer error.
func mustWrite(w io.Writer, p []byte) {
	if _, err := w.Write(p); err != nil {
		panic(fmt.Sprintf("incremental_mlkem768: unexpected hash write error: %v", err))
	}
}

// mustRead calls r.Read(p) and panics if it returns an error.
// sha3 XOF Read calls never fail; a non-nil error indicates programmer error.
func mustRead(r io.Reader, p []byte) {
	if _, err := r.Read(p); err != nil {
		panic(fmt.Sprintf("incremental_mlkem768: unexpected hash read error: %v", err))
	}
}

// ErrInvalidInputLength is returned when an input byte slice has the wrong length.
type ErrInvalidInputLength struct {
	Name     string
	Expected int
	Got      int
}

func (e *ErrInvalidInputLength) Error() string {
	return fmt.Sprintf("incremental_mlkem768: %s: expected %d bytes, got %d", e.Name, e.Expected, e.Got)
}

// ErrInvalidCoefficient is returned when a decoded polynomial coefficient is out of range.
type ErrInvalidCoefficient struct {
	Index int
	Value uint16
}

func (e *ErrInvalidCoefficient) Error() string {
	return fmt.Sprintf("incremental_mlkem768: coefficient %d out of range: %d >= q(%d)", e.Index, e.Value, q)
}

// ErrInvalidPublicKey is returned when a public key fails validation.
type ErrInvalidPublicKey struct {
	Detail string
}

func (e ErrInvalidPublicKey) Error() string {
	return fmt.Sprintf("incremental_mlkem768: invalid public key: %s", e.Detail)
}
