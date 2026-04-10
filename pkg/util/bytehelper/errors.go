package bytehelper

import "fmt"

// ErrInputTooSmall is returned when the input byte slice is smaller than
// the sum of the requested split lengths.
type ErrInputTooSmall struct {
	Required int
	Got      int
}

func (e *ErrInputTooSmall) Error() string {
	return fmt.Sprintf("bytehelper: input too small: need %d bytes, got %d", e.Required, e.Got)
}

// ErrNilInput is returned when a nil input byte slice is provided.
type ErrNilInput struct{}

func (e *ErrNilInput) Error() string {
	return "bytehelper: nil input"
}

// ErrNegativeLength is returned when a negative length parameter is provided.
type ErrNegativeLength struct {
	Lengths []int
}

func (e *ErrNegativeLength) Error() string {
	return fmt.Sprintf("bytehelper: negative length parameter: %v", e.Lengths)
}
