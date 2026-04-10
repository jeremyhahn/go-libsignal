package keyhelper

import "fmt"

// ErrRandomGeneration is returned when the cryptographic random number
// generator fails to produce the requested bytes.
type ErrRandomGeneration struct {
	Op  string
	Err error
}

func (e *ErrRandomGeneration) Error() string {
	return fmt.Sprintf("keyhelper: %s: random generation failed: %v", e.Op, e.Err)
}

func (e *ErrRandomGeneration) Unwrap() error {
	return e.Err
}
