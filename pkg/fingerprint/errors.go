package fingerprint

import "fmt"

// VersionMismatchError indicates the scanned fingerprint has a different
// version than the local fingerprint.
type VersionMismatchError struct {
	Theirs uint32
	Ours   uint32
}

func (e *VersionMismatchError) Error() string {
	return fmt.Sprintf("fingerprint version mismatch: theirs=%d ours=%d", e.Theirs, e.Ours)
}

// ParsingError indicates a failure to parse fingerprint data.
type ParsingError struct {
	Detail string
}

func (e *ParsingError) Error() string {
	return fmt.Sprintf("fingerprint parsing error: %s", e.Detail)
}

// InvalidIterationCountError indicates an out-of-range iteration count.
type InvalidIterationCountError struct {
	Count uint32
}

func (e *InvalidIterationCountError) Error() string {
	return fmt.Sprintf("invalid fingerprint iteration count: %d", e.Count)
}

// FingerprintTooShortError indicates the fingerprint byte slice is shorter
// than the minimum required length (30 bytes).
type FingerprintTooShortError struct {
	Length int
}

func (e *FingerprintTooShortError) Error() string {
	return fmt.Sprintf("fingerprint too short: %d bytes, need at least 30", e.Length)
}
