package backup

// Validator defines the interface for backup validation. Implementations
// can validate the structure and contents of backup frames according to
// the Signal backup specification.
type Validator interface {
	// ValidateBackupInfo validates the first frame (BackupInfo) of a backup.
	ValidateBackupInfo(raw []byte) error

	// ValidateFrame validates a single backup frame. The frameIndex is the
	// zero-based index of the frame within the backup (excluding the
	// BackupInfo frame).
	ValidateFrame(raw []byte, frameIndex int) error

	// Complete signals that all frames have been processed and performs
	// any final validation checks.
	Complete() error

	// UnknownFields returns all unknown fields found during validation.
	UnknownFields() []FoundUnknownField
}

// ValidationError represents an error found during backup validation.
type ValidationError struct {
	FrameIndex int
	Message    string
}

func (e *ValidationError) Error() string {
	if e.FrameIndex >= 0 {
		return "backup: validation error in frame " + itoa(e.FrameIndex) + ": " + e.Message
	}
	return "backup: validation error: " + e.Message
}

// itoa converts an int to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
