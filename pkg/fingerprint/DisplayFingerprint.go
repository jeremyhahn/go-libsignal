package fingerprint

import (
	"fmt"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
)

// minFingerprintLength is the minimum byte length required for a fingerprint.
// displayStringFor reads 6 chunks of 5 bytes each starting at offsets
// 0, 5, 10, 15, 20, 25, so at least 30 bytes are needed.
const minFingerprintLength = 30

// NewDisplay will return a new displayable fingerprint.
// Both local and remote fingerprint byte slices must be at least 30 bytes long.
func NewDisplay(localFingerprint, remoteFingerprint []byte) (*Display, error) {
	if len(localFingerprint) < minFingerprintLength || len(remoteFingerprint) < minFingerprintLength {
		shortest := len(localFingerprint)
		if len(remoteFingerprint) < shortest {
			shortest = len(remoteFingerprint)
		}
		return nil, &FingerprintTooShortError{Length: shortest}
	}
	return &Display{
		localFingerprintNumbers:  displayStringFor(localFingerprint),
		remoteFingerprintNumbers: displayStringFor(remoteFingerprint),
	}, nil
}

// Display is a structure for displayable fingerprints.
type Display struct {
	localFingerprintNumbers  string
	remoteFingerprintNumbers string
}

// DisplayText will return a string of the fingerprint numbers.
func (d *Display) DisplayText() string {
	if d.localFingerprintNumbers < d.remoteFingerprintNumbers {
		return d.localFingerprintNumbers + d.remoteFingerprintNumbers
	}
	return d.remoteFingerprintNumbers + d.localFingerprintNumbers
}

// displayStringFor will return a displayable string representation
// of the given fingerprint.
func displayStringFor(fingerprint []byte) string {
	return encodedChunk(fingerprint, 0) +
		encodedChunk(fingerprint, 5) +
		encodedChunk(fingerprint, 10) +
		encodedChunk(fingerprint, 15) +
		encodedChunk(fingerprint, 20) +
		encodedChunk(fingerprint, 25)
}

// encodedChunk will return an encoded string of the given hash.
func encodedChunk(hash []byte, offset int) string {
	chunk := bytehelper.Bytes5ToInt64(hash, offset) % 100000
	return fmt.Sprintf("%05d", chunk)
}
