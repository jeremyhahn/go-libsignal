package fingerprint

import (
	"crypto/subtle"

	"github.com/jeremyhahn/go-libsignal/pkg/proto/fingerprintpb"
	"google.golang.org/protobuf/proto"
)

// scannableFingerprintSize is the number of bytes taken from the SHA-512 hash
// for the scannable fingerprint (first 32 bytes).
const scannableFingerprintSize = 32

// Scannable holds a version and two 32-byte fingerprint hashes used for
// QR-code based identity verification. The local and remote fingerprints
// are the first 32 bytes of the iterative SHA-512 hash output.
type Scannable struct {
	version           uint32
	localFingerprint  [scannableFingerprintSize]byte
	remoteFingerprint [scannableFingerprintSize]byte
}

// newScannable creates a Scannable from the full SHA-512 hash outputs,
// taking the first 32 bytes of each.
func newScannable(version uint32, localHash, remoteHash []byte) *Scannable {
	s := &Scannable{version: version}
	copy(s.localFingerprint[:], localHash[:scannableFingerprintSize])
	copy(s.remoteFingerprint[:], remoteHash[:scannableFingerprintSize])
	return s
}

// Version returns the fingerprint protocol version.
func (s *Scannable) Version() uint32 {
	return s.version
}

// LocalFingerprint returns the local 32-byte fingerprint hash.
func (s *Scannable) LocalFingerprint() [scannableFingerprintSize]byte {
	return s.localFingerprint
}

// RemoteFingerprint returns the remote 32-byte fingerprint hash.
func (s *Scannable) RemoteFingerprint() [scannableFingerprintSize]byte {
	return s.remoteFingerprint
}

// Serialize encodes the scannable fingerprint as a protobuf message
// (CombinedFingerprints) for transmission via QR code or other channel.
func (s *Scannable) Serialize() ([]byte, error) {
	version := s.version
	combined := &fingerprintpb.CombinedFingerprints{
		Version: &version,
		LocalFingerprint: &fingerprintpb.LogicalFingerprint{
			Content: append([]byte(nil), s.localFingerprint[:]...),
		},
		RemoteFingerprint: &fingerprintpb.LogicalFingerprint{
			Content: append([]byte(nil), s.remoteFingerprint[:]...),
		},
	}
	data, err := proto.Marshal(combined)
	if err != nil {
		return nil, &ParsingError{Detail: "failed to marshal scannable fingerprint: " + err.Error()}
	}
	return data, nil
}

// DeserializeScannable decodes a protobuf-encoded CombinedFingerprints message
// into a Scannable.
func DeserializeScannable(data []byte) (*Scannable, error) {
	combined := &fingerprintpb.CombinedFingerprints{}
	if err := proto.Unmarshal(data, combined); err != nil {
		return nil, &ParsingError{Detail: "failed to decode protobuf"}
	}
	if combined.Version == nil {
		return nil, &ParsingError{Detail: "missing version"}
	}
	localFP := combined.GetLocalFingerprint()
	if localFP == nil || localFP.Content == nil {
		return nil, &ParsingError{Detail: "missing local fingerprint"}
	}
	remoteFP := combined.GetRemoteFingerprint()
	if remoteFP == nil || remoteFP.Content == nil {
		return nil, &ParsingError{Detail: "missing remote fingerprint"}
	}

	s := &Scannable{version: *combined.Version}
	copy(s.localFingerprint[:], localFP.Content)
	copy(s.remoteFingerprint[:], remoteFP.Content)
	return s, nil
}

// Compare verifies that a scanned fingerprint (from the remote party) matches
// this fingerprint. The remote party's local fingerprint should equal our
// remote fingerprint, and vice versa. Comparison uses constant-time operations
// to avoid timing side channels.
func (s *Scannable) Compare(scannedData []byte) (bool, error) {
	combined := &fingerprintpb.CombinedFingerprints{}
	if err := proto.Unmarshal(scannedData, combined); err != nil {
		return false, &ParsingError{Detail: "failed to decode their protobuf"}
	}

	theirVersion := combined.GetVersion()
	if theirVersion != s.version {
		return false, &VersionMismatchError{Ours: s.version, Theirs: theirVersion}
	}

	theirLocal := combined.GetLocalFingerprint()
	if theirLocal == nil || theirLocal.Content == nil {
		return false, &ParsingError{Detail: "missing their local fingerprint"}
	}
	theirRemote := combined.GetRemoteFingerprint()
	if theirRemote == nil || theirRemote.Content == nil {
		return false, &ParsingError{Detail: "missing their remote fingerprint"}
	}

	// Their local should match our remote, their remote should match our local.
	same1 := subtle.ConstantTimeCompare(theirLocal.Content, s.remoteFingerprint[:])
	same2 := subtle.ConstantTimeCompare(theirRemote.Content, s.localFingerprint[:])

	return same1 == 1 && same2 == 1, nil
}
