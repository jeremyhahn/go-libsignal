package fingerprint

// NewFingerprint returns a new Fingerprint with both display and scannable
// components.
func NewFingerprint(displayFingerprint *Display, scannableFingerprint *Scannable) *Fingerprint {
	return &Fingerprint{
		fingerprintDisplay:   displayFingerprint,
		fingerprintScannable: scannableFingerprint,
	}
}

// Fingerprint is a structure for returning a displayable and scannable
// fingerprint for identity verification.
type Fingerprint struct {
	fingerprintDisplay   *Display
	fingerprintScannable *Scannable
}

// Display returns the displayable fingerprint for generating a human-readable
// 60-digit string representation.
func (f *Fingerprint) Display() *Display {
	return f.fingerprintDisplay
}

// Scannable returns the scannable fingerprint for QR-code based verification.
func (f *Fingerprint) Scannable() *Scannable {
	return f.fingerprintScannable
}
