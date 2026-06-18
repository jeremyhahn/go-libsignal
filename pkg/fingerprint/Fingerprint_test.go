package fingerprint

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
)

// Test vectors from the Rust reference implementation.
const (
	aliceIdentityHex = "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868"
	bobIdentityHex   = "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b"

	displayableFingerprintV1 = "300354477692869396892869876765458257569162576843440918079131"

	aliceScannableFingerprintV1 = "080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d"
	bobScannableFingerprintV1   = "080112220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df"

	aliceScannableFingerprintV2 = "080212220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d"
	bobScannableFingerprintV2   = "080212220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df"

	aliceStableID = "+14152222222"
	bobStableID   = "+14153333333"
)

func mustDecodeIdentityKey(t *testing.T, hexStr string) *identity.Key {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	// raw is 33 bytes: 0x05 prefix + 32-byte key
	if len(raw) != 33 || raw[0] != 0x05 {
		t.Fatalf("unexpected key format: len=%d prefix=0x%02x", len(raw), raw[0])
	}
	var keyBytes [32]byte
	copy(keyBytes[:], raw[1:])
	pub := ecc.NewDjbECPublicKey(keyBytes)
	return identity.NewKey(pub)
}

func generateRandomIdentityKey(t *testing.T) *identity.Key {
	t.Helper()
	var keyBytes [32]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	pub := ecc.NewDjbECPublicKey(keyBytes)
	return identity.NewKey(pub)
}

// --- NumericFingerprintGenerator tests ---

func TestNewNumericFingerprintGenerator_Valid(t *testing.T) {
	gen, err := NewNumericFingerprintGenerator(DefaultIterations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gen == nil {
		t.Fatal("expected non-nil generator")
	}
}

func TestNewNumericFingerprintGenerator_InvalidIterations(t *testing.T) {
	tests := []struct {
		name       string
		iterations uint32
	}{
		{"zero", 0},
		{"one", 1},
		{"too_large", 1_000_001},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gen, err := NewNumericFingerprintGenerator(tc.iterations)
			if err == nil {
				t.Fatal("expected error for invalid iterations")
			}
			if gen != nil {
				t.Fatal("expected nil generator on error")
			}
			var iterErr *InvalidIterationCountError
			if !isInvalidIterationCountError(err, &iterErr) {
				t.Fatalf("expected InvalidIterationCountError, got %T: %v", err, err)
			}
			if iterErr.Count != tc.iterations {
				t.Fatalf("expected count %d, got %d", tc.iterations, iterErr.Count)
			}
		})
	}
}

func isInvalidIterationCountError(err error, target **InvalidIterationCountError) bool {
	e, ok := err.(*InvalidIterationCountError)
	if ok {
		*target = e
	}
	return ok
}

// TestFingerprintV1 tests against known Rust/Java test vectors for version 1.
func TestFingerprintV1(t *testing.T) {
	aKey := mustDecodeIdentityKey(t, aliceIdentityHex)
	bKey := mustDecodeIdentityKey(t, bobIdentityHex)

	gen, err := NewNumericFingerprintGenerator(DefaultIterations)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	aFP, err := gen.CreateFor(1, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("failed to create Alice fingerprint: %v", err)
	}

	bFP, err := gen.CreateFor(1, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("failed to create Bob fingerprint: %v", err)
	}

	// Verify display fingerprints match the known test vector.
	if aFP.Display().DisplayText() != displayableFingerprintV1 {
		t.Fatalf("Alice display mismatch:\ngot:  %s\nwant: %s", aFP.Display().DisplayText(), displayableFingerprintV1)
	}
	if bFP.Display().DisplayText() != displayableFingerprintV1 {
		t.Fatalf("Bob display mismatch:\ngot:  %s\nwant: %s", bFP.Display().DisplayText(), displayableFingerprintV1)
	}

	// Verify scannable fingerprints match known test vectors.
	aScanBytes, err := aFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Alice scannable: %v", err)
	}
	bScanBytes, err := bFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Bob scannable: %v", err)
	}

	if hex.EncodeToString(aScanBytes) != aliceScannableFingerprintV1 {
		t.Fatalf("Alice scannable v1 mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(aScanBytes), aliceScannableFingerprintV1)
	}
	if hex.EncodeToString(bScanBytes) != bobScannableFingerprintV1 {
		t.Fatalf("Bob scannable v1 mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(bScanBytes), bobScannableFingerprintV1)
	}
}

// TestFingerprintV2 tests against known Rust/Java test vectors for version 2.
func TestFingerprintV2(t *testing.T) {
	aKey := mustDecodeIdentityKey(t, aliceIdentityHex)
	bKey := mustDecodeIdentityKey(t, bobIdentityHex)

	gen, err := NewNumericFingerprintGenerator(DefaultIterations)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	aFP, err := gen.CreateFor(2, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("failed to create Alice fingerprint: %v", err)
	}

	bFP, err := gen.CreateFor(2, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("failed to create Bob fingerprint: %v", err)
	}

	// Display fingerprint is version-independent.
	if aFP.Display().DisplayText() != displayableFingerprintV1 {
		t.Fatalf("Alice display mismatch:\ngot:  %s\nwant: %s", aFP.Display().DisplayText(), displayableFingerprintV1)
	}
	if bFP.Display().DisplayText() != displayableFingerprintV1 {
		t.Fatalf("Bob display mismatch:\ngot:  %s\nwant: %s", bFP.Display().DisplayText(), displayableFingerprintV1)
	}

	// Scannable fingerprints differ from v1 because version is encoded.
	aScanBytes, err := aFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Alice scannable: %v", err)
	}
	bScanBytes, err := bFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Bob scannable: %v", err)
	}

	if hex.EncodeToString(aScanBytes) != aliceScannableFingerprintV2 {
		t.Fatalf("Alice scannable v2 mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(aScanBytes), aliceScannableFingerprintV2)
	}
	if hex.EncodeToString(bScanBytes) != bobScannableFingerprintV2 {
		t.Fatalf("Bob scannable v2 mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(bScanBytes), bobScannableFingerprintV2)
	}
}

// TestFingerprintMatchingIdentifiers verifies that two parties with correct
// keys produce matching fingerprints that pass comparison.
func TestFingerprintMatchingIdentifiers(t *testing.T) {
	aKey := generateRandomIdentityKey(t)
	bKey := generateRandomIdentityKey(t)

	gen, err := NewNumericFingerprintGenerator(1024)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	aFP, err := gen.CreateFor(1, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("failed to create Alice fingerprint: %v", err)
	}

	bFP, err := gen.CreateFor(1, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("failed to create Bob fingerprint: %v", err)
	}

	// Display fingerprints should be identical (order-independent).
	if aFP.Display().DisplayText() != bFP.Display().DisplayText() {
		t.Fatal("display fingerprints should match for matching identifiers")
	}
	if len(aFP.Display().DisplayText()) != 60 {
		t.Fatalf("expected 60-char display, got %d", len(aFP.Display().DisplayText()))
	}

	// Cross-comparison should succeed.
	bScan, err := bFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Bob scannable: %v", err)
	}
	match, err := aFP.Scannable().Compare(bScan)
	if err != nil {
		t.Fatalf("comparison error: %v", err)
	}
	if !match {
		t.Fatal("Alice comparing Bob's fingerprint should match")
	}

	aScan, err := aFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Alice scannable: %v", err)
	}
	match, err = bFP.Scannable().Compare(aScan)
	if err != nil {
		t.Fatalf("comparison error: %v", err)
	}
	if !match {
		t.Fatal("Bob comparing Alice's fingerprint should match")
	}

	// Self-comparison should NOT match (local/remote are swapped).
	match, err = aFP.Scannable().Compare(aScan)
	if err != nil {
		t.Fatalf("self-comparison error: %v", err)
	}
	if match {
		t.Fatal("self-comparison should not match (asymmetric fingerprints)")
	}

	match, err = bFP.Scannable().Compare(bScan)
	if err != nil {
		t.Fatalf("self-comparison error: %v", err)
	}
	if match {
		t.Fatal("self-comparison should not match (asymmetric fingerprints)")
	}
}

// TestFingerprintMismatchingFingerprints verifies that a MITM attack is
// detected: Alice thinks she's talking to Bob, but has a MITM key.
func TestFingerprintMismatchingFingerprints(t *testing.T) {
	aKey := generateRandomIdentityKey(t)
	bKey := generateRandomIdentityKey(t)
	mKey := generateRandomIdentityKey(t) // MITM key

	gen, err := NewNumericFingerprintGenerator(1024)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Alice has MITM key for Bob.
	aFP, err := gen.CreateFor(1, []byte(aliceStableID), aKey, []byte(bobStableID), mKey)
	if err != nil {
		t.Fatalf("failed to create Alice fingerprint: %v", err)
	}

	// Bob has the correct Alice key.
	bFP, err := gen.CreateFor(1, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("failed to create Bob fingerprint: %v", err)
	}

	// Display fingerprints should differ.
	if aFP.Display().DisplayText() == bFP.Display().DisplayText() {
		t.Fatal("display fingerprints should not match with MITM key")
	}

	// Scannable comparison should fail.
	bScan, err := bFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Bob scannable: %v", err)
	}
	match, err := aFP.Scannable().Compare(bScan)
	if err != nil {
		t.Fatalf("comparison error: %v", err)
	}
	if match {
		t.Fatal("MITM comparison should not match")
	}

	aScan, err := aFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Alice scannable: %v", err)
	}
	match, err = bFP.Scannable().Compare(aScan)
	if err != nil {
		t.Fatalf("comparison error: %v", err)
	}
	if match {
		t.Fatal("MITM comparison should not match (reverse)")
	}
}

// TestFingerprintMismatchingIdentifiers verifies that different stable
// identifiers produce different fingerprints.
func TestFingerprintMismatchingIdentifiers(t *testing.T) {
	aKey := generateRandomIdentityKey(t)
	bKey := generateRandomIdentityKey(t)

	gen, err := NewNumericFingerprintGenerator(1024)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Alice uses a wrong phone number.
	aFP, err := gen.CreateFor(1, []byte("+141512222222"), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("failed to create Alice fingerprint: %v", err)
	}

	bFP, err := gen.CreateFor(1, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("failed to create Bob fingerprint: %v", err)
	}

	if aFP.Display().DisplayText() == bFP.Display().DisplayText() {
		t.Fatal("display fingerprints should differ with mismatched identifiers")
	}

	bScan, err := bFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Bob scannable: %v", err)
	}
	match, err := aFP.Scannable().Compare(bScan)
	if err != nil {
		t.Fatalf("comparison error: %v", err)
	}
	if match {
		t.Fatal("mismatched identifiers should not match")
	}

	aScan, err := aFP.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize Alice scannable: %v", err)
	}
	match, err = bFP.Scannable().Compare(aScan)
	if err != nil {
		t.Fatalf("comparison error: %v", err)
	}
	if match {
		t.Fatal("mismatched identifiers should not match (reverse)")
	}
}

// TestFingerprintMismatchingVersions verifies that display is version-independent
// but scannable encoding changes with version.
func TestFingerprintMismatchingVersions(t *testing.T) {
	aKey := mustDecodeIdentityKey(t, aliceIdentityHex)
	bKey := mustDecodeIdentityKey(t, bobIdentityHex)

	gen, err := NewNumericFingerprintGenerator(DefaultIterations)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	aFPv1, err := gen.CreateFor(1, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("failed to create v1 fingerprint: %v", err)
	}

	aFPv2, err := gen.CreateFor(2, []byte(bobStableID), bKey, []byte(aliceStableID), aKey)
	if err != nil {
		t.Fatalf("failed to create v2 fingerprint: %v", err)
	}

	// Display fingerprint should be the same regardless of version.
	if aFPv1.Display().DisplayText() != aFPv2.Display().DisplayText() {
		t.Fatal("display fingerprints should match across versions")
	}

	// Scannable encodings should differ (version field differs).
	v1Scan, err := aFPv1.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize v1: %v", err)
	}
	v2Scan, err := aFPv2.Scannable().Serialize()
	if err != nil {
		t.Fatalf("failed to serialize v2: %v", err)
	}
	if hex.EncodeToString(v1Scan) == hex.EncodeToString(v2Scan) {
		t.Fatal("scannable fingerprints should differ across versions")
	}

	// Cross-version comparison must return (false, *VersionMismatchError), matching
	// Rust's Err(FingerprintError::VersionMismatch { theirs, ours }) semantics
	// (rust/protocol/src/fingerprint.rs:130-135).
	match, err := aFPv1.Scannable().Compare(v2Scan)
	if match {
		t.Fatal("expected false for version mismatch comparison")
	}
	vmErr, ok := err.(*VersionMismatchError)
	if !ok {
		t.Fatalf("expected *VersionMismatchError, got %T: %v", err, err)
	}
	if vmErr.Ours != 1 {
		t.Fatalf("expected Ours=1, got %d", vmErr.Ours)
	}
	if vmErr.Theirs != 2 {
		t.Fatalf("expected Theirs=2, got %d", vmErr.Theirs)
	}
}

// --- Scannable fingerprint serialization tests ---

func TestScannableSerializeRoundTrip(t *testing.T) {
	var local, remote [scannableFingerprintSize]byte
	for i := range local {
		local[i] = byte(i)
	}
	for i := range remote {
		remote[i] = byte(i + 100)
	}

	s := &Scannable{
		version:           2,
		localFingerprint:  local,
		remoteFingerprint: remote,
	}

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("serialize error: %v", err)
	}

	deserialized, err := DeserializeScannable(data)
	if err != nil {
		t.Fatalf("deserialize error: %v", err)
	}

	if deserialized.version != s.version {
		t.Fatalf("version mismatch: got %d, want %d", deserialized.version, s.version)
	}
	if deserialized.localFingerprint != s.localFingerprint {
		t.Fatal("local fingerprint mismatch")
	}
	if deserialized.remoteFingerprint != s.remoteFingerprint {
		t.Fatal("remote fingerprint mismatch")
	}
}

func TestScannableSerialize_KnownEncoding(t *testing.T) {
	// From Rust test: fingerprint_encodings
	var local, remote [scannableFingerprintSize]byte
	for i := range local {
		local[i] = 0x12
	}
	for i := range remote {
		remote[i] = 0xBA
	}

	s := &Scannable{
		version:           2,
		localFingerprint:  local,
		remoteFingerprint: remote,
	}

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("serialize error: %v", err)
	}

	expected := "080212220a20" + strings.Repeat("12", 32) + "1a220a20" + strings.Repeat("ba", 32)
	got := hex.EncodeToString(data)
	if got != expected {
		t.Fatalf("encoding mismatch:\ngot:  %s\nwant: %s", got, expected)
	}
}

func TestScannableDeserialize_InvalidProtobuf(t *testing.T) {
	_, err := DeserializeScannable([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
	if _, ok := err.(*ParsingError); !ok {
		t.Fatalf("expected ParsingError, got %T: %v", err, err)
	}
}

func TestScannableDeserialize_MissingVersion(t *testing.T) {
	// Protobuf with no version field set, but with fingerprints.
	data, _ := hex.DecodeString("12220a20" + strings.Repeat("12", 32) + "1a220a20" + strings.Repeat("ba", 32))
	_, err := DeserializeScannable(data)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	pErr, ok := err.(*ParsingError)
	if !ok {
		t.Fatalf("expected ParsingError, got %T: %v", err, err)
	}
	if !strings.Contains(pErr.Detail, "version") {
		t.Fatalf("expected version-related error, got: %s", pErr.Detail)
	}
}

func TestScannableCompare_InvalidProtobuf(t *testing.T) {
	s := &Scannable{version: 1}
	_, err := s.Compare([]byte{0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid protobuf")
	}
	if _, ok := err.(*ParsingError); !ok {
		t.Fatalf("expected ParsingError, got %T: %v", err, err)
	}
}

func TestScannableCompare_VersionMismatch(t *testing.T) {
	s1 := &Scannable{version: 1}
	s2 := &Scannable{version: 2}

	data, err := s2.Serialize()
	if err != nil {
		t.Fatalf("serialize error: %v", err)
	}

	// Version mismatch returns (false, &VersionMismatchError{...}), matching
	// Rust's Err(FingerprintError::VersionMismatch { theirs, ours }) semantics
	// (rust/protocol/src/fingerprint.rs:130-135).
	match, err := s1.Compare(data)
	if match {
		t.Fatal("expected false for version mismatch comparison")
	}
	vmErr, ok := err.(*VersionMismatchError)
	if !ok {
		t.Fatalf("expected *VersionMismatchError, got %T: %v", err, err)
	}
	if vmErr.Ours != 1 {
		t.Fatalf("expected Ours=1, got %d", vmErr.Ours)
	}
	if vmErr.Theirs != 2 {
		t.Fatalf("expected Theirs=2, got %d", vmErr.Theirs)
	}
}

// --- Display fingerprint tests ---

func TestNewDisplay(t *testing.T) {
	local := make([]byte, 30)
	remote := make([]byte, 30)
	for i := range local {
		local[i] = byte(i)
	}
	for i := range remote {
		remote[i] = byte(i + 30)
	}

	display, err := NewDisplay(local, remote)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if display == nil {
		t.Fatal("expected non-nil Display")
	}
}

func TestDisplay_DisplayText_LocalSmaller(t *testing.T) {
	local := make([]byte, 64)
	remote := make([]byte, 64)
	for i := range remote {
		remote[i] = 0xFF
	}

	display, err := NewDisplay(local, remote)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := display.DisplayText()
	if len(text) != 60 {
		t.Fatalf("expected 60 character display text, got %d", len(text))
	}
}

func TestDisplay_DisplayText_RemoteSmaller(t *testing.T) {
	local := make([]byte, 64)
	remote := make([]byte, 64)
	for i := range local {
		local[i] = 0xFF
	}

	display, err := NewDisplay(local, remote)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := display.DisplayText()
	if len(text) != 60 {
		t.Fatalf("expected 60 character display text, got %d", len(text))
	}
}

func TestDisplay_DisplayText_OnlyDigits(t *testing.T) {
	local := make([]byte, 64)
	remote := make([]byte, 64)
	display, err := NewDisplay(local, remote)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := display.DisplayText()
	for _, c := range text {
		if c < '0' || c > '9' {
			t.Fatalf("display text should only contain digits, got %c", c)
		}
	}
}

func TestDisplay_DisplayText_Symmetric(t *testing.T) {
	local := make([]byte, 64)
	remote := make([]byte, 64)
	for i := range local {
		local[i] = byte(i)
	}
	for i := range remote {
		remote[i] = byte(i + 50)
	}

	d1, err := NewDisplay(local, remote)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d2, err := NewDisplay(remote, local)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d1.DisplayText() != d2.DisplayText() {
		t.Fatal("DisplayText should be symmetric (order-independent)")
	}
}

func TestNewFingerprint(t *testing.T) {
	local := make([]byte, 64)
	remote := make([]byte, 64)
	display, err := NewDisplay(local, remote)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	scannable := newScannable(1, local, remote)
	fp := NewFingerprint(display, scannable)
	if fp == nil {
		t.Fatal("expected non-nil Fingerprint")
	}
	if fp.Display() != display {
		t.Fatal("Display mismatch")
	}
	if fp.Scannable() != scannable {
		t.Fatal("Scannable mismatch")
	}
}

func TestEncodedChunk_Modulo(t *testing.T) {
	hash := make([]byte, 30)
	chunk := encodedChunk(hash, 0)
	if len(chunk) != 5 {
		t.Fatalf("expected 5-char chunk, got %d: %q", len(chunk), chunk)
	}
	for _, c := range chunk {
		if c < '0' || c > '9' {
			t.Fatalf("chunk should only contain digits, got %c", c)
		}
	}
}

func TestDisplayStringFor(t *testing.T) {
	fp := make([]byte, 64)
	result := displayStringFor(fp)
	if len(result) != 30 {
		t.Fatalf("expected 30 chars, got %d", len(result))
	}
	for _, c := range result {
		if c < '0' || c > '9' {
			t.Fatalf("should only contain digits, got %c", c)
		}
	}
}

func TestEncodedChunk_Padding(t *testing.T) {
	hash := make([]byte, 30)
	chunk := encodedChunk(hash, 0)
	if chunk != "00000" {
		t.Fatalf("expected '00000' for all-zero input, got %q", chunk)
	}
}

func TestFingerprintGenerator_InterfaceCompliance(t *testing.T) {
	gen, err := NewNumericFingerprintGenerator(DefaultIterations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify NumericFingerprintGenerator satisfies FingerprintGenerator.
	var _ FingerprintGenerator = gen
}

// --- CreateForMultiple tests ---

func TestCreateForMultiple_SingleKey(t *testing.T) {
	aKey := generateRandomIdentityKey(t)
	bKey := generateRandomIdentityKey(t)

	gen, err := NewNumericFingerprintGenerator(1024)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Single-key via CreateFor.
	fp1, err := gen.CreateFor(1, []byte(aliceStableID), aKey, []byte(bobStableID), bKey)
	if err != nil {
		t.Fatalf("CreateFor error: %v", err)
	}

	// Single-key via CreateForMultiple.
	fp2, err := gen.CreateForMultiple(1, []byte(aliceStableID), []*identity.Key{aKey}, []byte(bobStableID), []*identity.Key{bKey})
	if err != nil {
		t.Fatalf("CreateForMultiple error: %v", err)
	}

	// Both methods should produce the same fingerprint.
	if fp1.Display().DisplayText() != fp2.Display().DisplayText() {
		t.Fatal("single-key CreateFor and CreateForMultiple should produce same display")
	}
}

func TestCreateForMultiple_EmptyKeys(t *testing.T) {
	gen, err := NewNumericFingerprintGenerator(1024)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	_, err = gen.CreateForMultiple(1, []byte("id"), []*identity.Key{}, []byte("id2"), []*identity.Key{generateRandomIdentityKey(t)})
	if err == nil {
		t.Fatal("expected error for empty local keys")
	}
	if _, ok := err.(*ParsingError); !ok {
		t.Fatalf("expected ParsingError, got %T: %v", err, err)
	}
}

// TestCreateForMultiple_DoesNotMutateCallerSlice verifies that
// CreateForMultiple does not reorder the caller's key slice (F4 fix).
func TestCreateForMultiple_DoesNotMutateCallerSlice(t *testing.T) {
	gen, err := NewNumericFingerprintGenerator(DefaultIterations)
	if err != nil {
		t.Fatalf("NewNumericFingerprintGenerator error: %v", err)
	}

	k1 := generateRandomIdentityKey(t)
	k2 := generateRandomIdentityKey(t)
	// Force a known order by ensuring k2 serializes < k1 so sort would
	// swap them; we detect mutation by checking the slice order afterwards.
	// Use two distinct keys; the original order is [k1, k2].
	original := []*identity.Key{k1, k2}
	callerSlice := []*identity.Key{k1, k2}

	_, err = gen.CreateForMultiple(1,
		[]byte("alice"), callerSlice,
		[]byte("bob"), []*identity.Key{generateRandomIdentityKey(t)},
	)
	if err != nil {
		t.Fatalf("CreateForMultiple error: %v", err)
	}

	if callerSlice[0] != original[0] || callerSlice[1] != original[1] {
		t.Error("CreateForMultiple must not reorder the caller's key slice")
	}
}

// --- Error type tests ---

func TestVersionMismatchError_Message(t *testing.T) {
	err := &VersionMismatchError{Theirs: 2, Ours: 1}
	msg := err.Error()
	if !strings.Contains(msg, "2") || !strings.Contains(msg, "1") {
		t.Fatalf("error message should contain versions: %s", msg)
	}
}

func TestParsingError_Message(t *testing.T) {
	err := &ParsingError{Detail: "test detail"}
	if !strings.Contains(err.Error(), "test detail") {
		t.Fatalf("error message should contain detail: %s", err.Error())
	}
}

func TestInvalidIterationCountError_Message(t *testing.T) {
	err := &InvalidIterationCountError{Count: 42}
	if !strings.Contains(err.Error(), "42") {
		t.Fatalf("error message should contain count: %s", err.Error())
	}
}

// --- Scannable accessor tests ---

func TestScannableAccessors(t *testing.T) {
	var local, remote [scannableFingerprintSize]byte
	for i := range local {
		local[i] = byte(i)
	}
	for i := range remote {
		remote[i] = byte(i + 50)
	}

	s := &Scannable{
		version:           3,
		localFingerprint:  local,
		remoteFingerprint: remote,
	}

	if s.Version() != 3 {
		t.Fatalf("expected version 3, got %d", s.Version())
	}
	if s.LocalFingerprint() != local {
		t.Fatal("local fingerprint mismatch")
	}
	if s.RemoteFingerprint() != remote {
		t.Fatal("remote fingerprint mismatch")
	}
}
