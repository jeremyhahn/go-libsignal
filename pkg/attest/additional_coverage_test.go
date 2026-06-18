// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"encoding/binary"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// extractStringField edge cases
// ---------------------------------------------------------------------------

func TestExtractStringField_NotFound(t *testing.T) {
	result := extractStringField(`{"other": "value"}`, "missing")
	if result != "" {
		t.Fatalf("expected empty string, got %q", result)
	}
}

func TestExtractStringField_NoQuoteAfterColon(t *testing.T) {
	// Field exists but value is a number, not a string
	result := extractStringField(`{"status": 42}`, "status")
	if result != "" {
		t.Fatalf("expected empty string for non-string value, got %q", result)
	}
}

func TestExtractStringField_NoClosingQuote(t *testing.T) {
	result := extractStringField(`{"status": "unclosed`, "status")
	if result != "" {
		t.Fatalf("expected empty string for unclosed string, got %q", result)
	}
}

func TestExtractStringField_Valid(t *testing.T) {
	result := extractStringField(`{"status": "UpToDate"}`, "status")
	if result != "UpToDate" {
		t.Fatalf("expected UpToDate, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// extractStringArrayField edge cases
// ---------------------------------------------------------------------------

func TestExtractStringArrayField_NotFound(t *testing.T) {
	result := extractStringArrayField(`{"other": []}`, "advisoryIDs")
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestExtractStringArrayField_NoOpenBracket(t *testing.T) {
	// Field exists but value is not an array
	result := extractStringArrayField(`{"advisoryIDs": "value"}`, "advisoryIDs")
	if result != nil {
		t.Fatalf("expected nil for non-array value, got %v", result)
	}
}

func TestExtractStringArrayField_NoCloseBracket(t *testing.T) {
	result := extractStringArrayField(`{"advisoryIDs": ["INTEL-SA-00001"`, "advisoryIDs")
	if result != nil {
		t.Fatalf("expected nil for unclosed array, got %v", result)
	}
}

func TestExtractStringArrayField_Valid(t *testing.T) {
	result := extractStringArrayField(`{"advisoryIDs": ["INTEL-SA-00001", "INTEL-SA-00002"]}`, "advisoryIDs")
	if len(result) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result))
	}
	if result[0] != "INTEL-SA-00001" {
		t.Fatalf("expected INTEL-SA-00001, got %q", result[0])
	}
}

func TestExtractStringArrayField_EmptyArray(t *testing.T) {
	result := extractStringArrayField(`{"advisoryIDs": []}`, "advisoryIDs")
	if result != nil {
		t.Fatalf("expected nil for empty array, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// extractUint16FieldSafe overflow path
// ---------------------------------------------------------------------------

func TestExtractUint16FieldSafe_Overflow(t *testing.T) {
	_, err := extractUint16FieldSafe(`{"isvsvn": 70000}`, "isvsvn")
	if err == nil {
		t.Fatal("expected error for overflow value")
	}
	var overflowErr *Uint16OverflowError
	if !errors.As(err, &overflowErr) {
		t.Fatalf("expected *Uint16OverflowError, got %T", err)
	}
	if overflowErr.Field != "isvsvn" {
		t.Fatalf("expected field=isvsvn, got %q", overflowErr.Field)
	}
}

func TestExtractUint16FieldSafe_NotFound(t *testing.T) {
	val, err := extractUint16FieldSafe(`{"other": 5}`, "isvsvn")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 0 {
		t.Fatalf("expected 0 for missing field, got %d", val)
	}
}

func TestExtractUint16FieldSafe_NotANumber(t *testing.T) {
	val, err := extractUint16FieldSafe(`{"isvsvn": "text"}`, "isvsvn")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 0 {
		t.Fatalf("expected 0 for non-numeric value, got %d", val)
	}
}

// ---------------------------------------------------------------------------
// computeClaimsSize edge cases
// ---------------------------------------------------------------------------

func TestComputeClaimsSize_TooShort(t *testing.T) {
	data := []byte{0x01, 0x02}
	size := computeClaimsSize(data)
	if size != len(data) {
		t.Fatalf("expected %d for short data, got %d", len(data), size)
	}
}

func TestComputeClaimsSize_TooManyClaimsGuard(t *testing.T) {
	// Build data with numClaims > 256
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[8:16], 257)
	size := computeClaimsSize(data)
	if size != len(data) {
		t.Fatalf("expected full length for excessive claims count, got %d", size)
	}
}

func TestComputeClaimsSize_TruncatedAtEntry(t *testing.T) {
	// numClaims=1 but data is too short to read entry header
	data := make([]byte, 20) // 16 header + only 4 bytes (need 16)
	binary.LittleEndian.PutUint64(data[8:16], 1)
	size := computeClaimsSize(data)
	if size != len(data) {
		t.Fatalf("expected full length for truncated entry, got %d", size)
	}
}

func TestComputeClaimsSize_OversizedEntry(t *testing.T) {
	// numClaims=1 with oversized name (> 1024)
	data := make([]byte, 32)
	binary.LittleEndian.PutUint64(data[8:16], 1)     // numClaims = 1
	binary.LittleEndian.PutUint64(data[16:24], 2000) // nameSize > 1024
	binary.LittleEndian.PutUint64(data[24:32], 0)    // valueSize = 0
	size := computeClaimsSize(data)
	if size != len(data) {
		t.Fatalf("expected full length for oversized entry, got %d", size)
	}
}

// ---------------------------------------------------------------------------
// parseEndorsements edge cases
// ---------------------------------------------------------------------------

func TestParseEndorsements_TooShort_Additional(t *testing.T) {
	_, err := parseEndorsements([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short data")
	}
	var parseErr *EndorsementParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *EndorsementParseError, got %T", err)
	}
}

func TestParseEndorsements_UnsupportedHeaderVersion(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], 99) // version != 1
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for unsupported header version")
	}
}

func TestParseEndorsements_UnsupportedEnclaveType(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], 1)  // version = 1
	binary.LittleEndian.PutUint32(data[4:8], 99) // enclaveType != 2
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for unsupported enclave type")
	}
}

func TestParseEndorsements_TooFewFields(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], 1)   // version = 1
	binary.LittleEndian.PutUint32(data[4:8], 2)   // enclaveType = 2
	binary.LittleEndian.PutUint32(data[12:16], 2) // numElements = 2 (< sgxEndorsementFieldCount)
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for too few fields")
	}
}

// ---------------------------------------------------------------------------
// parseEnclaveIdentityJSON edge cases
// ---------------------------------------------------------------------------

func TestParseEnclaveIdentityJSON_InvalidJSON(t *testing.T) {
	_, err := parseEnclaveIdentityJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	var parseErr *EnclaveIdentityParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *EnclaveIdentityParseError, got %T", err)
	}
}

func TestParseEnclaveIdentityJSON_WrongVersion(t *testing.T) {
	// Valid JSON but wrong enclave identity version
	jsonData := []byte(`{"id": "QE", "version": 1, "issueDate": "2024-01-01T00:00:00Z", "nextUpdate": "2025-01-01T00:00:00Z"}`)
	_, err := parseEnclaveIdentityJSON(jsonData)
	if err == nil {
		t.Fatal("expected error for version != 2")
	}
	var versionErr *EnclaveIdentityVersionError
	if !errors.As(err, &versionErr) {
		t.Fatalf("expected *EnclaveIdentityVersionError, got %T", err)
	}
}

func TestParseEnclaveIdentityJSON_WithWrapper(t *testing.T) {
	// Wrapped format: {"enclaveIdentity": {...}, "signature": "..."}
	// The inner version is wrong (not 2) so we test path execution.
	jsonData := []byte(`{"enclaveIdentity": {"id": "QE", "version": 1}}`)
	_, err := parseEnclaveIdentityJSON(jsonData)
	// Should get an error because version != 2
	if err == nil {
		t.Fatal("expected error for version != 2 in wrapped format")
	}
}

// ---------------------------------------------------------------------------
// parseIntelRootKey sanity check
// ---------------------------------------------------------------------------

func TestParseIntelRootKey_Additional(t *testing.T) {
	key, err := parseIntelRootKey()
	if err != nil {
		t.Fatalf("parseIntelRootKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if _, err := key.ECDH(); err != nil {
		t.Fatalf("key is not a valid P-256 point: %v", err)
	}
}

// ---------------------------------------------------------------------------
// findTCBStanding with unacceptable status
// ---------------------------------------------------------------------------

func TestFindTCBStanding_UnacceptableStatus(t *testing.T) {
	pckExt := &pckExtensionData{}
	levels := []tcbLevel{
		{status: "Revoked"},
	}
	_, _, err := findTCBStanding(pckExt, levels)
	if err == nil {
		t.Fatal("expected error for unacceptable TCB status")
	}
	var statusErr *TCBStatusUnacceptableError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected *TCBStatusUnacceptableError, got %T", err)
	}
	if statusErr.Status != "Revoked" {
		t.Fatalf("expected status=Revoked, got %q", statusErr.Status)
	}
}

func TestFindTCBStanding_SWHardeningNeeded(t *testing.T) {
	pckExt := &pckExtensionData{}
	levels := []tcbLevel{
		{status: "SWHardeningNeeded", advisoryIDs: []string{"INTEL-SA-12345"}},
	}
	standing, advisoryIDs, err := findTCBStanding(pckExt, levels)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if standing != tcbSWHardeningNeeded {
		t.Fatalf("expected tcbSWHardeningNeeded, got %v", standing)
	}
	if len(advisoryIDs) != 1 || advisoryIDs[0] != "INTEL-SA-12345" {
		t.Fatalf("expected advisory IDs, got %v", advisoryIDs)
	}
}

func TestFindTCBStanding_NoMatchingLevel(t *testing.T) {
	// PCK with all-zero SVNs vs a level with non-zero SVN requirement
	pckExt := &pckExtensionData{} // all zeros
	levels := []tcbLevel{
		{
			// Component 0 requires SVN >= 5, but PCK has 0
			compsvn: [16]byte{5},
			status:  "UpToDate",
		},
	}
	_, _, err := findTCBStanding(pckExt, levels)
	if err == nil {
		t.Fatal("expected error when no matching TCB level found")
	}
	var unsupportedErr *TCBUnsupportedError
	if !errors.As(err, &unsupportedErr) {
		t.Fatalf("expected *TCBUnsupportedError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// extractRawJSONValue edge cases
// ---------------------------------------------------------------------------

func TestExtractRawJSONValue_InvalidJSON(t *testing.T) {
	result := extractRawJSONValue("not json", "field")
	if result != "" {
		t.Fatalf("expected empty string for invalid JSON, got %q", result)
	}
}

func TestExtractRawJSONValue_MissingField(t *testing.T) {
	result := extractRawJSONValue(`{"other": "value"}`, "missing")
	if result != "" {
		t.Fatalf("expected empty string for missing field, got %q", result)
	}
}

func TestExtractRawJSONValue_Valid(t *testing.T) {
	result := extractRawJSONValue(`{"tcbInfo": {"version": 3}}`, "tcbInfo")
	if result == "" {
		t.Fatal("expected non-empty result for existing field")
	}
}

// ---------------------------------------------------------------------------
// parseQuoteBody version/signType branches
// ---------------------------------------------------------------------------

func TestParseQuoteBody_WrongVersion_Additional(t *testing.T) {
	data := make([]byte, sgxQuoteBodySize)
	binary.LittleEndian.PutUint16(data[0:2], 99) // version != 3
	binary.LittleEndian.PutUint16(data[2:4], ecdsaP256)
	_, err := parseQuoteBody(data)
	if err == nil {
		t.Fatal("expected error for wrong quote version")
	}
}

func TestParseQuoteBody_WrongSignType(t *testing.T) {
	data := make([]byte, sgxQuoteBodySize)
	binary.LittleEndian.PutUint16(data[0:2], quoteV3)
	binary.LittleEndian.PutUint16(data[2:4], 99) // signType != ecdsaP256
	_, err := parseQuoteBody(data)
	if err == nil {
		t.Fatal("expected error for wrong sign type")
	}
}

// ---------------------------------------------------------------------------
// verifyClaimsHash error paths
// ---------------------------------------------------------------------------

func TestVerifyClaimsHash_NilClaimsData_Additional(t *testing.T) {
	evidence := &dcapEvidence{claimsRawData: nil}
	err := verifyClaimsHash(evidence)
	if err == nil {
		t.Fatal("expected error for nil claims data")
	}
	var claimsErr *ClaimsError
	if !errors.As(err, &claimsErr) {
		t.Fatalf("expected *ClaimsError, got %T", err)
	}
}

// ---------------------------------------------------------------------------
// parsePCKExtension error paths
// ---------------------------------------------------------------------------

func TestParsePCKExtension_NilQuote(t *testing.T) {
	evidence := &dcapEvidence{quote: nil}
	_, err := parsePCKExtension(evidence)
	if err == nil {
		t.Fatal("expected error for nil quote")
	}
}

func TestParsePCKExtension_NilSupport(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{},
			support:   nil,
		},
	}
	_, err := parsePCKExtension(evidence)
	if err == nil {
		t.Fatal("expected error for nil support")
	}
}

func TestParsePCKExtension_EmptyCertChain(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{},
			support: &sgxQuoteSupport{
				pckCertChain: nil,
			},
		},
	}
	_, err := parsePCKExtension(evidence)
	if err == nil {
		t.Fatal("expected error for empty cert chain")
	}
}

// ---------------------------------------------------------------------------
// parseASN1Sequence with long-form length
// ---------------------------------------------------------------------------

func TestParseASN1Sequence_LongFormLength(t *testing.T) {
	// Build a SEQUENCE with a length that requires long-form encoding.
	// We'll build 130 zero bytes of content and use the 2-byte long form.
	content := make([]byte, 130) // 130 bytes
	// Tag + long-form length (0x81, 0x82)
	data := []byte{0x30, 0x81, 0x82}
	data = append(data, content...)

	// This should parse successfully (empty items since content doesn't parse into valid TLVs).
	items, err := parseASN1Sequence(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Items may be empty since the content doesn't have valid TLVs, but no error.
	_ = items
}

// ---------------------------------------------------------------------------
// parseTCBFromASN1 with invalid integer entries (cover -1 branch)
// ---------------------------------------------------------------------------

func TestParseTCBFromASN1_InvalidIntegerSkipped(t *testing.T) {
	ext := &pckExtensionData{}

	// Build a TCB sequence where the value is an OCTET STRING (not INTEGER)
	// The OID is valid but the value type is wrong, so extractASN1Integer returns -1.
	oid := buildASN1OIDBytes(encodeOIDTCBComp(1))
	// Use OCTET STRING instead of INTEGER for the value
	wrongValue := buildASN1OctetString([]byte{0x05})
	entry := buildASN1Sequence(oid, wrongValue)
	outer := buildASN1Sequence(entry)

	parseTCBFromASN1(outer, ext)
	// compsvn[0] should still be 0 since -1 from extractASN1Integer causes skip
	if ext.compsvn[0] != 0 {
		t.Fatalf("expected compsvn[0]=0 (skipped), got %d", ext.compsvn[0])
	}
}

// ---------------------------------------------------------------------------
// parseASN1Sequence with invalid inner item length
// ---------------------------------------------------------------------------

func TestParseASN1Sequence_ItemExceedsContent(t *testing.T) {
	// Build a SEQUENCE where an item claims to be larger than the content.
	// The loop should stop gracefully.
	// Item claims length=10 but only 2 bytes follow.
	content := []byte{0x04, 0x0A, 0xAA, 0xBB} // OCTET STRING, length=10, only 2 bytes
	data := []byte{0x30, byte(len(content))}
	data = append(data, content...)

	items, err := parseASN1Sequence(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return 0 items since the item exceeds content
	if len(items) != 0 {
		t.Fatalf("expected 0 items for truncated item, got %d", len(items))
	}
}
