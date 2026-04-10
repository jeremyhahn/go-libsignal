// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"bytes"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// Error type coverage: all untested Error()/Unwrap() methods
// ---------------------------------------------------------------------------

func TestUint16OverflowError(t *testing.T) {
	e := &Uint16OverflowError{Field: "isvsvn", Value: 70000}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	// Must mention the field name and value.
	if !contains(msg, "isvsvn") {
		t.Fatalf("Error() should mention field name, got: %s", msg)
	}
	if !contains(msg, "70000") {
		t.Fatalf("Error() should mention the value, got: %s", msg)
	}
}

func TestQEVendorIDMismatchError(t *testing.T) {
	var actual [16]byte
	actual[0] = 0xAB
	e := &QEVendorIDMismatchError{Actual: actual}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !contains(msg, "Intel") {
		t.Fatalf("Error() should mention Intel, got: %s", msg)
	}
}

func TestQEAttributesMismatchError(t *testing.T) {
	e := &QEAttributesMismatchError{Index: 3, Expected: 0x04, Actual: 0x08}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !contains(msg, "3") {
		t.Fatalf("Error() should mention index 3, got: %s", msg)
	}
}

func TestMRSignerMismatchError(t *testing.T) {
	var expected, actual [32]byte
	expected[0] = 0xAA
	actual[0] = 0xBB
	e := &MRSignerMismatchError{Expected: expected, Actual: actual}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !contains(msg, "mrsigner") {
		t.Fatalf("Error() should mention mrsigner, got: %s", msg)
	}
}

func TestISVProdIDMismatchError(t *testing.T) {
	e := &ISVProdIDMismatchError{Expected: 1, Actual: 2}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !contains(msg, "isvprodid") {
		t.Fatalf("Error() should mention isvprodid, got: %s", msg)
	}
}

func TestMiscselectMismatchError(t *testing.T) {
	e := &MiscselectMismatchError{Expected: 0x00000000, Actual: 0x00000001}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !contains(msg, "miscselect") {
		t.Fatalf("Error() should mention miscselect, got: %s", msg)
	}
}

func TestTCBStatusUnacceptableError(t *testing.T) {
	e := &TCBStatusUnacceptableError{Status: "Revoked"}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !contains(msg, "Revoked") {
		t.Fatalf("Error() should mention status Revoked, got: %s", msg)
	}
}

func TestEnclaveIdentityParseError_WithErr(t *testing.T) {
	inner := errors.New("json decode failure")
	e := &EnclaveIdentityParseError{Err: inner}
	msg := e.Error()
	if !contains(msg, "json decode failure") {
		t.Fatalf("Error() should contain inner error, got: %s", msg)
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestEnclaveIdentityParseError_NoErr(t *testing.T) {
	e := &EnclaveIdentityParseError{}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string even without inner error")
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

func TestTCBLevelVersionInconsistencyError_V3(t *testing.T) {
	e := &TCBLevelVersionInconsistencyError{ExpectedV3: true}
	msg := e.Error()
	if !contains(msg, "v3") {
		t.Fatalf("Error() should mention v3, got: %s", msg)
	}
}

func TestTCBLevelVersionInconsistencyError_V2(t *testing.T) {
	e := &TCBLevelVersionInconsistencyError{ExpectedV3: false}
	msg := e.Error()
	if !contains(msg, "v2") {
		t.Fatalf("Error() should mention v2, got: %s", msg)
	}
}

func TestTCBUnsupportedError(t *testing.T) {
	e := &TCBUnsupportedError{}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !contains(msg, "unsupported") {
		t.Fatalf("Error() should mention unsupported, got: %s", msg)
	}
}

func TestDcapOperationError_WithErr(t *testing.T) {
	inner := errors.New("cert chain error")
	e := &DcapOperationError{Operation: "verify certs", Err: inner}
	msg := e.Error()
	if !contains(msg, "verify certs") {
		t.Fatalf("Error() should mention operation, got: %s", msg)
	}
	if !contains(msg, "cert chain error") {
		t.Fatalf("Error() should contain inner error, got: %s", msg)
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestDcapOperationError_NoErr(t *testing.T) {
	e := &DcapOperationError{Operation: "parse endorsements"}
	msg := e.Error()
	if !contains(msg, "parse endorsements") {
		t.Fatalf("Error() should mention operation, got: %s", msg)
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

func TestDcapValidationError(t *testing.T) {
	e := &DcapValidationError{Detail: "MRENCLAVE mismatch"}
	msg := e.Error()
	if !contains(msg, "MRENCLAVE mismatch") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
}

func TestEvidenceParseError_WithErr(t *testing.T) {
	inner := errors.New("buffer too short")
	e := &EvidenceParseError{Detail: "quote body", Err: inner}
	msg := e.Error()
	if !contains(msg, "quote body") {
		t.Fatalf("Error() should mention detail, got: %s", msg)
	}
	if !contains(msg, "buffer too short") {
		t.Fatalf("Error() should contain inner error, got: %s", msg)
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestEvidenceParseError_NoErr(t *testing.T) {
	e := &EvidenceParseError{Detail: "invalid quote version"}
	msg := e.Error()
	if !contains(msg, "invalid quote version") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

func TestEndorsementParseError_WithErr(t *testing.T) {
	inner := errors.New("decode failure")
	e := &EndorsementParseError{Detail: "tcbInfo field", Err: inner}
	msg := e.Error()
	if !contains(msg, "tcbInfo field") {
		t.Fatalf("Error() should mention detail, got: %s", msg)
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestEndorsementParseError_NoErr(t *testing.T) {
	e := &EndorsementParseError{Detail: "missing signature"}
	msg := e.Error()
	if !contains(msg, "missing signature") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

func TestASN1ParseError_WithErr(t *testing.T) {
	inner := errors.New("unexpected tag")
	e := &ASN1ParseError{Detail: "SGX extension", Err: inner}
	msg := e.Error()
	if !contains(msg, "ASN.1") {
		t.Fatalf("Error() should mention ASN.1, got: %s", msg)
	}
	if !contains(msg, "SGX extension") {
		t.Fatalf("Error() should mention detail, got: %s", msg)
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestASN1ParseError_NoErr(t *testing.T) {
	e := &ASN1ParseError{Detail: "empty sequence"}
	msg := e.Error()
	if !contains(msg, "empty sequence") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

func TestCertChainError_WithErr(t *testing.T) {
	inner := errors.New("signature invalid")
	e := &CertChainError{Detail: "root cert verification", Err: inner}
	msg := e.Error()
	if !contains(msg, "root cert verification") {
		t.Fatalf("Error() should mention detail, got: %s", msg)
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestCertChainError_NoErr(t *testing.T) {
	e := &CertChainError{Detail: "chain length exceeded"}
	msg := e.Error()
	if !contains(msg, "chain length exceeded") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

func TestClaimsError(t *testing.T) {
	e := &ClaimsError{Detail: "claims hash mismatch"}
	msg := e.Error()
	if !contains(msg, "claims hash mismatch") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
}

func TestFMSPCMismatchError(t *testing.T) {
	e := &FMSPCMismatchError{
		PCKExtension: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		TCBInfo:      []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	}
	msg := e.Error()
	if !contains(msg, "fmspc") {
		t.Fatalf("Error() should mention fmspc, got: %s", msg)
	}
}

func TestPCEIDMismatchError(t *testing.T) {
	e := &PCEIDMismatchError{
		PCKExtension: []byte{0x00, 0x00},
		TCBInfo:      []byte{0x01, 0x00},
	}
	msg := e.Error()
	if !contains(msg, "pceid") {
		t.Fatalf("Error() should mention pceid, got: %s", msg)
	}
}

func TestHexDecodeError(t *testing.T) {
	e := &HexDecodeError{Char: 'G'}
	msg := e.Error()
	if !contains(msg, "G") {
		t.Fatalf("Error() should mention the invalid character, got: %s", msg)
	}
}

func TestJSONFieldError(t *testing.T) {
	e := &JSONFieldError{Field: "tcbStatus", Detail: "field missing"}
	msg := e.Error()
	if !contains(msg, "tcbStatus") {
		t.Fatalf("Error() should mention field name, got: %s", msg)
	}
	if !contains(msg, "field missing") {
		t.Fatalf("Error() should mention detail, got: %s", msg)
	}
}

func TestAttestKeyError(t *testing.T) {
	e := &AttestKeyError{Detail: "not a P-256 key"}
	msg := e.Error()
	if !contains(msg, "not a P-256 key") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
}

func TestSignatureFormatError(t *testing.T) {
	e := &SignatureFormatError{Expected: 64, Actual: 32}
	msg := e.Error()
	if !contains(msg, "64") {
		t.Fatalf("Error() should mention expected size, got: %s", msg)
	}
	if !contains(msg, "32") {
		t.Fatalf("Error() should mention actual size, got: %s", msg)
	}
}

func TestPEMParseError_WithErr(t *testing.T) {
	inner := errors.New("no PEM block")
	e := &PEMParseError{Detail: "PCK cert chain", Err: inner}
	msg := e.Error()
	if !contains(msg, "PCK cert chain") {
		t.Fatalf("Error() should mention detail, got: %s", msg)
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestPEMParseError_NoErr(t *testing.T) {
	e := &PEMParseError{Detail: "empty PEM data"}
	msg := e.Error()
	if !contains(msg, "empty PEM data") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

func TestCRLParseError_WithErr(t *testing.T) {
	inner := errors.New("DER decode failure")
	e := &CRLParseError{Err: inner}
	msg := e.Error()
	if !contains(msg, "DER decode failure") {
		t.Fatalf("Error() should contain inner error, got: %s", msg)
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestCRLParseError_NoErr(t *testing.T) {
	e := &CRLParseError{}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

func TestHandshakeIncompleteError(t *testing.T) {
	e := &HandshakeIncompleteError{}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !contains(msg, "handshake") {
		t.Fatalf("Error() should mention handshake, got: %s", msg)
	}
}

func TestProtobufWireTypeError(t *testing.T) {
	e := &ProtobufWireTypeError{WireType: 5, FieldNumber: 3}
	msg := e.Error()
	if !contains(msg, "5") {
		t.Fatalf("Error() should mention wire type 5, got: %s", msg)
	}
	if !contains(msg, "3") {
		t.Fatalf("Error() should mention field 3, got: %s", msg)
	}
}

func TestClaimsParseError(t *testing.T) {
	e := &ClaimsParseError{Detail: "unexpected claims format"}
	msg := e.Error()
	if !contains(msg, "unexpected claims format") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
}

func TestEndorsementValidationError(t *testing.T) {
	e := &EndorsementValidationError{Detail: "expired endorsement"}
	msg := e.Error()
	if !contains(msg, "expired endorsement") {
		t.Fatalf("Error() should contain detail, got: %s", msg)
	}
}

// ---------------------------------------------------------------------------
// ASN.1 parsing function coverage
// ---------------------------------------------------------------------------

// buildASN1OctetString builds an ASN.1 OCTET STRING TLV.
func buildASN1OctetString(value []byte) []byte {
	result := []byte{0x04, byte(len(value))}
	return append(result, value...)
}

// buildASN1Integer builds an ASN.1 INTEGER TLV.
func buildASN1Integer(value byte) []byte {
	return []byte{0x02, 0x01, value}
}

// buildASN1OID encodes a pre-built OID as an ASN.1 OID TLV.
func buildASN1OIDBytes(encoded []byte) []byte {
	result := []byte{0x06, byte(len(encoded))}
	return append(result, encoded...)
}

// buildASN1Sequence wraps items in an ASN.1 SEQUENCE TLV.
func buildASN1Sequence(items ...[]byte) []byte {
	var content []byte
	for _, item := range items {
		content = append(content, item...)
	}
	result := []byte{0x30, byte(len(content))}
	return append(result, content...)
}

// encodeOIDFMSPC encodes "1.2.840.113741.1.13.1.4" (FMSPC OID) in DER.
// The first two components 1.2 encode as (1*40+2)=42=0x2A.
// Remaining components use base-128 big-endian encoding with high bit set
// on all bytes except the last:
//   840     = 0x86, 0x48
//   113741  = 0x86, 0xF8, 0x4D
//   1       = 0x01
//   13      = 0x0D
//   1       = 0x01
//   4       = 0x04
func encodeOIDFMSPC() []byte {
	return []byte{0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x04}
}

// encodeOIDPCEID encodes "1.2.840.113741.1.13.1.3".
func encodeOIDPCEID() []byte {
	return []byte{0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x03}
}

// encodeOIDTCB encodes "1.2.840.113741.1.13.1.2".
func encodeOIDTCB() []byte {
	return []byte{0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x02}
}

// encodeOIDTCBComp encodes "1.2.840.113741.1.13.1.2.N" for component index N (1-based).
func encodeOIDTCBComp(n byte) []byte {
	return append(encodeOIDTCB(), n)
}

// encodeOIDTCBPCESVN encodes "1.2.840.113741.1.13.1.2.17".
func encodeOIDTCBPCESVN() []byte {
	return append(encodeOIDTCB(), 17)
}

func TestParseASN1Length_ShortForm(t *testing.T) {
	data := []byte{0x05}
	length, consumed, err := parseASN1Length(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 5 {
		t.Fatalf("expected length 5, got %d", length)
	}
	if consumed != 1 {
		t.Fatalf("expected consumed=1, got %d", consumed)
	}
}

func TestParseASN1Length_LongForm2Bytes(t *testing.T) {
	// 0x82 = long form, 2 bytes follow; value = 0x01, 0x00 = 256
	data := []byte{0x82, 0x01, 0x00}
	length, consumed, err := parseASN1Length(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 256 {
		t.Fatalf("expected length 256, got %d", length)
	}
	if consumed != 3 {
		t.Fatalf("expected consumed=3, got %d", consumed)
	}
}

func TestParseASN1Length_Empty(t *testing.T) {
	_, _, err := parseASN1Length([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	var asn1Err *ASN1ParseError
	if !errors.As(err, &asn1Err) {
		t.Fatalf("expected *ASN1ParseError, got %T", err)
	}
}

func TestParseASN1Length_InvalidLongForm_ZeroNumBytes(t *testing.T) {
	// 0x80 = indefinite length or invalid (numBytes=0)
	_, _, err := parseASN1Length([]byte{0x80})
	if err == nil {
		t.Fatal("expected error for invalid long form")
	}
}

func TestParseASN1Length_InvalidLongForm_TooShort(t *testing.T) {
	// 0x82 says 2 bytes follow, but only 1 byte available
	_, _, err := parseASN1Length([]byte{0x82, 0x01})
	if err == nil {
		t.Fatal("expected error for truncated long form length")
	}
}

func TestParseASN1Sequence_Basic(t *testing.T) {
	// Build: SEQUENCE { OCTET STRING "AB" }
	inner := buildASN1OctetString([]byte{0xAA, 0xBB})
	data := buildASN1Sequence(inner)

	items, err := parseASN1Sequence(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !bytes.Equal(items[0], inner) {
		t.Fatalf("item mismatch: got %x, want %x", items[0], inner)
	}
}

func TestParseASN1Sequence_TooShort(t *testing.T) {
	_, err := parseASN1Sequence([]byte{0x30})
	if err == nil {
		t.Fatal("expected error for truncated sequence")
	}
}

func TestParseASN1Sequence_WrongTag(t *testing.T) {
	// Tag 0x04 is OCTET STRING, not SEQUENCE
	_, err := parseASN1Sequence([]byte{0x04, 0x01, 0xAB})
	if err == nil {
		t.Fatal("expected error for wrong tag")
	}
	var asn1Err *ASN1ParseError
	if !errors.As(err, &asn1Err) {
		t.Fatalf("expected *ASN1ParseError, got %T", err)
	}
}

func TestParseASN1Sequence_MultipleItems(t *testing.T) {
	item1 := buildASN1OctetString([]byte{0x01})
	item2 := buildASN1OctetString([]byte{0x02, 0x03})
	data := buildASN1Sequence(item1, item2)

	items, err := parseASN1Sequence(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

func TestParseASN1OID_Basic(t *testing.T) {
	// OID 1.2 encodes as first byte = 1*40+2 = 42
	data := buildASN1OIDBytes([]byte{42})
	oid, err := parseASN1OID(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oid != "1.2" {
		t.Fatalf("expected OID 1.2, got %s", oid)
	}
}

func TestParseASN1OID_FMSPC(t *testing.T) {
	oidBytes := encodeOIDFMSPC()
	data := buildASN1OIDBytes(oidBytes)
	oid, err := parseASN1OID(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oid != "1.2.840.113741.1.13.1.4" {
		t.Fatalf("expected FMSPC OID, got %s", oid)
	}
}

func TestParseASN1OID_NotOIDTag(t *testing.T) {
	// Tag 0x04 is OCTET STRING, not OID
	_, err := parseASN1OID([]byte{0x04, 0x01, 0x01})
	if err == nil {
		t.Fatal("expected error for non-OID tag")
	}
}

func TestParseASN1OID_TooShort(t *testing.T) {
	// OID with length=2 but only 0 bytes of content
	_, err := parseASN1OID([]byte{0x06, 0x02})
	if err == nil {
		t.Fatal("expected error for truncated OID data")
	}
}

func TestParseASN1OID_EmptyContent(t *testing.T) {
	// OID with length=0 (empty)
	_, err := parseASN1OID([]byte{0x06, 0x00})
	if err == nil {
		t.Fatal("expected error for empty OID content")
	}
}

func TestParseASN1OID_TooFewBytes(t *testing.T) {
	// Only 1 byte total (needs at least 2 for tag+length)
	_, err := parseASN1OID([]byte{0x06})
	if err == nil {
		t.Fatal("expected error for only 1 byte")
	}
}

func TestExtractASN1OctetString_Valid(t *testing.T) {
	value := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34}
	data := buildASN1OctetString(value)
	got := extractASN1OctetString(data)
	if !bytes.Equal(got, value) {
		t.Fatalf("expected %x, got %x", value, got)
	}
}

func TestExtractASN1OctetString_WrongTag(t *testing.T) {
	// INTEGER tag, not OCTET STRING
	data := []byte{0x02, 0x01, 0xFF}
	got := extractASN1OctetString(data)
	if got != nil {
		t.Fatal("expected nil for wrong tag")
	}
}

func TestExtractASN1OctetString_TooShort(t *testing.T) {
	// OCTET STRING tag with length=5 but only 2 bytes of content
	data := []byte{0x04, 0x05, 0xAA, 0xBB}
	got := extractASN1OctetString(data)
	if got != nil {
		t.Fatal("expected nil for truncated octet string")
	}
}

func TestExtractASN1OctetString_Empty(t *testing.T) {
	// Only 1 byte total
	got := extractASN1OctetString([]byte{0x04})
	if got != nil {
		t.Fatal("expected nil for single byte")
	}
}

func TestExtractASN1Integer_Valid(t *testing.T) {
	data := buildASN1Integer(42)
	got := extractASN1Integer(data)
	if got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
}

func TestExtractASN1Integer_WrongTag(t *testing.T) {
	// OCTET STRING tag
	data := []byte{0x04, 0x01, 0x05}
	got := extractASN1Integer(data)
	if got != -1 {
		t.Fatalf("expected -1 for wrong tag, got %d", got)
	}
}

func TestExtractASN1Integer_TooShort(t *testing.T) {
	// INTEGER with length=3 but only 1 byte of data
	data := []byte{0x02, 0x03, 0xAA}
	got := extractASN1Integer(data)
	if got != -1 {
		t.Fatalf("expected -1 for truncated integer, got %d", got)
	}
}

func TestExtractASN1Integer_LengthZero(t *testing.T) {
	data := []byte{0x02, 0x00}
	got := extractASN1Integer(data)
	if got != -1 {
		t.Fatalf("expected -1 for zero-length integer, got %d", got)
	}
}

func TestExtractASN1Integer_OneByte(t *testing.T) {
	data := []byte{0x02, 0x01}
	got := extractASN1Integer(data)
	// Only 2 bytes but length says 1 byte follows - truncated
	if got != -1 {
		t.Fatalf("expected -1 for truncated single-byte integer, got %d", got)
	}
}

func TestExtractASN1Integer_MultiByteValue(t *testing.T) {
	// INTEGER 0x0102 (2 bytes)
	data := []byte{0x02, 0x02, 0x01, 0x02}
	got := extractASN1Integer(data)
	if got != 0x0102 {
		t.Fatalf("expected 0x0102, got %d", got)
	}
}

func TestParseSGXExtensionASN1_MissingFMSPC(t *testing.T) {
	// Build an extension with only PCEID, no FMSPC
	oidPCEID := buildASN1OIDBytes(encodeOIDPCEID())
	pceidValue := buildASN1OctetString([]byte{0x00, 0x00})
	pceidEntry := buildASN1Sequence(oidPCEID, pceidValue)
	outer := buildASN1Sequence(pceidEntry)

	_, err := parseSGXExtensionASN1(outer)
	if err == nil {
		t.Fatal("expected error when FMSPC is missing")
	}
}

func TestParseSGXExtensionASN1_MissingPCEID(t *testing.T) {
	// Build an extension with only FMSPC, no PCEID
	oidFMSPC := buildASN1OIDBytes(encodeOIDFMSPC())
	fmspcValue := buildASN1OctetString([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	fmspcEntry := buildASN1Sequence(oidFMSPC, fmspcValue)
	outer := buildASN1Sequence(fmspcEntry)

	_, err := parseSGXExtensionASN1(outer)
	if err == nil {
		t.Fatal("expected error when PCEID is missing")
	}
}

func TestParseSGXExtensionASN1_ValidFMSPCAndPCEID(t *testing.T) {
	fmspc := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	pceid := []byte{0x00, 0x00}

	oidFMSPC := buildASN1OIDBytes(encodeOIDFMSPC())
	fmspcValue := buildASN1OctetString(fmspc)
	fmspcEntry := buildASN1Sequence(oidFMSPC, fmspcValue)

	oidPCEID := buildASN1OIDBytes(encodeOIDPCEID())
	pceidValue := buildASN1OctetString(pceid)
	pceidEntry := buildASN1Sequence(oidPCEID, pceidValue)

	outer := buildASN1Sequence(fmspcEntry, pceidEntry)

	ext, err := parseSGXExtensionASN1(outer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(ext.fmspc, fmspc) {
		t.Fatalf("fmspc mismatch: got %x, want %x", ext.fmspc, fmspc)
	}
	if !bytes.Equal(ext.pceid, pceid) {
		t.Fatalf("pceid mismatch: got %x, want %x", ext.pceid, pceid)
	}
}

func TestParseSGXExtensionASN1_InvalidOuterSequence(t *testing.T) {
	// Not a SEQUENCE tag
	_, err := parseSGXExtensionASN1([]byte{0x04, 0x02, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for non-SEQUENCE outer structure")
	}
}

func TestParseSGXExtensionASN1_WithTCBComponents(t *testing.T) {
	// Build a complete extension with FMSPC, PCEID, and TCB components.
	fmspc := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	pceid := []byte{0x01, 0x00}

	// Build FMSPC entry
	oidFMSPC := buildASN1OIDBytes(encodeOIDFMSPC())
	fmspcEntry := buildASN1Sequence(oidFMSPC, buildASN1OctetString(fmspc))

	// Build PCEID entry
	oidPCEID := buildASN1OIDBytes(encodeOIDPCEID())
	pceidEntry := buildASN1Sequence(oidPCEID, buildASN1OctetString(pceid))

	// Build TCB entry with component 1 SVN=5
	comp1OID := buildASN1OIDBytes(encodeOIDTCBComp(1))
	comp1Entry := buildASN1Sequence(comp1OID, buildASN1Integer(5))

	pcesvnOID := buildASN1OIDBytes(encodeOIDTCBPCESVN())
	pcesvnEntry := buildASN1Sequence(pcesvnOID, buildASN1Integer(3))

	tcbInner := buildASN1Sequence(comp1Entry, pcesvnEntry)
	oidTCB := buildASN1OIDBytes(encodeOIDTCB())
	tcbEntry := buildASN1Sequence(oidTCB, tcbInner)

	outer := buildASN1Sequence(fmspcEntry, pceidEntry, tcbEntry)

	ext, err := parseSGXExtensionASN1(outer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(ext.fmspc, fmspc) {
		t.Fatalf("fmspc mismatch: got %x, want %x", ext.fmspc, fmspc)
	}
	if ext.compsvn[0] != 5 {
		t.Fatalf("compsvn[0] = %d, want 5", ext.compsvn[0])
	}
	if ext.pcesvn != 3 {
		t.Fatalf("pcesvn = %d, want 3", ext.pcesvn)
	}
}

func TestParseTCBFromASN1_InvalidSequence(t *testing.T) {
	// Not a sequence - should return without panic
	ext := &pckExtensionData{}
	parseTCBFromASN1([]byte{0x04, 0x01, 0x00}, ext)
	// No error returned, just silently skips
}

func TestParseTCBFromASN1_AllComponents(t *testing.T) {
	ext := &pckExtensionData{}

	var entries [][]byte
	// Build all 16 component entries
	for i := 1; i <= 16; i++ {
		oid := buildASN1OIDBytes(encodeOIDTCBComp(byte(i)))
		entry := buildASN1Sequence(oid, buildASN1Integer(byte(i*2)))
		entries = append(entries, entry)
	}
	// Build PCESVN entry (component 17)
	pcesvnOID := buildASN1OIDBytes(encodeOIDTCBPCESVN())
	pcesvnEntry := buildASN1Sequence(pcesvnOID, buildASN1Integer(7))
	entries = append(entries, pcesvnEntry)

	var allEntries []byte
	for _, e := range entries {
		allEntries = append(allEntries, e...)
	}
	outer := buildASN1Sequence(allEntries)

	parseTCBFromASN1(outer, ext)

	for i := 0; i < 16; i++ {
		expected := byte((i + 1) * 2)
		if ext.compsvn[i] != expected {
			t.Errorf("compsvn[%d] = %d, want %d", i, ext.compsvn[i], expected)
		}
	}
	if ext.pcesvn != 7 {
		t.Errorf("pcesvn = %d, want 7", ext.pcesvn)
	}
}

func TestParseTCBComponentsV3_Valid(t *testing.T) {
	// Build v3 JSON with sgxtcbcomponents array
	jsonStr := `{"tcb": {"sgxtcbcomponents": [{"svn": 5}, {"svn": 10}], "pcesvn": 3}}`
	level := &tcbLevel{}
	found := parseTCBComponentsV3(jsonStr, level)
	if !found {
		t.Fatal("parseTCBComponentsV3 should find v3 components")
	}
	if level.compsvn[0] != 5 {
		t.Fatalf("compsvn[0] = %d, want 5", level.compsvn[0])
	}
	if level.compsvn[1] != 10 {
		t.Fatalf("compsvn[1] = %d, want 10", level.compsvn[1])
	}
}

func TestParseTCBComponentsV3_NotPresent(t *testing.T) {
	jsonStr := `{"tcb": {"sgxtcbcomp01svn": 5}}`
	level := &tcbLevel{}
	found := parseTCBComponentsV3(jsonStr, level)
	if found {
		t.Fatal("parseTCBComponentsV3 should return false for v2 JSON")
	}
}

func TestParseTCBComponentsV3_NoOpeningBracket(t *testing.T) {
	// "sgxtcbcomponents" key exists but no array follows
	jsonStr := `{"sgxtcbcomponents": null}`
	level := &tcbLevel{}
	found := parseTCBComponentsV3(jsonStr, level)
	if found {
		t.Fatal("parseTCBComponentsV3 should return false when no bracket after key")
	}
}

func TestParseTCBComponentsV3_UnclosedBracket(t *testing.T) {
	// Array is never closed
	jsonStr := `{"sgxtcbcomponents": [{"svn": 5}`
	level := &tcbLevel{}
	found := parseTCBComponentsV3(jsonStr, level)
	if found {
		t.Fatal("parseTCBComponentsV3 should return false for unclosed bracket")
	}
}

func TestParseTCBComponentsV3_AllSixteen(t *testing.T) {
	// Build an array of 16 SVN components
	parts := make([]string, 16)
	for i := 0; i < 16; i++ {
		parts[i] = `{"svn": ` + itoa(i+1) + `}`
	}
	arr := "[" + join(parts, ",") + "]"
	jsonStr := `{"sgxtcbcomponents": ` + arr + `}`
	level := &tcbLevel{}
	found := parseTCBComponentsV3(jsonStr, level)
	if !found {
		t.Fatal("parseTCBComponentsV3 should find 16 components")
	}
	for i := 0; i < 16; i++ {
		if level.compsvn[i] != byte(i+1) {
			t.Errorf("compsvn[%d] = %d, want %d", i, level.compsvn[i], i+1)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		indexString(s, substr) >= 0)
}

func indexString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

func join(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}
