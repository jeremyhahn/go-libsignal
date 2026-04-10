// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// buildMinimalQuoteBody creates a minimal valid 432-byte SGX quote body.
func buildMinimalQuoteBody() []byte {
	body := make([]byte, sgxQuoteBodySize)
	// version = 3 (little-endian at offset 0)
	binary.LittleEndian.PutUint16(body[0:2], quoteV3)
	// attestation key type = ECDSA-P256 (at offset 2)
	binary.LittleEndian.PutUint16(body[2:4], ecdsaP256)
	// QE vendor ID at offset 12 (16 bytes) - set to Intel's
	copy(body[12:28], intelQEVendorID[:])
	// Report body starts at offset 48, needs at least 384 bytes
	// (already covered by the 432-byte allocation)
	return body
}

// buildMinimalQuoteSupport builds minimal quote support data including a real PEM cert chain.
func buildMinimalQuoteSupport(t *testing.T) []byte {
	t.Helper()

	// Generate a test cert for the PCK chain
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-pck"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	var buf []byte
	// ISV signature (64 bytes) - zeroed is fine for structure parsing
	buf = append(buf, make([]byte, 64)...)
	// Attest public key (64 bytes)
	buf = append(buf, make([]byte, 64)...)
	// QE report body (384 bytes)
	buf = append(buf, make([]byte, sgxReportBodySize)...)
	// QE report signature (64 bytes)
	buf = append(buf, make([]byte, 64)...)
	// Auth data size (2 bytes LE) = 0
	buf = append(buf, 0x00, 0x00)
	// Cert key type (2 bytes LE) = 5 (pckCertChainKeyType)
	binary.LittleEndian.PutUint16(buf[len(buf)-2:], 0) // fix: need to append properly
	buf = buf[:len(buf)-2]                               // remove the bad append
	buf = append(buf, 0x00, 0x00)                        // auth data size = 0

	// cert key type
	certKeyType := make([]byte, 2)
	binary.LittleEndian.PutUint16(certKeyType, pckCertChainKeyType)
	buf = append(buf, certKeyType...)

	// cert data size
	certDataSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(certDataSize, uint32(len(pemCert)))
	buf = append(buf, certDataSize...)

	// cert data
	buf = append(buf, pemCert...)

	return buf
}

func TestParseQuoteBody_HappyPath(t *testing.T) {
	body := buildMinimalQuoteBody()
	qb, err := parseQuoteBody(body)
	if err != nil {
		t.Fatalf("parseQuoteBody failed: %v", err)
	}
	if qb == nil {
		t.Fatal("quote body should not be nil")
	}
	if qb.reportBody == nil {
		t.Fatal("report body should not be nil")
	}
	if qb.qeVendorID != intelQEVendorID {
		t.Error("QE vendor ID mismatch")
	}
}

func TestParseQuoteBody_TooShort(t *testing.T) {
	_, err := parseQuoteBody(make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestParseQuoteBody_WrongVersion(t *testing.T) {
	body := buildMinimalQuoteBody()
	binary.LittleEndian.PutUint16(body[0:2], 4) // unsupported version
	_, err := parseQuoteBody(body)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestParseQuoteBody_WrongAlgorithm(t *testing.T) {
	body := buildMinimalQuoteBody()
	binary.LittleEndian.PutUint16(body[2:4], 1) // unsupported algorithm
	_, err := parseQuoteBody(body)
	if err == nil {
		t.Fatal("expected error for wrong algorithm")
	}
}

func TestParseReportBody_HappyPath(t *testing.T) {
	data := make([]byte, sgxReportBodySize)
	// Set some fields
	copy(data[0:16], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	binary.LittleEndian.PutUint32(data[16:20], 42) // miscselect
	data[64] = 0xAA                                  // mrenclave[0]
	binary.LittleEndian.PutUint16(data[256:258], 7)  // isvprodid
	binary.LittleEndian.PutUint16(data[258:260], 3)  // isvsvn

	rb, err := parseReportBody(data)
	if err != nil {
		t.Fatalf("parseReportBody failed: %v", err)
	}
	if rb.miscselect != 42 {
		t.Errorf("miscselect = %d, want 42", rb.miscselect)
	}
	if rb.mrenclave[0] != 0xAA {
		t.Errorf("mrenclave[0] = 0x%02x, want 0xAA", rb.mrenclave[0])
	}
	if rb.isvprodid != 7 {
		t.Errorf("isvprodid = %d, want 7", rb.isvprodid)
	}
	if rb.isvsvn != 3 {
		t.Errorf("isvsvn = %d, want 3", rb.isvsvn)
	}
	if rb.cpusvn[0] != 0x01 {
		t.Error("cpusvn not parsed correctly")
	}
}

func TestParseReportBody_TooShort(t *testing.T) {
	_, err := parseReportBody(make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestParseCustomClaims_HappyPath(t *testing.T) {
	// Build a minimal custom claims structure
	// version (8 bytes LE) = 1, numClaims (8 bytes LE) = 1
	var buf []byte
	b8 := make([]byte, 8)

	// version = 1
	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	buf = append(buf, b8...)

	// numClaims = 1
	binary.LittleEndian.PutUint64(b8, 1)
	buf = append(buf, b8...)

	// claim entry: nameSize (8), valueSize (8), name, value
	name := []byte("pk\x00")
	value := []byte{0x01, 0x02, 0x03}

	binary.LittleEndian.PutUint64(b8, uint64(len(name)))
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, uint64(len(value)))
	buf = append(buf, b8...)
	buf = append(buf, name...)
	buf = append(buf, value...)

	claims, err := parseCustomClaims(buf)
	if err != nil {
		t.Fatalf("parseCustomClaims failed: %v", err)
	}
	if val, ok := claims["pk"]; !ok {
		t.Error("pk claim not found")
	} else if len(val) != 3 {
		t.Errorf("pk value len = %d, want 3", len(val))
	}
}

func TestParseCustomClaims_MultipleClaims(t *testing.T) {
	var buf []byte
	b8 := make([]byte, 8)

	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	buf = append(buf, b8...)

	binary.LittleEndian.PutUint64(b8, 2)
	buf = append(buf, b8...)

	// Claim 1
	name1 := []byte("key1\x00")
	val1 := []byte("val1")
	binary.LittleEndian.PutUint64(b8, uint64(len(name1)))
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, uint64(len(val1)))
	buf = append(buf, b8...)
	buf = append(buf, name1...)
	buf = append(buf, val1...)

	// Claim 2
	name2 := []byte("key2\x00")
	val2 := []byte("val2")
	binary.LittleEndian.PutUint64(b8, uint64(len(name2)))
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, uint64(len(val2)))
	buf = append(buf, b8...)
	buf = append(buf, name2...)
	buf = append(buf, val2...)

	claims, err := parseCustomClaims(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(claims))
	}
	if string(claims["key1"]) != "val1" {
		t.Errorf("key1 = %q, want %q", claims["key1"], "val1")
	}
}

func TestParseCustomClaims_TooShort(t *testing.T) {
	_, err := parseCustomClaims(make([]byte, 8))
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestParseCustomClaims_WrongVersion(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], 99) // bad version
	binary.LittleEndian.PutUint64(buf[8:16], 0)
	_, err := parseCustomClaims(buf)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestParseCustomClaims_TooManyClaims(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], oeClaimsV1)
	binary.LittleEndian.PutUint64(buf[8:16], 300) // > 256
	_, err := parseCustomClaims(buf)
	if err == nil {
		t.Fatal("expected error for too many claims")
	}
}

func TestParseCustomClaims_TruncatedEntryHeader(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], oeClaimsV1)
	binary.LittleEndian.PutUint64(buf[8:16], 1) // 1 claim, but no entry data
	_, err := parseCustomClaims(buf)
	if err == nil {
		t.Fatal("expected error for truncated entry header")
	}
}

func TestParseCustomClaims_NameTooLong(t *testing.T) {
	var buf []byte
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 1)
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 2000) // name too long
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 0)
	buf = append(buf, b8...)

	_, err := parseCustomClaims(buf)
	if err == nil {
		t.Fatal("expected error for name too long")
	}
}

func TestParseCustomClaims_ValueTooLong(t *testing.T) {
	var buf []byte
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 1)
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 3) // name size
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 2*1024*1024) // value too long (>1MB)
	buf = append(buf, b8...)

	_, err := parseCustomClaims(buf)
	if err == nil {
		t.Fatal("expected error for value too long")
	}
}

func TestParseCustomClaims_TruncatedClaimData(t *testing.T) {
	var buf []byte
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 1)
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 5)  // name size
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, 10) // value size
	buf = append(buf, b8...)
	buf = append(buf, []byte("he")...)     // only 2 bytes, need 15

	_, err := parseCustomClaims(buf)
	if err == nil {
		t.Fatal("expected error for truncated claim data")
	}
}

func TestParseEvidence_TooShort(t *testing.T) {
	_, err := parseEvidence(make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for too-short evidence")
	}
}

func TestParseEvidence_InvalidQuoteVersion(t *testing.T) {
	data := make([]byte, sgxQuoteBodySize+100)
	binary.LittleEndian.PutUint16(data[0:2], 99) // bad version
	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestParseEvidence_TruncatedSignatureLength(t *testing.T) {
	// Valid quote body but not enough data for signature length
	data := buildMinimalQuoteBody()
	// Just the quote body, no sig length field
	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for missing signature length")
	}
}

func TestParseEvidence_TruncatedSignatureData(t *testing.T) {
	body := buildMinimalQuoteBody()
	// Add signature length = 9999 but only a few bytes of data
	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, 9999)
	data := append(body, sigLen...)
	data = append(data, make([]byte, 10)...)

	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for truncated signature data")
	}
}

func TestParseQuoteSupport_TooShort(t *testing.T) {
	_, _, err := parseQuoteSupport(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestParseQuoteSupport_AuthDataUnderflow(t *testing.T) {
	// Create header-sized data but with auth data size pointing beyond
	headerSize := 64 + 64 + sgxReportBodySize + 64 + 2
	data := make([]byte, headerSize)
	// Set auth data size to 9999
	binary.LittleEndian.PutUint16(data[headerSize-2:], 9999)
	_, _, err := parseQuoteSupport(data)
	if err == nil {
		t.Fatal("expected error for auth data underflow")
	}
}

func TestParseQuoteSupport_CertHeaderUnderflow(t *testing.T) {
	// Create data with auth_data_size=0 but no cert header after
	headerSize := 64 + 64 + sgxReportBodySize + 64 + 2
	data := make([]byte, headerSize)
	// auth data size = 0 (already zero)
	_, _, err := parseQuoteSupport(data)
	if err == nil {
		t.Fatal("expected error for cert header underflow")
	}
}

func TestParseQuoteSupport_WrongCertKeyType(t *testing.T) {
	headerSize := 64 + 64 + sgxReportBodySize + 64 + 2
	data := make([]byte, headerSize+6) // +6 for cert key type + cert data size
	// auth data size = 0 (default)
	// cert key type = 3 (not pckCertChainKeyType)
	binary.LittleEndian.PutUint16(data[headerSize:], 3)
	binary.LittleEndian.PutUint32(data[headerSize+2:], 0)
	_, _, err := parseQuoteSupport(data)
	if err == nil {
		t.Fatal("expected error for wrong cert key type")
	}
}

func TestParseQuoteSupport_CertDataUnderflow(t *testing.T) {
	headerSize := 64 + 64 + sgxReportBodySize + 64 + 2
	data := make([]byte, headerSize+6)
	binary.LittleEndian.PutUint16(data[headerSize:], pckCertChainKeyType)
	binary.LittleEndian.PutUint32(data[headerSize+2:], 9999) // cert data size too large
	_, _, err := parseQuoteSupport(data)
	if err == nil {
		t.Fatal("expected error for cert data underflow")
	}
}

func TestParseQuoteSupport_InvalidPEMCert(t *testing.T) {
	headerSize := 64 + 64 + sgxReportBodySize + 64 + 2
	invalidPEM := []byte("not a PEM cert")
	data := make([]byte, headerSize+6+len(invalidPEM))
	binary.LittleEndian.PutUint16(data[headerSize:], pckCertChainKeyType)
	binary.LittleEndian.PutUint32(data[headerSize+2:], uint32(len(invalidPEM)))
	copy(data[headerSize+6:], invalidPEM)
	_, _, err := parseQuoteSupport(data)
	if err == nil {
		t.Fatal("expected error for invalid PEM cert")
	}
}

func TestParseQuoteSupport_HappyPath(t *testing.T) {
	support := buildMinimalQuoteSupport(t)
	s, consumed, err := parseQuoteSupport(support)
	if err != nil {
		t.Fatalf("parseQuoteSupport failed: %v", err)
	}
	if s == nil {
		t.Fatal("support should not be nil")
	}
	if consumed <= 0 {
		t.Error("consumed should be > 0")
	}
	if len(s.pckCertChain) == 0 {
		t.Error("pckCertChain should not be empty")
	}
}

func TestParseEvidence_ValidStructure(t *testing.T) {
	quoteBody := buildMinimalQuoteBody()
	support := buildMinimalQuoteSupport(t)

	// Build custom claims
	var claims []byte
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	claims = append(claims, b8...)
	binary.LittleEndian.PutUint64(b8, 1) // 1 claim
	claims = append(claims, b8...)
	name := []byte("pk\x00")
	val := make([]byte, 32)
	binary.LittleEndian.PutUint64(b8, uint64(len(name)))
	claims = append(claims, b8...)
	binary.LittleEndian.PutUint64(b8, uint64(len(val)))
	claims = append(claims, b8...)
	claims = append(claims, name...)
	claims = append(claims, val...)

	// Assemble full evidence: quoteBody + sigLen(4) + support + claims
	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, uint32(len(support)))

	var data []byte
	data = append(data, quoteBody...)
	data = append(data, sigLen...)
	data = append(data, support...)
	data = append(data, claims...)

	evidence, err := parseEvidence(data)
	if err != nil {
		t.Fatalf("parseEvidence failed: %v", err)
	}
	if evidence == nil {
		t.Fatal("evidence should not be nil")
	}
	if evidence.quote == nil {
		t.Fatal("quote should not be nil")
	}
	if evidence.claims == nil {
		t.Fatal("claims should not be nil")
	}
	if _, ok := evidence.claims["pk"]; !ok {
		t.Error("claims should contain pk")
	}
}

func TestParseEvidence_InvalidCustomClaims(t *testing.T) {
	quoteBody := buildMinimalQuoteBody()
	support := buildMinimalQuoteSupport(t)

	// Invalid custom claims (bad version)
	claims := make([]byte, 16)
	binary.LittleEndian.PutUint64(claims[0:8], 99) // bad version

	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, uint32(len(support)))

	var data []byte
	data = append(data, quoteBody...)
	data = append(data, sigLen...)
	data = append(data, support...)
	data = append(data, claims...)

	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for invalid custom claims")
	}
}

func TestParseEvidence_InvalidQuoteSupport(t *testing.T) {
	quoteBody := buildMinimalQuoteBody()

	// Quote support too short
	support := make([]byte, 10)
	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, uint32(len(support)))

	var data []byte
	data = append(data, quoteBody...)
	data = append(data, sigLen...)
	data = append(data, support...)

	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for invalid quote support")
	}
}

// --- AT-W4: Trailing data tests ---

func TestParseEvidence_TrailingDataInSignature(t *testing.T) {
	quoteBody := buildMinimalQuoteBody()
	support := buildMinimalQuoteSupport(t)

	// Build valid custom claims
	claims := buildMinimalClaims()

	// Add extra bytes to the signature data area
	supportWithTrailing := append(support, []byte("TRAILING")...)

	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, uint32(len(supportWithTrailing)))

	var data []byte
	data = append(data, quoteBody...)
	data = append(data, sigLen...)
	data = append(data, supportWithTrailing...)
	data = append(data, claims...)

	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for trailing data in signature area")
	}
	var trailingErr *TrailingDataError
	if !errors.As(err, &trailingErr) {
		t.Errorf("expected TrailingDataError, got %T: %v", err, err)
	}
}

func TestParseEvidence_TrailingDataAfterClaims(t *testing.T) {
	quoteBody := buildMinimalQuoteBody()
	support := buildMinimalQuoteSupport(t)

	// Build valid custom claims
	claims := buildMinimalClaims()

	// Append trailing bytes after claims
	claimsWithTrailing := append(claims, []byte("EXTRA")...)

	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, uint32(len(support)))

	var data []byte
	data = append(data, quoteBody...)
	data = append(data, sigLen...)
	data = append(data, support...)
	data = append(data, claimsWithTrailing...)

	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for trailing data after claims")
	}
	var trailingErr *TrailingDataError
	if !errors.As(err, &trailingErr) {
		t.Errorf("expected TrailingDataError, got %T: %v", err, err)
	}
}

func TestParseEvidence_NoTrailingData(t *testing.T) {
	quoteBody := buildMinimalQuoteBody()
	support := buildMinimalQuoteSupport(t)
	claims := buildMinimalClaims()

	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, uint32(len(support)))

	var data []byte
	data = append(data, quoteBody...)
	data = append(data, sigLen...)
	data = append(data, support...)
	data = append(data, claims...)

	evidence, err := parseEvidence(data)
	if err != nil {
		t.Fatalf("parseEvidence failed: %v", err)
	}
	if evidence == nil {
		t.Fatal("evidence should not be nil")
	}
}

func TestComputeClaimsSize_Empty(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], oeClaimsV1)
	binary.LittleEndian.PutUint64(buf[8:16], 0) // 0 claims
	if got := computeClaimsSize(buf); got != 16 {
		t.Errorf("computeClaimsSize = %d, want 16", got)
	}
}

func TestComputeClaimsSize_WithClaims(t *testing.T) {
	claims := buildMinimalClaims()
	got := computeClaimsSize(claims)
	if got != len(claims) {
		t.Errorf("computeClaimsSize = %d, want %d", got, len(claims))
	}
}

// buildMinimalClaims creates a minimal valid custom claims structure.
func buildMinimalClaims() []byte {
	var buf []byte
	b8 := make([]byte, 8)

	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	buf = append(buf, b8...)

	binary.LittleEndian.PutUint64(b8, 1) // 1 claim
	buf = append(buf, b8...)

	name := []byte("pk\x00")
	val := make([]byte, 32)
	binary.LittleEndian.PutUint64(b8, uint64(len(name)))
	buf = append(buf, b8...)
	binary.LittleEndian.PutUint64(b8, uint64(len(val)))
	buf = append(buf, b8...)
	buf = append(buf, name...)
	buf = append(buf, val...)

	return buf
}
