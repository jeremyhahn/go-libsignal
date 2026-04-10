// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// verifyTCBStatus: empty tcbInfoRaw returns tcbUpToDate
// ---------------------------------------------------------------------------

func TestVerifyTCBStatus_EmptyTCBInfoRaw(t *testing.T) {
	evidence := &dcapEvidence{}
	endorsements := &sgxEndorsements{tcbInfoRaw: nil}
	standing, advisoryIDs, err := verifyTCBStatus(evidence, endorsements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if standing != tcbUpToDate {
		t.Fatalf("expected tcbUpToDate, got %d", standing)
	}
	if advisoryIDs != nil {
		t.Fatalf("expected nil advisoryIDs, got %v", advisoryIDs)
	}
}

// ---------------------------------------------------------------------------
// AttestationMetrics: empty evidence returns empty metrics gracefully
// ---------------------------------------------------------------------------

func TestAttestationMetrics_EmptyEvidence(t *testing.T) {
	metrics, err := AttestationMetrics(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics == nil {
		t.Fatal("expected non-nil metrics map")
	}
}

func TestAttestationMetrics_InvalidEvidence(t *testing.T) {
	// Garbage evidence should not return an error (silently returns empty metrics)
	metrics, err := AttestationMetrics([]byte{0x01, 0x02}, []byte{0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics == nil {
		t.Fatal("expected non-nil metrics map")
	}
}

// ---------------------------------------------------------------------------
// verifyCRLAgainstIssuers: no issuer matches
// ---------------------------------------------------------------------------

func TestVerifyCRLAgainstIssuers_NoMatch(t *testing.T) {
	// Create a real CRL signed by key1, but pass key2 as issuer.
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	template := x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Number:             big.NewInt(1),
		ThisUpdate:         time.Now(),
		NextUpdate:         time.Now().Add(24 * time.Hour),
	}

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA 1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	cert1DER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key1.PublicKey, key1)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert1, err := x509.ParseCertificate(cert1DER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	// CRL signed by key1
	crlDER, err := x509.CreateRevocationList(rand.Reader, &template, cert1, key1)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	// Create a cert with key2 as the issuer
	certTemplate2 := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test CA 2"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	cert2DER, err := x509.CreateCertificate(rand.Reader, certTemplate2, certTemplate2, &key2.PublicKey, key2)
	if err != nil {
		t.Fatalf("failed to create cert2: %v", err)
	}
	cert2, err := x509.ParseCertificate(cert2DER)
	if err != nil {
		t.Fatalf("failed to parse cert2: %v", err)
	}

	// Verify CRL against cert2 (wrong key) should fail
	err = verifyCRLAgainstIssuers(crl, []*x509.Certificate{cert2})
	if err == nil {
		t.Fatal("expected error when no issuer verifies the CRL")
	}
	var crlSigErr *CRLSignatureError
	if !errors.As(err, &crlSigErr) {
		t.Fatalf("expected *CRLSignatureError, got %T", err)
	}
}

// ---------------------------------------------------------------------------
// verifySignedJSON: content field not found
// ---------------------------------------------------------------------------

func TestVerifySignedJSON_SignatureFieldNotFound(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	// JSON without "signature" field
	jsonData := []byte(`{"tcbInfo": {"version": 3}}`)
	err = verifySignedJSON(jsonData, cert, "tcbInfo")
	if err == nil {
		t.Fatal("expected error when signature field is missing")
	}
	var sigErr *EndorsementSignatureError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected *EndorsementSignatureError, got %T", err)
	}
}

func TestVerifySignedJSON_ContentFieldNotFound(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	// JSON with signature but content field absent
	jsonData := []byte(`{"signature": "deadbeef"}`)
	err = verifySignedJSON(jsonData, cert, "tcbInfo")
	if err == nil {
		t.Fatal("expected error when content field is missing")
	}
}

func TestVerifySignedJSON_InvalidSignatureHex(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	// JSON with invalid hex signature
	jsonData := []byte(`{"tcbInfo": {"version": 3}, "signature": "ZZZZ"}`)
	err = verifySignedJSON(jsonData, cert, "tcbInfo")
	if err == nil {
		t.Fatal("expected error for invalid hex signature")
	}
}

// ---------------------------------------------------------------------------
// verifyRootCertificate: non-self-signed cert
// ---------------------------------------------------------------------------

func TestVerifyRootCertificate_NotSelfSigned_Additional(t *testing.T) {
	// Create two CAs and check that a cert signed by CA1 but presented as root fails.
	ca1Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca2Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	ca1Template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	ca1DER, err := x509.CreateCertificate(rand.Reader, ca1Template, ca1Template, &ca1Key.PublicKey, ca1Key)
	if err != nil {
		t.Fatalf("failed to create CA1: %v", err)
	}
	ca1, err := x509.ParseCertificate(ca1DER)
	if err != nil {
		t.Fatalf("failed to parse CA1: %v", err)
	}

	// Create cert signed by CA1 (not self-signed)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "NotRoot"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca1, &ca2Key.PublicKey, ca1Key)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	// Parse Intel root key (real one)
	intelKey, err := parseIntelRootKey()
	if err != nil {
		t.Fatalf("failed to get Intel root key: %v", err)
	}

	err = verifyRootCertificate(leaf, intelKey)
	if err == nil {
		t.Fatal("expected error for non-self-signed root certificate")
	}
}

// ---------------------------------------------------------------------------
// parseASN1Sequence with length-only content (first item too short)
// ---------------------------------------------------------------------------

func TestParseASN1Sequence_OnlyOneByteItem(t *testing.T) {
	// Content has just a single byte (no length byte for it)
	content := []byte{0x04} // just a tag, no length
	data := []byte{0x30, byte(len(content))}
	data = append(data, content...)
	// Should not panic, just return 0 items (offset+1 >= len breaks)
	items, err := parseASN1Sequence(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = items
}

// ---------------------------------------------------------------------------
// parseASN1Length with numBytes=4 (too large, >3 is invalid)
// ---------------------------------------------------------------------------

func TestParseASN1Length_TooManyLengthBytes(t *testing.T) {
	// 0x84 = long form with 4 bytes - should fail since max is 3
	_, _, err := parseASN1Length([]byte{0x84, 0x00, 0x00, 0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for numBytes=4 which exceeds max of 3")
	}
}

// ---------------------------------------------------------------------------
// parseSGXExtensionASN1: sub-items has <2 items (continue branch)
// ---------------------------------------------------------------------------

func TestParseSGXExtensionASN1_SingleItemSubSequence(t *testing.T) {
	// A sub-SEQUENCE with only 1 item (needs 2 for OID+value)
	oidFMSPC := buildASN1OIDBytes(encodeOIDFMSPC())
	singleItemSeq := buildASN1Sequence(oidFMSPC) // only OID, no value

	// Add a valid PCEID entry to ensure the outer seq is otherwise valid
	oidPCEID := buildASN1OIDBytes(encodeOIDPCEID())
	pceidValue := buildASN1OctetString([]byte{0x00, 0x00})
	pceidEntry := buildASN1Sequence(oidPCEID, pceidValue)

	// Add a valid FMSPC entry
	fmspcOID := buildASN1OIDBytes(encodeOIDFMSPC())
	fmspcValue := buildASN1OctetString([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	fmspcEntry := buildASN1Sequence(fmspcOID, fmspcValue)

	// singleItemSeq will be skipped (continue), fmspcEntry and pceidEntry will be found
	outer := buildASN1Sequence(singleItemSeq, fmspcEntry, pceidEntry)
	ext, err := parseSGXExtensionASN1(outer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ext.fmspc) == 0 {
		t.Fatal("expected FMSPC to be found")
	}
}

// ---------------------------------------------------------------------------
// parsePCKExtension: cert with no SGX extension
// ---------------------------------------------------------------------------

func TestParsePCKExtension_NoSGXExtension(t *testing.T) {
	// Create a real cert with no SGX extension
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{},
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
			},
		},
	}
	_, err = parsePCKExtension(evidence)
	if err == nil {
		t.Fatal("expected error for cert without SGX extension")
	}
}

// ---------------------------------------------------------------------------
// RootCRLVerificationError error type
// ---------------------------------------------------------------------------

func TestRootCRLVerificationError_WithErr(t *testing.T) {
	inner := errors.New("invalid signature")
	e := &RootCRLVerificationError{Err: inner}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if e.Unwrap() != inner {
		t.Fatal("Unwrap() should return inner error")
	}
}

func TestRootCRLVerificationError_NoErr(t *testing.T) {
	e := &RootCRLVerificationError{}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if e.Unwrap() != nil {
		t.Fatal("Unwrap() should return nil when no inner error")
	}
}

// ---------------------------------------------------------------------------
// PostQuantumUnsupportedError
// ---------------------------------------------------------------------------

func TestPostQuantumUnsupportedError(t *testing.T) {
	e := &PostQuantumUnsupportedError{}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() should return non-empty string")
	}
	if !containsStr(msg, "PostQuantum") {
		t.Fatalf("Error() should mention PostQuantum, got: %s", msg)
	}
}

func containsStr(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
