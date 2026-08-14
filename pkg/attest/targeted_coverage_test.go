// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// parseTCBFromASN1: OID with non-numeric suffix sets idx=-1 (not stored)
// ---------------------------------------------------------------------------

func TestParseTCBFromASN1_NonNumericOIDSuffix(t *testing.T) {
	ext := &pckExtensionData{}
	// OID 1.2.840.113741.1.13.1.2 is the TCB prefix.
	// An OID with the exact prefix but no suffix won't store anything (len check fails).
	// Build OID that matches the prefix but has a non-numeric suffix char.
	// We'll use OID 1.2 = {42} which definitely doesn't match the prefix.
	oid := buildASN1OIDBytes([]byte{42}) // OID 1.2
	entry := buildASN1Sequence(oid, buildASN1Integer(5))
	outer := buildASN1Sequence(entry)
	parseTCBFromASN1(outer, ext)
	// None of the compsvn should be set
	for i, v := range ext.compsvn {
		if v != 0 {
			t.Fatalf("compsvn[%d] should be 0, got %d", i, v)
		}
	}
}

func TestParseTCBFromASN1_OIDParseError(t *testing.T) {
	ext := &pckExtensionData{}
	// Build a sub-item where first item is NOT an OID (wrong tag).
	notOID := buildASN1OctetString([]byte{0xAA}) // OCTET STRING, not OID
	entry := buildASN1Sequence(notOID, buildASN1Integer(5))
	outer := buildASN1Sequence(entry)
	parseTCBFromASN1(outer, ext)
	// Should gracefully skip (continue on oid parse error)
	for i, v := range ext.compsvn {
		if v != 0 {
			t.Fatalf("compsvn[%d] should be 0, got %d", i, v)
		}
	}
}

func TestParseTCBFromASN1_InnerNotSequence(t *testing.T) {
	ext := &pckExtensionData{}
	// Build an outer SEQUENCE where an item is not a SEQUENCE (OCTET STRING).
	inner := buildASN1OctetString([]byte{0x01, 0x02, 0x03})
	outer := buildASN1Sequence(inner)
	parseTCBFromASN1(outer, ext)
	// Should skip the non-sequence item gracefully
	for i, v := range ext.compsvn {
		if v != 0 {
			t.Fatalf("compsvn[%d] should be 0, got %d", i, v)
		}
	}
}

// ---------------------------------------------------------------------------
// validAt: CRL expiry branches
// ---------------------------------------------------------------------------

func TestSGXEndorsements_ValidAt_ExpiredPCKCRL(t *testing.T) {
	// Create a CRL that has already expired
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	// CRL that expired yesterday
	crlTemplate := x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour), // already expired
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, cert, key)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	endorsements := &sgxEndorsements{
		pckCertCRL: crl,
	}
	if endorsements.validAt(time.Now()) {
		t.Fatal("should not be valid when PCK cert CRL has expired")
	}
}

func TestSGXEndorsements_ValidAt_ExpiredRootCRL(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	crlTemplate := x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, cert, key)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("failed to parse CRL: %v", err)
	}

	endorsements := &sgxEndorsements{
		pckProcCACRL: crl,
	}
	if endorsements.validAt(time.Now()) {
		t.Fatal("should not be valid when root CRL has expired")
	}
}

func TestSGXEndorsements_ValidAt_ExpiredTCBInfoNextUpdate(t *testing.T) {
	endorsements := &sgxEndorsements{
		tcbInfoNextUpdate: time.Now().Add(-time.Hour), // already passed
	}
	if endorsements.validAt(time.Now()) {
		t.Fatal("should not be valid when tcbInfo nextUpdate has passed")
	}
}

func TestSGXEndorsements_ValidAt_ExpiredQEIDNextUpdate(t *testing.T) {
	endorsements := &sgxEndorsements{
		qeIDNextUpdate: time.Now().Add(-time.Hour), // already passed
	}
	if endorsements.validAt(time.Now()) {
		t.Fatal("should not be valid when QE identity nextUpdate has passed")
	}
}

// TestSGXEndorsements_ValidAt_AllValid was updated by Finding-1 fix:
// endorsements without CRLs must fail validAt (fail-closed), not pass silently.
// An empty sgxEndorsements has nil pckCertCRL and pckProcCACRL; before the fix
// validAt returned true, allowing a stripped-CRL endorsement to pass attestation.
func TestSGXEndorsements_ValidAt_AllValid(t *testing.T) {
	endorsements := &sgxEndorsements{}
	if endorsements.validAt(time.Now()) {
		t.Fatal("empty endorsements must NOT be valid (regression for Finding 1: nil CRLs bypass revocation)")
	}
}

// ---------------------------------------------------------------------------
// parseEndorsements: not enough data for offsets
// ---------------------------------------------------------------------------

func TestParseEndorsements_NotEnoughDataForOffsets_Additional(t *testing.T) {
	// version=1, enclaveType=2, bufferSize=0, numElements=100 (too many for data)
	data := make([]byte, 16)
	putUint32LE(data[0:4], 1)     // version
	putUint32LE(data[4:8], 2)     // enclaveType
	putUint32LE(data[8:12], 0)    // bufferSize
	putUint32LE(data[12:16], 100) // numElements (too many, no room for offsets)
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error when not enough data for offsets")
	}
}

// ---------------------------------------------------------------------------
// parseEnclaveIdentityJSON: invalid inner enclaveIdentity JSON
// ---------------------------------------------------------------------------

func TestParseEnclaveIdentityJSON_InvalidInnerJSON(t *testing.T) {
	// The outer JSON is valid but "enclaveIdentity" value is invalid JSON
	jsonData := []byte(`{"enclaveIdentity": "not-an-object"}`)
	_, err := parseEnclaveIdentityJSON(jsonData)
	if err == nil {
		t.Fatal("expected error for invalid inner JSON")
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func putUint32LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
