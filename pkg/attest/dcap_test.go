// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestParseIntelRootKey(t *testing.T) {
	key, err := parseIntelRootKey()
	if err != nil {
		t.Fatalf("parseIntelRootKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}
	if key.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
	if _, err := key.ECDH(); err != nil {
		t.Errorf("key is not a valid P-256 point: %v", err)
	}
}

func TestParseIntelRootKey_ValidPoint(t *testing.T) {
	key, err := parseIntelRootKey()
	if err != nil {
		t.Fatalf("parseIntelRootKey failed: %v", err)
	}
	// parseIntelRootKey validates the point via ecdh.P256().NewPublicKey, which
	// rejects any point not on the curve. Verify the coordinates are non-zero.
	ecdhKey, err := key.ECDH()
	if err != nil {
		t.Errorf("Intel root key is not a valid P-256 point: %v", err)
	}
	// Bytes() returns 0x04 || X || Y; X starts at offset 1.
	raw := ecdhKey.Bytes()
	if len(raw) != 65 || raw[1] == 0 {
		t.Error("Intel root key has zero X coordinate")
	}
}

func TestParseAttestKey_HappyPath(t *testing.T) {
	// Generate a real P-256 key via crypto/ecdh to avoid deprecated big.Int fields.
	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	// Bytes() returns 0x04 || X(32) || Y(32); strip the 0x04 prefix.
	uncompressed := ecdhPriv.PublicKey().Bytes()
	pubBytes := uncompressed[1:] // 64-byte X||Y

	key, err := parseAttestKey(pubBytes)
	if err != nil {
		t.Fatalf("parseAttestKey failed: %v", err)
	}
	// Compare via canonical uncompressed encoding.
	parsedECDH, err := key.ECDH()
	if err != nil {
		t.Fatalf("parsed key is not a valid P-256 point: %v", err)
	}
	if !bytes.Equal(parsedECDH.Bytes(), ecdhPriv.PublicKey().Bytes()) {
		t.Error("parsed key does not match original")
	}
}

func TestParseAttestKey_WrongLength(t *testing.T) {
	_, err := parseAttestKey(make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

func TestParseAttestKey_PointNotOnCurve(t *testing.T) {
	// Create a point that is definitely not on P-256
	badBytes := make([]byte, 64)
	badBytes[0] = 0xFF
	badBytes[32] = 0xFF
	_, err := parseAttestKey(badBytes)
	if err == nil {
		t.Fatal("expected error for point not on curve")
	}
}

func TestEcdsaRawToDER_HappyPath(t *testing.T) {
	raw := make([]byte, 64)
	// Set r and s to small values
	raw[31] = 0x01
	raw[63] = 0x02

	der, err := ecdsaRawToDER(raw)
	if err != nil {
		t.Fatalf("ecdsaRawToDER failed: %v", err)
	}
	// DER should start with SEQUENCE tag 0x30
	if len(der) < 2 || der[0] != 0x30 {
		t.Error("DER output does not start with SEQUENCE tag")
	}
}

func TestEcdsaRawToDER_HighBitSet(t *testing.T) {
	// When the high bit of r or s is set, a leading 0x00 byte must be added
	raw := make([]byte, 64)
	raw[0] = 0x80 // high bit set on r
	raw[31] = 0x01
	raw[32] = 0x80 // high bit set on s
	raw[63] = 0x01

	der, err := ecdsaRawToDER(raw)
	if err != nil {
		t.Fatalf("ecdsaRawToDER failed: %v", err)
	}
	// Should have leading zero bytes for both r and s
	if der[0] != 0x30 {
		t.Error("expected SEQUENCE tag")
	}
	// The INTEGER for r should have a leading 0x00
	if der[2] != 0x02 { // INTEGER tag
		t.Errorf("expected INTEGER tag at offset 2, got 0x%02x", der[2])
	}
	rLen := der[3]
	if der[4] != 0x00 { // leading zero
		t.Error("expected leading zero byte for r with high bit set")
	}
	_ = rLen
}

func TestEcdsaRawToDER_WrongLength(t *testing.T) {
	_, err := ecdsaRawToDER(make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for wrong length")
	}
}

func TestParsePEMCertChain_HappyPath(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	certs, err := parsePEMCertChain(pemData)
	if err != nil {
		t.Fatalf("parsePEMCertChain failed: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
}

func TestParsePEMCertChain_MultipleCerts(t *testing.T) {
	cert1 := generateSelfSignedCert(t)
	cert2 := generateSelfSignedCert(t)

	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})...)

	certs, err := parsePEMCertChain(pemData)
	if err != nil {
		t.Fatalf("parsePEMCertChain failed: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
}

func TestParsePEMCertChain_NoCertificates(t *testing.T) {
	_, err := parsePEMCertChain([]byte("not a PEM block"))
	if err == nil {
		t.Fatal("expected error for no certificates")
	}
}

func TestParsePEMCertChain_SkipsNonCertBlocks(t *testing.T) {
	cert := generateSelfSignedCert(t)
	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)

	certs, err := parsePEMCertChain(pemData)
	if err != nil {
		t.Fatalf("parsePEMCertChain failed: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert (skipping RSA key block), got %d", len(certs))
	}
}

func TestParsePEMCertChain_InvalidCertDER(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not valid DER")})
	_, err := parsePEMCertChain(pemData)
	if err == nil {
		t.Fatal("expected error for invalid DER in PEM block")
	}
}

func TestContainsString(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		s     string
		want  bool
	}{
		{"found", []string{"a", "b", "c"}, "b", true},
		{"not found", []string{"a", "b", "c"}, "d", false},
		{"empty slice", nil, "a", false},
		{"empty string found", []string{""}, "", true},
		{"empty string not found", []string{"a"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsString(tt.slice, tt.s); got != tt.want {
				t.Errorf("containsString(%v, %q) = %v, want %v", tt.slice, tt.s, got, tt.want)
			}
		})
	}
}

func TestVerifyRootCertificate_NotSelfSigned(t *testing.T) {
	// Create two different keys
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create a cert signed by key1
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key1.PublicKey, key1)
	cert, _ := x509.ParseCertificate(certBytes)

	// Verify with key2 (different from the cert's key)
	err := verifyRootCertificate(cert, &key2.PublicKey)
	if err == nil {
		t.Fatal("expected error: cert's key does not match intelKey")
	}
}

func TestVerifyCertChain_EmptyChain(t *testing.T) {
	root := generateSelfSignedCert(t)
	err := verifyCertChain(nil, root, time.Now())
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
}

func TestAttestationMetrics(t *testing.T) {
	metrics, err := AttestationMetrics([]byte("ev"), []byte("end"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metrics == nil {
		t.Fatal("metrics should not be nil")
	}
	if len(metrics) != 0 {
		t.Errorf("expected empty metrics, got %d entries", len(metrics))
	}
}

func TestDcapAttest_TooShortEvidence(t *testing.T) {
	_, err := dcapAttest([]byte{0x01}, []byte{0x01}, time.Now())
	if err == nil {
		t.Fatal("expected error for too-short evidence")
	}
}

func TestDcapAttest_InvalidEndorsements(t *testing.T) {
	// Valid-looking evidence (enough bytes for quote body) but invalid endorsements
	evidence := make([]byte, 600)
	binary.LittleEndian.PutUint16(evidence[0:2], 3) // version 3
	binary.LittleEndian.PutUint16(evidence[2:4], 2) // ECDSA-P256
	_, err := dcapAttest(evidence, []byte{0x01}, time.Now())
	if err == nil {
		t.Fatal("expected error for invalid endorsements")
	}
}

func TestVerifyClaimsHash_NilClaimsData(t *testing.T) {
	evidence := &dcapEvidence{
		claimsRawData: nil,
	}
	err := verifyClaimsHash(evidence)
	if err == nil {
		t.Fatal("expected error for nil claims data")
	}
}

func TestVerifyClaimsHash_HashMismatch(t *testing.T) {
	claimsData := []byte("some claims data")
	evidence := &dcapEvidence{
		claimsRawData: claimsData,
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				reportBody: &sgxReportBody{
					// reportData is all zeros, so hash won't match
					sgxReportDataBytes: [64]byte{},
				},
			},
		},
	}
	err := verifyClaimsHash(evidence)
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
}

func TestVerifyClaimsHash_AllZeroHash(t *testing.T) {
	// Claims data that hashes to something, but report data is all zeros
	claimsData := []byte{}
	evidence := &dcapEvidence{
		claimsRawData: claimsData,
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				reportBody: &sgxReportBody{},
			},
		},
	}
	err := verifyClaimsHash(evidence)
	if err == nil {
		t.Fatal("expected error: hash of empty claims won't match zero report data (unless it does, then all-zero check triggers)")
	}
}

func TestVerifyClaimsHash_NonZeroPadding(t *testing.T) {
	// Set up claims data, compute its hash, put it in report data, but with non-zero padding
	claimsData := []byte("test claims")
	hash := sha256.Sum256(claimsData)
	var reportData [64]byte
	copy(reportData[:32], hash[:])
	reportData[32] = 0xFF // non-zero padding

	evidence := &dcapEvidence{
		claimsRawData: claimsData,
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				reportBody: &sgxReportBody{
					sgxReportDataBytes: reportData,
				},
			},
		},
	}
	err := verifyClaimsHash(evidence)
	if err == nil {
		t.Fatal("expected error for non-zero padding")
	}
}

func TestVerifyClaimsHash_ValidHash(t *testing.T) {
	claimsData := []byte("valid claims data here")
	hash := sha256.Sum256(claimsData)
	var reportData [64]byte
	copy(reportData[:32], hash[:])
	// Last 32 bytes remain zero

	evidence := &dcapEvidence{
		claimsRawData: claimsData,
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				reportBody: &sgxReportBody{
					sgxReportDataBytes: reportData,
				},
			},
		},
	}
	err := verifyClaimsHash(evidence)
	if err != nil {
		t.Fatalf("expected no error for valid hash, got: %v", err)
	}
}

func TestVerifyCertificates_EmptyTCBIssuerChain(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{},
		},
	}
	endorsements := &sgxEndorsements{
		tcbIssuerChain: nil,
	}
	err := verifyCertificates(evidence, endorsements, time.Now())
	if err == nil {
		t.Fatal("expected error for empty TCB issuer chain")
	}
}

func TestVerifyCertificates_NonECDSARootCert(t *testing.T) {
	// Create an RSA cert (not ECDSA) as root
	// Use a real ECDSA cert but the Intel root key won't match
	cert := generateSelfSignedCert(t)
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
			},
		},
	}
	endorsements := &sgxEndorsements{
		tcbIssuerChain: []*x509.Certificate{cert},
	}
	// The cert won't match Intel's root key
	err := verifyCertificates(evidence, endorsements, time.Now())
	if err == nil {
		t.Fatal("expected error: cert doesn't match Intel root key")
	}
}

func TestVerifyRootCertificate_SelfSignedMatchingKey(t *testing.T) {
	// Generate a self-signed cert and use its own public key as the expected key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	err := verifyRootCertificate(cert, &key.PublicKey)
	if err != nil {
		t.Fatalf("expected no error for matching key: %v", err)
	}
}

func TestVerifyEnclaveSource_WrongVendorID(t *testing.T) {
	wrongVendorID := [16]byte{0xFF}
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: wrongVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{},
	}
	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for wrong vendor ID")
	}
}

func TestVerifyEnclaveSource_MrsignerMismatch(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner: [32]byte{0x01},
				},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			mrsigner: [32]byte{0x02}, // different
		},
	}
	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for mrsigner mismatch")
	}
}

func TestVerifyEnclaveSource_IsvprodidMismatch(t *testing.T) {
	mrsigner := [32]byte{0x01}
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner:  mrsigner,
					isvprodid: 1,
				},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			mrsigner:  mrsigner,
			isvprodid: 2, // different
		},
	}
	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for isvprodid mismatch")
	}
}

func TestVerifyEnclaveSource_MiscselectMismatch(t *testing.T) {
	mrsigner := [32]byte{0x01}
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner:   mrsigner,
					isvprodid:  1,
					miscselect: 0x0F,
				},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			mrsigner:       mrsigner,
			isvprodid:      1,
			miscselect:     0x01,
			miscselectMask: 0xFF,
		},
	}
	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for miscselect mismatch")
	}
}

func TestVerifyEnclaveSource_AttributesMismatch(t *testing.T) {
	mrsigner := [32]byte{0x01}
	attrs := [16]byte{0xFF}
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner:      mrsigner,
					isvprodid:     1,
					miscselect:    0x01,
					sgxAttributes: attrs,
				},
			},
		},
	}
	attrsMask := [16]byte{0xFF}
	expectedAttrs := [16]byte{0x01} // different after masking
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			mrsigner:       mrsigner,
			isvprodid:      1,
			miscselect:     0x01,
			miscselectMask: 0xFF,
			attributes:     expectedAttrs,
			attributesMask: attrsMask,
		},
	}
	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for attributes mismatch")
	}
}

func TestVerifyEnclaveSource_AllMatch(t *testing.T) {
	mrsigner := [32]byte{0x01}
	attrs := [16]byte{0x05}
	attrsMask := [16]byte{0x0F}
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner:      mrsigner,
					isvprodid:     1,
					miscselect:    0x03,
					sgxAttributes: attrs,
				},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			mrsigner:       mrsigner,
			isvprodid:      1,
			miscselect:     0x03,
			miscselectMask: 0xFF,
			attributes:     [16]byte{0x05},
			attributesMask: attrsMask,
		},
	}
	err := verifyEnclaveSource(evidence, endorsements)
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestVerifyEnclaveSignatures_EmptyPCKCertChain(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: nil,
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for empty PCK cert chain")
	}
}

func TestVerifyEnclaveSignatures_NonECDSACert(t *testing.T) {
	// We need to create a cert without an ECDSA key - hard in practice,
	// but we can test the normal path with a valid ECDSA cert that fails signature verification.
	cert := generateSelfSignedCert(t)
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				rawBytes: make([]byte, sgxQuoteBodySize),
			},
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
				qeReportBody: &sgxReportBody{
					rawBytes: make([]byte, sgxReportBodySize),
				},
				qeReportSignatureDER: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, // dummy DER
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for signature verification failure")
	}
}

func TestVerifyCertChain_ValidSelfSignedChain(t *testing.T) {
	cert := generateSelfSignedCert(t)
	err := verifyCertChain([]*x509.Certificate{cert}, cert, time.Now())
	if err != nil {
		t.Fatalf("expected no error for self-signed chain: %v", err)
	}
}

func TestVerifyCertChain_ExpiredCert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour), // already expired
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	err := verifyCertChain([]*x509.Certificate{cert}, cert, time.Now())
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
}

func TestVerifyRemoteAttestation_InvalidEvidence(t *testing.T) {
	var mrenclave MREnclave
	_, err := VerifyRemoteAttestation(
		[]byte("bad evidence"),
		[]byte("bad endorsement"),
		&mrenclave,
		nil,
		time.Now(),
	)
	if err == nil {
		t.Fatal("expected error for invalid evidence")
	}
	_, ok := err.(*AttestationError)
	if !ok {
		t.Errorf("expected AttestationError, got %T", err)
	}
}

func TestVerifyEnclaveSignatures_QEReportSignatureVerifyFail(t *testing.T) {
	// Create a real cert so we get past the "not ECDSA" check
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pck"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				rawBytes: make([]byte, sgxQuoteBodySize),
			},
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
				qeReportBody: &sgxReportBody{
					rawBytes: make([]byte, sgxReportBodySize),
				},
				// Invalid DER signature
				qeReportSignatureDER: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for QE report signature verification failure")
	}
}

func TestVerifyEnclaveSignatures_QEReportDataMismatch(t *testing.T) {
	// To reach the "QE report data does not match" check, we need a valid QE report signature.
	// We can sign the zero report body hash ourselves.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pck"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	rawReportBody := make([]byte, sgxReportBodySize)
	reportBodyHash := sha256.Sum256(rawReportBody)

	// Sign the report body hash
	sig, _ := ecdsa.SignASN1(rand.Reader, key, reportBodyHash[:])

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				rawBytes: make([]byte, sgxQuoteBodySize),
			},
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
				qeReportBody: &sgxReportBody{
					rawBytes:           rawReportBody,
					sgxReportDataBytes: [64]byte{}, // will not match SHA256(attestKey||authData)
				},
				qeReportSignatureDER: sig,
				attestPubKey:         [64]byte{0x01}, // non-zero attest key
				authData:             []byte{0x02},
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for QE report data mismatch")
	}
}

func TestVerifyEnclaveSignatures_QEReportDataNonZeroPadding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pck"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	rawReportBody := make([]byte, sgxReportBodySize)
	reportBodyHash := sha256.Sum256(rawReportBody)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, reportBodyHash[:])

	// Compute the expected hash: SHA256(attestPubKey || authData)
	var attestPubKey [64]byte
	authData := []byte{}
	h := sha256.New()
	h.Write(attestPubKey[:])
	h.Write(authData)
	expectedHash := h.Sum(nil)

	// Set report data with correct hash but non-zero padding
	var reportData [64]byte
	copy(reportData[:32], expectedHash)
	reportData[32] = 0xFF // non-zero padding

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				rawBytes: make([]byte, sgxQuoteBodySize),
			},
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
				qeReportBody: &sgxReportBody{
					rawBytes:           rawReportBody,
					sgxReportDataBytes: reportData,
				},
				qeReportSignatureDER: sig,
				attestPubKey:         attestPubKey,
				authData:             authData,
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for non-zero padding in QE report data")
	}
}

func TestVerifyEnclaveSignatures_BadAttestKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pck"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	rawReportBody := make([]byte, sgxReportBodySize)
	reportBodyHash := sha256.Sum256(rawReportBody)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, reportBodyHash[:])

	// attestPubKey all zeros - this won't be on P-256 curve
	var attestPubKey [64]byte
	authData := []byte{}
	h2 := sha256.New()
	h2.Write(attestPubKey[:])
	h2.Write(authData)
	expectedHash := h2.Sum(nil)

	var reportData [64]byte
	copy(reportData[:32], expectedHash)
	// Last 32 bytes are zero (valid padding)

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				rawBytes: make([]byte, sgxQuoteBodySize),
			},
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
				qeReportBody: &sgxReportBody{
					rawBytes:           rawReportBody,
					sgxReportDataBytes: reportData,
				},
				qeReportSignatureDER: sig,
				attestPubKey:         attestPubKey, // all zeros, not on curve
				authData:             authData,
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for invalid attest key (not on curve)")
	}
}

func TestVerifyEnclaveSignatures_ISVReportSignatureFailure(t *testing.T) {
	// Build evidence that passes all checks except the ISV report signature
	pckKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pck"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &pckKey.PublicKey, pckKey)
	cert, _ := x509.ParseCertificate(certBytes)

	rawReportBody := make([]byte, sgxReportBodySize)
	reportBodyHash := sha256.Sum256(rawReportBody)
	qeSig, _ := ecdsa.SignASN1(rand.Reader, pckKey, reportBodyHash[:])

	// Generate a real attest key via crypto/ecdh to avoid deprecated big.Int fields.
	attestECDHKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	var attestPubKeyBytes [64]byte
	// Bytes() returns 0x04 || X(32) || Y(32); strip the prefix.
	copy(attestPubKeyBytes[:], attestECDHKey.PublicKey().Bytes()[1:])

	authData := []byte{}
	h2 := sha256.New()
	h2.Write(attestPubKeyBytes[:])
	h2.Write(authData)
	expectedHash := h2.Sum(nil)

	var reportData [64]byte
	copy(reportData[:32], expectedHash)

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				rawBytes: make([]byte, sgxQuoteBodySize),
			},
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
				qeReportBody: &sgxReportBody{
					rawBytes:           rawReportBody,
					sgxReportDataBytes: reportData,
				},
				qeReportSignatureDER: qeSig,
				attestPubKey:         attestPubKeyBytes,
				authData:             authData,
				// ISV signature is dummy - won't verify
				isvSignatureDER: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for ISV report signature failure")
	}
}

func TestVerifyCertificates_FullChain(t *testing.T) {
	// Create a self-signed root, then test the full verifyCertificates path
	// with matching Intel root key (obviously won't match the real one)
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Intel Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootBytes)

	// verifyCertificates uses parseIntelRootKey, so the root won't match Intel's key.
	// We can only test that it reaches that check.
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{rootCert},
			},
		},
	}
	endorsements := &sgxEndorsements{
		tcbIssuerChain:    []*x509.Certificate{rootCert},
		qeIDIssuerChain:   []*x509.Certificate{rootCert},
		pckIssuerCRLChain: []*x509.Certificate{rootCert},
	}
	err := verifyCertificates(evidence, endorsements, time.Now())
	if err == nil {
		t.Fatal("expected error: root cert won't match Intel root key")
	}
}

func TestVerifyRootCertificate_NonECDSAPublicKey(t *testing.T) {
	// We can't easily create a non-ECDSA cert here since we rely on the Go stdlib.
	// Instead test the key mismatch path more thoroughly.
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key1.PublicKey, key1)
	cert, _ := x509.ParseCertificate(certBytes)

	// X matches but Y doesn't — deliberate malformed-key fixture for negative test.
	// SA1019: accessing X/Y is intentional here; we need a structurally invalid key
	// that parseIntelRootKey / verifyRootCertificate must reject.
	mismatchKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     key1.X,
		Y:     key2.Y,
	}
	err := verifyRootCertificate(cert, mismatchKey)
	if err == nil {
		t.Fatal("expected error for Y coordinate mismatch")
	}
}

func TestDcapAttest_ValidEvidenceInvalidEndorsements(t *testing.T) {
	// Build valid-looking evidence structure that parses, but then endorsements fail
	quoteBody := make([]byte, sgxQuoteBodySize)
	binary.LittleEndian.PutUint16(quoteBody[0:2], quoteV3)
	binary.LittleEndian.PutUint16(quoteBody[2:4], ecdsaP256)

	// Need a valid quote support with a real PEM cert
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "t"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	cb, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cb})

	// Build support
	headerSize := 64 + 64 + sgxReportBodySize + 64 + 2
	support := make([]byte, headerSize)
	// cert key type
	certKeyType := make([]byte, 2)
	binary.LittleEndian.PutUint16(certKeyType, pckCertChainKeyType)
	support = append(support, certKeyType...)
	certDataSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(certDataSize, uint32(len(pemCert)))
	support = append(support, certDataSize...)
	support = append(support, pemCert...)

	// Build custom claims
	var claims []byte
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	claims = append(claims, b8...)
	binary.LittleEndian.PutUint64(b8, 0) // 0 claims
	claims = append(claims, b8...)

	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, uint32(len(support)))

	var evidenceData []byte
	evidenceData = append(evidenceData, quoteBody...)
	evidenceData = append(evidenceData, sigLen...)
	evidenceData = append(evidenceData, support...)
	evidenceData = append(evidenceData, claims...)

	// Now test dcapAttest with valid evidence but bad endorsements
	_, err := dcapAttest(evidenceData, []byte{0x01}, time.Now())
	if err == nil {
		t.Fatal("expected error for invalid endorsements")
	}
}

func TestVerifyTCBStatus_NoTCBInfo(t *testing.T) {
	// When no TCB info is present, should return UpToDate.
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{},
		},
	}
	endorsements := &sgxEndorsements{}
	standing, advisoryIDs, err := verifyTCBStatus(evidence, endorsements)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if standing != tcbUpToDate {
		t.Errorf("standing = %d, want %d", standing, tcbUpToDate)
	}
	if advisoryIDs != nil {
		t.Errorf("advisoryIDs should be nil, got %v", advisoryIDs)
	}
}

func TestVerifyTCBStatus_TCBInfoPresentButNoPCKExtension(t *testing.T) {
	// When TCB info is present but PCK extension cannot be parsed,
	// should return an error (fail-closed).
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{generateSelfSignedCert(t)},
			},
		},
	}
	endorsements := &sgxEndorsements{
		tcbInfoRaw: []byte(`{"fmspc":"00606A000000","pceId":"0000","tcbLevels":[]}`),
	}
	_, _, err := verifyTCBStatus(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error when PCK extension cannot be parsed")
	}
	var pckErr *PCKExtensionParseError
	if !errors.As(err, &pckErr) {
		t.Errorf("expected PCKExtensionParseError, got %T: %v", err, err)
	}
}

func TestVerifyTCBStatus_FMSPCMismatch(t *testing.T) {
	// If we could parse the PCK extension and the FMSPC doesn't match, it should error.
	// This tests the findTCBStanding path indirectly - but we can test with
	// the parseSingleTCBLevel and inTCBLevel functions directly.
	level, _ := parseSingleTCBLevel(`{"tcbStatus":"UpToDate","sgxtcbcomp01svn":4,"pcesvn":11}`)
	if level.status != "UpToDate" {
		t.Errorf("status = %q, want UpToDate", level.status)
	}
	if level.compsvn[0] != 4 {
		t.Errorf("compsvn[0] = %d, want 4", level.compsvn[0])
	}
	if level.pcesvn != 11 {
		t.Errorf("pcesvn = %d, want 11", level.pcesvn)
	}
}

func TestInTCBLevel(t *testing.T) {
	pckExt := &pckExtensionData{
		compsvn: [16]byte{4, 4, 3, 3, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0},
		pcesvn:  11,
	}

	tests := []struct {
		name     string
		level    tcbLevel
		expected bool
	}{
		{
			name: "exact match",
			level: tcbLevel{
				compsvn: [16]byte{4, 4, 3, 3, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0},
				pcesvn:  11,
			},
			expected: true,
		},
		{
			name: "pck higher",
			level: tcbLevel{
				compsvn: [16]byte{3, 3, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				pcesvn:  10,
			},
			expected: true,
		},
		{
			name: "component too high",
			level: tcbLevel{
				compsvn: [16]byte{5, 4, 3, 3, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0},
				pcesvn:  11,
			},
			expected: false,
		},
		{
			name: "pcesvn too high",
			level: tcbLevel{
				compsvn: [16]byte{4, 4, 3, 3, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0},
				pcesvn:  12,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inTCBLevel(pckExt, &tt.level); got != tt.expected {
				t.Errorf("inTCBLevel = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFindTCBStanding(t *testing.T) {
	pckExt := &pckExtensionData{
		compsvn: [16]byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		pcesvn:  11,
	}

	t.Run("UpToDate", func(t *testing.T) {
		levels := []tcbLevel{
			{compsvn: [16]byte{4}, pcesvn: 11, status: "UpToDate"},
		}
		standing, advisories, err := findTCBStanding(pckExt, levels)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if standing != tcbUpToDate {
			t.Errorf("standing = %d, want tcbUpToDate", standing)
		}
		if advisories != nil {
			t.Errorf("advisories should be nil")
		}
	})

	t.Run("SWHardeningNeeded", func(t *testing.T) {
		levels := []tcbLevel{
			{compsvn: [16]byte{5}, pcesvn: 11, status: "UpToDate"},
			{compsvn: [16]byte{4}, pcesvn: 11, status: "SWHardeningNeeded", advisoryIDs: []string{"INTEL-SA-00334"}},
		}
		standing, advisories, err := findTCBStanding(pckExt, levels)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if standing != tcbSWHardeningNeeded {
			t.Errorf("standing = %d, want tcbSWHardeningNeeded", standing)
		}
		if len(advisories) != 1 || advisories[0] != "INTEL-SA-00334" {
			t.Errorf("advisories = %v, want [INTEL-SA-00334]", advisories)
		}
	})

	t.Run("Revoked", func(t *testing.T) {
		levels := []tcbLevel{
			{compsvn: [16]byte{4}, pcesvn: 11, status: "Revoked"},
		}
		_, _, err := findTCBStanding(pckExt, levels)
		if err == nil {
			t.Fatal("expected error for Revoked status")
		}
	})

	t.Run("NoMatch", func(t *testing.T) {
		levels := []tcbLevel{
			{compsvn: [16]byte{5}, pcesvn: 12, status: "UpToDate"},
		}
		_, _, err := findTCBStanding(pckExt, levels)
		if err == nil {
			t.Fatal("expected error for no matching level")
		}
	})
}

func TestParseTCBLevels(t *testing.T) {
	jsonStr := `{"tcbLevels":[{"tcb":{"sgxtcbcomp01svn":4,"sgxtcbcomp02svn":2,"pcesvn":11},"tcbStatus":"UpToDate"},{"tcb":{"sgxtcbcomp01svn":3,"pcesvn":10},"tcbStatus":"SWHardeningNeeded","advisoryIDs":["INTEL-SA-00334"]}]}`
	levels, err := parseTCBLevels(jsonStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(levels) != 2 {
		t.Fatalf("expected 2 levels, got %d", len(levels))
	}
	if levels[0].status != "UpToDate" {
		t.Errorf("level[0].status = %q, want UpToDate", levels[0].status)
	}
	if levels[0].compsvn[0] != 4 {
		t.Errorf("level[0].compsvn[0] = %d, want 4", levels[0].compsvn[0])
	}
	if levels[0].compsvn[1] != 2 {
		t.Errorf("level[0].compsvn[1] = %d, want 2", levels[0].compsvn[1])
	}
	if levels[0].pcesvn != 11 {
		t.Errorf("level[0].pcesvn = %d, want 11", levels[0].pcesvn)
	}
	if levels[1].status != "SWHardeningNeeded" {
		t.Errorf("level[1].status = %q, want SWHardeningNeeded", levels[1].status)
	}
	if len(levels[1].advisoryIDs) != 1 || levels[1].advisoryIDs[0] != "INTEL-SA-00334" {
		t.Errorf("level[1].advisoryIDs = %v", levels[1].advisoryIDs)
	}
}

func TestParseTCBLevels_NoTCBLevels(t *testing.T) {
	levels, err := parseTCBLevels(`{"other":"value"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(levels) != 0 {
		t.Errorf("expected 0 levels, got %d", len(levels))
	}
}

func TestExtractStringField(t *testing.T) {
	tests := []struct {
		name  string
		json  string
		field string
		want  string
	}{
		{"found", `{"status":"UpToDate"}`, "status", "UpToDate"},
		{"not found", `{"other":"value"}`, "status", ""},
		{"non-string", `{"status":42}`, "status", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractStringField(tt.json, tt.field); got != tt.want {
				t.Errorf("extractStringField = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractStringArrayField(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		json := `{"advisoryIDs":["INTEL-SA-00334","INTEL-SA-00615"]}`
		got := extractStringArrayField(json, "advisoryIDs")
		if len(got) != 2 || got[0] != "INTEL-SA-00334" || got[1] != "INTEL-SA-00615" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("not found", func(t *testing.T) {
		got := extractStringArrayField(`{"other":"value"}`, "advisoryIDs")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty array", func(t *testing.T) {
		got := extractStringArrayField(`{"advisoryIDs":[]}`, "advisoryIDs")
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})
}

func TestSgxReportBody_HasFlag(t *testing.T) {
	rb := &sgxReportBody{}
	// Set debug flag (bit 1) in sgxAttributes
	rb.sgxAttributes[0] = 0x02

	if !rb.hasFlag(sgxFlagDebug) {
		t.Error("expected hasFlag(debug) to be true")
	}
	if rb.hasFlag(0x04) { // flag not set
		t.Error("expected hasFlag(0x04) to be false")
	}
}

func TestSgxReportBody_HasFlag_NotSet(t *testing.T) {
	rb := &sgxReportBody{}
	// All zeros
	if rb.hasFlag(sgxFlagDebug) {
		t.Error("expected hasFlag(debug) to be false for zero attributes")
	}
}

func TestDcapEvidence_ValidAt(t *testing.T) {
	now := time.Now()
	validCert := generateSelfSignedCert(t) // NotBefore=-1h, NotAfter=+1h

	t.Run("nil quote", func(t *testing.T) {
		evidence := &dcapEvidence{}
		if evidence.validAt(now) {
			t.Error("validAt should return false for nil quote")
		}
	})

	t.Run("valid cert", func(t *testing.T) {
		evidence := &dcapEvidence{
			quote: &sgxQuote{
				support: &sgxQuoteSupport{
					pckCertChain: []*x509.Certificate{validCert},
				},
			},
		}
		if !evidence.validAt(now) {
			t.Error("validAt should return true for valid cert")
		}
	})

	t.Run("future time", func(t *testing.T) {
		evidence := &dcapEvidence{
			quote: &sgxQuote{
				support: &sgxQuoteSupport{
					pckCertChain: []*x509.Certificate{validCert},
				},
			},
		}
		futureTime := now.Add(24 * time.Hour)
		if evidence.validAt(futureTime) {
			t.Error("validAt should return false for time past cert expiry")
		}
	})

	t.Run("past time", func(t *testing.T) {
		evidence := &dcapEvidence{
			quote: &sgxQuote{
				support: &sgxQuoteSupport{
					pckCertChain: []*x509.Certificate{validCert},
				},
			},
		}
		pastTime := now.Add(-24 * time.Hour)
		if evidence.validAt(pastTime) {
			t.Error("validAt should return false for time before cert validity")
		}
	})
}

// generateSelfSignedCert creates a self-signed ECDSA certificate for testing.
func generateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// --- AT-C3: verifyEnclaveSource identity type check tests ---

func TestVerifyEnclaveSource_WrongIdentityType(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			id:      "TDX",
			version: 2,
		},
	}

	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for wrong identity type")
	}
	var typeErr *EnclaveIdentityTypeError
	if !errors.As(err, &typeErr) {
		t.Errorf("expected EnclaveIdentityTypeError, got %T: %v", err, err)
	}
}

func TestVerifyEnclaveSource_CorrectIdentityType(t *testing.T) {
	// Build matching evidence and endorsements
	var mrsigner [32]byte
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner:  mrsigner,
					isvprodid: 0,
				},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			id:       "QE",
			version:  2,
			mrsigner: mrsigner,
		},
	}

	err := verifyEnclaveSource(evidence, endorsements)
	if err != nil {
		t.Fatalf("verifyEnclaveSource failed: %v", err)
	}
}

// --- AT-C2: QE TCB status check in verifyEnclaveSource ---

func TestVerifyEnclaveSource_QETCBStatusOutOfDate(t *testing.T) {
	var mrsigner [32]byte
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner:  mrsigner,
					isvprodid: 0,
					isvsvn:    1,
				},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			id:       "QE",
			version:  2,
			mrsigner: mrsigner,
			tcbLevels: []qeTcbLevel{
				{isvsvn: 5, tcbStatus: "UpToDate"},
				{isvsvn: 3, tcbStatus: "OutOfDate"},
				{isvsvn: 1, tcbStatus: "Revoked"},
			},
		},
	}

	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for Revoked QE TCB status")
	}
	var tcbErr *QETCBStatusError
	if !errors.As(err, &tcbErr) {
		t.Errorf("expected QETCBStatusError, got %T: %v", err, err)
	}
}

func TestVerifyEnclaveSource_QETCBStatusUpToDate(t *testing.T) {
	var mrsigner [32]byte
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{
				qeVendorID: intelQEVendorID,
			},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner:  mrsigner,
					isvprodid: 0,
					isvsvn:    5,
				},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			id:       "QE",
			version:  2,
			mrsigner: mrsigner,
			tcbLevels: []qeTcbLevel{
				{isvsvn: 5, tcbStatus: "UpToDate"},
				{isvsvn: 3, tcbStatus: "OutOfDate"},
			},
		},
	}

	err := verifyEnclaveSource(evidence, endorsements)
	if err != nil {
		t.Fatalf("verifyEnclaveSource failed: %v", err)
	}
}

// --- AT-C1: CRL verification in verifyCertificates ---

// TestVerifyCRLs_RevokedCert verifies that a cert present in pckCertCRL is rejected.
// pckProcCACRL is supplied to pass the mandatory-CRL check added by Finding-1 fix;
// the revocation error fires in step 1 (pckCertCRL check) before reaching the
// Intel-key verification of pckProcCACRL, so the test still catches CRLVerificationError.
func TestVerifyCRLs_RevokedCert(t *testing.T) {
	key, cert := generateTestCertAndKeyForDcap(t)

	// Create a CRL that revokes the cert.
	crlBytes := generateTestCRLWithRevokedForDcap(t, cert, key, cert.SerialNumber)
	crl, _ := x509.ParseRevocationList(crlBytes)

	// A non-nil pckProcCACRL is required (Finding-1 fix).  The function returns
	// CRLVerificationError at the pckCertCRL revocation check before reaching the
	// Intel-key check on pckProcCACRL, so any non-nil CRL value satisfies the test.
	emptyCRLBytes := generateTestEmptyCRLForDcap(t, cert, key)
	emptyCRL, _ := x509.ParseRevocationList(emptyCRLBytes)

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
			},
		},
	}
	endorsements := &sgxEndorsements{
		pckCertCRL:        crl,
		pckIssuerCRLChain: []*x509.Certificate{cert},
		pckProcCACRL:      emptyCRL,
	}

	err := verifyCRLs(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for revoked certificate")
	}
	var revErr *CRLVerificationError
	if !errors.As(err, &revErr) {
		t.Errorf("expected CRLVerificationError, got %T: %v", err, err)
	}
}

// TestVerifyCRLs_NoRevocation verifies that when no cert is in pckCertCRL, the
// function proceeds past the leaf-CRL revocation check and then enforces the
// Intel-root-key check on pckProcCACRL.  With test keys (non-Intel), we expect
// a RootCRLVerificationError rather than success.
//
// Before Finding-1 fix: verifyCRLs with nil pckProcCACRL silently returned nil.
// After fix: nil pckProcCACRL → CRLMissingError; test-signed pckProcCACRL →
// RootCRLVerificationError.  The function can no longer be short-circuited.
func TestVerifyCRLs_NoRevocation(t *testing.T) {
	key, cert := generateTestCertAndKeyForDcap(t)

	crlBytes := generateTestEmptyCRLForDcap(t, cert, key)
	crl, _ := x509.ParseRevocationList(crlBytes)

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{cert},
			},
		},
	}
	endorsements := &sgxEndorsements{
		pckCertCRL:        crl,
		pckIssuerCRLChain: []*x509.Certificate{cert},
		// Finding-1 fix requires pckProcCACRL to be non-nil.
		// A test-signed CRL cannot pass verifyRootCRLAgainstIntelKey, so we
		// expect a RootCRLVerificationError once the leaf-CRL check passes.
		pckProcCACRL: crl,
	}

	err := verifyCRLs(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error: pckProcCACRL must be Intel-signed (test key cannot pass Intel root key check)")
	}
	var rootErr *RootCRLVerificationError
	if !errors.As(err, &rootErr) {
		t.Errorf("expected RootCRLVerificationError, got %T: %v", err, err)
	}
}

// TestVerifyCRLs_NilCRLs is a regression test for Finding 1 (DCAP revocation
// bypass via CRL stripping).  Before the fix, verifyCRLs with nil CRLs returned
// nil (success), allowing a revoked PCK cert to pass attestation.  After the fix
// it must return a CRLMissingError immediately.
func TestVerifyCRLs_NilCRLs(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{},
			},
		},
	}
	endorsements := &sgxEndorsements{} // both CRLs are nil

	err := verifyCRLs(evidence, endorsements)
	if err == nil {
		t.Fatal("verifyCRLs must reject nil CRLs (regression for Finding 1: CRL stripping attack)")
	}
	var missingErr *CRLMissingError
	if !errors.As(err, &missingErr) {
		t.Errorf("expected CRLMissingError, got %T: %v", err, err)
	}
}

func generateTestCertAndKeyForDcap(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "test-dcap"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, cert
}

func generateTestEmptyCRLForDcap(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	// parseCRL now requires AKI and CRL Number (matches Rust reference).
	aki := issuer.SubjectKeyId
	if len(aki) == 0 {
		aki = []byte{0x01, 0x02, 0x03, 0x04}
	}
	template := &x509.RevocationList{
		Number:         big.NewInt(1),
		AuthorityKeyId: aki,
		ThisUpdate:     time.Now().Add(-time.Hour),
		NextUpdate:     time.Now().Add(time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuer, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return crlBytes
}

func generateTestCRLWithRevokedForDcap(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, serial *big.Int) []byte {
	t.Helper()
	// parseCRL now requires AKI and CRL Number (matches Rust reference).
	aki := issuer.SubjectKeyId
	if len(aki) == 0 {
		aki = []byte{0x01, 0x02, 0x03, 0x04}
	}
	template := &x509.RevocationList{
		Number:         big.NewInt(1),
		AuthorityKeyId: aki,
		ThisUpdate:     time.Now().Add(-time.Hour),
		NextUpdate:     time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   serial,
				RevocationTime: time.Now().Add(-30 * time.Minute),
			},
		},
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, issuer, key)
	if err != nil {
		t.Fatalf("create CRL with revoked: %v", err)
	}
	return crlBytes
}

func TestVerifyTCBStatus_FailsOnMissingFMSPC(t *testing.T) {
	// TCB info present but missing fmspc field should fail closed.
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{generateSelfSignedCert(t)},
			},
		},
	}
	endorsements := &sgxEndorsements{
		tcbInfoRaw: []byte(`{"pceId":"0000","tcbLevels":[]}`),
	}
	_, _, err := verifyTCBStatus(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error when FMSPC cannot be extracted")
	}
	var pckErr *PCKExtensionParseError
	if !errors.As(err, &pckErr) {
		t.Errorf("expected PCKExtensionParseError, got %T: %v", err, err)
	}
}

func TestVerifyTCBStatus_FailsOnMissingPCEID(t *testing.T) {
	// TCB info present but missing pceId field should fail closed.
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{generateSelfSignedCert(t)},
			},
		},
	}
	endorsements := &sgxEndorsements{
		tcbInfoRaw: []byte(`{"fmspc":"00606A000000","tcbLevels":[]}`),
	}
	_, _, err := verifyTCBStatus(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error when PCEID cannot be extracted")
	}
	var pckErr *PCKExtensionParseError
	if !errors.As(err, &pckErr) {
		t.Errorf("expected PCKExtensionParseError, got %T: %v", err, err)
	}
}

func TestVerifyRootCRLAgainstIntelKey_WrongKey(t *testing.T) {
	// Create a CRL signed by a non-Intel key; verification should fail.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		Subject:               pkix.Name{CommonName: "Test CA"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatal(err)
	}

	err = verifyRootCRLAgainstIntelKey(crl)
	if err == nil {
		t.Fatal("expected error when CRL is not signed by Intel root key")
	}
	var rootErr *RootCRLVerificationError
	if !errors.As(err, &rootErr) {
		t.Errorf("expected RootCRLVerificationError, got %T: %v", err, err)
	}
}

func TestVerifyRootCRLAgainstIntelKey_ErrorMessage(t *testing.T) {
	// Verify the error types produce meaningful messages.
	err := &RootCRLVerificationError{Err: errors.New("test inner")}
	msg := err.Error()
	if msg == "" {
		t.Fatal("error message should not be empty")
	}
	if unwrapped := err.Unwrap(); unwrapped == nil {
		t.Error("Unwrap should return inner error")
	}

	errNoInner := &RootCRLVerificationError{}
	if errNoInner.Error() == "" {
		t.Error("error message without inner error should not be empty")
	}
}

func TestPCKExtensionParseError_Message(t *testing.T) {
	err := &PCKExtensionParseError{Field: "fmspc", Err: errors.New("not found")}
	msg := err.Error()
	if msg == "" {
		t.Fatal("error message should not be empty")
	}
	if unwrapped := err.Unwrap(); unwrapped == nil {
		t.Error("Unwrap should return inner error")
	}

	errNoInner := &PCKExtensionParseError{Field: "pceId"}
	if errNoInner.Error() == "" {
		t.Error("error message without inner error should not be empty")
	}
}

// TestFinding2_PCKChainCheckedAgainstRootCRL is a regression test for Finding 2:
// PCK evidence chain was never checked against the root CRL (pckProcCACRL).
// Before the fix, verifyCRLs only checked pckCertChain against pckCertCRL
// (intermediate CRL), so a cert revoked by the root CA passed unchallenged.
// The fix adds a loop that calls checkCertAgainstCRL(cert, pckProcCACRL) for
// every cert in pckCertChain, mirroring Rust dcap.rs ~311 (CRL_CHECK_ALL on
// the trust store containing root_crl).
//
// The full integration path through verifyCRLs cannot be exercised in unit tests
// because verifyRootCRLAgainstIntelKey requires Intel-signed CRLs.  This test
// directly validates the security property: a cert revoked in the root CRL is
// detected by checkCertAgainstCRL — the call the fix adds for pckCertChain.
func TestFinding2_PCKChainCheckedAgainstRootCRL(t *testing.T) {
	key, cert := generateTestCertAndKeyForDcap(t)

	// Root CRL that revokes cert (simulates a cert whose CA revoked it at root level).
	rootCRLBytes := generateTestCRLWithRevokedForDcap(t, cert, key, cert.SerialNumber)
	rootCRL, err := x509.ParseRevocationList(rootCRLBytes)
	if err != nil {
		t.Fatalf("parse root CRL: %v", err)
	}

	// Before Fix 2: only pckCertCRL was checked against pckCertChain.
	// Simulate pckCertCRL being an empty CRL (cert not in leaf CRL).
	emptyCRLBytes := generateTestEmptyCRLForDcap(t, cert, key)
	emptyCRL, err := x509.ParseRevocationList(emptyCRLBytes)
	if err != nil {
		t.Fatalf("parse empty CRL: %v", err)
	}

	// Leaf CRL passes (cert not revoked there).
	if leafErr := checkCertAgainstCRL(cert, emptyCRL); leafErr != nil {
		t.Fatalf("cert should not be in empty leaf CRL: %v", leafErr)
	}

	// Root CRL must catch the cert (this is the check Fix 2 adds to verifyCRLs).
	rootErr := checkCertAgainstCRL(cert, rootCRL)
	if rootErr == nil {
		t.Fatal("Fix 2 regression: cert revoked in root CRL must be rejected by checkCertAgainstCRL(cert, pckProcCACRL)")
	}
	var revErr *CRLVerificationError
	if !errors.As(rootErr, &revErr) {
		t.Errorf("expected CRLVerificationError, got %T: %v", rootErr, rootErr)
	}
}
