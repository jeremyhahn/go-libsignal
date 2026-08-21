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
	"math/big"
	"testing"
	"time"
)

// --- dcapAttest: cover evidence validity and endorsement validity branches ---

func TestDcapAttest_EvidenceNotValidAtTime(t *testing.T) {
	_, err := dcapAttest(nil, nil, time.Now())
	if err == nil {
		t.Fatal("expected error for nil evidence")
	}
}

func TestDcapAttest_EmptyEvidence(t *testing.T) {
	_, err := dcapAttest([]byte{}, []byte{0x01}, time.Now())
	if err == nil {
		t.Fatal("expected error for empty evidence")
	}
}

func TestDcapAttest_ValidEvidenceBadEndorsements(t *testing.T) {
	evidence := buildMinimalValidEvidence(t)
	_, err := dcapAttest(evidence, []byte{0x00, 0x00, 0x00}, time.Now())
	if err == nil {
		t.Fatal("expected error for bad endorsements")
	}
}

func TestDcapAttest_ValidEvidenceAndEndorsements_CertVerifyFails(t *testing.T) {
	evidence := buildMinimalValidEvidence(t)
	versionField := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionField, oeEndorsementsV1)
	endorsements := buildEndorsementsData(t, versionField)

	_, err := dcapAttest(evidence, endorsements, time.Now())
	if err == nil {
		t.Fatal("expected error when certificate chain doesn't match Intel root")
	}
}

// --- verifyCertificates: PCK cert chain verification failure ---

func TestVerifyCertificates_PCKCertChainVerifyFails(t *testing.T) {
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

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &leafKey.PublicKey, leafKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	err := verifyCertChain([]*x509.Certificate{leafCert}, rootCert, time.Now())
	if err == nil {
		t.Fatal("expected error for PCK cert chain that doesn't chain to root")
	}
}

func TestVerifyCertificates_RootNotIntelKey(t *testing.T) {
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
	err := verifyCertificates(evidence, endorsements, time.Now())
	if err == nil {
		t.Fatal("expected error for non-Intel root key")
	}
}

// --- VerifyRemoteAttestation: short evidence ---

func TestVerifyRemoteAttestation_ShortEvidence(t *testing.T) {
	var mrenclave MREnclave
	_, err := VerifyRemoteAttestation(
		[]byte{0x01, 0x02},
		[]byte{0x03, 0x04},
		&mrenclave,
		[]string{"INTEL-SA-00615"},
		time.Now(),
	)
	if err == nil {
		t.Fatal("expected error for short evidence")
	}
	_, ok := err.(*AttestationError)
	if !ok {
		t.Errorf("expected *AttestationError, got %T", err)
	}
}

// --- parseQuoteBody: unsupported version/sign type ---

func TestParseQuoteBody_UnsupportedVersion(t *testing.T) {
	data := make([]byte, sgxQuoteBodySize)
	binary.LittleEndian.PutUint16(data[0:2], 2)
	binary.LittleEndian.PutUint16(data[2:4], ecdsaP256)
	_, err := parseQuoteBody(data)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestParseQuoteBody_UnsupportedSignType(t *testing.T) {
	data := make([]byte, sgxQuoteBodySize)
	binary.LittleEndian.PutUint16(data[0:2], quoteV3)
	binary.LittleEndian.PutUint16(data[2:4], 99)
	_, err := parseQuoteBody(data)
	if err == nil {
		t.Fatal("expected error for unsupported sign type")
	}
}

// --- parseReportBody: valid with all fields ---

func TestParseReportBody_Valid(t *testing.T) {
	data := make([]byte, sgxReportBodySize)
	data[0] = 0x42
	binary.LittleEndian.PutUint32(data[16:20], 0x1234)
	data[64] = 0xAB
	data[128] = 0xCD
	binary.LittleEndian.PutUint16(data[256:258], 42)
	binary.LittleEndian.PutUint16(data[258:260], 7)

	rb, err := parseReportBody(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rb.cpusvn[0] != 0x42 {
		t.Errorf("cpusvn[0] = %x, want 0x42", rb.cpusvn[0])
	}
	if rb.miscselect != 0x1234 {
		t.Errorf("miscselect = %x, want 0x1234", rb.miscselect)
	}
	if rb.mrenclave[0] != 0xAB {
		t.Errorf("mrenclave[0] = %x, want 0xAB", rb.mrenclave[0])
	}
	if rb.mrsigner[0] != 0xCD {
		t.Errorf("mrsigner[0] = %x, want 0xCD", rb.mrsigner[0])
	}
	if rb.isvprodid != 42 {
		t.Errorf("isvprodid = %d, want 42", rb.isvprodid)
	}
	if rb.isvsvn != 7 {
		t.Errorf("isvsvn = %d, want 7", rb.isvsvn)
	}
}

// --- validateOffsets: non-increasing ---

func TestValidateOffsets_NonIncreasing(t *testing.T) {
	offsets := []int{0, 10, 5, 20, 30, 40, 50, 60, 70}
	err := validateOffsets(offsets, make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for non-increasing offsets")
	}
}

// --- mustDecodeHex ---

func TestMustDecodeHex_OddLengthPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for odd length hex string")
		}
	}()
	mustDecodeHex("abc")
}

func TestMustDecodeHex_InvalidCharPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid hex character")
		}
	}()
	mustDecodeHex("zz")
}

func TestMustDecodeHex_Valid(t *testing.T) {
	got := mustDecodeHex("abcd01ff")
	want := []byte{0xAB, 0xCD, 0x01, 0xFF}
	if len(got) != len(want) {
		t.Fatalf("length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, got[i], want[i])
		}
	}
}

// --- hexNibble ---

func TestHexNibble_AllRanges(t *testing.T) {
	tests := []struct {
		input byte
		want  byte
	}{
		{'0', 0}, {'5', 5}, {'9', 9},
		{'a', 10}, {'c', 12}, {'f', 15},
		{'A', 10}, {'C', 12}, {'F', 15},
	}
	for _, tt := range tests {
		got, err := hexNibble(tt.input)
		if err != nil {
			t.Errorf("hexNibble(%c): unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("hexNibble(%c) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestHexNibble_Invalid(t *testing.T) {
	invalid := []byte{'g', 'G', 'z', ' ', '@', '['}
	for _, b := range invalid {
		_, err := hexNibble(b)
		if err == nil {
			t.Errorf("expected error for hexNibble(%c)", b)
		}
	}
}

// --- verifyEnclaveSignatures ---

func TestVerifyEnclaveSignatures_FullValidPath(t *testing.T) {
	pckKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pck"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pckKey.PublicKey, pckKey)
	cert, _ := x509.ParseCertificate(certBytes)

	rawReportBody := make([]byte, sgxReportBodySize)
	reportBodyHash := sha256.Sum256(rawReportBody)
	qeSig, _ := ecdsa.SignASN1(rand.Reader, pckKey, reportBodyHash[:])

	attestKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Bytes() returns 0x04 || X || Y with both coordinates already padded to
	// the curve's fixed width, which is exactly the encoding parseAttestKey
	// expects once the prefix is dropped.
	attestPub, encErr := attestKey.PublicKey.Bytes()
	if encErr != nil {
		t.Fatalf("encoding attest public key: %v", encErr)
	}
	var attestPubKeyBytes [64]byte
	copy(attestPubKeyBytes[:], attestPub[1:])

	authData := []byte{}
	h := sha256.New()
	h.Write(attestPubKeyBytes[:])
	h.Write(authData)
	expectedHash := h.Sum(nil)

	var reportData [64]byte
	copy(reportData[:32], expectedHash)

	quoteBodyRaw := make([]byte, sgxQuoteBodySize)
	isvHash := sha256.Sum256(quoteBodyRaw)
	isvSig, _ := ecdsa.SignASN1(rand.Reader, attestKey, isvHash[:])

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{rawBytes: quoteBodyRaw},
			support: &sgxQuoteSupport{
				pckCertChain:         []*x509.Certificate{cert},
				qeReportBody:         &sgxReportBody{rawBytes: rawReportBody, sgxReportDataBytes: reportData},
				qeReportSignatureDER: qeSig,
				attestPubKey:         attestPubKeyBytes,
				authData:             authData,
				isvSignatureDER:      isvSig,
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err != nil {
		t.Fatalf("expected no error for fully valid signatures: %v", err)
	}
}

func TestVerifyEnclaveSignatures_EmptyPCKChain(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{pckCertChain: nil},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for empty PCK chain")
	}
}

func TestVerifyEnclaveSignatures_BadQEReportSig(t *testing.T) {
	cert := generateSelfSignedCert(t)
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{rawBytes: make([]byte, sgxQuoteBodySize)},
			support: &sgxQuoteSupport{
				pckCertChain:         []*x509.Certificate{cert},
				qeReportBody:         &sgxReportBody{rawBytes: make([]byte, sgxReportBodySize)},
				qeReportSignatureDER: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for bad QE report signature")
	}
}

func TestVerifyEnclaveSignatures_BadReportDataHash(t *testing.T) {
	pckKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pck"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pckKey.PublicKey, pckKey)
	cert, _ := x509.ParseCertificate(certBytes)

	rawReportBody := make([]byte, sgxReportBodySize)
	reportBodyHash := sha256.Sum256(rawReportBody)
	qeSig, _ := ecdsa.SignASN1(rand.Reader, pckKey, reportBodyHash[:])

	var reportData [64]byte
	reportData[0] = 0xFF

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{rawBytes: make([]byte, sgxQuoteBodySize)},
			support: &sgxQuoteSupport{
				pckCertChain:         []*x509.Certificate{cert},
				qeReportBody:         &sgxReportBody{rawBytes: rawReportBody, sgxReportDataBytes: reportData},
				qeReportSignatureDER: qeSig,
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for report data hash mismatch")
	}
}

func TestVerifyEnclaveSignatures_NonZeroPaddingInReportData(t *testing.T) {
	pckKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pck"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pckKey.PublicKey, pckKey)
	cert, _ := x509.ParseCertificate(certBytes)

	rawReportBody := make([]byte, sgxReportBodySize)
	reportBodyHash := sha256.Sum256(rawReportBody)
	qeSig, _ := ecdsa.SignASN1(rand.Reader, pckKey, reportBodyHash[:])

	attestKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Bytes() returns 0x04 || X || Y with both coordinates already padded to
	// the curve's fixed width, which is exactly the encoding parseAttestKey
	// expects once the prefix is dropped.
	attestPub, encErr := attestKey.PublicKey.Bytes()
	if encErr != nil {
		t.Fatalf("encoding attest public key: %v", encErr)
	}
	var attestPubKeyBytes [64]byte
	copy(attestPubKeyBytes[:], attestPub[1:])

	authData := []byte{}
	h := sha256.New()
	h.Write(attestPubKeyBytes[:])
	h.Write(authData)
	expectedHash := h.Sum(nil)

	var reportData [64]byte
	copy(reportData[:32], expectedHash)
	reportData[32] = 0xFF // non-zero padding

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{rawBytes: make([]byte, sgxQuoteBodySize)},
			support: &sgxQuoteSupport{
				pckCertChain:         []*x509.Certificate{cert},
				qeReportBody:         &sgxReportBody{rawBytes: rawReportBody, sgxReportDataBytes: reportData},
				qeReportSignatureDER: qeSig,
				attestPubKey:         attestPubKeyBytes,
				authData:             authData,
			},
		},
	}
	err := verifyEnclaveSignatures(evidence)
	if err == nil {
		t.Fatal("expected error for non-zero padding in QE report data")
	}
}

// --- CDS2NewHandshake: empty evidence ---

func TestCDS2NewHandshake_EmptyEvidence(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	msg := buildProtobufBytesField(1, []byte("just_pubkey"))
	_, err := CDS2NewHandshake(mrenclave, msg, time.Now())
	if err == nil {
		t.Fatal("expected error for missing evidence")
	}
}

// --- SVR2NewHandshake ---

func TestSvr2NewHandshakeWithConstants_InvalidEvidence(t *testing.T) {
	mrenclave := make([]byte, MREnclaveSize)
	config := &RaftConfig{MinVotingReplicas: 4}

	var msg []byte
	msg = append(msg, buildProtobufBytesField(2, []byte("ev"))...)
	msg = append(msg, buildProtobufBytesField(3, []byte("end"))...)

	_, err := svr2NewHandshakeWithConstants(
		mrenclave, msg, time.Now(),
		[]string{"INTEL-SA-00615"},
		config, PreQuantum,
	)
	if err == nil {
		t.Fatal("expected error for invalid evidence")
	}
}

// --- Full parseQuoteSupport with valid PEM cert ---

func TestParseQuoteSupport_ValidStructure(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	cb, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cb})

	headerSize := 64 + 64 + sgxReportBodySize + 64 + 2
	data := make([]byte, headerSize)
	certKeyType := make([]byte, 2)
	binary.LittleEndian.PutUint16(certKeyType, pckCertChainKeyType)
	data = append(data, certKeyType...)
	certDataSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(certDataSize, uint32(len(pemCert)))
	data = append(data, certDataSize...)
	data = append(data, pemCert...)

	support, consumed, err := parseQuoteSupport(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if support == nil {
		t.Fatal("support should not be nil")
	}
	if consumed == 0 {
		t.Error("consumed should be > 0")
	}
	if len(support.pckCertChain) != 1 {
		t.Errorf("pckCertChain length = %d, want 1", len(support.pckCertChain))
	}
}

// --- GetSWAdvisories ---

func TestGetSWAdvisories_Known(t *testing.T) {
	advisories := GetSWAdvisories(EnclaveIDSVR2_2025Q3Prod)
	if len(advisories) == 0 {
		t.Error("expected non-empty advisories for known mrenclave")
	}
}

func TestGetSWAdvisories_Unknown(t *testing.T) {
	advisories := GetSWAdvisories(make([]byte, 32))
	if len(advisories) != len(DefaultSWAdvisories) {
		t.Errorf("expected default advisories length %d, got %d", len(DefaultSWAdvisories), len(advisories))
	}
}

// --- ClientConnection exact one chunk boundary ---

// --- Error types ---

func TestEnclaveError_UnwrapNil(t *testing.T) {
	e := &EnclaveError{Kind: ErrAttestationData, Message: "test"}
	if e.Unwrap() != nil {
		t.Error("expected nil Unwrap for error without Err")
	}
}

func TestClientConnectionError_MessageOnly(t *testing.T) {
	e := &ClientConnectionError{Message: "custom message"}
	want := "noise error: custom message"
	if e.Error() != want {
		t.Errorf("Error() = %q, want %q", e.Error(), want)
	}
	if e.Unwrap() != nil {
		t.Error("expected nil Unwrap")
	}
}

func TestHSMError_AllKinds(t *testing.T) {
	tests := []struct {
		kind HSMErrorKind
		want string
	}{
		{ErrHSMCommunication, "error in communication"},
		{ErrHSMHandshake, "error in handshake"},
		{ErrTrustedCode, "trusted HSM process"},
		{ErrInvalidPublicKey, "invalid public key"},
		{ErrInvalidCodeHash, "invalid code hashes"},
		{ErrHSMInvalidBridgeState, "invalid bridge state"},
	}
	for _, tt := range tests {
		e := &HSMError{Kind: tt.kind}
		msg := e.Error()
		if len(msg) == 0 {
			t.Errorf("empty error message for kind %d", tt.kind)
		}
	}
}

func TestHSMError_DefaultKind(t *testing.T) {
	e := &HSMError{Kind: HSMErrorKind(99), Message: "custom"}
	if e.Error() != "custom" {
		t.Errorf("Error() = %q, want %q", e.Error(), "custom")
	}
}

func TestDcapError_WithContext(t *testing.T) {
	e := newDcapError("test error")
	_ = e.withContext("ctx1").withContext("ctx2")
	msg := e.Error()
	if len(msg) == 0 {
		t.Error("expected non-empty error message")
	}
}

func TestDcapError_NoContext(t *testing.T) {
	e := newDcapError("plain error")
	if e.Error() != "plain error" {
		t.Errorf("Error() = %q, want %q", e.Error(), "plain error")
	}
}

// --- verifyRootCertificate: non-self-signed cert ---

func TestVerifyRootCertificate_NonSelfSigned(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key2.PublicKey, key1)
	cert, _ := x509.ParseCertificate(certBytes)

	intelKey, _ := parseIntelRootKey()
	err := verifyRootCertificate(cert, intelKey)
	if err == nil {
		t.Fatal("expected error for non-self-signed cert")
	}
}

// --- verifyEnclaveSource: all mismatch paths ---

func TestVerifyEnclaveSource_VendorIDMismatch(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{qeVendorID: [16]byte{0xFF}},
			support:   &sgxQuoteSupport{qeReportBody: &sgxReportBody{}},
		},
	}
	endorsements := &sgxEndorsements{qeIdentity: &enclaveIdentity{}}
	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for vendor ID mismatch")
	}
}

func TestVerifyEnclaveSource_MRSignerMismatch(t *testing.T) {
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{qeVendorID: intelQEVendorID},
			support:   &sgxQuoteSupport{qeReportBody: &sgxReportBody{mrsigner: [32]byte{0xAA}}},
		},
	}
	endorsements := &sgxEndorsements{qeIdentity: &enclaveIdentity{mrsigner: [32]byte{0xBB}}}
	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for mrsigner mismatch")
	}
}

func TestVerifyEnclaveSource_ISVProdIDMismatch(t *testing.T) {
	var signer [32]byte
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{qeVendorID: intelQEVendorID},
			support:   &sgxQuoteSupport{qeReportBody: &sgxReportBody{mrsigner: signer, isvprodid: 1}},
		},
	}
	endorsements := &sgxEndorsements{qeIdentity: &enclaveIdentity{mrsigner: signer, isvprodid: 2}}
	err := verifyEnclaveSource(evidence, endorsements)
	if err == nil {
		t.Fatal("expected error for isvprodid mismatch")
	}
}

// --- verifyClaimsHash ---

func TestVerifyClaimsHash_NoClaims(t *testing.T) {
	evidence := &dcapEvidence{claimsRawData: nil}
	err := verifyClaimsHash(evidence)
	if err == nil {
		t.Fatal("expected error for no claims data")
	}
}

func TestVerifyClaimsHash_Valid(t *testing.T) {
	claimsData := []byte("test claims data")
	claimsHash := sha256.Sum256(claimsData)
	var reportData [64]byte
	copy(reportData[:32], claimsHash[:])
	evidence := &dcapEvidence{
		claimsRawData: claimsData,
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{reportBody: &sgxReportBody{sgxReportDataBytes: reportData}},
		},
	}
	err := verifyClaimsHash(evidence)
	if err != nil {
		t.Fatalf("expected no error for valid claims hash: %v", err)
	}
}

// --- ecdsaRawToDER: high bit and normal ---

func TestEcdsaRawToDER_ValidWithHighBit(t *testing.T) {
	raw := make([]byte, 64)
	raw[0] = 0x80
	raw[32] = 0x80
	raw[1] = 0x42
	raw[33] = 0x42
	der, err := ecdsaRawToDER(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if der[0] != 0x30 {
		t.Errorf("expected SEQUENCE tag 0x30, got %02x", der[0])
	}
}

func TestEcdsaRawToDER_ValidNormal(t *testing.T) {
	raw := make([]byte, 64)
	raw[0] = 0x01
	raw[32] = 0x01
	der, err := ecdsaRawToDER(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("DER should not be empty")
	}
}

// --- parsePEMCertChain: error paths ---

func TestParsePEMCertChain_NoCerts(t *testing.T) {
	_, err := parsePEMCertChain([]byte("not a PEM"))
	if err == nil {
		t.Fatal("expected error for no certs")
	}
}

func TestParsePEMCertChain_InvalidCert(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})
	_, err := parsePEMCertChain(block)
	if err == nil {
		t.Fatal("expected error for invalid cert DER")
	}
}

// --- parseAttestKey: off-curve point ---

func TestParseAttestKey_OffCurve(t *testing.T) {
	raw := make([]byte, 64)
	raw[0] = 0xFF
	raw[32] = 0xFF
	_, err := parseAttestKey(raw)
	if err == nil {
		t.Fatal("expected error for off-curve point")
	}
}

// --- ForSGX: input validation ---

func TestForSGX_WrongMREnclaveSize(t *testing.T) {
	_, err := ForSGX(make([]byte, 16), []byte("ev"), []byte("end"), nil, time.Now(), PreQuantum)
	if err == nil {
		t.Fatal("expected error for wrong mrenclave size")
	}
}

func TestForSGX_InvalidEvidence(t *testing.T) {
	_, err := ForSGX(make([]byte, MREnclaveSize), []byte("ev"), []byte("end"), nil, time.Now(), PreQuantum)
	if err == nil {
		t.Fatal("expected error for invalid evidence")
	}
}

// --- verifyTCBStatus ---

func TestVerifyTCBStatus_ReturnsUpToDate(t *testing.T) {
	// With no TCB info raw data, verifyTCBStatus returns UpToDate.
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
		t.Errorf("expected tcbUpToDate, got %d", standing)
	}
	if len(advisoryIDs) != 0 {
		t.Errorf("expected no advisory IDs, got %v", advisoryIDs)
	}
}

// --- parseEvidence: underflow paths ---

func TestParseEvidence_SigLengthUnderflow(t *testing.T) {
	data := make([]byte, sgxQuoteBodySize)
	binary.LittleEndian.PutUint16(data[0:2], quoteV3)
	binary.LittleEndian.PutUint16(data[2:4], ecdsaP256)
	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for missing sig length")
	}
}

func TestParseEvidence_SigDataUnderflow(t *testing.T) {
	data := make([]byte, sgxQuoteBodySize+4)
	binary.LittleEndian.PutUint16(data[0:2], quoteV3)
	binary.LittleEndian.PutUint16(data[2:4], ecdsaP256)
	binary.LittleEndian.PutUint32(data[sgxQuoteBodySize:], 0xFFFFFFFF)
	_, err := parseEvidence(data)
	if err == nil {
		t.Fatal("expected error for sig data underflow")
	}
}

// --- sgxReportBody.hasFlag ---

func TestReportBody_HasFlag_Debug(t *testing.T) {
	rb := &sgxReportBody{}
	binary.LittleEndian.PutUint64(rb.sgxAttributes[:8], sgxFlagDebug)
	if !rb.hasFlag(sgxFlagDebug) {
		t.Error("expected hasFlag(debug) to be true")
	}
}

// --- validAt: cert-based and time-based checks ---

// TestSgxEndorsements_ValidAt_EmptyIsValid was updated by Finding-1 fix:
// empty endorsements (nil CRLs) must fail validAt rather than pass silently.
// Before the fix this test asserted true; after the fix the correct assertion is false.
func TestSgxEndorsements_ValidAt_EmptyIsValid(t *testing.T) {
	e := &sgxEndorsements{}
	if e.validAt(time.Now()) {
		t.Error("validAt must return false for endorsements without CRLs (regression for Finding 1)")
	}
}

// --- Handshake: full NK round-trip ---

// --- decodeRaftGroupConfig: truncated length-delimited field ---

func TestDecodeRaftGroupConfig_TruncatedLengthDelimited(t *testing.T) {
	// Wire type 2 (length-delimited), field 10: tag = (10<<3)|2 = 0x52
	// Follow with a truncated varint (0x80 without continuation)
	data := []byte{0x52, 0x80}
	_, err := decodeRaftGroupConfig(data)
	if err == nil {
		t.Fatal("expected error for truncated length in length-delimited field")
	}
}

// --- Handshake.Complete: invalid response message ---

// --- newHandshakeWithClaims: bad public key ---

func TestNewHandshakeWithClaims_BadPublicKey(t *testing.T) {
	claims := &Claims{PublicKey: []byte{0x01}, Custom: make(map[string][]byte)}
	_, err := newHandshakeWithClaims(claims, PreQuantum)
	if err == nil {
		t.Fatal("expected error for bad public key")
	}
}

// --- VerifyRemoteAttestation: successful dcapAttest but wrong mrenclave ---

func TestVerifyRemoteAttestation_ValidEvidenceWrongMREnclave(t *testing.T) {
	// Build evidence that parses successfully. dcapAttest will fail at
	// verifyCertificates (Intel root key), so we test the wrapping.
	evidence := buildMinimalValidEvidence(t)
	versionField := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionField, oeEndorsementsV1)
	endorsements := buildEndorsementsData(t, versionField)

	var mrenclave MREnclave
	_, err := VerifyRemoteAttestation(
		evidence,
		endorsements,
		&mrenclave,
		[]string{"INTEL-SA-00615"},
		time.Now(),
	)
	if err == nil {
		t.Fatal("expected error (certificate verification should fail)")
	}
	// Verify it's wrapped as AttestationError
	_, ok := err.(*AttestationError)
	if !ok {
		t.Errorf("expected *AttestationError, got %T", err)
	}
}

// --- verifyCertificates: valid self-signed root but not Intel key ---

func TestVerifyCertificates_RootSelfSignedButNotIntelKey(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Self-signed Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootBytes)

	// Create a leaf signed by the root
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "PCK Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	evidence := &dcapEvidence{
		quote: &sgxQuote{
			support: &sgxQuoteSupport{
				pckCertChain: []*x509.Certificate{leafCert, rootCert},
			},
		},
	}
	endorsements := &sgxEndorsements{
		tcbIssuerChain:  []*x509.Certificate{leafCert, rootCert},
		qeIDIssuerChain: []*x509.Certificate{leafCert, rootCert},
	}

	err := verifyCertificates(evidence, endorsements, time.Now())
	if err == nil {
		t.Fatal("expected error for non-Intel root key")
	}
}

// --- verifyRootCertificate: not an ECDSA key ---

func TestVerifyRootCertificate_NotECDSAKey(t *testing.T) {
	// Create a self-signed cert with ECDSA key
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootBytes)

	// Verify root passes self-signed check but fails Intel key check
	intelKey, _ := parseIntelRootKey()
	err := verifyRootCertificate(rootCert, intelKey)
	if err == nil {
		t.Fatal("expected error: root key should not match Intel key")
	}
}

// --- verifyCertChain: valid chain ---

func TestVerifyCertChain_ValidChain(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	err := verifyCertChain([]*x509.Certificate{leafCert}, rootCert, time.Now())
	if err != nil {
		t.Fatalf("expected no error for valid chain: %v", err)
	}
}

// --- verifyCertChain: expired leaf ---

func TestVerifyCertChain_ExpiredLeaf(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootBytes, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootBytes)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Expired Leaf"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired
		BasicConstraintsValid: true,
	}
	leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafBytes)

	err := verifyCertChain([]*x509.Certificate{leafCert}, rootCert, time.Now())
	if err == nil {
		t.Fatal("expected error for expired leaf cert")
	}
}

// --- ClientConnection: Send error when cipher is exhausted ---

// --- UnvalidatedHandshake.Validate: mismatch raft config ---

// --- UnvalidatedHandshake.Validate: nil raft config in claims ---

// --- UnvalidatedHandshake.Validate: success with matching config ---

// --- UnvalidatedHandshake.SkipRaftValidation with claims ---

// --- HSM Complete: encrypt/decrypt round-trip after handshake ---

// --- parseIntelRootKey: verify it returns a valid key ---

func TestParseIntelRootKey_Valid(t *testing.T) {
	key, err := parseIntelRootKey()
	if err != nil {
		t.Fatalf("parseIntelRootKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}
	if key.Curve != elliptic.P256() {
		t.Error("key should be on P-256 curve")
	}
}

// --- parseAttestKey: valid key ---

func TestParseAttestKey_ValidKey(t *testing.T) {
	// Use crypto/ecdh to avoid deprecated big.Int coordinate fields.
	ecdhPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	var raw [64]byte
	// Bytes() returns 0x04 || X(32) || Y(32); strip the 0x04 prefix.
	copy(raw[:], ecdhPriv.PublicKey().Bytes()[1:])

	parsed, err := parseAttestKey(raw[:])
	if err != nil {
		t.Fatalf("parseAttestKey failed: %v", err)
	}
	parsedECDH, err := parsed.ECDH()
	if err != nil {
		t.Fatalf("parsed key is not a valid P-256 point: %v", err)
	}
	if !bytes.Equal(parsedECDH.Bytes(), ecdhPriv.PublicKey().Bytes()) {
		t.Error("parsed key does not match original")
	}
}

// --- verifyEnclaveSource: all fields match with mask ---

func TestVerifyEnclaveSource_AllMatchWithMask(t *testing.T) {
	var signer [32]byte
	signer[0] = 0xAA
	// Use a mask that only checks specific bits
	evidence := &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: &sgxQuoteBody{qeVendorID: intelQEVendorID},
			support: &sgxQuoteSupport{
				qeReportBody: &sgxReportBody{
					mrsigner:      signer,
					isvprodid:     1,
					miscselect:    0xFF34,
					sgxAttributes: [16]byte{0xAB, 0xCD},
				},
			},
		},
	}
	endorsements := &sgxEndorsements{
		qeIdentity: &enclaveIdentity{
			mrsigner:       signer,
			isvprodid:      1,
			miscselect:     0x0034,
			miscselectMask: 0x00FF, // only check low byte
			attributes:     [16]byte{0x0B, 0x0D},
			attributesMask: [16]byte{0x0F, 0x0F}, // only check low nibbles
		},
	}
	err := verifyEnclaveSource(evidence, endorsements)
	if err != nil {
		t.Fatalf("expected no error for matching with mask: %v", err)
	}
}

// buildMinimalValidEvidence builds evidence bytes that will parse successfully
// through parseEvidence (valid quote body + signature data + claims).
func buildMinimalValidEvidence(t *testing.T) []byte {
	t.Helper()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	cb, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cb})

	quoteBody := make([]byte, sgxQuoteBodySize)
	binary.LittleEndian.PutUint16(quoteBody[0:2], quoteV3)
	binary.LittleEndian.PutUint16(quoteBody[2:4], ecdsaP256)

	supportHeaderSize := 64 + 64 + sgxReportBodySize + 64 + 2
	supportData := make([]byte, supportHeaderSize)

	certKeyTypeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(certKeyTypeBytes, pckCertChainKeyType)
	supportData = append(supportData, certKeyTypeBytes...)
	certDataSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(certDataSizeBytes, uint32(len(pemCert)))
	supportData = append(supportData, certDataSizeBytes...)
	supportData = append(supportData, pemCert...)

	var claimsData []byte
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, oeClaimsV1)
	claimsData = append(claimsData, b8...)
	binary.LittleEndian.PutUint64(b8, 1)
	claimsData = append(claimsData, b8...)
	binary.LittleEndian.PutUint64(b8, 3)
	claimsData = append(claimsData, b8...)
	binary.LittleEndian.PutUint64(b8, 32)
	claimsData = append(claimsData, b8...)
	claimsData = append(claimsData, []byte("pk\x00")...)
	claimsData = append(claimsData, make([]byte, 32)...)

	var evidence []byte
	evidence = append(evidence, quoteBody...)
	sigLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLen, uint32(len(supportData)))
	evidence = append(evidence, sigLen...)
	evidence = append(evidence, supportData...)
	evidence = append(evidence, claimsData...)

	return evidence
}
