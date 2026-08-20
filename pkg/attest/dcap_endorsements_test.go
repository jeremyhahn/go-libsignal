// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestHexNibble(t *testing.T) {
	tests := []struct {
		input byte
		want  byte
		isErr bool
	}{
		{'0', 0, false},
		{'9', 9, false},
		{'a', 10, false},
		{'f', 15, false},
		{'A', 10, false},
		{'F', 15, false},
		{'g', 0, true},
		{'z', 0, true},
		{' ', 0, true},
		{'/', 0, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got, err := hexNibble(tt.input)
			if tt.isErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("hexNibble(%c) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestHexByte(t *testing.T) {
	tests := []struct {
		hi, lo byte
		want   byte
		isErr  bool
	}{
		{'f', 'f', 0xff, false},
		{'0', '0', 0x00, false},
		{'a', 'b', 0xab, false},
		{'g', '0', 0, true},
		{'0', 'g', 0, true},
	}
	for _, tt := range tests {
		t.Run(string([]byte{tt.hi, tt.lo}), func(t *testing.T) {
			got, err := hexByte(tt.hi, tt.lo)
			if tt.isErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("hexByte = 0x%02x, want 0x%02x", got, tt.want)
			}
		})
	}
}

func TestExtractHexField_HappyPath(t *testing.T) {
	json := `{"mrsigner":"aabbccdd","other":"1234"}`
	got, err := extractHexField(json, "mrsigner")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	if len(got) != len(expected) {
		t.Fatalf("len = %d, want %d", len(got), len(expected))
	}
	for i := range got {
		if got[i] != expected[i] {
			t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, got[i], expected[i])
		}
	}
}

func TestExtractHexField_FieldNotFound(t *testing.T) {
	json := `{"other":"1234"}`
	_, err := extractHexField(json, "missing")
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestExtractHexField_NonStringValue(t *testing.T) {
	json := `{"field":123}`
	_, err := extractHexField(json, "field")
	if err == nil {
		t.Fatal("expected error for non-string value")
	}
}

func TestExtractHexField_UnterminatedString(t *testing.T) {
	json := `{"field":"aabb`
	_, err := extractHexField(json, "field")
	if err == nil {
		t.Fatal("expected error for unterminated string")
	}
}

func TestExtractHexField_InvalidHexInValue(t *testing.T) {
	json := `{"field":"zzzz"}`
	_, err := extractHexField(json, "field")
	if err == nil {
		t.Fatal("expected error for invalid hex in value")
	}
}

func TestExtractHexField_EmptyValue(t *testing.T) {
	json := `{"field":""}`
	got, err := extractHexField(json, "field")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(got))
	}
}

func TestExtractHexField_WithSpaces(t *testing.T) {
	json := `{"field" : "aabb"}`
	got, err := extractHexField(json, "field")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != 0xaa || got[1] != 0xbb {
		t.Errorf("unexpected result: %x", got)
	}
}

func TestExtractUint16Field_HappyPath(t *testing.T) {
	json := `{"isvprodid":42,"other":99}`
	got := extractUint16Field(json, "isvprodid")
	if got != 42 {
		t.Errorf("extractUint16Field = %d, want 42", got)
	}
}

func TestExtractUint16Field_NotFound(t *testing.T) {
	json := `{"other":99}`
	got := extractUint16Field(json, "missing")
	if got != 0 {
		t.Errorf("extractUint16Field = %d, want 0 for missing field", got)
	}
}

func TestExtractUint16Field_Zero(t *testing.T) {
	json := `{"field":0}`
	got := extractUint16Field(json, "field")
	if got != 0 {
		t.Errorf("extractUint16Field = %d, want 0", got)
	}
}

func TestExtractUint16Field_WithSpaces(t *testing.T) {
	json := `{"field" : 123}`
	got := extractUint16Field(json, "field")
	if got != 123 {
		t.Errorf("extractUint16Field = %d, want 123", got)
	}
}

func TestToCamelCase(t *testing.T) {
	// The function currently returns the input as-is
	if got := toCamelCase("test"); got != "test" {
		t.Errorf("toCamelCase(%q) = %q, want %q", "test", got, "test")
	}
	if got := toCamelCase(""); got != "" {
		t.Errorf("toCamelCase(%q) = %q, want %q", "", got, "")
	}
}

func TestParseEnclaveIdentityJSON_HappyPath(t *testing.T) {
	json := `{
		"enclaveIdentity": {
			"id":"QE",
			"version":2,
			"mrsigner":"` + "aa" + repeat("bb", 31) + `",
			"isvprodid":5,
			"miscselect":"01000000",
			"miscselectMask":"ffffffff",
			"attributes":"` + repeat("00", 16) + `",
			"attributesMask":"` + repeat("ff", 16) + `",
			"tcbLevels":[{"tcb":{"isvsvn":3},"tcbStatus":"UpToDate"},{"tcb":{"isvsvn":1},"tcbStatus":"OutOfDate"}]
		}
	}`

	identity, err := parseEnclaveIdentityJSON([]byte(json))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.id != "QE" {
		t.Errorf("id = %q, want %q", identity.id, "QE")
	}
	if identity.version != 2 {
		t.Errorf("version = %d, want 2", identity.version)
	}
	if identity.isvprodid != 5 {
		t.Errorf("isvprodid = %d, want 5", identity.isvprodid)
	}
	if identity.mrsigner[0] != 0xaa {
		t.Errorf("mrsigner[0] = 0x%02x, want 0xaa", identity.mrsigner[0])
	}
	if len(identity.tcbLevels) != 2 {
		t.Fatalf("tcbLevels len = %d, want 2", len(identity.tcbLevels))
	}
	if identity.tcbLevels[0].isvsvn != 3 {
		t.Errorf("tcbLevels[0].isvsvn = %d, want 3", identity.tcbLevels[0].isvsvn)
	}
	if identity.tcbLevels[0].tcbStatus != "UpToDate" {
		t.Errorf("tcbLevels[0].tcbStatus = %q, want %q", identity.tcbLevels[0].tcbStatus, "UpToDate")
	}
}

func TestParseEnclaveIdentityJSON_MissingFields(t *testing.T) {
	// Missing version field means version=0, which is now rejected.
	json := `{"other":"value"}`
	_, err := parseEnclaveIdentityJSON([]byte(json))
	if err == nil {
		t.Fatal("expected error for missing version field (version 0 not accepted)")
	}
	var verErr *EnclaveIdentityVersionError
	if !errors.As(err, &verErr) {
		t.Errorf("expected EnclaveIdentityVersionError, got %T: %v", err, err)
	}
}

func TestParseEnclaveIdentityJSON_EmptyJSON(t *testing.T) {
	// Empty JSON has version=0, which is now rejected.
	_, err := parseEnclaveIdentityJSON([]byte("{}"))
	if err == nil {
		t.Fatal("expected error for empty JSON (version 0 not accepted)")
	}
	var verErr *EnclaveIdentityVersionError
	if !errors.As(err, &verErr) {
		t.Errorf("expected EnclaveIdentityVersionError, got %T: %v", err, err)
	}
}

func TestStripTrailingNull(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  int
	}{
		{"with null", []byte("abc\x00"), 3},
		{"without null", []byte("abc"), 3},
		{"empty", []byte{}, 0},
		{"only null", []byte{0x00}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripTrailingNull(tt.input)
			if len(got) != tt.want {
				t.Errorf("len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestGetFieldData(t *testing.T) {
	data := []byte("aaa_bbb_ccc")
	offsets := []int{0, 4, 8}

	// First field (idx 0)
	got := getFieldData(0, offsets, data)
	if string(got) != "aaa_" {
		t.Errorf("field 0 = %q, want %q", got, "aaa_")
	}

	// Middle field (idx 1)
	got = getFieldData(1, offsets, data)
	if string(got) != "bbb_" {
		t.Errorf("field 1 = %q, want %q", got, "bbb_")
	}

	// Last field (idx 2, last offset)
	got = getFieldData(2, offsets, data)
	if string(got) != "ccc" {
		t.Errorf("field 2 = %q, want %q", got, "ccc")
	}
}

func TestValidateOffsets_HappyPath(t *testing.T) {
	offsets := make([]int, sgxEndorsementFieldCount)
	for i := range offsets {
		offsets[i] = i * 10
	}
	data := make([]byte, offsets[len(offsets)-1]+10) // enough data
	if err := validateOffsets(offsets, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOffsets_TooFewFields(t *testing.T) {
	offsets := []int{0, 10}
	data := make([]byte, 100)
	if err := validateOffsets(offsets, data); err == nil {
		t.Fatal("expected error for too few fields")
	}
}

func TestValidateOffsets_DataTooShort(t *testing.T) {
	offsets := make([]int, sgxEndorsementFieldCount)
	for i := range offsets {
		offsets[i] = i * 10
	}
	data := make([]byte, 5) // too short
	if err := validateOffsets(offsets, data); err == nil {
		t.Fatal("expected error for data too short")
	}
}

func TestValidateOffsets_NotStrictlyIncreasing(t *testing.T) {
	offsets := make([]int, sgxEndorsementFieldCount)
	for i := range offsets {
		offsets[i] = 0 // all same
	}
	data := make([]byte, 100)
	if err := validateOffsets(offsets, data); err == nil {
		t.Fatal("expected error for non-increasing offsets")
	}
}

func TestSgxEndorsements_ValidAt(t *testing.T) {
	now := time.Now()
	certKey, validCert := generateTestCertAndKey(t)
	validCRLBytes := generateTestCRL(t, validCert, certKey)
	validCRL, err := x509.ParseRevocationList(validCRLBytes)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}

	// Finding-1 fix: nil CRLs must cause validAt to return false (fail-closed),
	// not silently pass.  An attacker who strips CRL fields gets endorsements with
	// nil pckCertCRL / pckProcCACRL; validAt must reject them.
	t.Run("nil CRLs fail closed", func(t *testing.T) {
		e := &sgxEndorsements{}
		if e.validAt(now) {
			t.Error("validAt must return false when CRLs are missing (regression for Finding 1)")
		}
	})

	t.Run("valid certs and CRLs within window", func(t *testing.T) {
		e := &sgxEndorsements{
			tcbIssuerChain: []*x509.Certificate{validCert},
			pckCertCRL:     validCRL,
			pckProcCACRL:   validCRL,
		}
		if !e.validAt(now) {
			t.Error("validAt should return true with valid cert and valid CRLs")
		}
	})

	t.Run("expired cert", func(t *testing.T) {
		e := &sgxEndorsements{
			tcbIssuerChain: []*x509.Certificate{validCert},
			pckCertCRL:     validCRL,
			pckProcCACRL:   validCRL,
		}
		futureTime := now.Add(24 * time.Hour)
		if e.validAt(futureTime) {
			t.Error("validAt should return false for time past cert expiry")
		}
	})

	t.Run("tcb info expired", func(t *testing.T) {
		// No CRLs — validAt returns false due to nil CRL before reaching the
		// tcbInfoNextUpdate check.  The expected result (false) is unchanged.
		e := &sgxEndorsements{
			tcbInfoNextUpdate: now.Add(-time.Hour),
		}
		if e.validAt(now) {
			t.Error("validAt should return false when tcb info is past nextUpdate (or CRLs missing)")
		}
	})

	t.Run("qe identity expired", func(t *testing.T) {
		e := &sgxEndorsements{
			qeIDNextUpdate: now.Add(-time.Hour),
		}
		if e.validAt(now) {
			t.Error("validAt should return false when qe identity is past nextUpdate (or CRLs missing)")
		}
	})

	t.Run("tcb info not expired with valid CRLs", func(t *testing.T) {
		e := &sgxEndorsements{
			tcbInfoNextUpdate: now.Add(time.Hour),
			qeIDNextUpdate:    now.Add(time.Hour),
			pckCertCRL:        validCRL,
			pckProcCACRL:      validCRL,
		}
		if !e.validAt(now) {
			t.Error("validAt should return true when within validity period and CRLs present")
		}
	})
}

func TestExtractTimeField(t *testing.T) {
	t.Run("RFC3339", func(t *testing.T) {
		json := `{"nextUpdate":"2024-06-15T12:00:00Z"}`
		got := extractTimeField(json, "nextUpdate")
		if got.IsZero() {
			t.Fatal("expected non-zero time")
		}
		if got.Year() != 2024 || got.Month() != 6 || got.Day() != 15 {
			t.Errorf("unexpected time: %v", got)
		}
	})

	t.Run("not found", func(t *testing.T) {
		got := extractTimeField(`{"other":"value"}`, "nextUpdate")
		if !got.IsZero() {
			t.Errorf("expected zero time, got %v", got)
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		got := extractTimeField(`{"nextUpdate":"not-a-date"}`, "nextUpdate")
		if !got.IsZero() {
			t.Errorf("expected zero time for invalid format, got %v", got)
		}
	})

	t.Run("non-string value", func(t *testing.T) {
		got := extractTimeField(`{"nextUpdate":12345}`, "nextUpdate")
		if !got.IsZero() {
			t.Errorf("expected zero time for non-string, got %v", got)
		}
	})
}

func TestParseEndorsements_TooShort(t *testing.T) {
	_, err := parseEndorsements(make([]byte, 8))
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestParseEndorsements_WrongHeaderVersion(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], 99) // bad header version
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for wrong header version")
	}
}

func TestParseEndorsements_WrongEnclaveType(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], 1) // correct header version
	binary.LittleEndian.PutUint32(data[4:8], 1) // wrong enclave type (want 2)
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for wrong enclave type")
	}
}

func TestParseEndorsements_TooFewElements(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], 1)   // header version
	binary.LittleEndian.PutUint32(data[4:8], 2)   // enclave type
	binary.LittleEndian.PutUint32(data[8:12], 0)  // buffer size
	binary.LittleEndian.PutUint32(data[12:16], 2) // num elements < 9
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for too few elements")
	}
}

func TestParseEndorsements_NotEnoughDataForOffsets(t *testing.T) {
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[0:4], 1)
	binary.LittleEndian.PutUint32(data[4:8], 2)
	binary.LittleEndian.PutUint32(data[8:12], 0)
	binary.LittleEndian.PutUint32(data[12:16], uint32(sgxEndorsementFieldCount))
	// Only 4 more bytes, need 9*4=36
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for not enough data for offsets")
	}
}

func TestParseEndorsements_InvalidVersionField(t *testing.T) {
	// Build a valid header + offsets + field data but with invalid endorsement version
	data := buildEndorsementsData(t, []byte{0x02, 0x00, 0x00, 0x00}) // version=2, not 1
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for invalid endorsement version")
	}
}

func TestParseEndorsements_VersionFieldWrongSize(t *testing.T) {
	// Build with a version field that's too short (2 bytes instead of 4)
	data := buildEndorsementsDataRaw(t, []byte{0x01, 0x00})
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for version field wrong size")
	}
}

func TestParseEndorsements_InvalidOffsetsOrder(t *testing.T) {
	// Build header with offsets that are not strictly increasing
	numElements := uint32(sgxEndorsementFieldCount)
	headerSize := 16 + int(numElements)*4
	data := make([]byte, headerSize+100)
	binary.LittleEndian.PutUint32(data[0:4], 1)  // header version
	binary.LittleEndian.PutUint32(data[4:8], 2)  // enclave type
	binary.LittleEndian.PutUint32(data[8:12], 0) // buffer size
	binary.LittleEndian.PutUint32(data[12:16], numElements)

	// Set all offsets to 0 (not strictly increasing)
	for i := 0; i < int(numElements); i++ {
		binary.LittleEndian.PutUint32(data[16+i*4:], 0)
	}
	_, err := parseEndorsements(data)
	if err == nil {
		t.Fatal("expected error for non-increasing offsets")
	}
}

// buildEndorsementsData constructs endorsements binary data with a given version field value.
func buildEndorsementsData(t *testing.T, versionFieldBytes []byte) []byte {
	t.Helper()

	// We need 9 fields. Build simple field data.
	key, cert := generateTestCertAndKey(t)
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// Generate valid empty CRLs signed by the test cert.
	//
	// The endorsements buffer stores each CRL as a NUL-terminated field, and
	// parseEndorsements strips that terminator with stripTrailingNull before
	// parsing. The terminator therefore has to be here: without it, a DER CRL
	// whose final byte is 0x00 -- roughly 1 in 256, since the last byte is the
	// tail of a randomised ECDSA signature -- loses a real byte to the strip
	// and fails to parse. That made these tests flaky at about 1 in 500,
	// independent of FIPS mode.
	crlPCK := append(generateTestCRL(t, cert, key), 0x00)
	crlProcCA := append(generateTestCRL(t, cert, key), 0x00)

	// Build a properly signed QE identity JSON
	qeJSON := buildSignedQEIdentityJSON(t, key)

	// Build a properly signed TCB info JSON
	tcbJSON := buildSignedTCBInfoJSON(t, key)

	fields := make([][]byte, sgxEndorsementFieldCount)
	fields[0] = versionFieldBytes              // version
	fields[1] = tcbJSON                        // TCB info (signed)
	fields[2] = pemCert                        // TCB issuer chain
	fields[3] = crlPCK                         // CRL PCK cert (DER)
	fields[4] = crlProcCA                      // CRL PCK proc CA (DER)
	fields[5] = pemCert                        // PCK CRL issuer chain
	fields[6] = qeJSON                         // QE ID info (signed)
	fields[7] = pemCert                        // QE ID issuer chain
	fields[8] = []byte("2024-01-01T00:00:00Z") // creation datetime

	return buildEndorsementsFromFields(fields)
}

func generateTestCertAndKey(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
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
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, cert
}

func generateTestCRL(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	// parseCRL now requires AKI and CRL Number extensions (matches Rust reference).
	// Use the issuer's SubjectKeyId for AKI; fall back to a minimal test value.
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

func generateTestCRLWithRevoked(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, revokedSerial *big.Int) []byte {
	t.Helper()
	// parseCRL now requires AKI and CRL Number extensions (matches Rust reference).
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
				SerialNumber:   revokedSerial,
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

func buildSignedQEIdentityJSON(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	inner := `{"id":"QE","version":2,"mrsigner":"` + repeat("aa", 32) + `","isvprodid":0,"miscselect":"00000000","miscselectMask":"ffffffff","attributes":"` + repeat("00", 16) + `","attributesMask":"` + repeat("ff", 16) + `","tcbLevels":[{"tcb":{"isvsvn":0},"tcbStatus":"UpToDate"}]}`

	sig := signContent(t, key, []byte(inner))
	return []byte(fmt.Sprintf(`{"enclaveIdentity":%s,"signature":"%s"}`, inner, sig))
}

func buildSignedTCBInfoJSON(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	inner := `{"version":2,"tcbType":0,"fmspc":"000000000000","pceId":"0000","tcbLevels":[],"nextUpdate":"2030-01-01T00:00:00Z"}`

	sig := signContent(t, key, []byte(inner))
	return []byte(fmt.Sprintf(`{"tcbInfo":%s,"signature":"%s"}`, inner, sig))
}

func signContent(t *testing.T, key *ecdsa.PrivateKey, content []byte) string {
	t.Helper()
	hash := sha256.Sum256(content)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("sign content: %v", err)
	}
	// Produce raw r||s 64-byte signature
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	return hex.EncodeToString(sigBytes)
}

// buildEndorsementsDataRaw constructs endorsements with a raw version field (for testing invalid sizes).
func buildEndorsementsDataRaw(t *testing.T, versionFieldBytes []byte) []byte {
	t.Helper()
	return buildEndorsementsData(t, versionFieldBytes)
}

func buildEndorsementsFromFields(fields [][]byte) []byte {
	numElements := uint32(len(fields))

	// Calculate offsets
	var fieldData []byte
	offsets := make([]int, numElements)
	for i, f := range fields {
		offsets[i] = len(fieldData)
		fieldData = append(fieldData, f...)
	}

	// Build header
	var data []byte
	h := make([]byte, 4)
	binary.LittleEndian.PutUint32(h, 1) // header version
	data = append(data, h...)
	binary.LittleEndian.PutUint32(h, 2) // enclave type
	data = append(data, h...)
	binary.LittleEndian.PutUint32(h, uint32(len(fieldData))) // buffer size
	data = append(data, h...)
	binary.LittleEndian.PutUint32(h, numElements) // num elements
	data = append(data, h...)

	// Write offsets
	for _, off := range offsets {
		binary.LittleEndian.PutUint32(h, uint32(off))
		data = append(data, h...)
	}

	// Write field data
	data = append(data, fieldData...)

	return data
}

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	_, cert := generateTestCertAndKey(t)
	return cert
}

func TestParseEndorsements_ValidStructure(t *testing.T) {
	versionField := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionField, oeEndorsementsV1)
	data := buildEndorsementsData(t, versionField)

	endorsements, err := parseEndorsements(data)
	if err != nil {
		t.Fatalf("parseEndorsements failed: %v", err)
	}
	if endorsements == nil {
		t.Fatal("endorsements should not be nil")
	}
	if endorsements.version != oeEndorsementsV1 {
		t.Errorf("version = %d, want %d", endorsements.version, oeEndorsementsV1)
	}
	if len(endorsements.tcbIssuerChain) == 0 {
		t.Error("tcbIssuerChain should not be empty")
	}
	if len(endorsements.qeIDIssuerChain) == 0 {
		t.Error("qeIDIssuerChain should not be empty")
	}
	if endorsements.qeIdentity == nil {
		t.Error("qeIdentity should not be nil")
	}
}

// repeat returns a hex string with the pattern repeated n times.
func repeat(pattern string, n int) string {
	var s string
	for i := 0; i < n; i++ {
		s += pattern
	}
	return s
}

// --- AT-C4: Signature verification tests ---

func TestVerifySignedJSON_HappyPath(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// We need a cert with the matching key (generateTestCertAndKey produces a
	// mismatched key, so we construct a cert using the key generated above).
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	inner := `{"field":"value"}`
	sig := signContent(t, key, []byte(inner))
	data := []byte(fmt.Sprintf(`{"tcbInfo":%s,"signature":"%s"}`, inner, sig))

	if err := verifySignedJSON(data, cert, "tcbInfo"); err != nil {
		t.Fatalf("verifySignedJSON failed: %v", err)
	}
}

func TestVerifySignedJSON_InvalidSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	// Use a bad signature (64 zero bytes)
	badSig := hex.EncodeToString(make([]byte, 64))
	data := []byte(fmt.Sprintf(`{"tcbInfo":{"field":"value"},"signature":"%s"}`, badSig))

	err := verifySignedJSON(data, cert, "tcbInfo")
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	var sigErr *EndorsementSignatureError
	if !errors.As(err, &sigErr) {
		t.Errorf("expected EndorsementSignatureError, got %T", err)
	}
}

func TestVerifySignedJSON_MissingSignature(t *testing.T) {
	cert := generateTestCert(t)
	data := []byte(`{"tcbInfo":{"field":"value"}}`)

	err := verifySignedJSON(data, cert, "tcbInfo")
	if err == nil {
		t.Fatal("expected error for missing signature")
	}
	var sigErr *EndorsementSignatureError
	if !errors.As(err, &sigErr) {
		t.Errorf("expected EndorsementSignatureError, got %T", err)
	}
}

func TestVerifySignedJSON_MissingContentField(t *testing.T) {
	cert := generateTestCert(t)
	data := []byte(`{"signature":"aabb"}`)

	err := verifySignedJSON(data, cert, "tcbInfo")
	if err == nil {
		t.Fatal("expected error for missing content field")
	}
}

// TestVerifySignedJSON_DERSignature exercises the DER-encoded signature branch
// of verifySignedJSON (the fallback taken when the signature is not raw 64-byte
// r||s). ecdsa.SignASN1 produces a ~70-byte DER signature that the function
// verifies via ecdsa.VerifyASN1 directly.
func TestVerifySignedJSON_DERSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	inner := `{"field":"value"}`
	hash := sha256.Sum256([]byte(inner))
	derSig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	if len(derSig) == 64 {
		t.Fatalf("DER signature unexpectedly 64 bytes; cannot exercise DER branch")
	}
	data := []byte(fmt.Sprintf(`{"tcbInfo":%s,"signature":"%s"}`, inner, hex.EncodeToString(derSig)))

	if err := verifySignedJSON(data, cert, "tcbInfo"); err != nil {
		t.Fatalf("verifySignedJSON with DER signature: %v", err)
	}
}

// TestVerifySignedJSON_DERSignature_BadSig exercises the DER verification
// failure branch: a syntactically valid but cryptographically wrong DER
// signature must return an EndorsementSignatureError.
func TestVerifySignedJSON_DERSignature_BadSig(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certBytes)

	// DER signature over different content -> verification fails.
	wrongHash := sha256.Sum256([]byte("not the signed content"))
	derSig, _ := ecdsa.SignASN1(rand.Reader, key, wrongHash[:])
	data := []byte(fmt.Sprintf(`{"tcbInfo":{"field":"value"},"signature":"%s"}`, hex.EncodeToString(derSig)))

	err := verifySignedJSON(data, cert, "tcbInfo")
	if err == nil {
		t.Fatal("expected verification failure for wrong DER signature")
	}
	var sigErr *EndorsementSignatureError
	if !errors.As(err, &sigErr) {
		t.Errorf("expected EndorsementSignatureError, got %T", err)
	}
}

// --- AT-C1: CRL verification tests ---

// TestParseCRL_EmptyData verifies the Finding-1 fix: empty CRL data must be
// rejected with a typed error rather than silently returning (nil, nil).
// Before the fix parseCRL returned nil, nil for empty input, which let an
// attacker strip CRL fields and bypass all revocation checks.
func TestParseCRL_EmptyData(t *testing.T) {
	_, err := parseCRL(nil)
	if err == nil {
		t.Fatal("parseCRL must reject nil/empty data (regression for Finding 1: CRL stripping attack)")
	}
	var missingErr *CRLMissingError
	if !errors.As(err, &missingErr) {
		t.Errorf("expected CRLMissingError, got %T: %v", err, err)
	}
}

// TestParseCRL_EmptySliceRejected verifies that an explicitly empty byte slice
// is also rejected (same path as nil, regression for Finding 1).
func TestParseCRL_EmptySliceRejected(t *testing.T) {
	_, err := parseCRL([]byte{})
	if err == nil {
		t.Fatal("parseCRL must reject empty byte slice")
	}
	var missingErr *CRLMissingError
	if !errors.As(err, &missingErr) {
		t.Errorf("expected CRLMissingError, got %T: %v", err, err)
	}
}

func TestParseCRL_InvalidData(t *testing.T) {
	_, err := parseCRL([]byte("not a CRL"))
	if err == nil {
		t.Fatal("expected error for invalid CRL data")
	}
}

func TestParseCRL_ValidCRL(t *testing.T) {
	key, cert := generateTestCertAndKey(t)
	crlBytes := generateTestCRL(t, cert, key)
	crl, err := parseCRL(crlBytes)
	if err != nil {
		t.Fatalf("parseCRL failed: %v", err)
	}
	if crl == nil {
		t.Fatal("CRL should not be nil")
	}
}

func TestVerifyCRLSignature_HappyPath(t *testing.T) {
	key, cert := generateTestCertAndKey(t)
	crlBytes := generateTestCRL(t, cert, key)
	crl, _ := parseCRL(crlBytes)

	if err := verifyCRLSignature(crl, cert); err != nil {
		t.Fatalf("verifyCRLSignature failed: %v", err)
	}
}

func TestVerifyCRLSignature_WrongIssuer(t *testing.T) {
	key1, cert1 := generateTestCertAndKey(t)
	_, cert2 := generateTestCertAndKey(t)
	crlBytes := generateTestCRL(t, cert1, key1)
	crl, _ := parseCRL(crlBytes)

	err := verifyCRLSignature(crl, cert2)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
	var crlErr *CRLSignatureError
	if !errors.As(err, &crlErr) {
		t.Errorf("expected CRLSignatureError, got %T", err)
	}
}

func TestVerifyCRLSignature_NilCRL(t *testing.T) {
	cert := generateTestCert(t)
	if err := verifyCRLSignature(nil, cert); err != nil {
		t.Fatalf("unexpected error for nil CRL: %v", err)
	}
}

func TestCheckCertAgainstCRL_NotRevoked(t *testing.T) {
	key, issuer := generateTestCertAndKey(t)
	crlBytes := generateTestCRL(t, issuer, key)
	crl, _ := parseCRL(crlBytes)

	cert := generateTestCert(t) // different serial
	if err := checkCertAgainstCRL(cert, crl); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckCertAgainstCRL_Revoked(t *testing.T) {
	key, issuer := generateTestCertAndKey(t)
	target := generateTestCert(t)
	crlBytes := generateTestCRLWithRevoked(t, issuer, key, target.SerialNumber)
	crl, _ := parseCRL(crlBytes)

	err := checkCertAgainstCRL(target, crl)
	if err == nil {
		t.Fatal("expected error for revoked certificate")
	}
	var revErr *CRLVerificationError
	if !errors.As(err, &revErr) {
		t.Errorf("expected CRLVerificationError, got %T", err)
	}
}

func TestCheckCertAgainstCRL_NilInputs(t *testing.T) {
	if err := checkCertAgainstCRL(nil, nil); err != nil {
		t.Fatalf("unexpected error for nil inputs: %v", err)
	}
}

// --- AT-C3: Enclave identity type tests ---

func TestParseEnclaveIdentityJSON_CorrectType(t *testing.T) {
	json := `{"id":"QE","version":2,"mrsigner":"` + repeat("aa", 32) + `","isvprodid":0}`
	identity, err := parseEnclaveIdentityJSON([]byte(json))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.id != "QE" {
		t.Errorf("id = %q, want %q", identity.id, "QE")
	}
}

func TestParseEnclaveIdentityJSON_WrongType(t *testing.T) {
	// Wrong type is not rejected at parse time; it is rejected in verifyEnclaveSource.
	// But version != 2 is rejected at parse time.
	json := `{"id":"TDX","version":2,"mrsigner":"` + repeat("aa", 32) + `","isvprodid":0}`
	identity, err := parseEnclaveIdentityJSON([]byte(json))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.id != "TDX" {
		t.Errorf("id = %q, want %q", identity.id, "TDX")
	}
}

// --- AT-W1: Enclave identity version tests ---

func TestParseEnclaveIdentityJSON_ValidVersion(t *testing.T) {
	json := `{"id":"QE","version":2,"mrsigner":"` + repeat("aa", 32) + `"}`
	identity, err := parseEnclaveIdentityJSON([]byte(json))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.version != 2 {
		t.Errorf("version = %d, want 2", identity.version)
	}
}

func TestParseEnclaveIdentityJSON_InvalidVersion(t *testing.T) {
	json := `{"id":"QE","version":3,"mrsigner":"` + repeat("aa", 32) + `"}`
	_, err := parseEnclaveIdentityJSON([]byte(json))
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
	var verErr *EnclaveIdentityVersionError
	if !errors.As(err, &verErr) {
		t.Errorf("expected EnclaveIdentityVersionError, got %T", err)
	}
}

// --- AT-C2: QE TCB status tests ---

func TestEnclaveIdentity_TCBStatusForISVSVN_HappyPath(t *testing.T) {
	identity := &enclaveIdentity{
		tcbLevels: []qeTcbLevel{
			{isvsvn: 5, tcbStatus: "UpToDate"},
			{isvsvn: 3, tcbStatus: "SWHardeningNeeded"},
			{isvsvn: 1, tcbStatus: "OutOfDate"},
		},
	}

	status, err := identity.tcbStatusForISVSVN(5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "UpToDate" {
		t.Errorf("status = %q, want %q", status, "UpToDate")
	}

	status, err = identity.tcbStatusForISVSVN(4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != "SWHardeningNeeded" {
		t.Errorf("status = %q, want %q", status, "SWHardeningNeeded")
	}
}

func TestEnclaveIdentity_TCBStatusForISVSVN_NotFound(t *testing.T) {
	identity := &enclaveIdentity{
		tcbLevels: []qeTcbLevel{
			{isvsvn: 5, tcbStatus: "UpToDate"},
		},
	}

	_, err := identity.tcbStatusForISVSVN(2)
	if err == nil {
		t.Fatal("expected error for no matching TCB level")
	}
	var notFound *QETCBLevelNotFoundError
	if !errors.As(err, &notFound) {
		t.Errorf("expected QETCBLevelNotFoundError, got %T", err)
	}
}

// --- AT-W2: tcbType validation tests ---

func TestValidateTCBType_Valid(t *testing.T) {
	json := `{"tcbType":0,"fmspc":"000000000000"}`
	if err := validateTCBType(json); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTCBType_Invalid(t *testing.T) {
	json := `{"tcbType":1,"fmspc":"000000000000"}`
	err := validateTCBType(json)
	if err == nil {
		t.Fatal("expected error for invalid tcbType")
	}
	var tcbErr *TCBTypeError
	if !errors.As(err, &tcbErr) {
		t.Errorf("expected TCBTypeError, got %T", err)
	}
}

func TestValidateTCBType_FieldNotPresent(t *testing.T) {
	json := `{"fmspc":"000000000000"}`
	if err := validateTCBType(json); err != nil {
		t.Fatalf("unexpected error when tcbType not present: %v", err)
	}
}

// --- QE TCB level parsing tests ---

func TestParseQETcbLevels_HappyPath(t *testing.T) {
	json := `{"tcbLevels":[{"tcb":{"isvsvn":5},"tcbStatus":"UpToDate"},{"tcb":{"isvsvn":3},"tcbStatus":"OutOfDate"}]}`
	levels := parseQETcbLevels(json)
	if len(levels) != 2 {
		t.Fatalf("expected 2 levels, got %d", len(levels))
	}
	if levels[0].isvsvn != 5 {
		t.Errorf("levels[0].isvsvn = %d, want 5", levels[0].isvsvn)
	}
	if levels[0].tcbStatus != "UpToDate" {
		t.Errorf("levels[0].tcbStatus = %q, want %q", levels[0].tcbStatus, "UpToDate")
	}
	if levels[1].isvsvn != 3 {
		t.Errorf("levels[1].isvsvn = %d, want 3", levels[1].isvsvn)
	}
}

func TestParseQETcbLevels_Empty(t *testing.T) {
	json := `{"other":"value"}`
	levels := parseQETcbLevels(json)
	if len(levels) != 0 {
		t.Errorf("expected 0 levels, got %d", len(levels))
	}
}

// --- extractRawJSONValue tests ---

func TestExtractRawJSONValue_Object(t *testing.T) {
	json := `{"tcbInfo":{"field":"value"},"signature":"abc"}`
	got := extractRawJSONValue(json, "tcbInfo")
	if got != `{"field":"value"}` {
		t.Errorf("got %q, want %q", got, `{"field":"value"}`)
	}
}

func TestExtractRawJSONValue_String(t *testing.T) {
	json := `{"signature":"abc123"}`
	got := extractRawJSONValue(json, "signature")
	if got != `"abc123"` {
		t.Errorf("got %q, want %q", got, `"abc123"`)
	}
}

func TestExtractRawJSONValue_Missing(t *testing.T) {
	json := `{"other":"value"}`
	got := extractRawJSONValue(json, "missing")
	if got != "" {
		t.Errorf("expected empty string for missing field, got %q", got)
	}
}

// --- Endorsements with CRL data ---

func TestParseEndorsements_WithCRLs(t *testing.T) {
	versionField := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionField, oeEndorsementsV1)
	data := buildEndorsementsData(t, versionField)

	endorsements, err := parseEndorsements(data)
	if err != nil {
		t.Fatalf("parseEndorsements failed: %v", err)
	}
	if endorsements.pckCertCRL == nil {
		t.Error("pckCertCRL should not be nil")
	}
	if endorsements.pckProcCACRL == nil {
		t.Error("pckProcCACRL should not be nil")
	}
}

func TestParseEndorsements_WithQEIdentityFields(t *testing.T) {
	versionField := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionField, oeEndorsementsV1)
	data := buildEndorsementsData(t, versionField)

	endorsements, err := parseEndorsements(data)
	if err != nil {
		t.Fatalf("parseEndorsements failed: %v", err)
	}
	if endorsements.qeIdentity.id != "QE" {
		t.Errorf("qeIdentity.id = %q, want %q", endorsements.qeIdentity.id, "QE")
	}
	if endorsements.qeIdentity.version != 2 {
		t.Errorf("qeIdentity.version = %d, want 2", endorsements.qeIdentity.version)
	}
}
