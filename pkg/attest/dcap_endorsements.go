// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	// oeEndorsementsV1 is the version of the OE endorsements we support.
	oeEndorsementsV1 uint32 = 1

	// sgxEndorsementFieldCount is the number of fields in the endorsement structure.
	sgxEndorsementFieldCount = 9
)

// sgxEndorsementField identifies fields in the endorsement structure.
type sgxEndorsementField int

const (
	fieldVersion           sgxEndorsementField = 0
	fieldTCBInfo           sgxEndorsementField = 1
	fieldTCBIssuerChain    sgxEndorsementField = 2
	fieldCRLPCKCert        sgxEndorsementField = 3
	fieldCRLPCKProcCA      sgxEndorsementField = 4
	fieldPCKCRLIssuerChain sgxEndorsementField = 5
	fieldQEIDInfo          sgxEndorsementField = 6
	fieldQEIDIssuerChain   sgxEndorsementField = 7
	fieldCreationDatetime  sgxEndorsementField = 8
)

// sgxEndorsements contains data to verify DCAP Evidence.
type sgxEndorsements struct {
	version           uint32
	tcbIssuerChain    []*x509.Certificate
	pckIssuerCRLChain []*x509.Certificate
	qeIDIssuerChain   []*x509.Certificate
	qeIdentity        *enclaveIdentity
	tcbInfoNextUpdate time.Time
	qeIDNextUpdate    time.Time
	tcbInfoRaw        []byte
	pckCertCRL        *x509.RevocationList
	pckProcCACRL      *x509.RevocationList
}

// enclaveIdentity represents the QE identity information.
type enclaveIdentity struct {
	id             string
	version        int
	mrsigner       [32]byte
	isvprodid      uint16
	miscselect     uint32
	miscselectMask uint32
	attributes     [16]byte
	attributesMask [16]byte
	tcbLevels      []qeTcbLevel
}

// qeTcbLevel represents a single TCB level from the QE identity.
type qeTcbLevel struct {
	isvsvn    uint16
	tcbStatus string
}

// tcbStatus returns the TCB status for the given ISVSVN.
// It finds the first level where the given ISVSVN >= the level's ISVSVN.
func (e *enclaveIdentity) tcbStatusForISVSVN(isvsvn uint16) (string, error) {
	for _, level := range e.tcbLevels {
		if isvsvn >= level.isvsvn {
			return level.tcbStatus, nil
		}
	}
	return "", &QETCBLevelNotFoundError{ISVSVN: isvsvn}
}

func (e *sgxEndorsements) validAt(t time.Time) bool {
	// Check certificate chain validity periods.
	for _, chain := range [][]*x509.Certificate{
		e.tcbIssuerChain,
		e.pckIssuerCRLChain,
		e.qeIDIssuerChain,
	} {
		for _, cert := range chain {
			if t.Before(cert.NotBefore) || t.After(cert.NotAfter) {
				return false
			}
		}
	}

	// Check PCK issuer CRL validity.
	// A nil CRL means endorsements were stripped; fail closed rather than skip.
	if e.pckCertCRL == nil || t.Before(e.pckCertCRL.ThisUpdate) || t.After(e.pckCertCRL.NextUpdate) {
		return false
	}

	// Check root CRL validity.
	// A nil CRL means endorsements were stripped; fail closed rather than skip.
	if e.pckProcCACRL == nil || t.Before(e.pckProcCACRL.ThisUpdate) || t.After(e.pckProcCACRL.NextUpdate) {
		return false
	}

	// Check TCB info nextUpdate if set.
	if !e.tcbInfoNextUpdate.IsZero() && t.After(e.tcbInfoNextUpdate) {
		return false
	}

	// Check QE identity nextUpdate if set.
	if !e.qeIDNextUpdate.IsZero() && t.After(e.qeIDNextUpdate) {
		return false
	}

	return true
}

// parseEndorsements parses DCAP endorsement bytes.
func parseEndorsements(data []byte) (*sgxEndorsements, error) {
	if len(data) < 16 {
		return nil, &EndorsementParseError{Detail: "endorsements too short"}
	}

	// Parse header: version(4) + enclave_type(4) + buffer_size(4) + num_elements(4)
	headerVersion := binary.LittleEndian.Uint32(data[0:4])
	if headerVersion != 1 {
		return nil, &EndorsementParseError{Detail: fmt.Sprintf("unsupported endorsements header version: %d", headerVersion)}
	}

	enclaveType := binary.LittleEndian.Uint32(data[4:8])
	if enclaveType != 2 {
		return nil, &EndorsementParseError{Detail: fmt.Sprintf("unsupported enclave type: %d", enclaveType)}
	}

	_ = binary.LittleEndian.Uint32(data[8:12]) // buffer_size
	numElements := binary.LittleEndian.Uint32(data[12:16])

	offset := 16

	// Read offsets
	if int(numElements) < sgxEndorsementFieldCount {
		return nil, &EndorsementParseError{Detail: fmt.Sprintf("too few endorsement fields: %d", numElements)}
	}

	offsetsSize := int(numElements) * 4
	if offset+offsetsSize > len(data) {
		return nil, &EndorsementParseError{Detail: "not enough data for offsets"}
	}

	offsets := make([]int, numElements)
	for i := uint32(0); i < numElements; i++ {
		offsets[i] = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
	}

	fieldData := data[offset:]

	// Validate offsets
	if err := validateOffsets(offsets, fieldData); err != nil {
		return nil, err
	}

	// Parse version field
	versionBytes := getFieldData(fieldVersion, offsets, fieldData)
	if len(versionBytes) != 4 {
		return nil, &EndorsementParseError{Detail: "invalid endorsement version field"}
	}
	version := binary.LittleEndian.Uint32(versionBytes)
	if version != oeEndorsementsV1 {
		return nil, &EndorsementParseError{Detail: fmt.Sprintf("unsupported SGX endorsement version: %d", version)}
	}

	// Parse TCB issuer chain
	tcbIssuerChainData := getFieldData(fieldTCBIssuerChain, offsets, fieldData)
	tcbIssuerChainData = stripTrailingNull(tcbIssuerChainData)
	tcbIssuerChain, err := parsePEMCertChain(tcbIssuerChainData)
	if err != nil {
		return nil, &EndorsementParseError{Detail: "TCB issuer chain", Err: err}
	}

	// Parse PCK CRL issuer chain
	pckCRLIssuerChainData := getFieldData(fieldPCKCRLIssuerChain, offsets, fieldData)
	pckCRLIssuerChainData = stripTrailingNull(pckCRLIssuerChainData)
	pckCRLIssuerChain, err := parsePEMCertChain(pckCRLIssuerChainData)
	if err != nil {
		return nil, &EndorsementParseError{Detail: "PCK CRL issuer chain", Err: err}
	}

	// Parse QE ID issuer chain
	qeIDIssuerChainData := getFieldData(fieldQEIDIssuerChain, offsets, fieldData)
	qeIDIssuerChainData = stripTrailingNull(qeIDIssuerChainData)
	qeIDIssuerChain, err := parsePEMCertChain(qeIDIssuerChainData)
	if err != nil {
		return nil, &EndorsementParseError{Detail: "QE ID issuer chain", Err: err}
	}

	// Parse CRL data (AT-C1)
	crlPCKCertData := getFieldData(fieldCRLPCKCert, offsets, fieldData)
	crlPCKCertData = stripTrailingNull(crlPCKCertData)
	pckCertCRL, err := parseCRL(crlPCKCertData)
	if err != nil {
		return nil, &EndorsementParseError{Detail: "PCK cert CRL", Err: err}
	}

	crlPCKProcCAData := getFieldData(fieldCRLPCKProcCA, offsets, fieldData)
	crlPCKProcCAData = stripTrailingNull(crlPCKProcCAData)
	pckProcCACRL, err := parseCRL(crlPCKProcCAData)
	if err != nil {
		return nil, &EndorsementParseError{Detail: "PCK processor CA CRL", Err: err}
	}

	// Parse TCB info (extract nextUpdate for validity checking)
	tcbInfoData := getFieldData(fieldTCBInfo, offsets, fieldData)
	tcbInfoData = stripTrailingNull(tcbInfoData)

	// Verify TCB info signature (AT-C4)
	if len(tcbIssuerChain) > 0 {
		if err := verifySignedJSON(tcbInfoData, tcbIssuerChain[0], "tcbInfo"); err != nil {
			return nil, &EndorsementParseError{Detail: "TCB info signature", Err: err}
		}
	}

	tcbInfoNextUpdate := extractTimeField(string(tcbInfoData), "nextUpdate")

	// Validate tcbType (AT-W2)
	if err := validateTCBType(string(tcbInfoData)); err != nil {
		return nil, err
	}

	// Parse QE identity info
	qeIDInfoData := getFieldData(fieldQEIDInfo, offsets, fieldData)
	qeIDInfoData = stripTrailingNull(qeIDInfoData)

	// Verify QE identity signature (AT-C4)
	if len(qeIDIssuerChain) > 0 {
		if err := verifySignedJSON(qeIDInfoData, qeIDIssuerChain[0], "enclaveIdentity"); err != nil {
			return nil, &EndorsementParseError{Detail: "QE identity signature", Err: err}
		}
	}

	qeIdentity, err := parseEnclaveIdentityJSON(qeIDInfoData)
	if err != nil {
		return nil, &EndorsementParseError{Detail: "QE identity", Err: err}
	}
	qeIDNextUpdate := extractTimeField(string(qeIDInfoData), "nextUpdate")

	return &sgxEndorsements{
		version:           version,
		tcbIssuerChain:    tcbIssuerChain,
		pckIssuerCRLChain: pckCRLIssuerChain,
		qeIDIssuerChain:   qeIDIssuerChain,
		qeIdentity:        qeIdentity,
		tcbInfoNextUpdate: tcbInfoNextUpdate,
		qeIDNextUpdate:    qeIDNextUpdate,
		tcbInfoRaw:        tcbInfoData,
		pckCertCRL:        pckCertCRL,
		pckProcCACRL:      pckProcCACRL,
	}, nil
}

func validateOffsets(offsets []int, data []byte) error {
	if len(offsets) < sgxEndorsementFieldCount {
		return &EndorsementValidationError{Detail: "too few fields"}
	}

	lastOffset := offsets[len(offsets)-1]
	if len(data) <= lastOffset {
		return &EndorsementValidationError{Detail: "data is too short for offsets"}
	}

	for i := 1; i < len(offsets); i++ {
		if offsets[i] <= offsets[i-1] {
			return &EndorsementValidationError{Detail: "offsets are not strictly increasing"}
		}
	}

	return nil
}

func getFieldData(field sgxEndorsementField, offsets []int, data []byte) []byte {
	idx := int(field)
	if idx == len(offsets)-1 {
		return data[offsets[idx]:]
	}
	return data[offsets[idx]:offsets[idx+1]]
}

func stripTrailingNull(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == 0 {
		return data[:len(data)-1]
	}
	return data
}

// enclaveIdentityJSON represents the QE identity JSON structure for safe unmarshaling.
type enclaveIdentityJSON struct {
	ID             string           `json:"id"`
	Version        int              `json:"version"`
	MRSigner       string           `json:"mrsigner"`
	ISVProdID      uint16           `json:"isvprodid"`
	Miscselect     string           `json:"miscselect"`
	MiscselectMask string           `json:"miscselectMask"`
	Attributes     string           `json:"attributes"`
	AttributesMask string           `json:"attributesMask"`
	TcbLevels      []qeTcbLevelJSON `json:"tcbLevels"`
}

// qeTcbLevelJSON represents a single TCB level entry in the QE identity JSON.
type qeTcbLevelJSON struct {
	Tcb       qeTcbJSON `json:"tcb"`
	TcbStatus string    `json:"tcbStatus"`
}

// qeTcbJSON represents the TCB component within a QE TCB level.
type qeTcbJSON struct {
	ISVSVN uint16 `json:"isvsvn"`
}

// parseEnclaveIdentityJSON parses the QE identity from JSON.
// The JSON structure is:
// { "enclaveIdentity": { ... }, "signature": "hex..." }
func parseEnclaveIdentityJSON(data []byte) (*enclaveIdentity, error) {
	// Try parsing with the wrapper first (standard Intel format).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &EnclaveIdentityParseError{Err: err}
	}

	// If the wrapper "enclaveIdentity" field exists, parse from it.
	if innerRaw, ok := raw["enclaveIdentity"]; ok {
		var parsed enclaveIdentityJSON
		if err := json.Unmarshal(innerRaw, &parsed); err != nil {
			return nil, &EnclaveIdentityParseError{Err: err}
		}
		return buildEnclaveIdentity(&parsed)
	}

	// Otherwise, parse directly (no wrapper).
	var parsed enclaveIdentityJSON
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, &EnclaveIdentityParseError{Err: err}
	}
	return buildEnclaveIdentity(&parsed)
}

// buildEnclaveIdentity converts parsed JSON into the internal enclaveIdentity struct.
func buildEnclaveIdentity(parsed *enclaveIdentityJSON) (*enclaveIdentity, error) {
	identity := &enclaveIdentity{}

	identity.id = parsed.ID
	identity.version = parsed.Version

	// Validate version == 2 (AT-W1, AT-R21-C2)
	if identity.version != 2 {
		return nil, &EnclaveIdentityVersionError{Expected: 2, Actual: identity.version}
	}

	// Parse mrsigner hex.
	if parsed.MRSigner != "" {
		mrsigner, err := hex.DecodeString(parsed.MRSigner)
		if err == nil && len(mrsigner) == 32 {
			copy(identity.mrsigner[:], mrsigner)
		}
	}

	identity.isvprodid = parsed.ISVProdID

	// Parse miscselect hex.
	if parsed.Miscselect != "" {
		miscselect, err := hex.DecodeString(parsed.Miscselect)
		if err == nil && len(miscselect) == 4 {
			identity.miscselect = binary.LittleEndian.Uint32(miscselect)
		}
	}

	// Parse miscselectMask hex.
	if parsed.MiscselectMask != "" {
		miscselectMask, err := hex.DecodeString(parsed.MiscselectMask)
		if err == nil && len(miscselectMask) == 4 {
			identity.miscselectMask = binary.LittleEndian.Uint32(miscselectMask)
		}
	}

	// Parse attributes hex.
	if parsed.Attributes != "" {
		attributes, err := hex.DecodeString(parsed.Attributes)
		if err == nil && len(attributes) == 16 {
			copy(identity.attributes[:], attributes)
		}
	}

	// Parse attributesMask hex.
	if parsed.AttributesMask != "" {
		attributesMask, err := hex.DecodeString(parsed.AttributesMask)
		if err == nil && len(attributesMask) == 16 {
			copy(identity.attributesMask[:], attributesMask)
		}
	}

	// Parse tcbLevels (AT-C2).
	for _, level := range parsed.TcbLevels {
		identity.tcbLevels = append(identity.tcbLevels, qeTcbLevel{
			isvsvn:    level.Tcb.ISVSVN,
			tcbStatus: level.TcbStatus,
		})
	}

	return identity, nil
}

// extractHexField finds a JSON field by name and decodes its hex value.
func extractHexField(json string, fieldName string) ([]byte, error) {
	// Look for "fieldName":"hexvalue"
	key := fmt.Sprintf(`"%s"`, fieldName)
	idx := strings.Index(json, key)
	if idx < 0 {
		// Try camelCase variant
		key = fmt.Sprintf(`"%s"`, toCamelCase(fieldName))
		idx = strings.Index(json, key)
		if idx < 0 {
			return nil, &JSONFieldError{Field: fieldName, Detail: "field not found"}
		}
	}

	// Skip past the key and colon
	rest := json[idx+len(key):]
	rest = strings.TrimLeft(rest, " \t\n\r:")
	if len(rest) == 0 || rest[0] != '"' {
		return nil, &JSONFieldError{Field: fieldName, Detail: "expected string value"}
	}

	// Find the closing quote
	rest = rest[1:]
	endQuote := strings.IndexByte(rest, '"')
	if endQuote < 0 {
		return nil, &JSONFieldError{Field: fieldName, Detail: "unterminated string"}
	}

	hexStr := rest[:endQuote]

	// Decode hex
	decoded := make([]byte, len(hexStr)/2)
	for i := 0; i < len(decoded); i++ {
		b, err := hexByte(hexStr[i*2], hexStr[i*2+1])
		if err != nil {
			return nil, err
		}
		decoded[i] = b
	}

	return decoded, nil
}

func hexByte(hi, lo byte) (byte, error) {
	h, err := hexNibble(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexNibble(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func hexNibble(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, nil
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, nil
	default:
		return 0, &HexDecodeError{Char: b}
	}
}

// extractUint16Field finds a JSON integer field by name and returns its value.
// Returns 0 if the field is not found or the value overflows uint16.
func extractUint16Field(jsonStr string, fieldName string) uint16 {
	val, _ := extractUint16FieldSafe(jsonStr, fieldName)
	return val
}

// extractUint16FieldSafe finds a JSON integer field by name and returns its value.
// Returns an error if the value exceeds the uint16 range.
func extractUint16FieldSafe(jsonStr string, fieldName string) (uint16, error) {
	key := fmt.Sprintf(`"%s"`, fieldName)
	idx := strings.Index(jsonStr, key)
	if idx < 0 {
		return 0, nil
	}

	rest := jsonStr[idx+len(key):]
	rest = strings.TrimLeft(rest, " \t\n\r:")

	var val uint32
	found := false
	for _, ch := range rest {
		if ch >= '0' && ch <= '9' {
			val = val*10 + uint32(ch-'0')
			found = true
			if val > 65535 {
				return 0, &Uint16OverflowError{Field: fieldName, Value: val}
			}
		} else {
			break
		}
	}
	if !found {
		return 0, nil
	}
	return uint16(val), nil
}

func toCamelCase(s string) string {
	// Simple camelCase: just return as-is since our field names
	// are already in the expected format
	return s
}

// parseCRL parses a DER-encoded CRL.
// Empty data is a typed error: the Rust libsignal reference (dcap/revocation_list.rs)
// treats absent CRL fields as a hard failure, not a pass-through. Callers must
// supply both CRLs from the endorsements; an attacker stripping them is rejected here.
// The Authority Key Identifier and CRL Number extensions are mandatory per the
// Rust reference (revocation_list.rs requires AKI + CRL-number before trusting any CRL).
func parseCRL(data []byte) (*x509.RevocationList, error) {
	if len(data) == 0 {
		return nil, &CRLMissingError{Detail: "CRL data is empty"}
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, &CRLParseError{Err: err}
	}
	// Enforce mandatory extensions required by Rust libsignal reference.
	if len(crl.AuthorityKeyId) == 0 {
		return nil, &CRLMissingError{Detail: "Authority Key Identifier extension"}
	}
	if crl.Number == nil {
		return nil, &CRLMissingError{Detail: "CRL Number extension"}
	}
	return crl, nil
}

// verifyCRLSignature verifies a CRL's signature against the given certificate's public key.
func verifyCRLSignature(crl *x509.RevocationList, issuer *x509.Certificate) error {
	if crl == nil {
		return nil
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return &CRLSignatureError{Message: err.Error()}
	}
	return nil
}

// checkCertAgainstCRL checks if a certificate's serial number appears in the CRL.
func checkCertAgainstCRL(cert *x509.Certificate, crl *x509.RevocationList) error {
	if crl == nil || cert == nil {
		return nil
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return &CRLVerificationError{
				SerialNumber: cert.SerialNumber.String(),
				Issuer:       cert.Issuer.CommonName,
			}
		}
	}
	return nil
}

// verifySignedJSON verifies the ECDSA-P256 signature on a signed JSON structure.
// The structure is: {"<contentField>": <raw JSON>, "signature": "<hex>"}
// The signature is computed over the raw JSON value of the content field.
func verifySignedJSON(data []byte, leafCert *x509.Certificate, contentField string) error {
	jsonStr := string(data)

	// Extract signature hex string
	sigHex := extractStringField(jsonStr, "signature")
	if sigHex == "" {
		return &EndorsementSignatureError{
			Field:   contentField,
			Message: "signature field not found",
		}
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return &EndorsementSignatureError{
			Field:   contentField,
			Message: fmt.Sprintf("invalid signature hex: %v", err),
		}
	}

	// Extract the raw content for the given field.
	rawContent := extractRawJSONValue(jsonStr, contentField)
	if rawContent == "" {
		return &EndorsementSignatureError{
			Field:   contentField,
			Message: fmt.Sprintf("%s field not found", contentField),
		}
	}

	// Get the leaf certificate's ECDSA public key.
	pubKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &EndorsementSignatureError{
			Field:   contentField,
			Message: "leaf certificate does not contain ECDSA public key",
		}
	}

	// Hash the raw content and verify.
	hash := sha256.Sum256([]byte(rawContent))

	// Intel uses raw r||s format (64 bytes for P-256).
	if len(sigBytes) == 64 {
		derSig, convErr := ecdsaRawToDER(sigBytes)
		if convErr != nil {
			return &EndorsementSignatureError{
				Field:   contentField,
				Message: fmt.Sprintf("converting signature to DER: %v", convErr),
			}
		}
		if !ecdsa.VerifyASN1(pubKey, hash[:], derSig) {
			return &EndorsementSignatureError{
				Field:   contentField,
				Message: "ECDSA signature verification failed",
			}
		}
		return nil
	}

	// Try as DER-encoded signature.
	if !ecdsa.VerifyASN1(pubKey, hash[:], sigBytes) {
		return &EndorsementSignatureError{
			Field:   contentField,
			Message: "ECDSA signature verification failed",
		}
	}
	return nil
}

// extractRawJSONValue extracts the raw JSON value for a given top-level field
// using encoding/json for robust parsing. Returns the raw JSON bytes as a string,
// preserving exact formatting for signature verification.
func extractRawJSONValue(jsonStr string, fieldName string) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return ""
	}
	val, ok := raw[fieldName]
	if !ok {
		return ""
	}
	return string(val)
}

// parseQETcbLevels parses the tcbLevels array from QE identity JSON.
// Each entry has "tcb": {"isvsvn": N} and "tcbStatus": "..."
func parseQETcbLevels(jsonStr string) []qeTcbLevel {
	idx := strings.Index(jsonStr, `"tcbLevels"`)
	if idx < 0 {
		return nil
	}

	rest := jsonStr[idx:]
	bracketIdx := strings.IndexByte(rest, '[')
	if bracketIdx < 0 {
		return nil
	}
	rest = rest[bracketIdx:]

	// Find matching closing bracket.
	depth := 0
	endIdx := -1
	for i, ch := range rest {
		if ch == '[' {
			depth++
		} else if ch == ']' {
			depth--
			if depth == 0 {
				endIdx = i + 1
				break
			}
		}
	}
	if endIdx < 0 {
		return nil
	}

	arrayStr := rest[:endIdx]

	// Split into individual level objects.
	var levels []qeTcbLevel
	objStart := -1
	objDepth := 0
	for i, ch := range arrayStr {
		switch ch {
		case '{':
			if objDepth == 0 {
				objStart = i
			}
			objDepth++
		case '}':
			objDepth--
			if objDepth == 0 && objStart >= 0 {
				levelStr := arrayStr[objStart : i+1]
				level := qeTcbLevel{
					isvsvn:    extractUint16Field(levelStr, "isvsvn"),
					tcbStatus: extractStringField(levelStr, "tcbStatus"),
				}
				levels = append(levels, level)
				objStart = -1
			}
		}
	}

	return levels
}

// validateTCBType checks that the tcbType field in TCB info JSON is 0. (AT-W2)
func validateTCBType(jsonStr string) error {
	// Only validate if the field exists.
	key := `"tcbType"`
	idx := strings.Index(jsonStr, key)
	if idx < 0 {
		return nil
	}

	tcbType := int(extractUint16Field(jsonStr, "tcbType"))
	if tcbType != 0 {
		return &TCBTypeError{Expected: 0, Actual: tcbType}
	}
	return nil
}

// extractTimeField extracts a JSON string field containing an ISO 8601 timestamp.
// Returns the zero time if the field is not found or cannot be parsed.
func extractTimeField(json string, fieldName string) time.Time {
	key := fmt.Sprintf(`"%s"`, fieldName)
	idx := strings.Index(json, key)
	if idx < 0 {
		return time.Time{}
	}

	rest := json[idx+len(key):]
	rest = strings.TrimLeft(rest, " \t\n\r:")
	if len(rest) == 0 || rest[0] != '"' {
		return time.Time{}
	}

	rest = rest[1:]
	endQuote := strings.IndexByte(rest, '"')
	if endQuote < 0 {
		return time.Time{}
	}

	timeStr := rest[:endQuote]

	// Try common ISO 8601 formats used by Intel.
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, timeStr); err == nil {
			return t
		}
	}

	return time.Time{}
}
