// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	// quoteV3 is the supported SGX quote version.
	quoteV3 uint16 = 3

	// ecdsaP256 is the attestation algorithm identifier for ECDSA-P256.
	ecdsaP256 uint16 = 2

	// sgxReportBodySize is the size of an SGX report body in bytes.
	sgxReportBodySize = 384

	// sgxQuoteBodySize is the size of the SGX quote body (header + ISV report).
	sgxQuoteBodySize = 432

	// pckCertChainKeyType is the certification key type for PCK cert chain.
	pckCertChainKeyType uint16 = 5

	// SGX flags
	sgxFlagDebug uint64 = 0x02

	// OE custom claims version
	oeClaimsV1 uint64 = 1
)

// dcapEvidence represents parsed DCAP evidence.
type dcapEvidence struct {
	quote         *sgxQuote
	claims        map[string][]byte
	claimsRawData []byte
}

// sgxQuote represents a parsed SGX quote.
type sgxQuote struct {
	quoteBody *sgxQuoteBody
	support   *sgxQuoteSupport
}

// sgxQuoteBody is the Quote Header + ISV enclave report.
type sgxQuoteBody struct {
	rawBytes   []byte
	reportBody *sgxReportBody
	qeVendorID [16]byte
}

// sgxReportBody is a parsed SGX report body.
type sgxReportBody struct {
	rawBytes           []byte
	cpusvn             [16]byte
	miscselect         uint32
	sgxAttributes      [16]byte
	mrenclave          MREnclave
	mrsigner           [32]byte
	isvprodid          uint16
	isvsvn             uint16
	sgxReportDataBytes [64]byte
}

func (r *sgxReportBody) hasFlag(flag uint64) bool {
	flags := binary.LittleEndian.Uint64(r.sgxAttributes[:8])
	return flags&flag != 0
}

// sgxQuoteSupport contains signatures and supporting material for verifying the quote.
type sgxQuoteSupport struct {
	isvSignatureDER      []byte
	attestPubKey         [64]byte
	qeReportBody         *sgxReportBody
	qeReportSignatureDER []byte
	authData             []byte
	pckCertChain         []*x509.Certificate
}

func (e *dcapEvidence) validAt(t time.Time) bool {
	if e.quote == nil || e.quote.support == nil {
		return false
	}
	// Check PCK certificate chain validity period against the provided time.
	for _, cert := range e.quote.support.pckCertChain {
		if t.Before(cert.NotBefore) || t.After(cert.NotAfter) {
			return false
		}
	}
	return true
}

// parseEvidence parses DCAP evidence bytes into structured data.
func parseEvidence(data []byte) (*dcapEvidence, error) {
	if len(data) < sgxQuoteBodySize {
		return nil, &EvidenceParseError{Detail: fmt.Sprintf("evidence too short: %d bytes", len(data))}
	}

	// Parse quote body
	quoteBody, err := parseQuoteBody(data[:sgxQuoteBodySize])
	if err != nil {
		return nil, &EvidenceParseError{Detail: "quote body", Err: err}
	}

	offset := sgxQuoteBodySize

	// Read signature length (4 bytes LE)
	if offset+4 > len(data) {
		return nil, &EvidenceParseError{Detail: "underflow reading signature length"}
	}
	sigLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset+int(sigLen) > len(data) {
		return nil, &EvidenceParseError{Detail: "underflow reading signature data"}
	}

	// Parse quote support (signature data)
	support, supportEnd, err := parseQuoteSupport(data[offset : offset+int(sigLen)])
	if err != nil {
		return nil, &EvidenceParseError{Detail: "quote support", Err: err}
	}

	// Verify all signature bytes were consumed (AT-W4)
	if supportEnd != int(sigLen) {
		return nil, &TrailingDataError{
			Expected: supportEnd,
			Actual:   int(sigLen),
		}
	}
	offset += supportEnd

	// Remaining bytes are custom claims
	claimsData := data[offset:]
	claims, claimsConsumed, err := parseCustomClaimsStrict(claimsData)
	if err != nil {
		return nil, &EvidenceParseError{Detail: "custom claims", Err: err}
	}

	// Reject trailing data after claims (AT-W4)
	if claimsConsumed != len(claimsData) {
		return nil, &TrailingDataError{
			Expected: claimsConsumed,
			Actual:   len(claimsData),
		}
	}

	return &dcapEvidence{
		quote: &sgxQuote{
			quoteBody: quoteBody,
			support:   support,
		},
		claims:        claims,
		claimsRawData: claimsData[:claimsConsumed],
	}, nil
}

// parseQuoteBody parses the 432-byte SGX quote body.
func parseQuoteBody(data []byte) (*sgxQuoteBody, error) {
	if len(data) < sgxQuoteBodySize {
		return nil, &EvidenceParseError{Detail: "quote body too short"}
	}

	version := binary.LittleEndian.Uint16(data[0:2])
	if version != quoteV3 {
		return nil, &EvidenceParseError{Detail: fmt.Sprintf("unsupported quote version: %d", version)}
	}

	signType := binary.LittleEndian.Uint16(data[2:4])
	if signType != ecdsaP256 {
		return nil, &EvidenceParseError{Detail: fmt.Sprintf("unsupported attestation algorithm: %d", signType)}
	}

	body := &sgxQuoteBody{
		rawBytes: make([]byte, sgxQuoteBodySize),
	}
	copy(body.rawBytes, data[:sgxQuoteBodySize])

	// QE vendor ID at offset 12
	copy(body.qeVendorID[:], data[12:28])

	// Report body starts at offset 48
	reportBody, err := parseReportBody(data[48:432])
	if err != nil {
		return nil, &EvidenceParseError{Detail: "report body", Err: err}
	}
	body.reportBody = reportBody

	return body, nil
}

// parseReportBody parses a 384-byte SGX report body.
func parseReportBody(data []byte) (*sgxReportBody, error) {
	if len(data) < sgxReportBodySize {
		return nil, &EvidenceParseError{Detail: fmt.Sprintf("report body too short: %d", len(data))}
	}

	rb := &sgxReportBody{
		rawBytes: make([]byte, sgxReportBodySize),
	}
	copy(rb.rawBytes, data[:sgxReportBodySize])

	// cpusvn at offset 0
	copy(rb.cpusvn[:], data[0:16])

	// miscselect at offset 16
	rb.miscselect = binary.LittleEndian.Uint32(data[16:20])

	// sgx_attributes at offset 48
	copy(rb.sgxAttributes[:], data[48:64])

	// mrenclave at offset 64
	copy(rb.mrenclave[:], data[64:96])

	// mrsigner at offset 128
	copy(rb.mrsigner[:], data[128:160])

	// isvprodid at offset 256
	rb.isvprodid = binary.LittleEndian.Uint16(data[256:258])

	// isvsvn at offset 258
	rb.isvsvn = binary.LittleEndian.Uint16(data[258:260])

	// sgx_report_data at offset 320
	copy(rb.sgxReportDataBytes[:], data[320:384])

	return rb, nil
}

// parseQuoteSupport parses the ECDSA signature data structure (A4.4).
// Returns the support structure and the number of bytes consumed.
func parseQuoteSupport(data []byte) (*sgxQuoteSupport, int, error) {
	// SgxEcdsaSignatureHeader is:
	//   signature: [64]byte
	//   attest_pub_key: [64]byte
	//   qe_report_body: [384]byte (SgxReportBody)
	//   qe_report_signature: [64]byte
	//   auth_data_size: uint16
	headerSize := 64 + 64 + sgxReportBodySize + 64 + 2
	if len(data) < headerSize {
		return nil, 0, &EvidenceParseError{Detail: "quote support too short"}
	}

	offset := 0
	isvSigRaw := data[offset : offset+64]
	offset += 64

	var attestPubKey [64]byte
	copy(attestPubKey[:], data[offset:offset+64])
	offset += 64

	qeReportBody, err := parseReportBody(data[offset : offset+sgxReportBodySize])
	if err != nil {
		return nil, 0, &EvidenceParseError{Detail: "QE report body", Err: err}
	}
	offset += sgxReportBodySize

	qeReportSigRaw := data[offset : offset+64]
	offset += 64

	authDataSize := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(authDataSize) > len(data) {
		return nil, 0, &EvidenceParseError{Detail: "auth data underflow"}
	}
	authData := make([]byte, authDataSize)
	copy(authData, data[offset:offset+int(authDataSize)])
	offset += int(authDataSize)

	// cert key type (2 bytes) + cert data size (4 bytes)
	if offset+6 > len(data) {
		return nil, 0, &EvidenceParseError{Detail: "cert header underflow"}
	}
	certKeyType := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	certDataSize := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	if certKeyType != pckCertChainKeyType {
		return nil, 0, &EvidenceParseError{Detail: fmt.Sprintf("unsupported certification key type: %d", certKeyType)}
	}

	if offset+int(certDataSize) > len(data) {
		return nil, 0, &EvidenceParseError{Detail: "cert data underflow"}
	}

	pckCertData := data[offset : offset+int(certDataSize)]
	offset += int(certDataSize)

	pckCerts, err := parsePEMCertChain(pckCertData)
	if err != nil {
		return nil, 0, &EvidenceParseError{Detail: "PCK cert chain", Err: err}
	}

	// Convert raw ECDSA signatures to DER
	isvSigDER, err := ecdsaRawToDER(isvSigRaw)
	if err != nil {
		return nil, 0, &EvidenceParseError{Detail: "ISV signature", Err: err}
	}

	qeReportSigDER, err := ecdsaRawToDER(qeReportSigRaw)
	if err != nil {
		return nil, 0, &EvidenceParseError{Detail: "QE report signature", Err: err}
	}

	return &sgxQuoteSupport{
		isvSignatureDER:      isvSigDER,
		attestPubKey:         attestPubKey,
		qeReportBody:         qeReportBody,
		qeReportSignatureDER: qeReportSigDER,
		authData:             authData,
		pckCertChain:         pckCerts,
	}, offset, nil
}

// parseCustomClaimsStrict parses Open Enclave custom claims format and returns
// the number of bytes consumed. Callers should verify no trailing data remains.
func parseCustomClaimsStrict(data []byte) (map[string][]byte, int, error) {
	claims, err := parseCustomClaims(data)
	if err != nil {
		return nil, 0, err
	}
	// Calculate consumed bytes by re-walking the structure.
	consumed := computeClaimsSize(data)
	return claims, consumed, nil
}

// computeClaimsSize walks the claims structure to determine exact byte count.
// Uses the same bounds checks as parseCustomClaims to avoid integer overflow.
func computeClaimsSize(data []byte) int {
	if len(data) < 16 {
		return len(data)
	}
	numClaims := binary.LittleEndian.Uint64(data[8:16])
	if numClaims > 256 {
		return len(data)
	}
	offset := 16
	for i := uint64(0); i < numClaims; i++ {
		if offset+16 > len(data) {
			return len(data)
		}
		nameSize := binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
		valueSize := binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8

		// Apply same bounds as parseCustomClaims to prevent overflow
		if nameSize > 1024 || valueSize > 1024*1024 {
			return len(data)
		}
		entrySize := int(nameSize) + int(valueSize)
		if offset+entrySize > len(data) {
			return len(data)
		}
		offset += entrySize
	}
	return offset
}

// parseCustomClaims parses Open Enclave custom claims format.
func parseCustomClaims(data []byte) (map[string][]byte, error) {
	if len(data) < 16 {
		return nil, &ClaimsParseError{Detail: "custom claims too short"}
	}

	version := binary.LittleEndian.Uint64(data[0:8])
	if version != oeClaimsV1 {
		return nil, &ClaimsParseError{Detail: fmt.Sprintf("unsupported claims version: %d", version)}
	}

	numClaims := binary.LittleEndian.Uint64(data[8:16])
	if numClaims > 256 {
		return nil, &ClaimsParseError{Detail: fmt.Sprintf("too many custom claims: %d", numClaims)}
	}

	claims := make(map[string][]byte, numClaims)
	offset := 16

	for i := uint64(0); i < numClaims; i++ {
		if offset+16 > len(data) {
			return nil, &ClaimsParseError{Detail: "underflow reading claim entry header"}
		}

		nameSize := binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
		valueSize := binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8

		if nameSize > 1024 {
			return nil, &ClaimsParseError{Detail: "custom claim name too long"}
		}
		if valueSize > 1024*1024 {
			return nil, &ClaimsParseError{Detail: "custom claim value too long"}
		}

		if offset+int(nameSize)+int(valueSize) > len(data) {
			return nil, &ClaimsParseError{Detail: "underflow reading claim data"}
		}

		nameBytes := data[offset : offset+int(nameSize)]
		offset += int(nameSize)

		// Strip trailing null byte
		name := string(nameBytes)
		name = strings.TrimRight(name, "\x00")

		value := make([]byte, valueSize)
		copy(value, data[offset:offset+int(valueSize)])
		offset += int(valueSize)

		if _, exists := claims[name]; exists {
			return nil, &ClaimsParseError{Detail: fmt.Sprintf("duplicate custom claim name: %s", name)}
		}
		claims[name] = value
	}

	return claims, nil
}
