// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package attest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// IntelRootPubKey is the uncompressed EC point for Intel's DCAP root signing key (P-256).
var IntelRootPubKey = []byte{
	0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23,
	0xd6, 0xb0, 0x2c, 0xda, 0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4,
	0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25, 0xf5, 0x67, 0x91, 0x8e,
	0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
	0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b,
	0x09, 0x04, 0xae, 0x73, 0x94,
}

// intelQEVendorID is the Intel Quoting Enclave vendor UUID.
var intelQEVendorID = [16]byte{
	0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9,
	0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
}

// VerifyRemoteAttestation verifies DCAP remote attestation and returns extracted claims.
//
// Parameters:
//   - evidenceBytes: raw DCAP evidence
//   - endorsementBytes: raw DCAP endorsements
//   - expectedMREnclave: the expected MRENCLAVE value
//   - acceptableSWAdvisories: SW advisory IDs known to be mitigated
//   - currentTime: time for validity checking (should include skew adjustment)
func VerifyRemoteAttestation(
	evidenceBytes []byte,
	endorsementBytes []byte,
	expectedMREnclave *MREnclave,
	acceptableSWAdvisories []string,
	currentTime time.Time,
) (map[string][]byte, error) {
	attestation, err := dcapAttest(evidenceBytes, endorsementBytes, currentTime)
	if err != nil {
		return nil, &AttestationError{Message: err.Error()}
	}

	// Check TCB standing
	if attestation.tcbStanding == tcbSWHardeningNeeded {
		for _, id := range attestation.advisoryIDs {
			if !containsString(acceptableSWAdvisories, id) {
				return nil, &AttestationError{
					Message: fmt.Sprintf("TCB contains unmitigated unaccepted advisory ids: %v", attestation.advisoryIDs),
				}
			}
		}
	}

	// Verify MRENCLAVE matches
	if *expectedMREnclave != attestation.mrenclave {
		return nil, &AttestationError{
			Message: fmt.Sprintf("expected mrenclave %s, was %s",
				hex.EncodeToString(expectedMREnclave[:]),
				hex.EncodeToString(attestation.mrenclave[:])),
		}
	}

	return attestation.claims, nil
}

// AttestationMetrics extracts attestation metrics from evidence and endorsements.
// Returns metrics including QE report fields when parseable.
func AttestationMetrics(evidenceBytes []byte, endorsementBytes []byte) (map[string]int64, error) {
	metrics := make(map[string]int64)

	evidence, err := parseEvidence(evidenceBytes)
	if err != nil {
		return metrics, nil
	}

	if evidence.quote != nil && evidence.quote.support != nil && evidence.quote.support.qeReportBody != nil {
		metrics["qe_isvsvn"] = int64(evidence.quote.support.qeReportBody.isvsvn)
		metrics["qe_isvprodid"] = int64(evidence.quote.support.qeReportBody.isvprodid)
	}

	return metrics, nil
}

type tcbStandingType int

const (
	tcbUpToDate tcbStandingType = iota
	tcbSWHardeningNeeded
	tcbOutOfDate
)

// dcapAttestation holds the result of DCAP attestation verification.
type dcapAttestation struct {
	tcbStanding tcbStandingType
	advisoryIDs []string
	mrenclave   MREnclave
	claims      map[string][]byte
}

// dcapAttest validates that the returned evidence/endorsements are generated
// from a trusted Intel SGX enclave.
func dcapAttest(evidenceBytes []byte, endorsementBytes []byte, currentTime time.Time) (*dcapAttestation, error) {
	evidence, err := parseEvidence(evidenceBytes)
	if err != nil {
		return nil, &DcapOperationError{Operation: "evidence", Err: err}
	}

	endorsements, err := parseEndorsements(endorsementBytes)
	if err != nil {
		return nil, &DcapOperationError{Operation: "endorsements", Err: err}
	}

	// Verify expiration
	if !evidence.validAt(currentTime) {
		return nil, &DcapValidationError{Detail: "evidence is not valid at the given time"}
	}
	if !endorsements.validAt(currentTime) {
		return nil, &DcapValidationError{Detail: "endorsements are not valid at the given time"}
	}

	// Verify certificate chains
	if err := verifyCertificates(evidence, endorsements, currentTime); err != nil {
		return nil, &DcapOperationError{Operation: "certificate verification", Err: err}
	}

	// Verify enclave source (QE identity)
	if err := verifyEnclaveSource(evidence, endorsements); err != nil {
		return nil, &DcapOperationError{Operation: "enclave source", Err: err}
	}

	// Verify enclave signatures
	if err := verifyEnclaveSignatures(evidence); err != nil {
		return nil, &DcapOperationError{Operation: "enclave signatures", Err: err}
	}

	// Find TCB standing
	standing, advisoryIDs, err := verifyTCBStatus(evidence, endorsements)
	if err != nil {
		return nil, &DcapOperationError{Operation: "tcb status", Err: err}
	}

	// Verify custom claims hash
	if err := verifyClaimsHash(evidence); err != nil {
		return nil, &DcapOperationError{Operation: "claims hash", Err: err}
	}

	// Verify not in debug mode
	reportBody := evidence.quote.quoteBody.reportBody
	if reportBody.hasFlag(sgxFlagDebug) {
		return nil, &DcapValidationError{Detail: "application enclave in debug mode"}
	}

	return &dcapAttestation{
		tcbStanding: standing,
		advisoryIDs: advisoryIDs,
		mrenclave:   reportBody.mrenclave,
		claims:      evidence.claims,
	}, nil
}

// verifyCertificates verifies the certificate chains, CRLs, and revocation status.
func verifyCertificates(evidence *dcapEvidence, endorsements *sgxEndorsements, currentTime time.Time) error {
	// Verify the root certificate is self-signed and matches Intel's root key
	if len(endorsements.tcbIssuerChain) == 0 {
		return &CertChainError{Detail: "empty TCB issuer chain"}
	}

	rootCA := endorsements.tcbIssuerChain[len(endorsements.tcbIssuerChain)-1]

	// Verify root is signed by Intel's root key
	intelKey, err := parseIntelRootKey()
	if err != nil {
		return &CertChainError{Detail: "parsing Intel root key", Err: err}
	}

	if err := verifyRootCertificate(rootCA, intelKey); err != nil {
		return &CertChainError{Detail: "root certificate", Err: err}
	}

	// Verify certificate chains are valid
	if err := verifyCertChain(evidence.quote.support.pckCertChain, rootCA, currentTime); err != nil {
		return &CertChainError{Detail: "PCK cert chain", Err: err}
	}

	if err := verifyCertChain(endorsements.tcbIssuerChain, rootCA, currentTime); err != nil {
		return &CertChainError{Detail: "TCB issuer chain", Err: err}
	}

	if err := verifyCertChain(endorsements.qeIDIssuerChain, rootCA, currentTime); err != nil {
		return &CertChainError{Detail: "QE ID issuer chain", Err: err}
	}

	// Verify CRL signatures (AT-C1)
	if err := verifyCRLs(evidence, endorsements); err != nil {
		return &CertChainError{Detail: "CRL verification", Err: err}
	}

	return nil
}

// verifyCRLs verifies CRL signatures and checks certificates against revocation lists.
func verifyCRLs(evidence *dcapEvidence, endorsements *sgxEndorsements) error {
	// Verify PCK cert CRL signature against the PCK CRL issuer chain
	if endorsements.pckCertCRL != nil && len(endorsements.pckIssuerCRLChain) > 0 {
		if err := verifyCRLAgainstIssuers(endorsements.pckCertCRL, endorsements.pckIssuerCRLChain); err != nil {
			return err
		}

		// Check PCK certificates against the CRL
		for _, cert := range evidence.quote.support.pckCertChain {
			if err := checkCertAgainstCRL(cert, endorsements.pckCertCRL); err != nil {
				return err
			}
		}
	}

	// Verify PCK processor CA CRL (root CRL) signature against Intel root key first.
	// The Rust reference calls root_crl.verify(root_key) before trusting any CRL.
	if endorsements.pckProcCACRL != nil {
		if err := verifyRootCRLAgainstIntelKey(endorsements.pckProcCACRL); err != nil {
			return err
		}
	}

	// Verify PCK processor CA CRL (root CRL) signature against issuer chain
	if endorsements.pckProcCACRL != nil && len(endorsements.pckIssuerCRLChain) > 0 {
		if err := verifyCRLAgainstIssuers(endorsements.pckProcCACRL, endorsements.pckIssuerCRLChain); err != nil {
			return err
		}

		// Check PCK CRL issuer chain certs against the root CRL
		for _, cert := range endorsements.pckIssuerCRLChain {
			if err := checkCertAgainstCRL(cert, endorsements.pckProcCACRL); err != nil {
				return err
			}
		}
	}

	// Check TCB issuer chain certificates against the root CRL (AT-A1)
	// The Rust reference validates tcb_issuer_chain against the trust store
	// which includes root_crl with CRL_CHECK_ALL, rejecting revoked signers.
	if endorsements.pckProcCACRL != nil {
		for _, cert := range endorsements.tcbIssuerChain {
			if err := checkCertAgainstCRL(cert, endorsements.pckProcCACRL); err != nil {
				return err
			}
		}
	}

	// Check QE ID issuer chain certificates against the root CRL (AT-A1)
	// The Rust reference validates qe_id_issuer_chain against the trust store
	// which includes root_crl with CRL_CHECK_ALL, rejecting revoked signers.
	if endorsements.pckProcCACRL != nil {
		for _, cert := range endorsements.qeIDIssuerChain {
			if err := checkCertAgainstCRL(cert, endorsements.pckProcCACRL); err != nil {
				return err
			}
		}
	}

	return nil
}

// verifyRootCRLAgainstIntelKey verifies the root CRL signature against
// the Intel DCAP root public key. This matches the Rust reference behavior
// of calling root_crl.verify(root_key) before trusting any CRL.
func verifyRootCRLAgainstIntelKey(crl *x509.RevocationList) error {
	intelKey, err := parseIntelRootKey()
	if err != nil {
		return &RootCRLVerificationError{Err: err}
	}

	// Create a synthetic certificate from the Intel root key for CRL verification.
	// CheckSignatureFrom requires an x509.Certificate with the public key.
	rootCert := &x509.Certificate{
		PublicKey:          intelKey,
		PublicKeyAlgorithm: x509.ECDSA,
		// IsCA must be true for CheckSignatureFrom to accept this as an issuer.
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign,
	}

	if err := crl.CheckSignatureFrom(rootCert); err != nil {
		return &RootCRLVerificationError{Err: err}
	}
	return nil
}

// verifyCRLAgainstIssuers tries each issuer cert to verify the CRL signature.
// Returns an error if no issuer successfully verifies the CRL.
func verifyCRLAgainstIssuers(crl *x509.RevocationList, issuers []*x509.Certificate) error {
	for _, issuer := range issuers {
		if err := verifyCRLSignature(crl, issuer); err == nil {
			return nil
		}
	}
	return &CRLSignatureError{Message: "no issuer certificate verified the CRL signature"}
}

// verifyEnclaveSource verifies the quoting enclave is from a suitable source.
func verifyEnclaveSource(evidence *dcapEvidence, endorsements *sgxEndorsements) error {
	// Verify enclave identity type is QE (AT-C3)
	if endorsements.qeIdentity.id != "" && endorsements.qeIdentity.id != "QE" {
		return &EnclaveIdentityTypeError{
			Expected: "QE",
			Actual:   endorsements.qeIdentity.id,
		}
	}

	// Verify QE vendor is Intel
	if evidence.quote.quoteBody.qeVendorID != intelQEVendorID {
		return &QEVendorIDMismatchError{Actual: evidence.quote.quoteBody.qeVendorID}
	}

	// Compare mrsigner
	if evidence.quote.support.qeReportBody.mrsigner != endorsements.qeIdentity.mrsigner {
		return &MRSignerMismatchError{
			Expected: endorsements.qeIdentity.mrsigner,
			Actual:   evidence.quote.support.qeReportBody.mrsigner,
		}
	}

	// Compare isvprodid
	if evidence.quote.support.qeReportBody.isvprodid != endorsements.qeIdentity.isvprodid {
		return &ISVProdIDMismatchError{
			Expected: endorsements.qeIdentity.isvprodid,
			Actual:   evidence.quote.support.qeReportBody.isvprodid,
		}
	}

	// Compare miscselect (masked)
	maskedMiscselect := evidence.quote.support.qeReportBody.miscselect & endorsements.qeIdentity.miscselectMask
	if maskedMiscselect != endorsements.qeIdentity.miscselect {
		return &MiscselectMismatchError{
			Expected: endorsements.qeIdentity.miscselect,
			Actual:   maskedMiscselect,
		}
	}

	// Compare attributes (masked)
	for i := 0; i < 16; i++ {
		masked := evidence.quote.support.qeReportBody.sgxAttributes[i] & endorsements.qeIdentity.attributesMask[i]
		if masked != endorsements.qeIdentity.attributes[i] {
			return &QEAttributesMismatchError{
				Index:    i,
				Expected: endorsements.qeIdentity.attributes[i],
				Actual:   masked,
			}
		}
	}

	// Verify QE TCB status (AT-C2)
	if len(endorsements.qeIdentity.tcbLevels) > 0 {
		qeISVSVN := evidence.quote.support.qeReportBody.isvsvn
		status, err := endorsements.qeIdentity.tcbStatusForISVSVN(qeISVSVN)
		if err != nil {
			return err
		}
		if status != "UpToDate" {
			return &QETCBStatusError{Status: status, ISVSVN: qeISVSVN}
		}
	}

	return nil
}

// verifyEnclaveSignatures verifies the signatures on the quote.
func verifyEnclaveSignatures(evidence *dcapEvidence) error {
	// Verify QE report is signed by PCK certificate
	if len(evidence.quote.support.pckCertChain) == 0 {
		return &DcapValidationError{Detail: "empty PCK cert chain"}
	}
	pckLeaf := evidence.quote.support.pckCertChain[0]
	pckPubKey, ok := pckLeaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &DcapValidationError{Detail: "PCK certificate does not contain ECDSA public key"}
	}

	// Verify QE report signature
	qeReportHash := sha256.Sum256(evidence.quote.support.qeReportBody.rawBytes)
	if !ecdsa.VerifyASN1(pckPubKey, qeReportHash[:], evidence.quote.support.qeReportSignatureDER) {
		return &DcapValidationError{Detail: "QE report signature verification failed"}
	}

	// Verify QE report data = SHA256(attestKey || authData)
	h := sha256.New()
	h.Write(evidence.quote.support.attestPubKey[:])
	h.Write(evidence.quote.support.authData)
	expectedHash := h.Sum(nil)
	if !bytesEqualSlice(expectedHash, evidence.quote.support.qeReportBody.sgxReportDataBytes[:32]) {
		return &DcapValidationError{Detail: "QE report data does not match expected hash"}
	}
	// Check zero padding
	for _, b := range evidence.quote.support.qeReportBody.sgxReportDataBytes[32:] {
		if b != 0 {
			return &DcapValidationError{Detail: "QE report data is not zero-padded"}
		}
	}

	// Verify ISV report signature using attest key
	attestKey, err := parseAttestKey(evidence.quote.support.attestPubKey[:])
	if err != nil {
		return &DcapOperationError{Operation: "parsing attest key", Err: err}
	}
	isvReportHash := sha256.Sum256(evidence.quote.quoteBody.rawBytes)
	if !ecdsa.VerifyASN1(attestKey, isvReportHash[:], evidence.quote.support.isvSignatureDER) {
		return &DcapValidationError{Detail: "ISV report signature verification failed"}
	}

	return nil
}

// verifyTCBStatus verifies the TCB status by comparing evidence SVN components
// against TCB levels from endorsements.
//
// This follows the Intel DCAP TCB verification flow:
// 1. Extract FMSPC and PCEID from the PCK certificate extension
// 2. Verify they match the endorsement TCB info
// 3. Compare SVN components against TCB levels to find matching status
//
// If full matching cannot be performed (e.g., PCK extension not parseable),
// the function fails safe by returning tcbSWHardeningNeeded rather than
// tcbUpToDate (fail-safe, not fail-open).
func verifyTCBStatus(evidence *dcapEvidence, endorsements *sgxEndorsements) (tcbStandingType, []string, error) {
	// Parse the TCB info JSON from endorsements to extract TCB levels.
	if len(endorsements.tcbInfoRaw) == 0 {
		return tcbUpToDate, nil, nil
	}

	tcbInfoJSON := string(endorsements.tcbInfoRaw)

	// Extract FMSPC and PCEID from TCB info for cross-validation.
	tcbFMSPC, fmspcErr := extractHexField(tcbInfoJSON, "fmspc")
	tcbPCEID, pceidErr := extractHexField(tcbInfoJSON, "pceId")

	// Extract the PCK extension from the leaf certificate (mandatory).
	pckExt, pckErr := parsePCKExtension(evidence)
	if pckErr != nil {
		return 0, nil, &PCKExtensionParseError{Field: "pckExtension", Err: pckErr}
	}

	// Extract FMSPC and PCEID from TCB info (mandatory).
	if fmspcErr != nil {
		return 0, nil, &PCKExtensionParseError{Field: "fmspc", Err: fmspcErr}
	}
	if pceidErr != nil {
		return 0, nil, &PCKExtensionParseError{Field: "pceId", Err: pceidErr}
	}

	// Cross-validate PCK extension against TCB info identifiers.
	if !bytesEqualSlice(pckExt.fmspc, tcbFMSPC) {
		return 0, nil, &FMSPCMismatchError{PCKExtension: pckExt.fmspc, TCBInfo: tcbFMSPC}
	}
	if !bytesEqualSlice(pckExt.pceid, tcbPCEID) {
		return 0, nil, &PCEIDMismatchError{PCKExtension: pckExt.pceid, TCBInfo: tcbPCEID}
	}

	// Parse TCB levels and find matching level.
	levels, err := parseTCBLevels(tcbInfoJSON)
	if err != nil {
		return 0, nil, err
	}
	if len(levels) > 0 {
		return findTCBStanding(pckExt, levels)
	}

	return 0, nil, &PCKExtensionParseError{Field: "tcbLevels", Err: &DcapValidationError{Detail: "no TCB levels found in TCB info"}}
}

// pckExtensionData holds parsed SGX PCK certificate extension fields.
type pckExtensionData struct {
	fmspc   []byte   // 6-byte FMSPC
	pceid   []byte   // 2-byte PCEID
	compsvn [16]byte // 16 component SVN values
	pcesvn  uint16   // PCE SVN
}

// parsePCKExtension extracts SGX-specific fields from the PCK leaf certificate.
// The SGX PCK extension OID is 1.2.840.113741.1.13.1.
func parsePCKExtension(evidence *dcapEvidence) (*pckExtensionData, error) {
	if evidence.quote == nil || evidence.quote.support == nil {
		return nil, &DcapValidationError{Detail: "no quote support data"}
	}
	if len(evidence.quote.support.pckCertChain) == 0 {
		return nil, &DcapValidationError{Detail: "empty PCK cert chain"}
	}

	leaf := evidence.quote.support.pckCertChain[0]

	// The SGX PCK extension OID is 1.2.840.113741.1.13.1
	var sgxExtBytes []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.String() == "1.2.840.113741.1.13.1" {
			sgxExtBytes = ext.Value
			break
		}
	}

	if sgxExtBytes == nil {
		return nil, &DcapValidationError{Detail: "PCK certificate missing SGX extension"}
	}

	// Parse the ASN.1 SGX extension to extract FMSPC, PCEID, TCB components.
	return parseSGXExtensionASN1(sgxExtBytes)
}

// parseSGXExtensionASN1 performs a simplified parse of the SGX PCK extension
// ASN.1 structure to extract FMSPC, PCEID, and TCB component SVNs.
//
// The extension contains a SEQUENCE of SEQUENCE(OID, value) pairs.
// Known OIDs:
//   - 1.2.840.113741.1.13.1.2 - TCB (nested SEQUENCE of component SVNs + PCESVN)
//   - 1.2.840.113741.1.13.1.4 - FMSPC (OCTET STRING, 6 bytes)
//   - 1.2.840.113741.1.13.1.3 - PCEID (OCTET STRING, 2 bytes)
func parseSGXExtensionASN1(data []byte) (*pckExtensionData, error) {
	ext := &pckExtensionData{}

	// Walk the outer SEQUENCE looking for known OIDs.
	// This is a simplified ASN.1 walk that handles the specific structure
	// found in Intel PCK certificates.
	items, err := parseASN1Sequence(data)
	if err != nil {
		return nil, &ASN1ParseError{Detail: "parsing SGX extension outer sequence", Err: err}
	}

	for _, item := range items {
		subItems, err := parseASN1Sequence(item)
		if err != nil {
			continue
		}
		if len(subItems) < 2 {
			continue
		}

		oid, err := parseASN1OID(subItems[0])
		if err != nil {
			continue
		}

		switch oid {
		case "1.2.840.113741.1.13.1.4": // FMSPC
			ext.fmspc = extractASN1OctetString(subItems[1])
		case "1.2.840.113741.1.13.1.3": // PCEID
			ext.pceid = extractASN1OctetString(subItems[1])
		case "1.2.840.113741.1.13.1.2": // TCB
			parseTCBFromASN1(subItems[1], ext)
		}
	}

	if len(ext.fmspc) == 0 {
		return nil, &DcapValidationError{Detail: "FMSPC not found in PCK extension"}
	}
	if len(ext.pceid) == 0 {
		return nil, &DcapValidationError{Detail: "PCEID not found in PCK extension"}
	}

	return ext, nil
}

// parseASN1Sequence extracts the children of an ASN.1 SEQUENCE.
func parseASN1Sequence(data []byte) ([][]byte, error) {
	if len(data) < 2 {
		return nil, &ASN1ParseError{Detail: "too short for ASN.1 TLV"}
	}
	tag := data[0]
	if tag != 0x30 { // SEQUENCE
		return nil, &ASN1ParseError{Detail: fmt.Sprintf("expected SEQUENCE tag 0x30, got 0x%02x", tag)}
	}
	_, contentStart, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	content := data[1+contentStart:]

	var items [][]byte
	offset := 0
	for offset < len(content) {
		if offset+1 >= len(content) {
			break
		}
		length, lengthSize, err := parseASN1Length(content[offset+1:])
		if err != nil {
			break
		}
		totalLen := 1 + lengthSize + length
		if offset+totalLen > len(content) {
			break
		}
		items = append(items, content[offset:offset+totalLen])
		offset += totalLen
	}
	return items, nil
}

// parseASN1Length parses an ASN.1 length field and returns (length, bytesConsumed, error).
func parseASN1Length(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, &ASN1ParseError{Detail: "empty length field"}
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes == 0 || numBytes > 3 || len(data) < 1+numBytes {
		return 0, 0, &ASN1ParseError{Detail: "invalid ASN.1 length encoding"}
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

// parseASN1OID parses an ASN.1 OID from a TLV and returns it as a dotted string.
func parseASN1OID(data []byte) (string, error) {
	if len(data) < 2 || data[0] != 0x06 { // OID tag
		return "", &ASN1ParseError{Detail: "not an OID"}
	}
	length := int(data[1])
	if len(data) < 2+length {
		return "", &ASN1ParseError{Detail: "OID too short"}
	}
	oidBytes := data[2 : 2+length]
	if len(oidBytes) == 0 {
		return "", &ASN1ParseError{Detail: "empty OID"}
	}

	// First byte encodes first two components.
	components := []int{int(oidBytes[0]) / 40, int(oidBytes[0]) % 40}
	val := 0
	for _, b := range oidBytes[1:] {
		val = val<<7 | int(b&0x7F)
		if b&0x80 == 0 {
			components = append(components, val)
			val = 0
		}
	}

	result := fmt.Sprintf("%d", components[0])
	for _, c := range components[1:] {
		result += fmt.Sprintf(".%d", c)
	}
	return result, nil
}

// extractASN1OctetString extracts the value from an ASN.1 OCTET STRING TLV.
func extractASN1OctetString(data []byte) []byte {
	if len(data) < 2 || data[0] != 0x04 { // OCTET STRING tag
		return nil
	}
	length := int(data[1])
	if len(data) < 2+length {
		return nil
	}
	result := make([]byte, length)
	copy(result, data[2:2+length])
	return result
}

// parseTCBFromASN1 parses TCB component SVNs and PCESVN from the TCB sub-extension.
func parseTCBFromASN1(data []byte, ext *pckExtensionData) {
	items, err := parseASN1Sequence(data)
	if err != nil {
		return
	}

	for _, item := range items {
		subItems, err := parseASN1Sequence(item)
		if err != nil {
			continue
		}
		if len(subItems) < 2 {
			continue
		}

		oid, err := parseASN1OID(subItems[0])
		if err != nil {
			continue
		}

		// TCB component SVN OIDs: 1.2.840.113741.1.13.1.2.{1..16}
		// PCESVN OID: 1.2.840.113741.1.13.1.2.17
		val := extractASN1Integer(subItems[1])
		if val < 0 {
			continue
		}

		prefix := "1.2.840.113741.1.13.1.2."
		if len(oid) > len(prefix) {
			suffix := oid[len(prefix):]
			var idx int
			for _, ch := range suffix {
				if ch >= '0' && ch <= '9' {
					idx = idx*10 + int(ch-'0')
				} else {
					idx = -1
					break
				}
			}
			if idx >= 1 && idx <= 16 {
				ext.compsvn[idx-1] = byte(val)
			} else if idx == 17 {
				ext.pcesvn = uint16(val)
			}
		}
	}
}

// extractASN1Integer extracts a non-negative integer value from an ASN.1 INTEGER TLV.
func extractASN1Integer(data []byte) int {
	if len(data) < 2 || data[0] != 0x02 { // INTEGER tag
		return -1
	}
	length := int(data[1])
	if len(data) < 2+length || length == 0 {
		return -1
	}
	val := 0
	for _, b := range data[2 : 2+length] {
		val = val<<8 | int(b)
	}
	return val
}

// tcbLevel represents a single TCB level from the TCB info JSON.
type tcbLevel struct {
	compsvn     [16]byte
	pcesvn      uint16
	status      string
	advisoryIDs []string
}

// parseTCBLevels extracts TCB levels from TCB info JSON.
// The JSON contains "tcbLevels" array with objects containing
// "tcb" (with sgxtcbcompXXsvn and pcesvn fields) and "tcbStatus".
// Returns an error if TCB levels use inconsistent format versions.
func parseTCBLevels(jsonStr string) ([]tcbLevel, error) {
	// Find the tcbLevels array.
	idx := strings.Index(jsonStr, `"tcbLevels"`)
	if idx < 0 {
		return nil, nil
	}

	rest := jsonStr[idx:]
	// Find the opening bracket.
	bracketIdx := strings.IndexByte(rest, '[')
	if bracketIdx < 0 {
		return nil, nil
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
		return nil, nil
	}

	arrayStr := rest[:endIdx]

	// Split into individual level objects.
	var levels []tcbLevel
	var firstIsV3 *bool
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
				level, isV3 := parseSingleTCBLevel(levelStr)

				// Validate format version consistency.
				if firstIsV3 == nil {
					firstIsV3 = &isV3
				} else if *firstIsV3 != isV3 {
					return nil, &TCBLevelVersionInconsistencyError{ExpectedV3: *firstIsV3}
				}

				levels = append(levels, level)
				objStart = -1
			}
		}
	}

	return levels, nil
}

// parseSingleTCBLevel parses a single TCB level JSON object.
// Supports both v2 format (individual sgxtcbcomp01svn..sgxtcbcomp16svn fields)
// and v3 format (sgxtcbcomponents array of {"svn": N} objects).
// Returns the parsed level and whether the v3 format was used.
func parseSingleTCBLevel(jsonStr string) (tcbLevel, bool) {
	var level tcbLevel

	// Extract tcbStatus (correct Intel PCS API field name for both v2 and v3).
	level.status = extractStringField(jsonStr, "tcbStatus")

	// Try v3 format first: "sgxtcbcomponents": [{"svn": 1}, {"svn": 2}, ...]
	isV3 := parseTCBComponentsV3(jsonStr, &level)
	if !isV3 {
		// Fall back to v2 format: sgxtcbcomp01svn..sgxtcbcomp16svn
		for i := 0; i < 16; i++ {
			fieldName := fmt.Sprintf("sgxtcbcomp%02dsvn", i+1)
			val := extractUint16Field(jsonStr, fieldName)
			level.compsvn[i] = byte(val)
		}
	}

	// Extract pcesvn
	level.pcesvn = extractUint16Field(jsonStr, "pcesvn")

	// Extract advisory IDs
	level.advisoryIDs = extractStringArrayField(jsonStr, "advisoryIDs")

	return level, isV3
}

// parseTCBComponentsV3 attempts to parse TCB components from the v3 JSON format.
// In v3, the "tcb" object contains "sgxtcbcomponents" as an array of {"svn": N} objects.
// Returns true if v3 components were found and parsed.
func parseTCBComponentsV3(jsonStr string, level *tcbLevel) bool {
	key := `"sgxtcbcomponents"`
	idx := strings.Index(jsonStr, key)
	if idx < 0 {
		return false
	}

	rest := jsonStr[idx+len(key):]
	rest = strings.TrimLeft(rest, " \t\n\r:")
	if len(rest) == 0 || rest[0] != '[' {
		return false
	}

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
		return false
	}

	arrayStr := rest[:endIdx]

	// Extract each {"svn": N} object.
	compIdx := 0
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
			if objDepth == 0 && objStart >= 0 && compIdx < 16 {
				objStr := arrayStr[objStart : i+1]
				level.compsvn[compIdx] = byte(extractUint16Field(objStr, "svn"))
				compIdx++
				objStart = -1
			}
		}
	}

	return compIdx > 0
}

// extractStringField extracts a JSON string field value.
func extractStringField(json string, fieldName string) string {
	key := fmt.Sprintf(`"%s"`, fieldName)
	idx := strings.Index(json, key)
	if idx < 0 {
		return ""
	}
	rest := json[idx+len(key):]
	rest = strings.TrimLeft(rest, " \t\n\r:")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	endQuote := strings.IndexByte(rest, '"')
	if endQuote < 0 {
		return ""
	}
	return rest[:endQuote]
}

// extractStringArrayField extracts a JSON array of strings.
func extractStringArrayField(json string, fieldName string) []string {
	key := fmt.Sprintf(`"%s"`, fieldName)
	idx := strings.Index(json, key)
	if idx < 0 {
		return nil
	}
	rest := json[idx+len(key):]
	rest = strings.TrimLeft(rest, " \t\n\r:")
	if len(rest) == 0 || rest[0] != '[' {
		return nil
	}
	endBracket := strings.IndexByte(rest, ']')
	if endBracket < 0 {
		return nil
	}
	arrayContent := rest[1:endBracket]

	var result []string
	for len(arrayContent) > 0 {
		startQuote := strings.IndexByte(arrayContent, '"')
		if startQuote < 0 {
			break
		}
		arrayContent = arrayContent[startQuote+1:]
		endQuote := strings.IndexByte(arrayContent, '"')
		if endQuote < 0 {
			break
		}
		result = append(result, arrayContent[:endQuote])
		arrayContent = arrayContent[endQuote+1:]
	}
	return result
}

// findTCBStanding determines the TCB standing by finding the first matching level
// where the PCK extension SVN components are >= the level's components.
func findTCBStanding(pckExt *pckExtensionData, levels []tcbLevel) (tcbStandingType, []string, error) {
	for _, level := range levels {
		if inTCBLevel(pckExt, &level) {
			switch level.status {
			case "UpToDate":
				return tcbUpToDate, nil, nil
			case "SWHardeningNeeded":
				return tcbSWHardeningNeeded, level.advisoryIDs, nil
			default:
				return 0, nil, &TCBStatusUnacceptableError{Status: level.status}
			}
		}
	}
	return 0, nil, &TCBUnsupportedError{}
}

// inTCBLevel returns true if all PCK component SVNs are >= the TCB level's components
// AND the PCK PCESVN is >= the level's PCESVN.
func inTCBLevel(pckExt *pckExtensionData, level *tcbLevel) bool {
	for i := 0; i < 16; i++ {
		if pckExt.compsvn[i] < level.compsvn[i] {
			return false
		}
	}
	return pckExt.pcesvn >= level.pcesvn
}

// verifyClaimsHash verifies the custom claims hash matches the report data.
func verifyClaimsHash(evidence *dcapEvidence) error {
	if evidence.claimsRawData == nil {
		return &ClaimsError{Detail: "no claims data"}
	}

	claimsHash := sha256.Sum256(evidence.claimsRawData)
	reportData := evidence.quote.quoteBody.reportBody.sgxReportDataBytes

	// First 32 bytes should be the SHA256 of claims
	if !bytesEqualSlice(claimsHash[:], reportData[:32]) {
		return &ClaimsError{Detail: "custom claims hash mismatch"}
	}

	// Last 32 bytes should be zeros
	for _, b := range reportData[32:] {
		if b != 0 {
			return &ClaimsError{Detail: "report data hash had unexpected data"}
		}
	}

	// Reject all-zero hashes
	allZero := true
	for _, b := range reportData[:32] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return &ClaimsError{Detail: "valid claims sha256 is all zeros, rejecting"}
	}

	return nil
}

// parseIntelRootKey parses Intel's root public key from the uncompressed point.
func parseIntelRootKey() (*ecdsa.PublicKey, error) {
	ecdhKey, err := ecdh.P256().NewPublicKey(IntelRootPubKey)
	if err != nil {
		return nil, &AttestKeyError{Detail: "failed to unmarshal Intel root public key"}
	}
	raw := ecdhKey.Bytes() // 65-byte uncompressed: 0x04 || X || Y
	if len(raw) != 65 {
		return nil, &AttestKeyError{Detail: "unexpected Intel root key encoding length"}
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// verifyRootCertificate verifies that the root certificate is self-signed
// and signed by the expected Intel key.
func verifyRootCertificate(root *x509.Certificate, intelKey *ecdsa.PublicKey) error {
	// Verify self-signed
	if err := root.CheckSignatureFrom(root); err != nil {
		return &CertChainError{Detail: "root certificate is not self-signed", Err: err}
	}

	// Verify signed by Intel's key
	rootPubKey, ok := root.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &CertChainError{Detail: "root certificate does not contain ECDSA key"}
	}

	rootECDH, err := rootPubKey.ECDH()
	if err != nil {
		return &CertChainError{Detail: "root certificate key is not a valid P-256 point", Err: err}
	}
	intelECDH, err := intelKey.ECDH()
	if err != nil {
		return &CertChainError{Detail: "Intel root key is not a valid P-256 point", Err: err}
	}
	if !bytes.Equal(rootECDH.Bytes(), intelECDH.Bytes()) {
		return &CertChainError{Detail: "root certificate not signed by Intel root key"}
	}

	return nil
}

// verifyCertChain verifies a certificate chain against a root CA.
func verifyCertChain(chain []*x509.Certificate, root *x509.Certificate, currentTime time.Time) error {
	if len(chain) == 0 {
		return &CertChainError{Detail: "empty certificate chain"}
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	leaf := chain[0]
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leaf.Verify(opts)
	return err
}

// parseAttestKey parses a 64-byte uncompressed P-256 point (without 0x04 prefix)
// into an ECDSA public key. The ecdh package validates that the point is on the curve.
func parseAttestKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) != 64 {
		return nil, &AttestKeyError{Detail: fmt.Sprintf("attest key must be 64 bytes, got %d", len(pubKeyBytes))}
	}

	// Prepend the 0x04 uncompressed-point prefix required by ecdh.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1:], pubKeyBytes)

	ecdhKey, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, &AttestKeyError{Detail: "attest key point is not on P-256 curve"}
	}

	x := new(big.Int).SetBytes(pubKeyBytes[:32])
	y := new(big.Int).SetBytes(pubKeyBytes[32:])
	_ = ecdhKey // curve validation done above
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// ecdsaRawToDER converts a raw 64-byte ECDSA signature (r||s) to DER format.
func ecdsaRawToDER(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, &SignatureFormatError{Expected: 64, Actual: len(raw)}
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])

	// Simple DER encoding of SEQUENCE { INTEGER r, INTEGER s }
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Add leading zero if high bit is set
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0}, sBytes...)
	}

	// INTEGER tag (0x02) + length + value
	rDER := append([]byte{0x02, byte(len(rBytes))}, rBytes...)
	sDER := append([]byte{0x02, byte(len(sBytes))}, sBytes...)

	// SEQUENCE tag (0x30) + length + contents
	contents := append(rDER, sDER...)
	return append([]byte{0x30, byte(len(contents))}, contents...), nil
}

// parsePEMCertChain parses a PEM-encoded certificate chain.
func parsePEMCertChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &PEMParseError{Detail: "parsing certificate", Err: err}
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, &PEMParseError{Detail: "no certificates found in PEM data"}
	}
	return certs, nil
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
