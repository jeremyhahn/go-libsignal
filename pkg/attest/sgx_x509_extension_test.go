// SGX X.509 extension DER fixture test.
//
// Loads the binary fixture tests/interop/fixtures/attest/sgx_x509_extension.der
// (verbatim copy of rust/attest/tests/data/sgx_x509_extension.der) and parses
// it via parseSGXExtensionASN1. Asserts that the structural fields match the
// values asserted by Rust's test_deserialization:
//
//	ext.pceid      == [0x00, 0x00]   (rust: ext.pceid)
//	ext.pcesvn     == 11             (rust: ext.tcb.pcesvn)
//	ext.compsvn[0] == 4              (rust: ext.tcb.compsvn[0])
//
// Rust source: rust/attest/src/dcap/sgx_x509.rs:392 (test_deserialization)
// Upstream commit: 98915c44
package attest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// readSGXFixture reads the sgx_x509_extension.der binary fixture from the
// tests/interop/fixtures/attest/ directory, located relative to this source file.
func readSGXFixture(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate fixture")
	}
	// pkg/attest/sgx_x509_extension_test.go → tests/interop/fixtures/attest/
	root := filepath.Join(filepath.Dir(file), "..", "..", "tests", "interop", "fixtures", "attest")
	path := filepath.Join(root, "sgx_x509_extension.der")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SGX extension fixture %q: %v", path, err)
	}
	return data
}

// TestParseSGXExtensionASN1_UpstreamDERFixture parses the upstream
// sgx_x509_extension.der and asserts the structural fields that Rust's
// test_deserialization verifies (rust/attest/src/dcap/sgx_x509.rs:392).
//
// Assertions:
//
//	pceid   == [0x00, 0x00]  (rust: ext.pceid == [0u8, 0u8])
//	pcesvn  == 11             (rust: ext.tcb.pcesvn == 11)
//	compsvn[0] == 4          (rust: ext.tcb.compsvn[0] == 4)
func TestParseSGXExtensionASN1_UpstreamDERFixture(t *testing.T) {
	derBytes := readSGXFixture(t)
	if len(derBytes) == 0 {
		t.Fatal("sgx_x509_extension.der is empty")
	}

	ext, err := parseSGXExtensionASN1(derBytes)
	if err != nil {
		t.Fatalf("parseSGXExtensionASN1: %v", err)
	}

	// pceid must be [0x00, 0x00] (Rust: ext.pceid == [0u8, 0u8])
	if len(ext.pceid) != 2 {
		t.Fatalf("pceid length = %d, want 2", len(ext.pceid))
	}
	if ext.pceid[0] != 0x00 || ext.pceid[1] != 0x00 {
		t.Errorf("pceid = [%02x %02x], want [00 00]", ext.pceid[0], ext.pceid[1])
	}

	// pcesvn must be 11 (Rust: ext.tcb.pcesvn == 11)
	if ext.pcesvn != 11 {
		t.Errorf("pcesvn = %d, want 11", ext.pcesvn)
	}

	// compsvn[0] must be 4 (Rust: ext.tcb.compsvn[0] == 4)
	if ext.compsvn[0] != 4 {
		t.Errorf("compsvn[0] = %d, want 4", ext.compsvn[0])
	}
}

// TestParseSGXExtensionASN1_UpstreamDERFixture_FMSPCSanity asserts structural
// sanity beyond the three Rust-reference fields: FMSPC must be present and
// exactly 6 bytes per the Intel SGX PCK certificate extension specification.
func TestParseSGXExtensionASN1_UpstreamDERFixture_FMSPCSanity(t *testing.T) {
	derBytes := readSGXFixture(t)

	ext, err := parseSGXExtensionASN1(derBytes)
	if err != nil {
		t.Fatalf("parseSGXExtensionASN1: %v", err)
	}

	if len(ext.fmspc) == 0 {
		t.Error("fmspc must not be empty in the fixture")
	}
	if len(ext.fmspc) != 6 {
		t.Errorf("fmspc length = %d, want 6", len(ext.fmspc))
	}
}
