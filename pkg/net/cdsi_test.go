package net

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCdsiLookupResponseEntry_HasACI(t *testing.T) {
	t.Run("has ACI", func(t *testing.T) {
		e := &CdsiLookupResponseEntry{ACI: [16]byte{1}}
		if !e.HasACI() {
			t.Error("expected HasACI=true")
		}
	})

	t.Run("no ACI", func(t *testing.T) {
		e := &CdsiLookupResponseEntry{}
		if e.HasACI() {
			t.Error("expected HasACI=false")
		}
	})
}

func TestCdsiLookupResponseEntry_HasPNI(t *testing.T) {
	t.Run("has PNI", func(t *testing.T) {
		e := &CdsiLookupResponseEntry{PNI: [16]byte{1}}
		if !e.HasPNI() {
			t.Error("expected HasPNI=true")
		}
	})

	t.Run("no PNI", func(t *testing.T) {
		e := &CdsiLookupResponseEntry{}
		if e.HasPNI() {
			t.Error("expected HasPNI=false")
		}
	})
}

func TestCdsiLookupError(t *testing.T) {
	tests := []struct {
		name string
		err  *CdsiLookupError
		want string
	}{
		{
			"attestation failed",
			&CdsiLookupError{Kind: CdsiLookupErrorAttestationFailed, Err: errors.New("bad")},
			"cdsi: attestation failed: bad",
		},
		{
			"rate limited",
			&CdsiLookupError{Kind: CdsiLookupErrorRateLimited, RetryAfter: 5 * time.Second},
			fmt.Sprintf("cdsi: rate limited, retry after %v", 5*time.Second),
		},
		{
			"invalid token",
			&CdsiLookupError{Kind: CdsiLookupErrorInvalidToken},
			"cdsi: invalid token",
		},
		{
			"invalid argument",
			&CdsiLookupError{Kind: CdsiLookupErrorInvalidArgument, ServerReason: "bad input"},
			"cdsi: invalid argument: bad input",
		},
		{
			"server error",
			&CdsiLookupError{Kind: CdsiLookupErrorServer, Err: errors.New("internal")},
			"cdsi: server error: internal",
		},
		{
			"unknown with err",
			&CdsiLookupError{Kind: CdsiLookupErrorTransport, Err: errors.New("timeout")},
			"cdsi: timeout",
		},
		{
			"unknown without err",
			&CdsiLookupError{Kind: CdsiLookupErrorTransport},
			"cdsi: unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCdsiLookupError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &CdsiLookupError{Err: inner}
	if err.Unwrap() != inner {
		t.Error("Unwrap mismatch")
	}
}

// TestE164Bytes verifies the E.164 big-endian wire encoding matches the Rust
// FixedLengthSerializable implementation (rust/net/src/cdsi.rs, SERIALIZED_LEN=8).
func TestE164Bytes(t *testing.T) {
	e := E164(18005551001)
	b := e.Bytes()
	if len(b) != E164SerializedLen {
		t.Fatalf("Bytes len = %d, want %d", len(b), E164SerializedLen)
	}
	want := make([]byte, 8)
	binary.BigEndian.PutUint64(want, 18005551001)
	if !bytes.Equal(b[:], want) {
		t.Errorf("Bytes = %x, want %x", b, want)
	}
}

// TestE164FromBytes_Valid round-trips an E164 through Bytes/FromBytes.
func TestE164FromBytes_Valid(t *testing.T) {
	orig := E164(12025550199)
	b := orig.Bytes()
	got, err := E164FromBytes(b)
	if err != nil {
		t.Fatalf("E164FromBytes error: %v", err)
	}
	if got != orig {
		t.Errorf("got %d, want %d", got, orig)
	}
}

// TestE164FromBytes_Zero verifies that a zero-valued E164 wire form is rejected.
func TestE164FromBytes_Zero(t *testing.T) {
	var b [E164SerializedLen]byte
	_, err := E164FromBytes(b)
	if err == nil {
		t.Fatal("expected error for zero E164, got nil")
	}
	var serr *CdsiSerializeError
	if !errors.As(err, &serr) {
		t.Errorf("expected *CdsiSerializeError, got %T", err)
	}
}

// TestAciAndAccessKeyBytes verifies the 32-byte wire encoding: ACI || access_key.
// Matches rust/net/src/cdsi.rs AciAndAccessKey::serialize_into.
func TestAciAndAccessKeyBytes(t *testing.T) {
	pair := AciAndAccessKey{
		ACI:       [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		AccessKey: [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	b := pair.Bytes()
	if len(b) != AciAndAccessKeySerializedLen {
		t.Fatalf("len = %d, want %d", len(b), AciAndAccessKeySerializedLen)
	}
	if !bytes.Equal(b[:16], pair.ACI[:]) {
		t.Errorf("first 16 bytes (ACI) mismatch")
	}
	if !bytes.Equal(b[16:], pair.AccessKey[:]) {
		t.Errorf("last 16 bytes (AccessKey) mismatch")
	}
}

// TestCdsiLookupResponseEntryBytes verifies the 40-byte wire encoding:
// E164 (8 BE) || PNI (16) || ACI (16).
// Layout matches rust/net/src/cdsi.rs LookupResponseEntry::serialize_into.
func TestCdsiLookupResponseEntryBytes(t *testing.T) {
	entry := CdsiLookupResponseEntry{
		E164: 18005551001,
		PNI:  [16]byte{0x10, 0x20},
		ACI:  [16]byte{0x30, 0x40},
	}
	b := entry.Bytes()
	if len(b) != LookupResponseEntrySerializedLen {
		t.Fatalf("len = %d, want %d", len(b), LookupResponseEntrySerializedLen)
	}
	wantE164 := make([]byte, 8)
	binary.BigEndian.PutUint64(wantE164, uint64(entry.E164))
	if !bytes.Equal(b[:8], wantE164) {
		t.Errorf("E164 bytes mismatch: got %x, want %x", b[:8], wantE164)
	}
	if !bytes.Equal(b[8:24], entry.PNI[:]) {
		t.Errorf("PNI bytes mismatch")
	}
	if !bytes.Equal(b[24:], entry.ACI[:]) {
		t.Errorf("ACI bytes mismatch")
	}
}

// TestLookupResponseEntryFromBytes round-trips an entry through Bytes/FromBytes.
func TestLookupResponseEntryFromBytes(t *testing.T) {
	orig := CdsiLookupResponseEntry{
		E164: 12025550199,
		PNI:  [16]byte{0xaa},
		ACI:  [16]byte{0xbb},
	}
	b := orig.Bytes()
	got, err := LookupResponseEntryFromBytes(b)
	if err != nil {
		t.Fatalf("FromBytes error: %v", err)
	}
	if got.E164 != orig.E164 || got.PNI != orig.PNI || got.ACI != orig.ACI {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, orig)
	}
}

// TestDeserializeLookupResponseEntries_Valid verifies packed multi-record decoding.
func TestDeserializeLookupResponseEntries_Valid(t *testing.T) {
	e1 := CdsiLookupResponseEntry{E164: 18005551001, PNI: [16]byte{1}, ACI: [16]byte{2}}
	e2 := CdsiLookupResponseEntry{E164: 12025550199, PNI: [16]byte{3}, ACI: [16]byte{4}}

	b1 := e1.Bytes()
	b2 := e2.Bytes()
	packed := append(b1[:], b2[:]...)

	entries, err := DeserializeLookupResponseEntries(packed)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len = %d, want 2", len(entries))
	}
	if entries[0].E164 != e1.E164 || entries[1].E164 != e2.E164 {
		t.Errorf("E164 mismatch")
	}
}

// TestDeserializeLookupResponseEntries_BadLength verifies that non-multiple-of-40
// input is rejected.
func TestDeserializeLookupResponseEntries_BadLength(t *testing.T) {
	_, err := DeserializeLookupResponseEntries(make([]byte, 41))
	if err == nil {
		t.Fatal("expected error for 41 bytes, got nil")
	}
	var serr *CdsiSerializeError
	if !errors.As(err, &serr) {
		t.Errorf("expected *CdsiSerializeError, got %T", err)
	}
}

// TestDeserializeLookupResponseEntries_ZeroE164Skipped mirrors Rust behaviour:
// a zero-E164 record is silently skipped by try_parse_from.
func TestDeserializeLookupResponseEntries_ZeroE164Skipped(t *testing.T) {
	// Build a 40-byte block with zero E164 (all zeros).
	var zeroEntry [LookupResponseEntrySerializedLen]byte
	good := CdsiLookupResponseEntry{E164: 18005551001}
	goodBytes := good.Bytes()
	packed := append(zeroEntry[:], goodBytes[:]...)

	entries, err := DeserializeLookupResponseEntries(packed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The zero-E164 entry is skipped; only the good one survives.
	if len(entries) != 1 {
		t.Errorf("len = %d, want 1 (zero-E164 entry should be skipped)", len(entries))
	}
}

// TestSerializeE164s verifies SerializeE164s packs big-endian values correctly.
func TestSerializeE164s(t *testing.T) {
	e164s := []E164{18005551001, 12025550199}
	b := SerializeE164s(e164s)
	if len(b) != len(e164s)*E164SerializedLen {
		t.Fatalf("len = %d, want %d", len(b), len(e164s)*E164SerializedLen)
	}
	for i, e := range e164s {
		got := binary.BigEndian.Uint64(b[i*8:])
		if E164(got) != e {
			t.Errorf("[%d] got %d, want %d", i, got, e)
		}
	}
}

// TestSerializeAciAndAccessKeys verifies SerializeAciAndAccessKeys packs pairs correctly.
func TestSerializeAciAndAccessKeys(t *testing.T) {
	pairs := []AciAndAccessKey{
		{ACI: [16]byte{1}, AccessKey: [16]byte{0xaa}},
		{ACI: [16]byte{2}, AccessKey: [16]byte{0xbb}},
	}
	b := SerializeAciAndAccessKeys(pairs)
	if len(b) != len(pairs)*AciAndAccessKeySerializedLen {
		t.Fatalf("len = %d, want %d", len(b), len(pairs)*AciAndAccessKeySerializedLen)
	}
	// First pair's ACI at offset 0.
	if !bytes.Equal(b[:16], pairs[0].ACI[:]) {
		t.Errorf("first ACI mismatch")
	}
}

// TestCdsiSerializeError_Error verifies the typed error message format.
func TestCdsiSerializeError_Error(t *testing.T) {
	err := &CdsiSerializeError{Field: "E164", Msg: "zero is not valid"}
	got := err.Error()
	want := "cdsi: serialize error on E164: zero is not valid"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
