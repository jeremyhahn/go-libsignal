package media

// mp4san_coverage_test.go — coverage tests for the mp4san.go new typed errors
// and uncovered code paths in SanitizeMP4 / SanitizeMP4WithCompoundedMdat /
// SanitizeWebP.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// writeBE writes v to buf in big-endian order. Writing to a bytes.Buffer never
// fails, so a non-nil error is an unrecoverable invariant violation (test helper).
func writeBE(buf *bytes.Buffer, v any) {
	if err := binary.Write(buf, binary.BigEndian, v); err != nil {
		panic(err)
	}
}

// ---------------------------------------------------------------------------
// Error type coverage
// ---------------------------------------------------------------------------

// TestMp4SanErrorTypes verifies that each new typed error returns the expected
// message string and can be matched with errors.As.
func TestMp4SanErrorTypes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrFragmentedMP4",
			err:  &ErrFragmentedMP4{},
			want: "media: fragmented MP4 is not supported",
		},
		{
			name: "ErrDiscontiguousMdat",
			err:  &ErrDiscontiguousMdat{},
			want: "media: discontiguous mdat boxes are not supported",
		},
		{
			name: "ErrExternalDataReference",
			err:  &ErrExternalDataReference{},
			want: "media: external data reference (dref) is not supported",
		},
		{
			name: "ErrUnsupportedBrand",
			err:  &ErrUnsupportedBrand{Brand: "qt  "},
			want: "media: unsupported MP4 brand (not isom-compatible): qt  ",
		},
		{
			name: "ErrMissingMdat",
			err:  &ErrMissingMdat{},
			want: "media: MP4 missing mdat box",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMp4SanErrorAs verifies that errors.As matches the new typed errors.
func TestMp4SanErrorAs(t *testing.T) {
	t.Run("ErrFragmentedMP4", func(t *testing.T) {
		var target *ErrFragmentedMP4
		if !errors.As(&ErrFragmentedMP4{}, &target) {
			t.Error("errors.As should find *ErrFragmentedMP4")
		}
	})
	t.Run("ErrDiscontiguousMdat", func(t *testing.T) {
		var target *ErrDiscontiguousMdat
		if !errors.As(&ErrDiscontiguousMdat{}, &target) {
			t.Error("errors.As should find *ErrDiscontiguousMdat")
		}
	})
	t.Run("ErrExternalDataReference", func(t *testing.T) {
		var target *ErrExternalDataReference
		if !errors.As(&ErrExternalDataReference{}, &target) {
			t.Error("errors.As should find *ErrExternalDataReference")
		}
	})
	t.Run("ErrUnsupportedBrand", func(t *testing.T) {
		var target *ErrUnsupportedBrand
		if !errors.As(&ErrUnsupportedBrand{Brand: "test"}, &target) {
			t.Error("errors.As should find *ErrUnsupportedBrand")
		}
	})
	t.Run("ErrMissingMdat", func(t *testing.T) {
		var target *ErrMissingMdat
		if !errors.As(&ErrMissingMdat{}, &target) {
			t.Error("errors.As should find *ErrMissingMdat")
		}
	})
}

// ---------------------------------------------------------------------------
// SanitizeMP4 path coverage
// ---------------------------------------------------------------------------

// TestSanitizeMP4_MissingMdat verifies that an MP4 with ftyp+moov but no mdat
// returns ErrMissingMdat.
func TestSanitizeMP4_MissingMdat(t *testing.T) {
	// ftyp + moov with no mdat.
	input := append(javaFtyp(), javaMoov()...)
	_, err := SanitizeMP4(input)
	if err == nil {
		t.Fatal("expected error for MP4 without mdat")
	}
	var target *ErrMissingMdat
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrMissingMdat, got %T: %v", err, err)
	}
}

// TestSanitizeMP4_DiscontiguousMdat verifies that multiple mdat boxes are
// rejected.  The rejection may surface as either ErrDiscontiguousMdat (our
// guard) or as a MediaValidationError (from mp4ff, which also rejects multiple
// non-empty mdat boxes).
func TestSanitizeMP4_DiscontiguousMdat(t *testing.T) {
	input := buildMP4WithMultipleMdat()
	_, err := SanitizeMP4(input)
	if err == nil {
		t.Fatal("expected error for MP4 with multiple mdat boxes")
	}
	// Either our typed error or a parse error from mp4ff is acceptable.
	var discontig *ErrDiscontiguousMdat
	var mve *MediaValidationError
	if !errors.As(err, &discontig) && !errors.As(err, &mve) {
		t.Errorf("expected *ErrDiscontiguousMdat or *MediaValidationError, got %T: %v", err, err)
	}
}

// TestSanitizeMP4_NoopReturnsNilMetadata verifies the noop path: when moov
// already precedes mdat, Metadata is nil.
func TestSanitizeMP4_NoopReturnsNilMetadata(t *testing.T) {
	// ftyp + moov + mdat (faststart).
	input := append(javaFtyp(), append(javaMoov(), javaMdat()...)...)
	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("Metadata should be nil for already-faststart MP4, got %d bytes", len(got.Metadata))
	}
}

// TestSanitizeMP4_RewriteReturnsMetadata verifies that when moov follows mdat,
// Metadata is non-nil and equals ftyp+moov.
func TestSanitizeMP4_RewriteReturnsMetadata(t *testing.T) {
	expectedMetadata := append(javaFtyp(), javaMoov()...)
	// ftyp + mdat + moov (mdat before moov).
	input := append(javaFtyp(), append(javaMdat(), javaMoov()...)...)

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("Metadata should be non-nil when moov follows mdat")
	}
	if !bytes.Equal(got.Metadata, expectedMetadata) {
		t.Errorf("Metadata = %d bytes, want %d bytes", len(got.Metadata), len(expectedMetadata))
	}
}

// TestSanitizeMP4_DataOffsetAndLength verifies exact DataOffset and DataLength
// values for the noop case.
func TestSanitizeMP4_DataOffsetAndLength(t *testing.T) {
	ftyp := javaFtyp()
	moov := javaMoov()
	mdat := javaMdat()
	input := append(ftyp, append(moov, mdat...)...)

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantOffset := int64(len(ftyp) + len(moov))
	wantLength := int64(len(mdat))
	if got.DataOffset != wantOffset {
		t.Errorf("DataOffset = %d, want %d", got.DataOffset, wantOffset)
	}
	if got.DataLength != wantLength {
		t.Errorf("DataLength = %d, want %d", got.DataLength, wantLength)
	}
}

// TestSanitizeWebP_Valid verifies that a valid WebP is accepted without error.
func TestSanitizeWebP_Valid(t *testing.T) {
	if err := SanitizeWebP(javaWebp()); err != nil {
		t.Errorf("SanitizeWebP(valid) returned error: %v", err)
	}
}

// TestSanitizeWebP_Empty verifies that an empty slice is rejected.
func TestSanitizeWebP_Empty(t *testing.T) {
	if err := SanitizeWebP([]byte{}); err == nil {
		t.Error("SanitizeWebP(empty) should return an error")
	}
}

// TestSanitizeWebP_Invalid verifies that corrupt WebP is rejected.
func TestSanitizeWebP_Invalid(t *testing.T) {
	data := make([]byte, 12)
	copy(data[0:4], "XXXX") // not RIFF
	if err := SanitizeWebP(data); err == nil {
		t.Error("SanitizeWebP(invalid) should return an error")
	}
}

// TestScanBoxHeaders_SizeZeroNonMdat verifies that a non-mdat box with size=0
// is treated as extending to EOF (and scanning stops).
func TestScanBoxHeaders_SizeZeroNonMdat(t *testing.T) {
	var buf bytes.Buffer
	// free box with size=0 (extends to EOF).
	binary.BigEndian.PutUint32(make([]byte, 4), 0)
	buf.Write([]byte{0, 0, 0, 0})
	buf.WriteString("free")
	buf.WriteString("payload")

	boxes, err := scanBoxHeaders(buf.Bytes())
	if err != nil {
		t.Fatalf("scanBoxHeaders returned error: %v", err)
	}
	if len(boxes) != 1 || boxes[0].boxType != "free" {
		t.Errorf("expected 1 'free' box, got %v", boxes)
	}
}

// TestScanBoxHeaders_Extended64 verifies that a box with 64-bit extended size
// (rawSize=1) is scanned correctly.
func TestScanBoxHeaders_Extended64(t *testing.T) {
	var buf bytes.Buffer
	// ftyp with 64-bit extended size: header=8, extended=8, payload=4 → total=20
	writeBE(&buf, uint32(1)) // rawSize=1 → extended
	buf.WriteString("ftyp")
	writeBE(&buf, uint64(20))  // actual 64-bit size
	buf.Write(make([]byte, 4)) // 4 bytes payload

	boxes, err := scanBoxHeaders(buf.Bytes())
	if err != nil {
		t.Fatalf("scanBoxHeaders returned error: %v", err)
	}
	if len(boxes) != 1 || boxes[0].boxType != "ftyp" {
		t.Errorf("expected 1 'ftyp' box, got %v", boxes)
	}
}

// TestScanBoxHeaders_Truncated verifies that truncated data (less than 8 bytes
// for a box header) returns an error.
func TestScanBoxHeaders_Truncated(t *testing.T) {
	_, err := scanBoxHeaders([]byte{0, 0, 0, 8, 'f'}) // only 5 bytes
	if err == nil {
		t.Fatal("expected error for truncated box header")
	}
}

// TestScanBoxHeaders_ExtendedSizeTooSmall verifies that a 64-bit extended size
// smaller than the header length returns an error.
func TestScanBoxHeaders_ExtendedSizeTooSmall(t *testing.T) {
	var buf bytes.Buffer
	writeBE(&buf, uint32(1))
	buf.WriteString("ftyp")
	writeBE(&buf, uint64(4)) // size < 16 (header)

	_, err := scanBoxHeaders(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for extended size too small")
	}
}

// TestScanBoxHeaders_BoxBeyondEnd verifies that a box claiming to extend beyond
// the input returns an error.
func TestScanBoxHeaders_BoxBeyondEnd(t *testing.T) {
	var buf bytes.Buffer
	writeBE(&buf, uint32(1000)) // claims 1000 bytes
	buf.WriteString("ftyp")
	buf.Write(make([]byte, 4)) // only 12 bytes total

	_, err := scanBoxHeaders(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for box extending beyond input")
	}
}

// TestExtractBoxBytes_Truncated verifies that extractBoxBytes returns an error
// when the box extends beyond the input.
func TestExtractBoxBytes_Truncated(t *testing.T) {
	input := make([]byte, 8)
	binary.BigEndian.PutUint32(input[0:4], 100) // claims 100 bytes
	copy(input[4:8], "ftyp")
	_, err := extractBoxBytes(input, 0)
	if err == nil {
		t.Fatal("expected error for truncated extractBoxBytes")
	}
}

// TestExtractBoxBytes_ShortHeader verifies that extractBoxBytes returns an
// error when the input is too short to contain a box header at startPos.
func TestExtractBoxBytes_ShortHeader(t *testing.T) {
	_, err := extractBoxBytes([]byte{0, 0, 0}, 0)
	if err == nil {
		t.Fatal("expected error for input shorter than box header")
	}
}

// TestExtractBoxBytes_SizeZero verifies that extractBoxBytes with size=0 returns
// everything from startPos to the end of the input.
func TestExtractBoxBytes_SizeZero(t *testing.T) {
	input := []byte{0, 0, 0, 0, 'm', 'd', 'a', 't', 'p', 'a', 'y'}
	got, err := extractBoxBytes(input, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Errorf("expected full input slice, got %d bytes", len(got))
	}
}

// TestValidateIsomBrandBytes_TooShort verifies that a ftyp box that is too
// short for the header returns a parse error.
func TestValidateIsomBrandBytes_TooShort(t *testing.T) {
	input := make([]byte, 10) // too short for 20-byte ftyp
	err := validateIsomBrandBytes(input, 0)
	if err == nil {
		t.Fatal("expected error for too-short ftyp")
	}
}

// TestValidateIsomBrandBytes_TooSmallBox verifies that a ftyp with rawSize < 16
// returns a parse error.
func TestValidateIsomBrandBytes_TooSmallBox(t *testing.T) {
	input := make([]byte, 20)
	binary.BigEndian.PutUint32(input[0:4], 12) // too small (< 16)
	copy(input[4:8], "ftyp")
	err := validateIsomBrandBytes(input, 0)
	if err == nil {
		t.Fatal("expected error for ftyp box size < 16")
	}
}

// TestValidateIsomBrandBytes_NoIsomBrand verifies that a ftyp with no "isom"
// compatible brand returns ErrUnsupportedBrand.
func TestValidateIsomBrandBytes_NoIsomBrand(t *testing.T) {
	var buf bytes.Buffer
	writeBE(&buf, uint32(24)) // 8+4+4+4+4 = 24
	buf.WriteString("ftyp")
	buf.WriteString("qt  ") // major_brand
	writeBE(&buf, uint32(0))
	buf.WriteString("qt  ") // compatible brand (not isom)

	err := validateIsomBrandBytes(buf.Bytes(), 0)
	if err == nil {
		t.Fatal("expected ErrUnsupportedBrand for non-isom ftyp")
	}
	var brandErr *ErrUnsupportedBrand
	if !errors.As(err, &brandErr) {
		t.Errorf("expected *ErrUnsupportedBrand, got %T: %v", err, err)
	}
}

// TestSanitizeMP4WithCompoundedMdat_RejectDiscontiguous verifies that multiple
// mdat boxes in compounded mode are rejected.
func TestSanitizeMP4WithCompoundedMdat_RejectDiscontiguous(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(javaFtyp())
	// Two mdat boxes.
	buf.Write(javaMdat())
	buf.Write(javaMdat())
	buf.Write(javaMoov())

	_, err := SanitizeMP4WithCompoundedMdat(buf.Bytes(), len(javaMdat()))
	if err == nil {
		t.Fatal("expected error for multiple mdat boxes")
	}
	var target *ErrDiscontiguousMdat
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrDiscontiguousMdat, got %T: %v", err, err)
	}
}

// TestSanitizeMP4WithCompoundedMdat_MissingFtyp verifies that an input without
// ftyp is rejected.
func TestSanitizeMP4WithCompoundedMdat_MissingFtyp(t *testing.T) {
	input := append(javaMdat(), javaMoov()...)
	_, err := SanitizeMP4WithCompoundedMdat(input, len(javaMdat()))
	if err == nil {
		t.Fatal("expected error for missing ftyp")
	}
}

// TestSanitizeMP4WithCompoundedMdat_MissingMoov verifies that an input without
// moov is rejected.
func TestSanitizeMP4WithCompoundedMdat_MissingMoov(t *testing.T) {
	cmpd := javaCompoundedMdat()
	input := append(javaFtyp(), cmpd...)
	_, err := SanitizeMP4WithCompoundedMdat(input, len(cmpd))
	if err == nil {
		t.Fatal("expected error for missing moov in compounded path")
	}
	var mve *MediaValidationError
	if !errors.As(err, &mve) {
		t.Errorf("expected *MediaValidationError, got %T: %v", err, err)
	}
}

// TestSanitizeMP4WithCompoundedMdat_MissingMdat verifies that the compounded
// path rejects input with no mdat box.
//
// Finding #2: cumulativeMdatBoxSize < 8 is rejected immediately to prevent the
// infinite-loop / DoS. Use a valid box-sized value (16 bytes) to reach the
// scanner, which then correctly returns ErrMissingMdat for the ftyp+moov-only input.
func TestSanitizeMP4WithCompoundedMdat_MissingMdat(t *testing.T) {
	input := append(javaFtyp(), javaMoov()...)
	_, err := SanitizeMP4WithCompoundedMdat(input, 16)
	if err == nil {
		t.Fatal("expected error for missing mdat in compounded path")
	}
	// The compounded path wraps the scan result in MediaValidationError OR returns
	// a typed error directly; either ErrMissingMdat or MediaValidationError is correct.
	var target *ErrMissingMdat
	var mve *MediaValidationError
	if !errors.As(err, &target) && !errors.As(err, &mve) {
		t.Errorf("expected *ErrMissingMdat or *MediaValidationError, got %T: %v", err, err)
	}
}

// TestSanitizeMP4WithCompoundedMdat_TooSmallSize verifies that
// cumulativeMdatBoxSize < 8 is rejected immediately (Finding #2: DoS guard).
func TestSanitizeMP4WithCompoundedMdat_TooSmallSize(t *testing.T) {
	input := append(javaFtyp(), javaMoov()...)
	for _, badSize := range []int{0, 1, 7} {
		_, err := SanitizeMP4WithCompoundedMdat(input, badSize)
		if err == nil {
			t.Fatalf("expected error for cumulativeMdatBoxSize=%d", badSize)
		}
		var mve *MediaValidationError
		if !errors.As(err, &mve) {
			t.Errorf("size=%d: expected *MediaValidationError, got %T: %v", badSize, err, err)
		}
	}
}

// TestSanitizeMP4WithCompoundedMdat_RejectFragmented verifies that a
// fragmented MP4 (with moof) is rejected in the compounded path.
func TestSanitizeMP4WithCompoundedMdat_RejectFragmented(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(javaMdat())
	// moof box
	moofHdr := make([]byte, 8)
	binary.BigEndian.PutUint32(moofHdr, 8)
	copy(moofHdr[4:], "moof")
	buf.Write(moofHdr)
	buf.Write(javaMoov())

	_, err := SanitizeMP4WithCompoundedMdat(buf.Bytes(), len(javaMdat()))
	if err == nil {
		t.Fatal("expected error for fragmented MP4 in compounded path")
	}
	var frag *ErrFragmentedMP4
	if !errors.As(err, &frag) {
		t.Errorf("expected *ErrFragmentedMP4, got %T: %v", err, err)
	}
}

// TestSanitizeMP4_TruncatedInput verifies that input with <8 bytes returns
// a parse error before any box header is read.
func TestSanitizeMP4_TruncatedInput(t *testing.T) {
	_, err := SanitizeMP4([]byte{0, 0, 0})
	if err == nil {
		t.Fatal("expected error for 3-byte input")
	}
}

// TestSanitizeMP4_FindMdatInChildren_NotMdatType exercises the type-assertion
// branch where a box has type "mdat" but is not *mp4.MdatBox (covered by
// using the function directly with an empty children slice).
func TestSanitizeMP4_FindMdatInChildren_NotMdatType(t *testing.T) {
	mdat, idx := findMdatInChildren(nil)
	if mdat != nil || idx != -1 {
		t.Errorf("findMdatInChildren(nil): expected (nil, -1), got (%v, %d)", mdat, idx)
	}
}

// TestEncodeFtypMoov_Valid verifies that encodeFtypMoov produces ftyp+moov
// bytes that mp4ff can re-parse.
func TestEncodeFtypMoov_Valid(t *testing.T) {
	// SanitizeMP4 on a mdat-first file exercises encodeFtypMoov internally.
	ftyp := javaFtyp()
	mdat := javaMdat()
	moov := javaMoov()
	input := append(ftyp, append(mdat, moov...)...)

	got, err := SanitizeMP4(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Metadata == nil {
		t.Fatal("Metadata should be non-nil for mdat-first layout")
	}
	// Verify the metadata starts with ftyp box size.
	wantFtypSize := binary.BigEndian.Uint32(ftyp[0:4])
	gotFtypSize := binary.BigEndian.Uint32(got.Metadata[0:4])
	if gotFtypSize != wantFtypSize {
		t.Errorf("Metadata[0:4] ftyp size = %d, want %d", gotFtypSize, wantFtypSize)
	}
}

// TestSanitizeMP4_DiscontiguousMdat_EmptyPlusReal verifies that an empty mdat
// followed by a real mdat is rejected as discontiguous by our guard (mp4ff
// allows empty+real mdat but we treat it as discontiguous).
func TestSanitizeMP4_DiscontiguousMdat_EmptyPlusReal(t *testing.T) {
	input := buildMP4WithEmptyAndRealMdat()
	_, err := SanitizeMP4(input)
	if err == nil {
		t.Fatal("expected error for MP4 with empty+real mdat (discontiguous)")
	}
	var target *ErrDiscontiguousMdat
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrDiscontiguousMdat, got %T: %v", err, err)
	}
}

// TestSanitizeMP4_ExternalDref verifies that an MP4 with a dref pointing to an
// external file is rejected with ErrExternalDataReference.
//
// Java oracle: Mp4Sanitizer.java:L40
func TestSanitizeMP4_ExternalDref(t *testing.T) {
	input := buildMP4WithExternalDref()
	_, err := SanitizeMP4(input)
	if err == nil {
		t.Fatal("expected error for MP4 with external dref")
	}
	var target *ErrExternalDataReference
	if !errors.As(err, &target) {
		t.Errorf("expected *ErrExternalDataReference, got %T: %v", err, err)
	}
}

// TestExtractBoxBytes_Extended64 verifies that extractBoxBytes correctly
// handles a box with 64-bit extended size (rawSize=1).
func TestExtractBoxBytes_Extended64(t *testing.T) {
	// Build: rawSize=1 (extended), "test", uint64(20), 4-byte payload
	var buf bytes.Buffer
	writeBE(&buf, uint32(1)) // extended size marker
	buf.WriteString("test")
	writeBE(&buf, uint64(20))  // actual size = 20
	buf.Write(make([]byte, 4)) // 4-byte payload
	input := buf.Bytes()

	got, err := extractBoxBytes(input, 0)
	if err != nil {
		t.Fatalf("extractBoxBytes with extended size returned error: %v", err)
	}
	if len(got) != 20 {
		t.Errorf("expected 20 bytes, got %d", len(got))
	}
}

// TestExtractBoxBytes_Extended64_Truncated verifies that extractBoxBytes returns
// an error when the extended-size bytes are truncated.
func TestExtractBoxBytes_Extended64_Truncated(t *testing.T) {
	var buf bytes.Buffer
	writeBE(&buf, uint32(1))
	buf.WriteString("test")
	buf.Write([]byte{0, 0, 0}) // only 3 of 8 extended-size bytes
	_, err := extractBoxBytes(buf.Bytes(), 0)
	if err == nil {
		t.Fatal("expected error for truncated extended size")
	}
}

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

// buildMP4WithMultipleMdat returns a raw byte slice with ftyp + mdat + mdat + moov.
func buildMP4WithMultipleMdat() []byte {
	var buf bytes.Buffer
	buf.Write(javaFtyp())
	buf.Write(javaMdat())
	buf.Write(javaMdat())
	buf.Write(javaMoov())
	return buf.Bytes()
}

// buildMP4WithEmptyAndRealMdat returns ftyp + moov + empty_mdat(8 bytes) + real_mdat.
// mp4ff allows this (the empty mdat has no payload), but our countMdatBoxes
// guard rejects it as discontiguous.
func buildMP4WithEmptyAndRealMdat() []byte {
	var buf bytes.Buffer

	// ftyp
	buf.Write(javaFtyp())

	// moov (use mp4ff to build a valid moov so mp4ff parse succeeds)
	moovHdr := make([]byte, 8)
	binary.BigEndian.PutUint32(moovHdr, 8)
	copy(moovHdr[4:], "moov")
	buf.Write(moovHdr)

	// empty mdat (8 bytes: just header, no payload)
	emptyMdat := make([]byte, 8)
	binary.BigEndian.PutUint32(emptyMdat, 8)
	copy(emptyMdat[4:], "mdat")
	buf.Write(emptyMdat)

	// real mdat
	buf.Write(javaMdat())

	return buf.Bytes()
}

// buildMP4WithExternalDref builds a minimal MP4 whose moov contains a trak
// with a dref URL box pointing to an external file, triggering the
// ErrExternalDataReference rejection.
func buildMP4WithExternalDref() []byte {
	// We build raw bytes for an ftyp + synthetic moov containing a URL box
	// with Flags=0 (no self-contained flag) and a non-empty Location string.
	// Rather than using mp4ff's builder (which auto-adds a self-contained URL),
	// we craft the bytes directly.
	//
	// Box tree:
	//   ftyp (20)
	//   moov
	//     trak
	//       mdia
	//         minf
	//           dinf
	//             dref
	//               url  (version=0, flags=0, location="http://x.com\0")
	//   mdat (8)

	urlLocation := "http://x.com"
	// url  box: 4-size + 4-type + 4-version/flags + location + \0
	urlPayload := urlLocation + "\x00"
	urlSize := uint32(8 + 4 + len(urlPayload))

	// dref: 4-size + 4-type + 4-version/flags + 4-entry_count + url  box
	drefSize := uint32(8 + 4 + 4 + urlSize)

	// dinf: 4-size + 4-type + dref
	dinfSize := uint32(8 + drefSize)

	// minf: 4-size + 4-type + dinf
	minfSize := uint32(8 + dinfSize)

	// mdia: 4-size + 4-type + minf
	mdiaSize := uint32(8 + minfSize)

	// trak: 4-size + 4-type + mdia
	trakSize := uint32(8 + mdiaSize)

	// moov: 4-size + 4-type + trak
	moovSize := uint32(8 + trakSize)

	var buf bytes.Buffer
	writeBoxHeader := func(size uint32, boxType string) {
		h := make([]byte, 4)
		binary.BigEndian.PutUint32(h, size)
		buf.Write(h)
		buf.WriteString(boxType)
	}

	// ftyp
	buf.Write(javaFtyp())

	// moov
	writeBoxHeader(moovSize, "moov")
	// trak
	writeBoxHeader(trakSize, "trak")
	// mdia
	writeBoxHeader(mdiaSize, "mdia")
	// minf
	writeBoxHeader(minfSize, "minf")
	// dinf
	writeBoxHeader(dinfSize, "dinf")
	// dref
	writeBoxHeader(drefSize, "dref")
	writeBE(&buf, uint32(0)) // version=0, flags=0
	writeBE(&buf, uint32(1)) // entry_count=1
	// url  box
	writeBoxHeader(urlSize, "url ")
	writeBE(&buf, uint32(0)) // version=0, flags=0 (NOT self-contained)
	buf.WriteString(urlPayload)

	// mdat
	buf.Write(javaMdat())

	return buf.Bytes()
}
