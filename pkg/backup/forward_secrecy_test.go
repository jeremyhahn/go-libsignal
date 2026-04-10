package backup

import (
	"bytes"
	"strings"
	"testing"
)

func TestMagicNumber(t *testing.T) {
	if len(MagicNumber) != MagicNumberLen {
		t.Errorf("MagicNumber length = %d, want %d", len(MagicNumber), MagicNumberLen)
	}
	if MagicNumber != "SBACKUP\x01" {
		t.Errorf("MagicNumber = %q, want %q", MagicNumber, "SBACKUP\x01")
	}
}

func TestIsMagicNumber(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"exact match", []byte("SBACKUP\x01"), true},
		{"with trailing data", []byte("SBACKUP\x01extra"), true},
		{"wrong version", []byte("SBACKUP\x02"), false},
		{"too short", []byte("SBACKUP"), false},
		{"empty", nil, false},
		{"completely wrong", []byte("XXXXXXXX"), false},
		{"partial match", []byte("SBACK"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsMagicNumber(tt.data); got != tt.want {
				t.Errorf("IsMagicNumber(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestIsCloseToMagicNumber(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"wrong version", []byte("SBACKUP\x02"), true},
		{"wrong version 0xff", []byte("SBACKUP\xff"), true},
		{"exact match is not close", []byte("SBACKUP\x01"), false},
		{"too short", []byte("SBACKUP"), false},
		{"completely wrong", []byte("XXXXXXXX"), false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCloseToMagicNumber(tt.data); got != tt.want {
				t.Errorf("IsCloseToMagicNumber(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestReadMagicNumber(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		data := []byte("SBACKUP\x01more data")
		got, err := ReadMagicNumber(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ReadMagicNumber: %v", err)
		}
		if !bytes.Equal(got, []byte("SBACKUP\x01")) {
			t.Errorf("got %q, want %q", got, "SBACKUP\x01")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ReadMagicNumber(bytes.NewReader([]byte("SHORT")))
		if err == nil {
			t.Fatal("expected error for short data")
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := ReadMagicNumber(bytes.NewReader(nil))
		if err == nil {
			t.Fatal("expected error for empty data")
		}
	})
}

func TestDetectFormat(t *testing.T) {
	t.Run("modern format", func(t *testing.T) {
		data := []byte("SBACKUP\x01encrypted data here")
		magic, isModern, err := DetectFormat(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("DetectFormat: %v", err)
		}
		if !isModern {
			t.Error("expected modern format")
		}
		if !bytes.Equal(magic, []byte("SBACKUP\x01")) {
			t.Errorf("magic = %q, want SBACKUP\\x01", magic)
		}
	})

	t.Run("legacy format", func(t *testing.T) {
		data := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
		magic, isModern, err := DetectFormat(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("DetectFormat: %v", err)
		}
		if isModern {
			t.Error("expected legacy format")
		}
		if !bytes.Equal(magic, data[:MagicNumberLen]) {
			t.Errorf("magic mismatch")
		}
	})

	t.Run("too short for detection", func(t *testing.T) {
		_, _, err := DetectFormat(bytes.NewReader([]byte("short")))
		if err == nil {
			t.Fatal("expected error for short data")
		}
	})
}

func TestValidateMetadata(t *testing.T) {
	t.Run("valid with two pairs", func(t *testing.T) {
		m := TestMetadata()
		if err := ValidateMetadata(m); err != nil {
			t.Fatalf("ValidateMetadata: %v", err)
		}
	})

	t.Run("valid with one pair", func(t *testing.T) {
		m := &BackupMetadata{
			IV: make([]byte, backupMetadataIVLen),
			Pairs: []ForwardSecrecyPair{
				{
					CT:     bytes.Repeat([]byte{1}, expectedCTLen),
					PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen),
				},
			},
		}
		if err := ValidateMetadata(m); err != nil {
			t.Fatalf("ValidateMetadata: %v", err)
		}
	})

	t.Run("no pairs", func(t *testing.T) {
		m := &BackupMetadata{
			IV:    make([]byte, backupMetadataIVLen),
			Pairs: nil,
		}
		err := ValidateMetadata(m)
		if err == nil {
			t.Fatal("expected error for no pairs")
		}
		fsErr, ok := err.(*ForwardSecrecyError)
		if !ok {
			t.Fatalf("expected *ForwardSecrecyError, got %T", err)
		}
		if fsErr.Kind != ForwardSecrecyErrorMissingField {
			t.Errorf("error kind = %d, want ForwardSecrecyErrorMissingField", fsErr.Kind)
		}
		if !strings.Contains(fsErr.Message, "pair") {
			t.Errorf("error message %q should mention 'pair'", fsErr.Message)
		}
	})

	t.Run("too many pairs", func(t *testing.T) {
		m := &BackupMetadata{
			IV: make([]byte, backupMetadataIVLen),
			Pairs: []ForwardSecrecyPair{
				{CT: bytes.Repeat([]byte{1}, expectedCTLen), PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen)},
				{CT: bytes.Repeat([]byte{3}, expectedCTLen), PWSalt: bytes.Repeat([]byte{4}, expectedPWSaltLen)},
				{CT: bytes.Repeat([]byte{5}, expectedCTLen), PWSalt: bytes.Repeat([]byte{6}, expectedPWSaltLen)},
			},
		}
		err := ValidateMetadata(m)
		if err == nil {
			t.Fatal("expected error for too many pairs")
		}
		fsErr, ok := err.(*ForwardSecrecyError)
		if !ok {
			t.Fatalf("expected *ForwardSecrecyError, got %T", err)
		}
		if fsErr.Kind != ForwardSecrecyErrorTooManyPairs {
			t.Errorf("error kind = %d, want ForwardSecrecyErrorTooManyPairs", fsErr.Kind)
		}
		if !strings.Contains(fsErr.Message, "3") {
			t.Errorf("error message %q should mention count '3'", fsErr.Message)
		}
	})

	t.Run("empty ct", func(t *testing.T) {
		m := &BackupMetadata{
			IV: make([]byte, backupMetadataIVLen),
			Pairs: []ForwardSecrecyPair{
				{CT: nil, PWSalt: bytes.Repeat([]byte{1}, expectedPWSaltLen)},
			},
		}
		err := ValidateMetadata(m)
		if err == nil {
			t.Fatal("expected error for empty ct")
		}
		fsErr := err.(*ForwardSecrecyError)
		if fsErr.Kind != ForwardSecrecyErrorMissingField {
			t.Errorf("error kind = %d, want ForwardSecrecyErrorMissingField", fsErr.Kind)
		}
		if !strings.Contains(fsErr.Message, "pair.ct") {
			t.Errorf("error message %q should mention 'pair.ct'", fsErr.Message)
		}
	})

	t.Run("wrong ct length", func(t *testing.T) {
		m := &BackupMetadata{
			IV: make([]byte, backupMetadataIVLen),
			Pairs: []ForwardSecrecyPair{
				{CT: bytes.Repeat([]byte{1}, 30), PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen)},
			},
		}
		err := ValidateMetadata(m)
		if err == nil {
			t.Fatal("expected error for wrong ct length")
		}
		fsErr := err.(*ForwardSecrecyError)
		if fsErr.Kind != ForwardSecrecyErrorInvalidLength {
			t.Errorf("error kind = %d, want ForwardSecrecyErrorInvalidLength", fsErr.Kind)
		}
		if !strings.Contains(fsErr.Message, "30") || !strings.Contains(fsErr.Message, "48") {
			t.Errorf("error message %q should mention actual and expected lengths", fsErr.Message)
		}
	})

	t.Run("empty pw_salt", func(t *testing.T) {
		m := &BackupMetadata{
			IV: make([]byte, backupMetadataIVLen),
			Pairs: []ForwardSecrecyPair{
				{CT: bytes.Repeat([]byte{1}, expectedCTLen), PWSalt: nil},
			},
		}
		err := ValidateMetadata(m)
		if err == nil {
			t.Fatal("expected error for empty pw_salt")
		}
		fsErr := err.(*ForwardSecrecyError)
		if fsErr.Kind != ForwardSecrecyErrorMissingField {
			t.Errorf("error kind = %d, want ForwardSecrecyErrorMissingField", fsErr.Kind)
		}
		if !strings.Contains(fsErr.Message, "pair.pw_salt") {
			t.Errorf("error message %q should mention 'pair.pw_salt'", fsErr.Message)
		}
	})

	t.Run("wrong pw_salt length", func(t *testing.T) {
		m := &BackupMetadata{
			IV: make([]byte, backupMetadataIVLen),
			Pairs: []ForwardSecrecyPair{
				{CT: bytes.Repeat([]byte{1}, expectedCTLen), PWSalt: bytes.Repeat([]byte{2}, 16)},
			},
		}
		err := ValidateMetadata(m)
		if err == nil {
			t.Fatal("expected error for wrong pw_salt length")
		}
		fsErr := err.(*ForwardSecrecyError)
		if fsErr.Kind != ForwardSecrecyErrorInvalidLength {
			t.Errorf("error kind = %d, want ForwardSecrecyErrorInvalidLength", fsErr.Kind)
		}
	})

	t.Run("wrong iv length", func(t *testing.T) {
		m := &BackupMetadata{
			IV: make([]byte, 16), // Should be 12.
			Pairs: []ForwardSecrecyPair{
				{CT: bytes.Repeat([]byte{1}, expectedCTLen), PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen)},
			},
		}
		err := ValidateMetadata(m)
		if err == nil {
			t.Fatal("expected error for wrong iv length")
		}
		fsErr := err.(*ForwardSecrecyError)
		if fsErr.Kind != ForwardSecrecyErrorInvalidLength {
			t.Errorf("error kind = %d, want ForwardSecrecyErrorInvalidLength", fsErr.Kind)
		}
		if !strings.Contains(fsErr.Message, "iv") {
			t.Errorf("error message %q should mention 'iv'", fsErr.Message)
		}
	})

	t.Run("empty iv", func(t *testing.T) {
		m := &BackupMetadata{
			IV: nil,
			Pairs: []ForwardSecrecyPair{
				{CT: bytes.Repeat([]byte{1}, expectedCTLen), PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen)},
			},
		}
		err := ValidateMetadata(m)
		if err == nil {
			t.Fatal("expected error for empty iv")
		}
		fsErr := err.(*ForwardSecrecyError)
		if fsErr.Kind != ForwardSecrecyErrorInvalidLength {
			t.Errorf("error kind = %d, want ForwardSecrecyErrorInvalidLength", fsErr.Kind)
		}
	})
}

func TestNewBackupMetadata(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		m, err := NewBackupMetadata(
			make([]byte, backupMetadataIVLen),
			[]ForwardSecrecyPair{
				{CT: bytes.Repeat([]byte{1}, expectedCTLen), PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen)},
			},
		)
		if err != nil {
			t.Fatalf("NewBackupMetadata: %v", err)
		}
		if m == nil {
			t.Fatal("expected non-nil metadata")
		}
		if len(m.Pairs) != 1 {
			t.Errorf("pairs count = %d, want 1", len(m.Pairs))
		}
	})

	t.Run("invalid returns error", func(t *testing.T) {
		_, err := NewBackupMetadata(nil, nil)
		if err == nil {
			t.Fatal("expected error for invalid metadata")
		}
	})
}

func TestTestMetadata(t *testing.T) {
	m := TestMetadata()
	if err := ValidateMetadata(m); err != nil {
		t.Fatalf("TestMetadata should be valid: %v", err)
	}
	if len(m.Pairs) != 2 {
		t.Errorf("pairs count = %d, want 2", len(m.Pairs))
	}
	if len(m.IV) != backupMetadataIVLen {
		t.Errorf("IV length = %d, want %d", len(m.IV), backupMetadataIVLen)
	}

	// Verify pair values match the Rust test_metadata().
	if !bytes.Equal(m.Pairs[0].CT, bytes.Repeat([]byte{1}, expectedCTLen)) {
		t.Error("pair[0].CT mismatch")
	}
	if !bytes.Equal(m.Pairs[0].PWSalt, bytes.Repeat([]byte{2}, expectedPWSaltLen)) {
		t.Error("pair[0].PWSalt mismatch")
	}
	if !bytes.Equal(m.Pairs[1].CT, bytes.Repeat([]byte{3}, expectedCTLen)) {
		t.Error("pair[1].CT mismatch")
	}
	if !bytes.Equal(m.Pairs[1].PWSalt, bytes.Repeat([]byte{4}, expectedPWSaltLen)) {
		t.Error("pair[1].PWSalt mismatch")
	}
}

func TestForwardSecrecyErrorString(t *testing.T) {
	e := &ForwardSecrecyError{
		Kind:    ForwardSecrecyErrorMissingField,
		Message: "missing field 'pair' in unencrypted metadata",
	}
	got := e.Error()
	if !strings.Contains(got, "forward secrecy") {
		t.Errorf("Error() = %q, should contain 'forward secrecy'", got)
	}
	if !strings.Contains(got, "missing field 'pair'") {
		t.Errorf("Error() = %q, should contain field name", got)
	}
}

func TestConstants(t *testing.T) {
	// Verify constants match the Rust implementation.
	if BackupForwardSecrecyTokenLen != 32 {
		t.Errorf("BackupForwardSecrecyTokenLen = %d, want 32", BackupForwardSecrecyTokenLen)
	}
	if ctMACLen != 16 {
		t.Errorf("ctMACLen = %d, want 16", ctMACLen)
	}
	if expectedCTLen != 48 {
		t.Errorf("expectedCTLen = %d, want 48", expectedCTLen)
	}
	if expectedPWSaltLen != 32 {
		t.Errorf("expectedPWSaltLen = %d, want 32", expectedPWSaltLen)
	}
	if backupMetadataIVLen != 12 {
		t.Errorf("backupMetadataIVLen = %d, want 12", backupMetadataIVLen)
	}
	if maxForwardSecrecyPairs != 2 {
		t.Errorf("maxForwardSecrecyPairs = %d, want 2", maxForwardSecrecyPairs)
	}
}

func TestForwardSecrecyPairFields(t *testing.T) {
	pair := ForwardSecrecyPair{
		CT:     bytes.Repeat([]byte{0xab}, expectedCTLen),
		PWSalt: bytes.Repeat([]byte{0xcd}, expectedPWSaltLen),
	}
	if len(pair.CT) != expectedCTLen {
		t.Errorf("CT length = %d, want %d", len(pair.CT), expectedCTLen)
	}
	if len(pair.PWSalt) != expectedPWSaltLen {
		t.Errorf("PWSalt length = %d, want %d", len(pair.PWSalt), expectedPWSaltLen)
	}
}

func TestValidateMetadataSecondPairInvalid(t *testing.T) {
	// First pair valid, second pair has invalid ct length.
	m := &BackupMetadata{
		IV: make([]byte, backupMetadataIVLen),
		Pairs: []ForwardSecrecyPair{
			{CT: bytes.Repeat([]byte{1}, expectedCTLen), PWSalt: bytes.Repeat([]byte{2}, expectedPWSaltLen)},
			{CT: bytes.Repeat([]byte{3}, 10), PWSalt: bytes.Repeat([]byte{4}, expectedPWSaltLen)},
		},
	}
	err := ValidateMetadata(m)
	if err == nil {
		t.Fatal("expected error for second pair with invalid ct length")
	}
	fsErr := err.(*ForwardSecrecyError)
	if fsErr.Kind != ForwardSecrecyErrorInvalidLength {
		t.Errorf("error kind = %d, want ForwardSecrecyErrorInvalidLength", fsErr.Kind)
	}
}

func TestDetectFormatWithModernPrefix(t *testing.T) {
	// Build a stream: magic + some payload.
	var buf bytes.Buffer
	buf.WriteString(MagicNumber)
	buf.WriteString("payload data after magic number")

	magic, isModern, err := DetectFormat(&buf)
	if err != nil {
		t.Fatalf("DetectFormat: %v", err)
	}
	if !isModern {
		t.Error("expected modern format detection")
	}
	if !bytes.Equal(magic, []byte(MagicNumber)) {
		t.Errorf("magic = %q, want %q", magic, MagicNumber)
	}
}
