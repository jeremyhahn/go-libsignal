package kem

import (
	"bytes"
	"errors"
	"testing"
)

func TestValidKeyType(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		expected bool
	}{
		{"Kyber768", KeyTypeKyber768, true},
		{"Kyber1024", KeyTypeKyber1024, true},
		{"MLKEM1024", KeyTypeMLKEM1024, true},
		{"invalid zero", KeyType(0x00), false},
		{"invalid 0xFF", KeyType(0xFF), false},
		{"invalid 0x01", KeyType(0x01), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validKeyType(tt.keyType); got != tt.expected {
				t.Errorf("validKeyType(0x%02x) = %v, want %v", tt.keyType, got, tt.expected)
			}
		})
	}
}

func TestNewPublicKey(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	pk := NewPublicKey(KeyTypeKyber1024, data)

	if pk.Type() != KeyTypeKyber1024 {
		t.Errorf("Type() = 0x%02x, want 0x%02x", pk.Type(), KeyTypeKyber1024)
	}
	if !bytes.Equal(pk.Data(), data) {
		t.Error("Data() does not match input")
	}
	// Verify defensive copy
	data[0] = 0xFF
	if pk.Data()[0] == 0xFF {
		t.Error("PublicKey should make a defensive copy of data")
	}
}

func TestPublicKeySerialize(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC}
	pk := NewPublicKey(KeyTypeKyber1024, data)

	serialized := pk.Serialize()
	if serialized[0] != byte(KeyTypeKyber1024) {
		t.Errorf("Serialized[0] = 0x%02x, want 0x%02x", serialized[0], KeyTypeKyber1024)
	}
	if !bytes.Equal(serialized[1:], data) {
		t.Error("Serialized data does not match")
	}
}

func TestPublicKeyDataDefensiveCopy(t *testing.T) {
	data := []byte{1, 2, 3}
	pk := NewPublicKey(KeyTypeKyber1024, data)

	d1 := pk.Data()
	d2 := pk.Data()
	d1[0] = 0xFF
	if d2[0] == 0xFF {
		t.Error("Data() should return a copy each time")
	}
}

func TestDeserializePublicKey(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantKT  KeyType
	}{
		{
			name:    "valid Kyber1024",
			input:   append([]byte{byte(KeyTypeKyber1024)}, make([]byte, 1568)...),
			wantErr: false,
			wantKT:  KeyTypeKyber1024,
		},
		{
			name:    "valid Kyber768",
			input:   append([]byte{byte(KeyTypeKyber768)}, make([]byte, 1184)...),
			wantErr: false,
			wantKT:  KeyTypeKyber768,
		},
		{
			name:    "valid MLKEM1024",
			input:   append([]byte{byte(KeyTypeMLKEM1024)}, make([]byte, 1568)...),
			wantErr: false,
			wantKT:  KeyTypeMLKEM1024,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "single byte",
			input:   []byte{byte(KeyTypeKyber1024)},
			wantErr: true,
		},
		{
			name:    "invalid key type",
			input:   []byte{0xFF, 0x01},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, err := DeserializePublicKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeserializePublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && pk.Type() != tt.wantKT {
				t.Errorf("Type() = 0x%02x, want 0x%02x", pk.Type(), tt.wantKT)
			}
		})
	}
}

func TestDeserializePublicKeyRoundTrip(t *testing.T) {
	data := make([]byte, 1568)
	for i := range data {
		data[i] = byte(i)
	}
	original := NewPublicKey(KeyTypeKyber1024, data)
	serialized := original.Serialize()

	restored, err := DeserializePublicKey(serialized)
	if err != nil {
		t.Fatalf("DeserializePublicKey() error: %v", err)
	}
	if restored.Type() != original.Type() {
		t.Error("Type mismatch after round trip")
	}
	if !bytes.Equal(restored.Data(), original.Data()) {
		t.Error("Data mismatch after round trip")
	}
}

func TestNewSecretKey(t *testing.T) {
	data := make([]byte, 3168) // Kyber1024 secret key size
	data[0] = 1
	data[1] = 2
	data[2] = 3
	sk, err := NewSecretKey(KeyTypeKyber1024, data)
	if err != nil {
		t.Fatalf("NewSecretKey() error: %v", err)
	}

	if sk.Type() != KeyTypeKyber1024 {
		t.Errorf("Type() = 0x%02x, want 0x%02x", sk.Type(), KeyTypeKyber1024)
	}
	if !bytes.Equal(sk.Data(), data) {
		t.Error("Data() does not match input")
	}
	// Verify defensive copy
	data[0] = 0xFF
	if sk.Data()[0] == 0xFF {
		t.Error("SecretKey should make a defensive copy of data")
	}
}

func TestNewSecretKeyInvalidSize(t *testing.T) {
	_, err := NewSecretKey(KeyTypeKyber1024, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("NewSecretKey with wrong size should return error")
	}
	var badLen *BadKeyLengthError
	if !errors.As(err, &badLen) {
		t.Errorf("expected BadKeyLengthError, got %T: %v", err, err)
	}
}

func TestNewSecretKeyInvalidType(t *testing.T) {
	_, err := NewSecretKey(KeyType(0xFF), make([]byte, 100))
	if err == nil {
		t.Fatal("NewSecretKey with invalid type should return error")
	}
	if !errors.Is(err, ErrInvalidKeyType) {
		t.Errorf("expected ErrInvalidKeyType, got: %v", err)
	}
}

func TestSecretKeyDataDefensiveCopy(t *testing.T) {
	data := make([]byte, 3168) // Kyber1024 secret key size
	data[0] = 1
	data[1] = 2
	data[2] = 3
	sk, err := NewSecretKey(KeyTypeKyber1024, data)
	if err != nil {
		t.Fatalf("NewSecretKey() error: %v", err)
	}

	d1 := sk.Data()
	d2 := sk.Data()
	d1[0] = 0xFF
	if d2[0] == 0xFF {
		t.Error("Data() should return a copy each time")
	}
}

func TestNewCiphertext(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	ct := NewCiphertext(KeyTypeKyber1024, data)

	if ct.Type() != KeyTypeKyber1024 {
		t.Errorf("Type() = 0x%02x, want 0x%02x", ct.Type(), KeyTypeKyber1024)
	}
	if !bytes.Equal(ct.Data(), data) {
		t.Error("Data() does not match input")
	}
	// Verify defensive copy
	data[0] = 0xFF
	if ct.Data()[0] == 0xFF {
		t.Error("Ciphertext should make a defensive copy of data")
	}
}

func TestCiphertextSerialize(t *testing.T) {
	data := []byte{0xAA, 0xBB}
	ct := NewCiphertext(KeyTypeKyber1024, data)

	serialized := ct.Serialize()
	if serialized[0] != byte(KeyTypeKyber1024) {
		t.Errorf("Serialized[0] = 0x%02x, want 0x%02x", serialized[0], KeyTypeKyber1024)
	}
	if !bytes.Equal(serialized[1:], data) {
		t.Error("Serialized data does not match")
	}
}

func TestCiphertextDataDefensiveCopy(t *testing.T) {
	data := []byte{1, 2, 3}
	ct := NewCiphertext(KeyTypeKyber1024, data)

	d1 := ct.Data()
	d2 := ct.Data()
	d1[0] = 0xFF
	if d2[0] == 0xFF {
		t.Error("Data() should return a copy each time")
	}
}

func TestDeserializeCiphertext(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		wantKT  KeyType
	}{
		{
			name:    "valid Kyber1024",
			input:   append([]byte{byte(KeyTypeKyber1024)}, make([]byte, 1568)...),
			wantErr: false,
			wantKT:  KeyTypeKyber1024,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "single byte",
			input:   []byte{byte(KeyTypeKyber1024)},
			wantErr: true,
		},
		{
			name:    "invalid key type",
			input:   []byte{0xFF, 0x01},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := DeserializeCiphertext(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeserializeCiphertext() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && ct.Type() != tt.wantKT {
				t.Errorf("Type() = 0x%02x, want 0x%02x", ct.Type(), tt.wantKT)
			}
		})
	}
}

func TestDeserializeCiphertextRoundTrip(t *testing.T) {
	data := make([]byte, 1568)
	for i := range data {
		data[i] = byte(i * 3)
	}
	original := NewCiphertext(KeyTypeKyber1024, data)
	serialized := original.Serialize()

	restored, err := DeserializeCiphertext(serialized)
	if err != nil {
		t.Fatalf("DeserializeCiphertext() error: %v", err)
	}
	if restored.Type() != original.Type() {
		t.Error("Type mismatch after round trip")
	}
	if !bytes.Equal(restored.Data(), original.Data()) {
		t.Error("Data mismatch after round trip")
	}
}

func TestSentinelErrors(t *testing.T) {
	if ErrInvalidKeyType == nil {
		t.Error("ErrInvalidKeyType should not be nil")
	}
	if ErrEmptyInput == nil {
		t.Error("ErrEmptyInput should not be nil")
	}
	if ErrKeyTypeMismatch == nil {
		t.Error("ErrKeyTypeMismatch should not be nil")
	}
}

func TestDeserializePublicKeyBadLength(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		dataSize int
		expected int
	}{
		{"Kyber768 too short", KeyTypeKyber768, 100, 1184},
		{"Kyber768 too long", KeyTypeKyber768, 1185, 1184},
		{"Kyber768 off by one short", KeyTypeKyber768, 1183, 1184},
		{"Kyber1024 too short", KeyTypeKyber1024, 100, 1568},
		{"Kyber1024 too long", KeyTypeKyber1024, 1569, 1568},
		{"Kyber1024 off by one short", KeyTypeKyber1024, 1567, 1568},
		{"MLKEM1024 too short", KeyTypeMLKEM1024, 100, 1568},
		{"MLKEM1024 too long", KeyTypeMLKEM1024, 1569, 1568},
		{"MLKEM1024 off by one short", KeyTypeMLKEM1024, 1567, 1568},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, 1+tt.dataSize)
			input[0] = byte(tt.keyType)

			_, err := DeserializePublicKey(input)
			if err == nil {
				t.Fatal("DeserializePublicKey() should return error for wrong-sized data")
			}

			var badLen *BadKeyLengthError
			if !errors.As(err, &badLen) {
				t.Fatalf("expected BadKeyLengthError, got %T: %v", err, err)
			}
			if badLen.KeyType != tt.keyType {
				t.Errorf("BadKeyLengthError.KeyType = 0x%02x, want 0x%02x", badLen.KeyType, tt.keyType)
			}
			if badLen.Expected != tt.expected {
				t.Errorf("BadKeyLengthError.Expected = %d, want %d", badLen.Expected, tt.expected)
			}
			if badLen.Actual != tt.dataSize {
				t.Errorf("BadKeyLengthError.Actual = %d, want %d", badLen.Actual, tt.dataSize)
			}
		})
	}
}

func TestDeserializeCiphertextBadLength(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		dataSize int
		expected int
	}{
		{"Kyber768 too short", KeyTypeKyber768, 100, 1088},
		{"Kyber768 too long", KeyTypeKyber768, 1089, 1088},
		{"Kyber768 off by one short", KeyTypeKyber768, 1087, 1088},
		{"Kyber1024 too short", KeyTypeKyber1024, 100, 1568},
		{"Kyber1024 too long", KeyTypeKyber1024, 1569, 1568},
		{"Kyber1024 off by one short", KeyTypeKyber1024, 1567, 1568},
		{"MLKEM1024 too short", KeyTypeMLKEM1024, 100, 1568},
		{"MLKEM1024 too long", KeyTypeMLKEM1024, 1569, 1568},
		{"MLKEM1024 off by one short", KeyTypeMLKEM1024, 1567, 1568},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, 1+tt.dataSize)
			input[0] = byte(tt.keyType)

			_, err := DeserializeCiphertext(input)
			if err == nil {
				t.Fatal("DeserializeCiphertext() should return error for wrong-sized data")
			}

			var badLen *BadKeyLengthError
			if !errors.As(err, &badLen) {
				t.Fatalf("expected BadKeyLengthError, got %T: %v", err, err)
			}
			if badLen.KeyType != tt.keyType {
				t.Errorf("BadKeyLengthError.KeyType = 0x%02x, want 0x%02x", badLen.KeyType, tt.keyType)
			}
			if badLen.Expected != tt.expected {
				t.Errorf("BadKeyLengthError.Expected = %d, want %d", badLen.Expected, tt.expected)
			}
			if badLen.Actual != tt.dataSize {
				t.Errorf("BadKeyLengthError.Actual = %d, want %d", badLen.Actual, tt.dataSize)
			}
		})
	}
}

func TestBadKeyLengthErrorMessage(t *testing.T) {
	err := &BadKeyLengthError{
		KeyType:  KeyTypeKyber1024,
		Expected: 1568,
		Actual:   100,
	}
	msg := err.Error()
	if msg == "" {
		t.Fatal("BadKeyLengthError.Error() should not be empty")
	}
	if !bytes.Contains([]byte(msg), []byte("1568")) {
		t.Errorf("error message should contain expected size, got: %s", msg)
	}
	if !bytes.Contains([]byte(msg), []byte("100")) {
		t.Errorf("error message should contain actual size, got: %s", msg)
	}
}

func TestExpectedPublicKeySizeValues(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		want    int
	}{
		{"Kyber768", KeyTypeKyber768, 1184},
		{"Kyber1024", KeyTypeKyber1024, 1568},
		{"MLKEM1024", KeyTypeMLKEM1024, 1568},
		{"unknown", KeyType(0xFF), -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expectedPublicKeySize(tt.keyType); got != tt.want {
				t.Errorf("expectedPublicKeySize(0x%02x) = %d, want %d", tt.keyType, got, tt.want)
			}
		})
	}
}

func TestExpectedCiphertextSizeValues(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		want    int
	}{
		{"Kyber768", KeyTypeKyber768, 1088},
		{"Kyber1024", KeyTypeKyber1024, 1568},
		{"MLKEM1024", KeyTypeMLKEM1024, 1568},
		{"unknown", KeyType(0xFF), -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expectedCiphertextSize(tt.keyType); got != tt.want {
				t.Errorf("expectedCiphertextSize(0x%02x) = %d, want %d", tt.keyType, got, tt.want)
			}
		})
	}
}

func TestDeserializePublicKeyCorrectSizeAccepted(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		size    int
	}{
		{"Kyber768", KeyTypeKyber768, 1184},
		{"Kyber1024", KeyTypeKyber1024, 1568},
		{"MLKEM1024", KeyTypeMLKEM1024, 1568},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, 1+tt.size)
			input[0] = byte(tt.keyType)
			pk, err := DeserializePublicKey(input)
			if err != nil {
				t.Fatalf("DeserializePublicKey() unexpected error: %v", err)
			}
			if pk.Type() != tt.keyType {
				t.Errorf("Type() = 0x%02x, want 0x%02x", pk.Type(), tt.keyType)
			}
			if len(pk.Data()) != tt.size {
				t.Errorf("Data() length = %d, want %d", len(pk.Data()), tt.size)
			}
		})
	}
}

func TestDeserializeCiphertextCorrectSizeAccepted(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		size    int
	}{
		{"Kyber768", KeyTypeKyber768, 1088},
		{"Kyber1024", KeyTypeKyber1024, 1568},
		{"MLKEM1024", KeyTypeMLKEM1024, 1568},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, 1+tt.size)
			input[0] = byte(tt.keyType)
			ct, err := DeserializeCiphertext(input)
			if err != nil {
				t.Fatalf("DeserializeCiphertext() unexpected error: %v", err)
			}
			if ct.Type() != tt.keyType {
				t.Errorf("Type() = 0x%02x, want 0x%02x", ct.Type(), tt.keyType)
			}
			if len(ct.Data()) != tt.size {
				t.Errorf("Data() length = %d, want %d", len(ct.Data()), tt.size)
			}
		})
	}
}
