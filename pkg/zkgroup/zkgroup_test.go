package zkgroup

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

func TestNewTimestamp(t *testing.T) {
	ts := NewTimestamp(1000)
	if ts.EpochSeconds() != 1000 {
		t.Errorf("EpochSeconds() = %d, want 1000", ts.EpochSeconds())
	}
}

func TestTimestampFromTime(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	ts := TimestampFromTime(now)
	if ts.EpochSeconds() != uint64(now.Unix()) {
		t.Errorf("EpochSeconds() = %d, want %d", ts.EpochSeconds(), now.Unix())
	}
}

func TestTimestamp_ToTime(t *testing.T) {
	ts := NewTimestamp(1718452800) // 2024-06-15 12:00:00 UTC
	tt := ts.ToTime()
	if tt.Unix() != 1718452800 {
		t.Errorf("ToTime().Unix() = %d, want 1718452800", tt.Unix())
	}
}

func TestTimestamp_AddSeconds(t *testing.T) {
	ts := NewTimestamp(1000)
	result := ts.AddSeconds(500)
	if result.EpochSeconds() != 1500 {
		t.Errorf("AddSeconds(500) = %d, want 1500", result.EpochSeconds())
	}
}

func TestTimestamp_SubSeconds(t *testing.T) {
	ts := NewTimestamp(1000)
	result := ts.SubSeconds(500)
	if result.EpochSeconds() != 500 {
		t.Errorf("SubSeconds(500) = %d, want 500", result.EpochSeconds())
	}
}

func TestTimestamp_CheckedAddSeconds(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		ts := NewTimestamp(1000)
		result, ok := ts.CheckedAddSeconds(500)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if result.EpochSeconds() != 1500 {
			t.Errorf("got %d, want 1500", result.EpochSeconds())
		}
	})

	t.Run("overflow", func(t *testing.T) {
		ts := NewTimestamp(^uint64(0))
		_, ok := ts.CheckedAddSeconds(1)
		if ok {
			t.Fatal("expected ok=false for overflow")
		}
	})
}

func TestTimestamp_CheckedSubSeconds(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		ts := NewTimestamp(1000)
		result, ok := ts.CheckedSubSeconds(500)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if result.EpochSeconds() != 500 {
			t.Errorf("got %d, want 500", result.EpochSeconds())
		}
	})

	t.Run("underflow", func(t *testing.T) {
		ts := NewTimestamp(100)
		_, ok := ts.CheckedSubSeconds(200)
		if ok {
			t.Fatal("expected ok=false for underflow")
		}
	})
}

func TestTimestamp_IsDayAligned(t *testing.T) {
	tests := []struct {
		seconds uint64
		want    bool
	}{
		{0, true},
		{SecondsPerDay, true},
		{2 * SecondsPerDay, true},
		{1, false},
		{SecondsPerDay + 1, false},
	}
	for _, tt := range tests {
		ts := NewTimestamp(tt.seconds)
		if got := ts.IsDayAligned(); got != tt.want {
			t.Errorf("IsDayAligned(%d) = %v, want %v", tt.seconds, got, tt.want)
		}
	}
}

func TestTimestamp_ToBeBytes(t *testing.T) {
	ts := NewTimestamp(0x0102030405060708)
	b := ts.ToBeBytes()
	expected := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if b != expected {
		t.Errorf("ToBeBytes() = %x, want %x", b, expected)
	}
}

func TestTimestamp_SaturatingSecondsSince(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		ts := NewTimestamp(1000)
		before := NewTimestamp(500)
		if got := ts.SaturatingSecondsSince(before); got != 500 {
			t.Errorf("got %d, want 500", got)
		}
	})

	t.Run("saturating", func(t *testing.T) {
		ts := NewTimestamp(500)
		before := NewTimestamp(1000)
		if got := ts.SaturatingSecondsSince(before); got != 0 {
			t.Errorf("got %d, want 0", got)
		}
	})

	t.Run("equal", func(t *testing.T) {
		ts := NewTimestamp(500)
		before := NewTimestamp(500)
		if got := ts.SaturatingSecondsSince(before); got != 0 {
			t.Errorf("got %d, want 0", got)
		}
	})
}

func TestTimestamp_HashInto(t *testing.T) {
	ts := NewTimestamp(86400)
	sho := zkcredential.NewShoHmacSha256Ext("test")
	ts.HashInto(sho)
	// Just verify it doesn't panic
}

func TestServiceID(t *testing.T) {
	uuid := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	t.Run("NewACI", func(t *testing.T) {
		sid := NewACI(uuid)
		if sid.Type != ServiceIDTypeACI {
			t.Errorf("Type = %d, want %d", sid.Type, ServiceIDTypeACI)
		}
		if sid.RawUUID != uuid {
			t.Error("UUID mismatch")
		}
		if sid.Bytes() != uuid {
			t.Error("Bytes() mismatch")
		}
	})

	t.Run("NewPNI", func(t *testing.T) {
		sid := NewPNI(uuid)
		if sid.Type != ServiceIDTypePNI {
			t.Errorf("Type = %d, want %d", sid.Type, ServiceIDTypePNI)
		}
		if sid.RawUUID != uuid {
			t.Error("UUID mismatch")
		}
	})
}

func TestEncodeRedemptionTime(t *testing.T) {
	sc := encodeRedemptionTime(1000)
	if sc == nil {
		t.Fatal("returned nil")
	}
	// Same input should produce same scalar
	sc2 := encodeRedemptionTime(1000)
	if sc.Equal(sc2) != 1 {
		t.Error("not deterministic")
	}

	// Different inputs should differ
	sc3 := encodeRedemptionTime(2000)
	if sc.Equal(sc3) == 1 {
		t.Error("different inputs produced same scalar")
	}
}

func TestEncodeReceiptSerialBytes(t *testing.T) {
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i)
	}
	sc := encodeReceiptSerialBytes(serial)
	if sc == nil {
		t.Fatal("returned nil")
	}
	sc2 := encodeReceiptSerialBytes(serial)
	if sc.Equal(sc2) != 1 {
		t.Error("not deterministic")
	}
}

func TestHexEncode(t *testing.T) {
	result := hexEncode([]byte{0xAB, 0xCD})
	if result != "abcd" {
		t.Errorf("hexEncode = %q, want %q", result, "abcd")
	}
}

func TestSerialize(t *testing.T) {
	data := []byte{1, 2, 3}
	serialized := Serialize(data)
	if len(serialized) != 4 {
		t.Fatalf("len = %d, want 4", len(serialized))
	}
	if serialized[0] != 0 {
		t.Errorf("reserved byte = %d, want 0", serialized[0])
	}
	if serialized[1] != 1 || serialized[2] != 2 || serialized[3] != 3 {
		t.Error("data mismatch")
	}
}

func TestDeserialize(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := []byte{0, 1, 2, 3}
		result, err := Deserialize(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 3 || result[0] != 1 || result[1] != 2 || result[2] != 3 {
			t.Error("data mismatch")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := Deserialize(nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("bad reserved byte", func(t *testing.T) {
		_, err := Deserialize([]byte{1, 2, 3})
		if err == nil {
			t.Fatal("expected error for non-zero reserved byte")
		}
	})
}

func TestEncodeRedemptionTimeZero(t *testing.T) {
	sc := encodeRedemptionTime(0)
	if sc == nil {
		t.Fatal("returned nil for zero")
	}
}

func TestEncodeRedemptionTimeMaxUint32(t *testing.T) {
	sc := encodeRedemptionTime(^uint32(0))
	if sc == nil {
		t.Fatal("returned nil for max uint32")
	}
	// Should produce a valid non-zero scalar.
	sc2 := encodeRedemptionTime(0)
	if sc.Equal(sc2) == 1 {
		t.Error("max uint32 should differ from zero")
	}
}

func TestEncodeReceiptSerialBytesZero(t *testing.T) {
	var serial ReceiptSerialBytes
	sc := encodeReceiptSerialBytes(serial)
	if sc == nil {
		t.Fatal("returned nil for zero serial")
	}
}

func TestEncodeReceiptSerialBytesMaxValue(t *testing.T) {
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = 0xFF
	}
	sc := encodeReceiptSerialBytes(serial)
	if sc == nil {
		t.Fatal("returned nil for max serial")
	}
	// The fallback path (SetUniformBytes) may be triggered for large values.
	// Verify the result is deterministic.
	sc2 := encodeReceiptSerialBytes(serial)
	if sc.Equal(sc2) != 1 {
		t.Error("not deterministic for max serial")
	}
}

func TestHexEncodeEmpty(t *testing.T) {
	result := hexEncode(nil)
	if result != "" {
		t.Errorf("hexEncode(nil) = %q, want empty", result)
	}
}

func TestSerializeEmpty(t *testing.T) {
	data := Serialize(nil)
	if len(data) != 1 || data[0] != 0 {
		t.Errorf("Serialize(nil) = %v, want [0]", data)
	}
}

func TestDeserializeMinimalValid(t *testing.T) {
	data, err := Deserialize([]byte{0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
}

func TestDeserializeEmpty(t *testing.T) {
	_, err := Deserialize([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestSerializeDeserializeRoundTrip(t *testing.T) {
	original := []byte{10, 20, 30, 40, 50}
	serialized := Serialize(original)
	deserialized, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}
	if len(deserialized) != len(original) {
		t.Fatalf("len mismatch: %d != %d", len(deserialized), len(original))
	}
	for i := range original {
		if deserialized[i] != original[i] {
			t.Errorf("byte %d: %d != %d", i, deserialized[i], original[i])
		}
	}
}
