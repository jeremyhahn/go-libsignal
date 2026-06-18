package protocol

import (
	"testing"
	"time"
)

func TestTimestampFromEpochMillis(t *testing.T) {
	ts := TimestampFromEpochMillis(1_000_000)
	if ts.EpochMillis() != 1_000_000 {
		t.Fatalf("expected 1000000, got %d", ts.EpochMillis())
	}
}

func TestTimestampFromTime(t *testing.T) {
	// Use a known time: 2000-01-01 00:00:00 UTC = 946684800000 ms.
	known := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	const wantMs uint64 = 946_684_800_000
	ts := TimestampFromTime(known)
	if ts.EpochMillis() != wantMs {
		t.Fatalf("expected %d, got %d", wantMs, ts.EpochMillis())
	}
}

func TestTimestampTime(t *testing.T) {
	const ms uint64 = 946_684_800_000
	ts := TimestampFromEpochMillis(ms)
	got := ts.Time()
	want := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestTimestampAddMillis(t *testing.T) {
	ts := TimestampFromEpochMillis(1000)
	got := ts.AddMillis(500)
	if got.EpochMillis() != 1500 {
		t.Fatalf("expected 1500, got %d", got.EpochMillis())
	}
}

func TestTimestampSubMillis(t *testing.T) {
	ts := TimestampFromEpochMillis(1000)
	got := ts.SubMillis(400)
	if got.EpochMillis() != 600 {
		t.Fatalf("expected 600, got %d", got.EpochMillis())
	}
}

// TestTimestampSubMillis_Underflow verifies that underflow clamps to 0.
func TestTimestampSubMillis_Underflow(t *testing.T) {
	ts := TimestampFromEpochMillis(100)
	got := ts.SubMillis(999)
	if got.EpochMillis() != 0 {
		t.Fatalf("expected 0 on underflow, got %d", got.EpochMillis())
	}
}

// TestTimestampFromTime_BeforeEpoch verifies that pre-epoch times produce 0.
func TestTimestampFromTime_BeforeEpoch(t *testing.T) {
	before := time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)
	ts := TimestampFromTime(before)
	if ts.EpochMillis() != 0 {
		t.Fatalf("expected 0 for pre-epoch time, got %d", ts.EpochMillis())
	}
}
