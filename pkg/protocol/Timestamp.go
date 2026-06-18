package protocol

import "time"

// Timestamp is a millisecond-precision Unix epoch timestamp. It wraps a uint64
// and provides helpers for converting to and from Go's time.Time.
//
// Rust libsignal defines an equivalent newtype at rust/protocol/src/timestamp.rs
// with from_epoch_millis / epoch_millis / add_millis / sub_millis and a
// From<Timestamp> for SystemTime conversion. This Go type mirrors those semantics.
//
// Wire encoding: uint64 milliseconds since 1970-01-01T00:00:00Z (UTC).
// This matches the DecryptionErrorMessage.timestamp field
// (rust/protocol/src/protocol.rs:904-905) and all sealed-sender certificate
// expiry fields.
type Timestamp uint64

// TimestampFromEpochMillis creates a Timestamp from raw milliseconds since
// the Unix epoch. Mirrors Rust Timestamp::from_epoch_millis.
func TimestampFromEpochMillis(ms uint64) Timestamp {
	return Timestamp(ms)
}

// TimestampFromTime converts a time.Time to a Timestamp, truncating to
// millisecond precision. Values before the Unix epoch produce 0.
func TimestampFromTime(t time.Time) Timestamp {
	ms := t.UnixMilli()
	if ms < 0 {
		return 0
	}
	return Timestamp(ms) //nolint:gosec // value is non-negative
}

// EpochMillis returns the timestamp as milliseconds since the Unix epoch.
// Mirrors Rust Timestamp::epoch_millis.
func (ts Timestamp) EpochMillis() uint64 {
	return uint64(ts)
}

// Time converts the Timestamp to a time.Time in UTC.
// Mirrors Rust From<Timestamp> for SystemTime.
func (ts Timestamp) Time() time.Time {
	return time.UnixMilli(int64(ts)).UTC() //nolint:gosec // timestamp fits int64 for all practical values
}

// AddMillis returns a new Timestamp advanced by the given number of milliseconds.
// Mirrors Rust Timestamp::add_millis.
func (ts Timestamp) AddMillis(ms uint64) Timestamp {
	return Timestamp(uint64(ts) + ms)
}

// SubMillis returns a new Timestamp retracted by the given number of milliseconds.
// If the result would underflow, 0 is returned.
// Mirrors Rust Timestamp::sub_millis.
func (ts Timestamp) SubMillis(ms uint64) Timestamp {
	if ms > uint64(ts) {
		return 0
	}
	return Timestamp(uint64(ts) - ms)
}
