package protocol

import "time"

// Timestamp is milliseconds since the Unix epoch, as Rust timestamp.rs and the DecryptionErrorMessage and certificate expiry fields.
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
