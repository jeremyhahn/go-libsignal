package spqr

const (
	// wireVersion is the version byte prepended to SCKA wire messages.
	// Matches the Rust sparsepostquantumratchet wire format (version 0x01).
	wireVersion uint8 = 0x01
)

// sckaToChainEpoch converts a 1-indexed SCKA wire epoch to a 0-indexed Go chain epoch.
// Rust SCKA wire messages carry epochs starting at 1; Go chains are 0-indexed.
// Callers must validate that sckaEpoch >= 1 before calling this function.
func sckaToChainEpoch(sckaEpoch uint64) uint64 {
	return sckaEpoch - 1
}

// chainToSckaEpoch converts a 0-indexed Go chain epoch to a 1-indexed SCKA wire epoch.
// Rust SCKA wire messages carry epochs starting at 1; Go chains are 0-indexed.
func chainToSckaEpoch(chainEpoch uint64) uint64 {
	return chainEpoch + 1
}
