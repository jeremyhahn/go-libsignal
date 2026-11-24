package spqr

const (
	// wireVersion is the SCKA wire version byte (Rust 0x01).
	wireVersion uint8 = 0x01
)

// sckaToChainEpoch converts a 1-indexed SCKA epoch to a 0-indexed chain epoch; sckaEpoch must be at least 1.
func sckaToChainEpoch(sckaEpoch uint64) uint64 {
	return sckaEpoch - 1
}

// chainToSckaEpoch converts a 0-indexed chain epoch to a 1-indexed SCKA epoch.
func chainToSckaEpoch(chainEpoch uint64) uint64 {
	return chainEpoch + 1
}
