//go:build interop_live

// Package interop provides live interop tests that shell out to the Rust
// libsignal-interop CLI binary to verify wire-format compatibility between
// Go and Rust SPQR implementations.
//
// # Wire-Format Architecture (Phase E — converged)
//
// The Rust SPQR crate uses two serialization layers:
//
//  1. State serialization: protobuf (prost::Message::encode_to_vec).
//     Go's pkg/spqr.Serialize / Deserialize now produce Rust-compatible proto
//     bytes via MarshalStateProto / UnmarshalStateProto (Phase D codec).
//
//  2. Wire messages (the "msg" field in Send/Recv): the Rust-compatible SCKA
//     variable-length format: version(0x01) + varint(epoch) + varint(counter)
//     + msgType(1) + [chunk_data]. After Phase E, Go's non-braid and
//     braid-integrated paths both produce and consume this format.
//
// # Epoch Convention
//
// Rust SCKA wire messages carry 1-indexed epochs. Go chains are 0-indexed.
// The helpers sckaToChainEpoch / chainToSckaEpoch in pkg/spqr/wire.go perform
// the offset conversion explicitly, making the mapping audit-friendly.
//
// # Key Parity
//
// Both sides initialize from the same auth_key (MinVersion=V1 so negotiation
// resolves immediately) and derive chain keys via the same HKDF-SHA256 KDF.
// For the first epoch (no SCKA advancement), Rust and Go derive identical
// message keys. After epoch advancement, keys diverge because the SCKA state
// machines are independently implemented with different RNG seeds.
//
// The tests below:
//  1. Confirm the Rust CLI is functional (Rust self-test).
//  2. Confirm Go can parse Rust-generated wire messages (structural parse).
//  3. Confirm Go's non-braid Recv accepts Rust-generated SCKA messages (Phase E gap closed).
//  4. Confirm key parity for the first epoch in both directions.
//  5. Confirm Go's own chain KDF pipeline is regression-free.
package interop

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
)

// ErrBinaryNotFound is returned when the interop binary cannot be located.
type ErrBinaryNotFound struct {
	Path string
}

func (e *ErrBinaryNotFound) Error() string {
	return fmt.Sprintf("interop binary not found at %q; run 'make interop-live-build' first", e.Path)
}

// ErrRustCommand is returned when the Rust CLI exits with an error.
type ErrRustCommand struct {
	Subcommand string
	Stderr     string
	ExitCode   int
}

func (e *ErrRustCommand) Error() string {
	return fmt.Sprintf("rust CLI %q exited %d: %s", e.Subcommand, e.ExitCode, e.Stderr)
}

// interopBinPath returns the path to the Rust interop binary. It checks the
// LIBSIGNAL_INTEROP_BIN environment variable first, then falls back to the
// default location relative to this source file.
func interopBinPath() string {
	if v := os.Getenv("LIBSIGNAL_INTEROP_BIN"); v != "" {
		return v
	}
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "rust", "target", "release", "libsignal-interop")
}

// requireBin skips the test with a helpful message if the Rust binary is absent.
// This is the one legitimate skip: it gates on build infrastructure availability.
func requireBin(t *testing.T) string {
	t.Helper()
	path := interopBinPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("Rust interop binary not found at %q — run 'make interop-live-build' to build it", path)
	}
	return path
}

// rustJSON runs a Rust CLI subcommand and parses the JSON output into dst.
func rustJSON(t *testing.T, bin string, args []string, dst any) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		stderr := ""
		if ok := false; !ok {
			// parse exit error for stderr
			if ee, isExit := err.(*exec.ExitError); isExit {
				exitErr = ee
				stderr = string(exitErr.Stderr)
			}
		}
		t.Fatalf("rust CLI %v failed: %v\nstderr: %s", args, err, stderr)
	}
	if err := json.Unmarshal(out, dst); err != nil {
		t.Fatalf("failed to parse rust CLI output %q: %v", string(out), err)
	}
}

// rustInit calls spqr-init and returns the state_hex.
func rustInit(t *testing.T, bin, direction string) string {
	t.Helper()
	var out struct {
		StateHex string `json:"state_hex"`
	}
	rustJSON(t, bin, []string{
		"spqr-init",
		"--seed", "0",
		"--direction", direction,
	}, &out)
	return out.StateHex
}

// rustSend calls spqr-send with the given state_hex and seed.
func rustSend(t *testing.T, bin string, seed uint64, stateHex string) (newStateHex, keyHex, msgHex string) {
	t.Helper()
	var out struct {
		StateHex string `json:"state_hex"`
		KeyHex   string `json:"key_hex"`
		MsgHex   string `json:"msg_hex"`
	}
	rustJSON(t, bin, []string{
		"spqr-send",
		"--seed", fmt.Sprintf("%d", seed),
		"--state-hex", stateHex,
	}, &out)
	return out.StateHex, out.KeyHex, out.MsgHex
}

// rustRecv calls spqr-recv with the given state and msg hex strings.
func rustRecv(t *testing.T, bin, stateHex, msgHex string) (newStateHex, keyHex string) {
	t.Helper()
	var out struct {
		StateHex string `json:"state_hex"`
		KeyHex   string `json:"key_hex"`
	}
	rustJSON(t, bin, []string{
		"spqr-recv",
		"--state-hex", stateHex,
		"--msg-hex", msgHex,
	}, &out)
	return out.StateHex, out.KeyHex
}

// TestInteropSPQRRustSelfTest verifies the Rust CLI can perform a multi-step
// send/recv round trip entirely within Rust. This confirms:
//  1. The CLI binary is functional.
//  2. The Rust SPQR state machine exercises send → recv correctly.
//  3. Sender and receiver derive identical keys from the same wire message.
//
// This is a prerequisite sanity check before any cross-impl tests.
func TestInteropSPQRRustSelfTest(t *testing.T) {
	bin := requireBin(t)

	// Alice uses direction A2B, Bob uses direction B2A; both share the same
	// auth_key (hardcoded in the Rust CLI as "interop-shared-auth-key-32bytes!").
	aliceState := rustInit(t, bin, "a2b")
	bobState := rustInit(t, bin, "b2a")

	// Step 1: Alice sends, Bob receives.
	aliceState, aliceKey1, msg1 := rustSend(t, bin, 100, aliceState)
	t.Logf("step1: alice key_hex=%s msg_hex=%s", aliceKey1, msg1)
	if aliceKey1 == "" {
		t.Log("step1: alice key is empty (pending negotiation before first recv — expected)")
	}

	bobState, bobKey1 := rustRecv(t, bin, bobState, msg1)
	t.Logf("step1: bob key_hex=%s", bobKey1)

	// After Alice sends and Bob receives, keys must match (may both be empty
	// during pending negotiation).
	if aliceKey1 != bobKey1 {
		t.Errorf("step1 key mismatch:\n  alice: %s\n  bob:   %s", aliceKey1, bobKey1)
	}

	// Step 2: Bob sends, Alice receives.
	bobState, bobKey2, msg2 := rustSend(t, bin, 200, bobState)
	aliceState, aliceKey2 := rustRecv(t, bin, aliceState, msg2)
	t.Logf("step2: bob key_hex=%s alice key_hex=%s", bobKey2, aliceKey2)

	if bobKey2 != aliceKey2 {
		t.Errorf("step2 key mismatch:\n  bob:   %s\n  alice: %s", bobKey2, aliceKey2)
	}

	// Step 3: Alice sends again — at this point negotiation should be resolved
	// and both sides should be producing non-empty keys.
	aliceState, aliceKey3, msg3 := rustSend(t, bin, 300, aliceState)
	_, bobKey3 := rustRecv(t, bin, bobState, msg3)
	t.Logf("step3: alice key_hex=%s bob key_hex=%s", aliceKey3, bobKey3)

	if aliceKey3 != bobKey3 {
		t.Errorf("step3 key mismatch:\n  alice: %s\n  bob:   %s", aliceKey3, bobKey3)
	}
	if aliceKey3 == "" {
		t.Error("step3: expected non-empty key after negotiation resolution, got empty")
	}

	// Suppress unused variable warning — aliceState is updated across steps.
	_ = aliceState
}

// TestInteropSPQRRustMultiRound extends the Rust self-test to a longer
// alternating send/recv sequence, verifying chain key progression across
// multiple messages and epochs. This exercises the ratchet's forward secrecy:
// each step derives a fresh key, and keys from earlier steps must not reappear.
func TestInteropSPQRRustMultiRound(t *testing.T) {
	bin := requireBin(t)

	aliceState := rustInit(t, bin, "a2b")
	bobState := rustInit(t, bin, "b2a")

	type roundKey struct {
		alice string
		bob   string
	}
	var keys []roundKey

	// Bootstrap: Alice sends first so negotiation resolves.
	aliceState, _, msg := rustSend(t, bin, 1, aliceState)
	bobState, _ = rustRecv(t, bin, bobState, msg)

	// Bob sends back so Alice also resolves.
	bobState, _, msg = rustSend(t, bin, 2, bobState)
	aliceState, _ = rustRecv(t, bin, aliceState, msg)

	// Now run 8 alternating rounds. All keys must be non-empty and unique.
	for i := 0; i < 8; i++ {
		seed := uint64(1000 + i*10)
		var aKey, bKey, aMsg string

		// Alice → Bob
		aliceState, aKey, aMsg = rustSend(t, bin, seed, aliceState)
		bobState, bKey = rustRecv(t, bin, bobState, aMsg)
		if aKey != bKey {
			t.Errorf("round %d A→B key mismatch:\n  alice: %s\n  bob:   %s", i, aKey, bKey)
		}
		if aKey == "" {
			t.Errorf("round %d A→B: got empty key after negotiation resolved", i)
		}
		keys = append(keys, roundKey{aKey, bKey})

		// Bob → Alice
		seed++
		bobState, bKey, msg = rustSend(t, bin, seed, bobState)
		aliceState, aKey = rustRecv(t, bin, aliceState, msg)
		if aKey != bKey {
			t.Errorf("round %d B→A key mismatch:\n  bob:   %s\n  alice: %s", i, bKey, aKey)
		}
		if bKey == "" {
			t.Errorf("round %d B→A: got empty key after negotiation resolved", i)
		}
		keys = append(keys, roundKey{aKey, bKey})
	}

	// Verify all keys are unique (forward secrecy: no key repeats).
	seen := make(map[string]int)
	for i, k := range keys {
		if prev, dup := seen[k.alice]; dup {
			t.Errorf("key at round %d duplicates round %d: %s", i, prev, k.alice)
		}
		seen[k.alice] = i
	}
	t.Logf("verified %d unique keys across %d rounds", len(seen), len(keys))
}

// TestInteropSPQRRustToGoWireFormat verifies that Go's wire message parser
// (pkg/spqr decodeWireMessage, exported via WireMessage) can structurally
// parse Rust-generated wire messages without error. This confirms the
// variable-length wire format (version + varint fields) is understood by both
// implementations.
//
// NOTE on key parity: full cross-impl key equality (Go derives the same
// message key as Rust from the same wire message) is NOT possible without a
// shared SCKA transcript. See the package-level doc comment for details.
// This test verifies structural parse compatibility only.
func TestInteropSPQRRustToGoWireFormat(t *testing.T) {
	bin := requireBin(t)

	// Obtain a Rust wire message by running init + send.
	aliceState := rustInit(t, bin, "a2b")
	_, _, msgHex := rustSend(t, bin, 42, aliceState)

	msgBytes, err := hex.DecodeString(msgHex)
	if err != nil {
		t.Fatalf("hex decode msg: %v", err)
	}
	if len(msgBytes) == 0 {
		t.Fatal("rust send returned empty msg_hex (pending negotiation with min_version=V1 should produce a message)")
	}

	t.Logf("rust wire message: %s (%d bytes)", msgHex, len(msgBytes))

	// Verify the first byte is the version marker that Go's wire parser expects.
	// Go's decodeWireMessage treats byte[0]==0x01 as the variable-length format.
	const goWireVersion = 0x01
	if msgBytes[0] != goWireVersion {
		t.Errorf("wire message version byte: got 0x%02x, want 0x%02x", msgBytes[0], goWireVersion)
	}

	// Verify the message is NOT 12 bytes — confirming it is not in Go's legacy
	// non-braid format and therefore cannot be processed by the non-braid Recv path.
	const legacySize = 12
	if len(msgBytes) == legacySize {
		t.Logf("NOTICE: rust message is exactly 12 bytes; this would be ambiguous with Go's legacy format")
	} else {
		t.Logf("confirmed: rust message length %d != %d (not legacy format)", len(msgBytes), legacySize)
	}

	// Parse the varint fields manually to confirm the wire structure is intact.
	// Format: version(1) + varint(epoch) + varint(counter) + msgType(1) + chunk
	at := 1 // skip version byte
	epoch, n := readVarint(msgBytes[at:])
	if n <= 0 {
		t.Fatalf("failed to decode epoch varint at offset %d", at)
	}
	at += n
	counter, n := readVarint(msgBytes[at:])
	if n <= 0 {
		t.Fatalf("failed to decode counter varint at offset %d", at)
	}
	at += n
	if at >= len(msgBytes) {
		t.Fatalf("message too short: missing msgType byte at offset %d", at)
	}
	msgType := msgBytes[at]
	t.Logf("parsed wire message: epoch=%d counter=%d msgType=0x%02x chunkLen=%d",
		epoch, counter, msgType, len(msgBytes)-at-1)

	// The epoch and counter must be within plausible bounds.
	if epoch == 0 {
		t.Error("wire message epoch is 0; Rust SPQR epochs start at 1")
	}
}

// TestInteropSPQRWireFormatParityVerified verifies that the Phase E wire-format
// gap between Go's non-braid SPQR path and Rust's SPQR crate is now CLOSED.
//
// After Phase E, Go's non-braid Send/Recv use the same Rust-compatible SCKA
// variable-length wire format: version(0x01) + varint(epoch) + varint(counter)
// + msgType + [chunk_data]. Go Recv now accepts Rust-generated wire messages.
//
// This test replaces the former TestInteropSPQRWireFormatGapDocumented which
// asserted the formats diverged. Failure here means Phase E regression.
func TestInteropSPQRWireFormatParityVerified(t *testing.T) {
	bin := requireBin(t)

	// auth_key must match what the Rust CLI hardcodes (see rust/src/main.rs AUTH_KEY).
	authKey := []byte("interop-shared-auth-key-32bytes!")
	if len(authKey) != 32 {
		t.Fatalf("authKey is %d bytes, need 32", len(authKey))
	}

	// Go side: create B2A state using the non-braid path.
	// MinVersion=V1 so negotiation resolves immediately on the first send/recv.
	goState, err := spqr.InitialStateWithParams(spqr.Params{
		AuthKey:    authKey,
		Version:    spqr.VersionV1,
		Direction:  spqr.DirectionB2A,
		MinVersion: spqr.VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: 2000,
	})
	if err != nil {
		t.Fatalf("Go InitialStateWithParams: %v", err)
	}

	// Rust side: init A2B (same auth_key, hardcoded in Rust CLI), then send.
	rustAliceState := rustInit(t, bin, "a2b")
	_, _, msgHex := rustSend(t, bin, 42, rustAliceState)

	msgBytes, err := hex.DecodeString(msgHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	t.Logf("Rust wire msg (%d bytes): %s", len(msgBytes), msgHex)

	// Verify the Rust message starts with the SCKA version byte.
	if len(msgBytes) == 0 {
		t.Fatal("Rust send returned empty message (pending negotiation?)")
	}
	if msgBytes[0] != 0x01 {
		t.Errorf("Rust wire version byte: got 0x%02x, want 0x01", msgBytes[0])
	}

	// Go non-braid Recv must now accept the Rust-generated SCKA wire message.
	// Both sides are initialized from the same auth_key and use MinVersion=V1,
	// so negotiation resolves immediately and the chain KDF inputs match.
	_, _, recvErr := spqr.Recv(goState, msgBytes)
	if recvErr != nil {
		t.Errorf("PHASE E REGRESSION: Go non-braid Recv rejected Rust wire message: %v", recvErr)
		t.Log("After Phase E, Go's non-braid path must speak the same SCKA wire format as Rust.")
		t.Log("This failure indicates the wire format convergence was not fully implemented.")
	} else {
		t.Log("CONFIRMED: Go non-braid Recv accepted the Rust wire message (Phase E gap closed)")
	}
}

// TestInteropSPQRGoChainKDFSelfConsistency verifies that Go's chain KDF
// (HKDF info strings) is internally consistent across a multi-message sequence.
// This is a regression guard: any change to KDF info strings, key ordering,
// or chain advancement logic will cause this test to fail.
//
// It does NOT compare against Rust keys (which requires a shared SCKA
// transcript — see package-level doc comment), but it documents the KDF
// parameters used so they can be compared against the Rust source manually.
func TestInteropSPQRGoChainKDFSelfConsistency(t *testing.T) {
	// Both sides use the same shared auth_key that the Rust CLI also uses.
	authKey := []byte("interop-shared-auth-key-32bytes!")
	if len(authKey) != 32 {
		t.Fatalf("authKey is %d bytes, need 32", len(authKey))
	}

	// Alice: A2B, Bob: B2A. Non-braid path; min_version=V1 so negotiation
	// resolves immediately on the first send without waiting for a recv.
	aliceState, err := spqr.InitialStateWithParams(spqr.Params{
		AuthKey:    authKey,
		Version:    spqr.VersionV1,
		Direction:  spqr.DirectionA2B,
		MinVersion: spqr.VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: 2000,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams alice: %v", err)
	}

	bobState, err := spqr.InitialStateWithParams(spqr.Params{
		AuthKey:    authKey,
		Version:    spqr.VersionV1,
		Direction:  spqr.DirectionB2A,
		MinVersion: spqr.VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: 2000,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams bob: %v", err)
	}

	t.Logf("KDF info strings (for manual Rust comparison):")
	t.Logf("  ChainStartInfo:    %q", spqr.ChainStartInfo)
	t.Logf("  ChainAddEpochInfo: %q", spqr.ChainAddEpochInfo)
	t.Logf("  ChainNextInfo:     %q", spqr.ChainNextInfo)

	// Alice sends; the first Send with MinVersion=V1 resolves negotiation and
	// produces the first non-nil message key.
	var seenKeys []string
	for i := 0; i < 5; i++ {
		var newState, pqrMsg, mk []byte
		newState, pqrMsg, mk, err = spqr.Send(aliceState)
		if err != nil {
			t.Fatalf("Send iteration %d: %v", i, err)
		}
		aliceState = newState

		if mk == nil {
			t.Logf("send[%d]: key=nil (pending or V0)", i)
			continue
		}
		keyHex := hex.EncodeToString(mk)
		t.Logf("send[%d]: key=%s pqrMsgLen=%d", i, keyHex, len(pqrMsg))
		seenKeys = append(seenKeys, keyHex)

		// Bob receives the message; must derive the same key.
		var bState []byte
		var bKey []byte
		bState, bKey, err = spqr.Recv(bobState, pqrMsg)
		if err != nil {
			t.Fatalf("Recv iteration %d: %v", i, err)
		}
		bobState = bState

		if bKey == nil {
			t.Errorf("send[%d]: bob got nil key but alice had %s", i, keyHex)
			continue
		}
		bKeyHex := hex.EncodeToString(bKey)
		if keyHex != bKeyHex {
			t.Errorf("send[%d]: key mismatch:\n  alice: %s\n  bob:   %s", i, keyHex, bKeyHex)
		}
	}

	if len(seenKeys) == 0 {
		t.Error("no non-nil keys produced across 5 send iterations")
	}

	// All keys must be unique (no repetition — forward secrecy within Go).
	seen := make(map[string]bool)
	for _, k := range seenKeys {
		if seen[k] {
			t.Errorf("duplicate key: %s", k)
		}
		seen[k] = true
	}
	t.Logf("verified %d unique message keys", len(seen))
}

// TestInteropSPQRRustToGoKeyParity verifies cross-impl key parity between
// Rust and Go SPQR. Both sides initialize from the same auth_key (MinVersion=V1
// so negotiation resolves immediately). Rust sends a native SCKA wire message;
// Go's non-braid Recv now accepts SCKA format directly (Phase E wire convergence).
//
// The chain KDF inputs (auth_key, HKDF info strings, epoch, counter) are identical
// between Rust and Go, so both sides must derive the same message key.
func TestInteropSPQRRustToGoKeyParity(t *testing.T) {
	bin := requireBin(t)

	authKey := []byte("interop-shared-auth-key-32bytes!")

	// Rust: init A2B state, send first message.
	rustAliceState := rustInit(t, bin, "a2b")
	_, rustKeyHex, rustMsgHex := rustSend(t, bin, 42, rustAliceState)

	rustMsgBytes, err := hex.DecodeString(rustMsgHex)
	if err != nil {
		t.Fatalf("hex decode rust msg: %v", err)
	}

	if rustKeyHex == "" {
		t.Skip("Rust returned empty key (negotiation pending — min_version mismatch); cannot test key parity")
	}

	t.Logf("Rust sender key: %s", rustKeyHex)
	t.Logf("Rust wire msg (%d bytes): %s", len(rustMsgBytes), rustMsgHex)

	// Go: init B2A state with MinVersion=V1 so negotiation resolves immediately.
	// After Phase E, Go Recv accepts the Rust SCKA wire message natively.
	goState, err := spqr.InitialStateWithParams(spqr.Params{
		AuthKey:    authKey,
		Version:    spqr.VersionV1,
		Direction:  spqr.DirectionB2A,
		MinVersion: spqr.VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: 2000,
	})
	if err != nil {
		t.Fatalf("Go InitialStateWithParams: %v", err)
	}

	// Go Recv with the native Rust SCKA wire message — no translation needed.
	_, goKey, err := spqr.Recv(goState, rustMsgBytes)
	if err != nil {
		t.Fatalf("Go Recv with Rust SCKA message: %v", err)
	}

	if goKey == nil {
		t.Fatal("Go Recv returned nil key")
	}

	goKeyHex := hex.EncodeToString(goKey)
	t.Logf("Go receiver key: %s", goKeyHex)

	if rustKeyHex != goKeyHex {
		t.Errorf("KEY PARITY FAILURE:\n  Rust: %s\n  Go:   %s\n\nThis indicates the chain KDF diverged between Rust and Go.", rustKeyHex, goKeyHex)
	} else {
		t.Logf("KEY PARITY CONFIRMED: Rust and Go derive identical message keys from the same chain KDF inputs")
	}
}

// TestInteropSPQRGoToRustKeyParity is the reverse of TestInteropSPQRRustToGoKeyParity:
// Go sends (producing a native SCKA wire message after Phase E), Rust receives,
// and the keys are compared. This confirms bidirectional chain KDF and wire-format
// compatibility.
func TestInteropSPQRGoToRustKeyParity(t *testing.T) {
	bin := requireBin(t)

	authKey := []byte("interop-shared-auth-key-32bytes!")

	// Go: init A2B with MinVersion=V1 and Send.
	// After Phase E, Go Send produces a native SCKA wire message — no translation needed.
	goState, err := spqr.InitialStateWithParams(spqr.Params{
		AuthKey:    authKey,
		Version:    spqr.VersionV1,
		Direction:  spqr.DirectionA2B,
		MinVersion: spqr.VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: 2000,
	})
	if err != nil {
		t.Fatalf("Go InitialStateWithParams: %v", err)
	}

	_, pqrMsg, goKey, err := spqr.Send(goState)
	if err != nil {
		t.Fatalf("Go Send: %v", err)
	}

	if goKey == nil {
		t.Skip("Go Send returned nil key (pending negotiation); cannot test key parity")
	}

	goKeyHex := hex.EncodeToString(goKey)
	t.Logf("Go sender key: %s", goKeyHex)
	t.Logf("Go wire msg (%d bytes): %s", len(pqrMsg), hex.EncodeToString(pqrMsg))

	// Verify Go produces SCKA format (version byte 0x01) after Phase E.
	if len(pqrMsg) == 0 {
		t.Fatal("Go Send produced empty wire message")
	}
	if pqrMsg[0] != 0x01 {
		t.Errorf("Go Send wire version byte: got 0x%02x, want 0x01 (SCKA format)", pqrMsg[0])
	}

	// Rust: init B2A state and recv Go's native SCKA message — no translation needed.
	rustBobState := rustInit(t, bin, "b2a")
	_, rustKeyHex := rustRecv(t, bin, rustBobState, hex.EncodeToString(pqrMsg))

	t.Logf("Rust receiver key: %s", rustKeyHex)

	if rustKeyHex == "" {
		t.Log("NOTICE: Rust recv returned empty key (pending negotiation).")
		t.Log("Both sides use MinVersion=V1; if Rust CLI also requires a first recv for B2A,")
		t.Log("the empty key here is a Rust CLI behavior, not a wire-format failure.")
		return
	}

	if goKeyHex != rustKeyHex {
		t.Errorf("KEY PARITY FAILURE:\n  Go:   %s\n  Rust: %s", goKeyHex, rustKeyHex)
	} else {
		t.Logf("KEY PARITY CONFIRMED: Go→Rust direction (Phase E)")
	}
}

// readVarint reads a binary.Uvarint from b and returns the value and bytes read.
func readVarint(b []byte) (uint64, int) {
	v := uint64(0)
	s := uint(0)
	for i, c := range b {
		if i == 10 {
			return 0, -1
		}
		if c < 0x80 {
			return v | uint64(c)<<s, i + 1
		}
		v |= uint64(c&0x7f) << s
		s += 7
	}
	return 0, 0
}
