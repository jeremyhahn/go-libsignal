//go:build interop_live

package spqr

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// rustInteropBinary is the path to the Rust libsignal interop CLI used for
// byte-parity tests. Build it with `make interop-live-build`.
const rustInteropBinary = "../../tests/interop/rust/target/release/libsignal-interop"

// TestProtoCodec_RustParity runs byte-parity tests against a live Rust interop
// binary. It verifies that Go's UnmarshalStateProto + MarshalStateProto round-trip
// produces byte-identical output to the Rust prost serializer for each
// (seed, direction) combination.
//
// This test is compiled only under the interop_live build tag. If the binary is
// absent, the test fails hard (t.Fatalf) rather than skipping, because the tag
// signals the environment is expected to have the binary present.
//
// Build the binary first:
//
//	make interop-live-build
func TestProtoCodec_RustParity(t *testing.T) {
	if _, err := os.Stat(rustInteropBinary); err != nil {
		t.Fatalf("Rust interop binary not found at %s — build with `make interop-live-build`", rustInteropBinary)
	}

	seeds := []int{1, 2, 3, 5, 7}
	directions := []string{"a2b", "b2a"}

	for _, dir := range directions {
		for _, seed := range seeds {
			dir := dir
			seed := seed
			t.Run(fmt.Sprintf("%s/seed=%d", dir, seed), func(t *testing.T) {
				out, err := exec.Command(rustInteropBinary,
					"spqr-init",
					fmt.Sprintf("--seed=%d", seed),
					fmt.Sprintf("--direction=%s", dir),
				).Output()
				if err != nil {
					t.Fatalf("Rust interop binary invocation failed: %v", err)
				}

				var resp struct {
					StateHex string `json:"state_hex"`
				}
				if err := json.Unmarshal(out, &resp); err != nil {
					t.Fatalf("parsing Rust JSON output %q: %v", string(out), err)
				}
				stateBytes, err := hex.DecodeString(resp.StateHex)
				if err != nil {
					t.Fatalf("decoding Rust state_hex: %v", err)
				}

				s, err := UnmarshalStateProto(stateBytes)
				if err != nil {
					t.Fatalf("UnmarshalStateProto of Rust bytes: %v", err)
				}
				defer s.Zeroize()

				reencoded, err := MarshalStateProto(s)
				if err != nil {
					t.Fatalf("MarshalStateProto: %v", err)
				}

				if !bytes.Equal(stateBytes, reencoded) {
					t.Errorf("byte-parity mismatch (%s seed=%d):\nrust: %s\ngo:   %s",
						dir, seed,
						hex.EncodeToString(stateBytes),
						hex.EncodeToString(reencoded))
				}
			})
		}
	}
}
