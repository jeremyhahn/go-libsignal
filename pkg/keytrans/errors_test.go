package keytrans

import (
	"strings"
	"testing"
)

// TestKeytransErrorMessages exercises the Error() method on all keytrans error
// types to guard against message regressions.
func TestKeytransErrorMessages(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"ErrKeytransEmptyChain", &ErrKeytransEmptyChain{}, "empty"},
		{"ErrKeytransMalformedChain", &ErrKeytransMalformedChain{}, "malformed"},
		{"ErrKeytransRootHasNoParent", &ErrKeytransRootHasNoParent{}, "parent"},
		{"ErrKeytransMalformedPrefixProof", &ErrKeytransMalformedPrefixProof{}, "prefix"},
		{"ErrKeytransInvalidCurvePoint", &ErrKeytransInvalidCurvePoint{}, "curve"},
		{"ErrKeytransInvalidVRFProof", &ErrKeytransInvalidVRFProof{}, "VRF"},
		{"ErrKeytransTryAndIncrementFailed", &ErrKeytransTryAndIncrementFailed{}, "256"},
		{"ErrKeytransInvalidGuideState", &ErrKeytransInvalidGuideState{}, "monotonic"},
		{"ErrKeytransLeafNodeHasNoChildren", &ErrKeytransLeafNodeHasNoChildren{}, "leaf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatalf("%s.Error() returned empty string", tc.name)
			}
			if !strings.Contains(msg, tc.want) {
				t.Errorf("%s.Error() = %q, want to contain %q", tc.name, msg, tc.want)
			}
		})
	}
}
