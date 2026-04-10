package net

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCdsiLookupResponseEntry_HasACI(t *testing.T) {
	t.Run("has ACI", func(t *testing.T) {
		e := &CdsiLookupResponseEntry{ACI: [16]byte{1}}
		if !e.HasACI() {
			t.Error("expected HasACI=true")
		}
	})

	t.Run("no ACI", func(t *testing.T) {
		e := &CdsiLookupResponseEntry{}
		if e.HasACI() {
			t.Error("expected HasACI=false")
		}
	})
}

func TestCdsiLookupResponseEntry_HasPNI(t *testing.T) {
	t.Run("has PNI", func(t *testing.T) {
		e := &CdsiLookupResponseEntry{PNI: [16]byte{1}}
		if !e.HasPNI() {
			t.Error("expected HasPNI=true")
		}
	})

	t.Run("no PNI", func(t *testing.T) {
		e := &CdsiLookupResponseEntry{}
		if e.HasPNI() {
			t.Error("expected HasPNI=false")
		}
	})
}

func TestCdsiLookupError(t *testing.T) {
	tests := []struct {
		name string
		err  *CdsiLookupError
		want string
	}{
		{
			"attestation failed",
			&CdsiLookupError{Kind: CdsiLookupErrorAttestationFailed, Err: errors.New("bad")},
			"cdsi: attestation failed: bad",
		},
		{
			"rate limited",
			&CdsiLookupError{Kind: CdsiLookupErrorRateLimited, RetryAfter: 5 * time.Second},
			fmt.Sprintf("cdsi: rate limited, retry after %v", 5*time.Second),
		},
		{
			"invalid token",
			&CdsiLookupError{Kind: CdsiLookupErrorInvalidToken},
			"cdsi: invalid token",
		},
		{
			"invalid argument",
			&CdsiLookupError{Kind: CdsiLookupErrorInvalidArgument, ServerReason: "bad input"},
			"cdsi: invalid argument: bad input",
		},
		{
			"server error",
			&CdsiLookupError{Kind: CdsiLookupErrorServer, Err: errors.New("internal")},
			"cdsi: server error: internal",
		},
		{
			"unknown with err",
			&CdsiLookupError{Kind: CdsiLookupErrorTransport, Err: errors.New("timeout")},
			"cdsi: timeout",
		},
		{
			"unknown without err",
			&CdsiLookupError{Kind: CdsiLookupErrorTransport},
			"cdsi: unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCdsiLookupError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &CdsiLookupError{Err: inner}
	if err.Unwrap() != inner {
		t.Error("Unwrap mismatch")
	}
}
