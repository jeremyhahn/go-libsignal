package net

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSvrError(t *testing.T) {
	tests := []struct {
		name string
		err  *SvrError
		want string
	}{
		{
			"rate limited",
			&SvrError{Kind: SvrErrorRateLimited, RetryAfter: 10 * time.Second},
			fmt.Sprintf("svr: rate limited, retry after %v", 10*time.Second),
		},
		{
			"attestation failed",
			&SvrError{Kind: SvrErrorAttestation, Err: errors.New("bad")},
			"svr: attestation failed: bad",
		},
		{
			"all attempts failed",
			&SvrError{Kind: SvrErrorAllAttemptsFailed},
			"svr: all connection attempts failed",
		},
		{
			"unknown with err",
			&SvrError{Kind: SvrErrorWebSocket, Err: errors.New("ws")},
			"svr: ws",
		},
		{
			"unknown no err",
			&SvrError{Kind: SvrErrorWebSocket},
			"svr: unknown error",
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

func TestSvrError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &SvrError{Err: inner}
	if err.Unwrap() != inner {
		t.Error("Unwrap mismatch")
	}
}
