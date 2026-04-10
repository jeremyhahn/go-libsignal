package net

import (
	"testing"
)

func TestEnvironment_String(t *testing.T) {
	tests := []struct {
		env  Environment
		want string
	}{
		{EnvironmentProduction, "production"},
		{EnvironmentStaging, "staging"},
		{Environment(99), "Environment(99)"},
	}
	for _, tt := range tests {
		if got := tt.env.String(); got != tt.want {
			t.Errorf("Environment(%d).String() = %q, want %q", tt.env, got, tt.want)
		}
	}
}
