// Validation tests for AccountEntropyPool alphabet, uniqueness and parse errors (rust/account-keys/src/lib.rs).
package accountkeys

import (
	"errors"
	"strings"
	"testing"
)

// TestAccountEntropyPool_OnlyAlphabetCharactersAreUsed checks 1000 generated pools use only [0-9a-z] (lib.rs:127).
func TestAccountEntropyPool_OnlyAlphabetCharactersAreUsed(t *testing.T) {
	const iterations = 1000
	allowed := make(map[rune]bool, 36)
	for c := '0'; c <= '9'; c++ {
		allowed[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		allowed[c] = true
	}

	for i := 0; i < iterations; i++ {
		pool, err := GenerateAccountEntropyPool()
		if err != nil {
			t.Fatalf("iteration %d: GenerateAccountEntropyPool: %v", i, err)
		}
		for pos, ch := range string(pool) {
			if !allowed[ch] {
				t.Errorf("iteration %d: disallowed character %q at position %d in pool %q",
					i, ch, pos, pool)
			}
		}
	}
}

// TestAccountEntropyPool_Uniqueness verifies that 1000 independently generated
// pools are all distinct. Collisions are astronomically unlikely (alphabet^64
// space) but the test guards against degenerate implementations.
//
// Rust libsignal ref: rust/account-keys/src/lib.rs uniqueness (line 139)
func TestAccountEntropyPool_Uniqueness(t *testing.T) {
	const iterations = 1000
	seen := make(map[AccountEntropyPool]bool, iterations)

	for i := 0; i < iterations; i++ {
		pool, err := GenerateAccountEntropyPool()
		if err != nil {
			t.Fatalf("iteration %d: GenerateAccountEntropyPool: %v", i, err)
		}
		if seen[pool] {
			t.Fatalf("iteration %d: duplicate pool %q", i, pool)
		}
		seen[pool] = true
	}
}

// TestAccountEntropyPool_Validate_ParseErrorCases covers the Rust from_str error cases (lib.rs:154).
func TestAccountEntropyPool_Validate_ParseErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		input       AccountEntropyPool
		wantErr     bool
		errContains string // non-empty: substring expected in error message
		errType     interface{}
	}{
		{
			name:    "valid 64 ms",
			input:   AccountEntropyPool(strings.Repeat("m", 64)),
			wantErr: false,
		},
		{
			name:        "wrong length short",
			input:       AccountEntropyPool("abc"),
			wantErr:     true,
			errContains: "3",
			errType:     &ErrEntropyPoolLength{},
		},
		{
			name:        "wrong length empty",
			input:       AccountEntropyPool(""),
			wantErr:     true,
			errContains: "0",
			errType:     &ErrEntropyPoolLength{},
		},
		{
			name:        "wrong length too long",
			input:       AccountEntropyPool(strings.Repeat("a", 65)),
			wantErr:     true,
			errContains: "65",
			errType:     &ErrEntropyPoolLength{},
		},
		{
			name:        "invalid character space",
			input:       AccountEntropyPool(strings.Repeat(" ", 64)),
			wantErr:     true,
			errContains: "position 0",
			errType:     &ErrEntropyPoolInvalidChar{},
		},
		{
			name:        "invalid character uppercase",
			input:       AccountEntropyPool(strings.Repeat("A", 64)),
			wantErr:     true,
			errContains: "position 0",
			errType:     &ErrEntropyPoolInvalidChar{},
		},
		{
			name:        "invalid character punctuation in otherwise valid length string",
			input:       AccountEntropyPool(strings.Repeat("a", 63) + "!"),
			wantErr:     true,
			errContains: "position 63",
			errType:     &ErrEntropyPoolInvalidChar{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate() returned nil; want error")
				}
				if tt.errType != nil {
					var lengthErr *ErrEntropyPoolLength
					var charErr *ErrEntropyPoolInvalidChar
					switch tt.errType.(type) {
					case *ErrEntropyPoolLength:
						if !errors.As(err, &lengthErr) {
							t.Errorf("Validate() error %T, want *ErrEntropyPoolLength", err)
						}
					case *ErrEntropyPoolInvalidChar:
						if !errors.As(err, &charErr) {
							t.Errorf("Validate() error %T, want *ErrEntropyPoolInvalidChar", err)
						}
					}
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("Validate() returned unexpected error: %v", err)
				}
			}
		})
	}
}

// TestAccountEntropyPool_Validate_LengthErrors verifies the exact length values
// reported by ErrEntropyPoolLength match what was passed.
func TestAccountEntropyPool_Validate_LengthErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"length 3", "abc", 3},
		{"length 0", "", 0},
		{"length 1", "z", 1},
		{"length 63", strings.Repeat("a", 63), 63},
		{"length 65", strings.Repeat("a", 65), 65},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := AccountEntropyPool(tt.input)
			err := pool.Validate()
			if err == nil {
				t.Fatal("expected error for wrong length")
			}
			var lengthErr *ErrEntropyPoolLength
			if !errors.As(err, &lengthErr) {
				t.Fatalf("expected *ErrEntropyPoolLength, got %T", err)
			}
			if lengthErr.Got != tt.wantLen {
				t.Errorf("ErrEntropyPoolLength.Got = %d, want %d", lengthErr.Got, tt.wantLen)
			}
			if lengthErr.Expected != EntropyPoolLength {
				t.Errorf("ErrEntropyPoolLength.Expected = %d, want %d", lengthErr.Expected, EntropyPoolLength)
			}
		})
	}
}
