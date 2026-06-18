package net

import (
	"testing"
	"time"
)

func TestDefaultWSConfig(t *testing.T) {
	cfg := DefaultWSConfig()
	if cfg.LocalIdleTimeout != 30*time.Second {
		t.Errorf("LocalIdleTimeout = %v", cfg.LocalIdleTimeout)
	}
	if cfg.RemoteIdlePingTimeout != 3*time.Second {
		t.Errorf("RemoteIdlePingTimeout = %v", cfg.RemoteIdlePingTimeout)
	}
	if cfg.RemoteIdleDisconnectTimeout != 30*time.Second {
		t.Errorf("RemoteIdleDisconnectTimeout = %v", cfg.RemoteIdleDisconnectTimeout)
	}
}

func TestProduction(t *testing.T) {
	env := Production()
	if env == nil {
		t.Fatal("returned nil")
	}
	if env.ChatDomainConfig.Connect.Hostname != "chat.signal.org" {
		t.Errorf("ChatDomainConfig.Connect.Hostname = %q", env.ChatDomainConfig.Connect.Hostname)
	}
	if env.ChatDomainConfig.Connect.Port != DefaultHTTPSPort {
		t.Errorf("Port = %d", env.ChatDomainConfig.Connect.Port)
	}
	if len(env.ChatDomainConfig.IPv4) == 0 {
		t.Error("no IPv4 addresses")
	}
	if len(env.ChatDomainConfig.IPv6) == 0 {
		t.Error("no IPv6 addresses")
	}
	if env.CDSI.DomainConfig.Connect.Hostname != "cdsi.signal.org" {
		t.Error("CDSI hostname wrong")
	}
	if env.SVR2.DomainConfig.Connect.Hostname != "svr2.signal.org" {
		t.Error("SVR2 hostname wrong")
	}
	if len(env.SVRB.Current) == 0 {
		t.Error("no current SVRB endpoints")
	}
	if len(env.SVRB.Previous) == 0 {
		t.Error("no previous SVRB endpoints")
	}

	// Verify MinTLSVersion and HTTPVersion are set on all endpoints (Finding F).
	// Rust sets TLS1_3 + Http1_1 for every production endpoint.
	for _, tc := range []struct {
		name   string
		config ConnectionConfig
		wantH  HTTPVersion
	}{
		{"chat", env.ChatDomainConfig.Connect, HTTPVersion1_1},
		{"chat-h2", env.ExperimentalChatH2DomainConfig.Connect, HTTPVersion2},
		{"cdsi", env.CDSI.DomainConfig.Connect, HTTPVersion1_1},
		{"svr2", env.SVR2.DomainConfig.Connect, HTTPVersion1_1},
		{"svrb-current", env.SVRB.Current[0].DomainConfig.Connect, HTTPVersion1_1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config.MinTLSVersion == nil {
				t.Error("MinTLSVersion is nil, want TLSVersion13")
			} else if *tc.config.MinTLSVersion != TLSVersion13 {
				t.Errorf("MinTLSVersion = %v, want TLSVersion13", *tc.config.MinTLSVersion)
			}
			if tc.config.HTTPVersion == nil {
				t.Errorf("HTTPVersion is nil, want %v", tc.wantH)
			} else if *tc.config.HTTPVersion != tc.wantH {
				t.Errorf("HTTPVersion = %v, want %v", *tc.config.HTTPVersion, tc.wantH)
			}
		})
	}

	// Verify KeyTrans production keys are populated (Finding D).
	var zeroByte [32]byte
	if env.KeyTrans.SigningKeyMaterial == zeroByte {
		t.Error("KeyTrans.SigningKeyMaterial is all zeros")
	}
	if env.KeyTrans.VRFKeyMaterial == zeroByte {
		t.Error("KeyTrans.VRFKeyMaterial is all zeros")
	}
	if len(env.KeyTrans.AuditorKeyMaterials) != 3 {
		t.Errorf("KeyTrans.AuditorKeyMaterials len = %d, want 3", len(env.KeyTrans.AuditorKeyMaterials))
	}
}

func TestKeyTransConfigProduction_ByteValues(t *testing.T) {
	// Verify the verbatim hex bytes from Rust rust/net/src/env.rs KEYTRANS_*_PROD.
	cfg := KeyTransConfigProduction

	// Signing key: a3973067984382cfa89ec26d7cc176680aefe92b3d2eba85159dad0b8354b622
	wantSigning := [32]byte{
		0xa3, 0x97, 0x30, 0x67, 0x98, 0x43, 0x82, 0xcf,
		0xa8, 0x9e, 0xc2, 0x6d, 0x7c, 0xc1, 0x76, 0x68,
		0x0a, 0xef, 0xe9, 0x2b, 0x3d, 0x2e, 0xba, 0x85,
		0x15, 0x9d, 0xad, 0x0b, 0x83, 0x54, 0xb6, 0x22,
	}
	if cfg.SigningKeyMaterial != wantSigning {
		t.Errorf("SigningKeyMaterial mismatch")
	}

	// VRF key: 3849cf116c7bc9aef5f13f0c61a7c246e5bade4eb7e1c7b0efcacdd8c1e6a6ff
	wantVRF := [32]byte{
		0x38, 0x49, 0xcf, 0x11, 0x6c, 0x7b, 0xc9, 0xae,
		0xf5, 0xf1, 0x3f, 0x0c, 0x61, 0xa7, 0xc2, 0x46,
		0xe5, 0xba, 0xde, 0x4e, 0xb7, 0xe1, 0xc7, 0xb0,
		0xef, 0xca, 0xcd, 0xd8, 0xc1, 0xe6, 0xa6, 0xff,
	}
	if cfg.VRFKeyMaterial != wantVRF {
		t.Errorf("VRFKeyMaterial mismatch")
	}

	if len(cfg.AuditorKeyMaterials) != 3 {
		t.Fatalf("AuditorKeyMaterials len = %d, want 3", len(cfg.AuditorKeyMaterials))
	}
}

func TestKeyTransConfigStaging_ByteValues(t *testing.T) {
	// Verify the verbatim hex bytes from Rust rust/net/src/env.rs KEYTRANS_*_STAGING.
	cfg := KeyTransConfigStaging

	// Signing key: ac0de1fd7f33552bbeb6ebc12b9d4ea10bf5f025c45073d3fb5f5648955a749e
	wantSigning := [32]byte{
		0xac, 0x0d, 0xe1, 0xfd, 0x7f, 0x33, 0x55, 0x2b,
		0xbe, 0xb6, 0xeb, 0xc1, 0x2b, 0x9d, 0x4e, 0xa1,
		0x0b, 0xf5, 0xf0, 0x25, 0xc4, 0x50, 0x73, 0xd3,
		0xfb, 0x5f, 0x56, 0x48, 0x95, 0x5a, 0x74, 0x9e,
	}
	if cfg.SigningKeyMaterial != wantSigning {
		t.Errorf("SigningKeyMaterial mismatch")
	}

	if len(cfg.AuditorKeyMaterials) != 3 {
		t.Fatalf("AuditorKeyMaterials len = %d, want 3", len(cfg.AuditorKeyMaterials))
	}
}

func TestStaging(t *testing.T) {
	env := Staging()
	if env == nil {
		t.Fatal("returned nil")
	}
	if env.ChatDomainConfig.Connect.Hostname != "chat.staging.signal.org" {
		t.Errorf("ChatDomainConfig.Connect.Hostname = %q", env.ChatDomainConfig.Connect.Hostname)
	}
	if env.CDSI.DomainConfig.Connect.Hostname != "cdsi.staging.signal.org" {
		t.Error("CDSI hostname wrong")
	}
	if env.SVR2.DomainConfig.Connect.Hostname != "svr2.staging.signal.org" {
		t.Error("SVR2 hostname wrong")
	}
}

func TestSvrBEnv_CurrentAndPrevious(t *testing.T) {
	env := Production()
	all := env.SVRB.CurrentAndPrevious()
	expectedLen := len(env.SVRB.Current) + len(env.SVRB.Previous)
	if len(all) != expectedLen {
		t.Errorf("len = %d, want %d", len(all), expectedLen)
	}
}

func TestSvrBEnv_CurrentAndPrevious_Empty(t *testing.T) {
	s := &SvrBEnv{}
	all := s.CurrentAndPrevious()
	if len(all) != 0 {
		t.Errorf("expected empty, got %d", len(all))
	}
}

// TestProduction_TLSVersionIsolation verifies that mutating the MinTLSVersion
// pointer of one Production() Env does not affect a separately-obtained Env.
func TestProduction_TLSVersionIsolation(t *testing.T) {
	env1 := Production()
	env2 := Production()

	if env1.ChatDomainConfig.Connect.MinTLSVersion == nil {
		t.Fatal("env1 ChatDomainConfig MinTLSVersion is nil")
	}
	if env2.ChatDomainConfig.Connect.MinTLSVersion == nil {
		t.Fatal("env2 ChatDomainConfig MinTLSVersion is nil")
	}

	// Pointers must be distinct allocations.
	if env1.ChatDomainConfig.Connect.MinTLSVersion == env2.ChatDomainConfig.Connect.MinTLSVersion {
		t.Error("env1 and env2 ChatDomainConfig share the same MinTLSVersion pointer; mutation would be shared")
	}

	// Mutate env1 in place; env2 must be unaffected.
	*env1.ChatDomainConfig.Connect.MinTLSVersion = TLSVersion12
	if *env2.ChatDomainConfig.Connect.MinTLSVersion != TLSVersion13 {
		t.Errorf("env2 MinTLSVersion = %v after mutating env1; want TLSVersion13", *env2.ChatDomainConfig.Connect.MinTLSVersion)
	}
}

// TestProduction_HTTPVersionIsolation verifies that mutating the HTTPVersion
// pointer of one Production() Env does not affect a separately-obtained Env.
func TestProduction_HTTPVersionIsolation(t *testing.T) {
	env1 := Production()
	env2 := Production()

	if env1.ChatDomainConfig.Connect.HTTPVersion == nil {
		t.Fatal("env1 ChatDomainConfig HTTPVersion is nil")
	}
	if env2.ChatDomainConfig.Connect.HTTPVersion == nil {
		t.Fatal("env2 ChatDomainConfig HTTPVersion is nil")
	}

	// Pointers must be distinct allocations.
	if env1.ChatDomainConfig.Connect.HTTPVersion == env2.ChatDomainConfig.Connect.HTTPVersion {
		t.Error("env1 and env2 ChatDomainConfig share the same HTTPVersion pointer; mutation would be shared")
	}

	// Mutate env1 in place; env2 must be unaffected.
	*env1.ChatDomainConfig.Connect.HTTPVersion = HTTPVersion2
	if *env2.ChatDomainConfig.Connect.HTTPVersion != HTTPVersion1_1 {
		t.Errorf("env2 HTTPVersion = %v after mutating env1; want HTTPVersion1_1", *env2.ChatDomainConfig.Connect.HTTPVersion)
	}
}

// TestProduction_KeyTransAuditorIsolation verifies that mutating the
// AuditorKeyMaterials slice of one Production() Env does not corrupt the
// package-level KeyTransConfigProduction constant or a subsequent Production()
// call.
func TestProduction_KeyTransAuditorIsolation(t *testing.T) {
	// Save the original first byte of the first auditor key.
	original := KeyTransConfigProduction.AuditorKeyMaterials[0][0]

	env1 := Production()
	// Corrupt env1's auditor material in place.
	env1.KeyTrans.AuditorKeyMaterials[0][0] = 0xFF

	// The package-level constant must be unchanged.
	if KeyTransConfigProduction.AuditorKeyMaterials[0][0] != original {
		// Restore before failing so we don't break subsequent tests.
		KeyTransConfigProduction.AuditorKeyMaterials[0][0] = original
		t.Fatal("mutating env.KeyTrans.AuditorKeyMaterials corrupted KeyTransConfigProduction")
	}

	// A fresh Production() call must return the uncorrupted value.
	env2 := Production()
	if env2.KeyTrans.AuditorKeyMaterials[0][0] != original {
		t.Errorf("Production() after mutation returned AuditorKeyMaterials[0][0] = 0x%02x, want 0x%02x",
			env2.KeyTrans.AuditorKeyMaterials[0][0], original)
	}
}

// TestStaging_KeyTransAuditorIsolation performs the same isolation check for
// Staging().
func TestStaging_KeyTransAuditorIsolation(t *testing.T) {
	original := KeyTransConfigStaging.AuditorKeyMaterials[0][0]

	env1 := Staging()
	env1.KeyTrans.AuditorKeyMaterials[0][0] = 0xFF

	if KeyTransConfigStaging.AuditorKeyMaterials[0][0] != original {
		KeyTransConfigStaging.AuditorKeyMaterials[0][0] = original
		t.Fatal("mutating env.KeyTrans.AuditorKeyMaterials corrupted KeyTransConfigStaging")
	}

	env2 := Staging()
	if env2.KeyTrans.AuditorKeyMaterials[0][0] != original {
		t.Errorf("Staging() after mutation returned AuditorKeyMaterials[0][0] = 0x%02x, want 0x%02x",
			env2.KeyTrans.AuditorKeyMaterials[0][0], original)
	}
}

func TestEnvForEnvironment(t *testing.T) {
	t.Run("production", func(t *testing.T) {
		env := EnvForEnvironment(EnvironmentProduction)
		if env.ChatDomainConfig.Connect.Hostname != "chat.signal.org" {
			t.Error("wrong hostname for production")
		}
	})

	t.Run("staging", func(t *testing.T) {
		env := EnvForEnvironment(EnvironmentStaging)
		if env.ChatDomainConfig.Connect.Hostname != "chat.staging.signal.org" {
			t.Error("wrong hostname for staging")
		}
	})

	t.Run("default", func(t *testing.T) {
		env := EnvForEnvironment(Environment(99))
		if env.ChatDomainConfig.Connect.Hostname != "chat.signal.org" {
			t.Error("default should be production")
		}
	})
}
