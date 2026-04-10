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
