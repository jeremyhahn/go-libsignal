package net

import (
	"testing"
	"time"
)

func TestDefaultConnectConfig(t *testing.T) {
	cfg := DefaultConnectConfig()
	if cfg.ConnectTimeout != 10*time.Second {
		t.Errorf("ConnectTimeout = %v", cfg.ConnectTimeout)
	}
	if cfg.NetworkInterfacePollInterval != 100*time.Millisecond {
		t.Errorf("NetworkInterfacePollInterval = %v", cfg.NetworkInterfacePollInterval)
	}
	if cfg.MaxConnectionAttempts != 5 {
		t.Errorf("MaxConnectionAttempts = %d", cfg.MaxConnectionAttempts)
	}
	if cfg.CooldownMaxDelay != 30*time.Second {
		t.Errorf("CooldownMaxDelay = %v", cfg.CooldownMaxDelay)
	}
}

func TestRouteInfo_String(t *testing.T) {
	ri := RouteInfo{Description: "direct to chat.signal.org"}
	if ri.String() != "direct to chat.signal.org" {
		t.Errorf("String() = %q", ri.String())
	}
}

func TestNewConnectState(t *testing.T) {
	cfg := DefaultConnectConfig()
	cs := NewConnectState(cfg)
	if cs == nil {
		t.Fatal("returned nil")
	}
}

func TestConnectState_RecordSuccessAndFailure(t *testing.T) {
	cs := NewConnectState(DefaultConnectConfig())

	cs.RecordFailure("route1")
	cs.RecordFailure("route1")
	cs.RecordSuccess("route1")

	// After success, failures should be reset
	cs.mu.Lock()
	o := cs.outcomes["route1"]
	if o.recentFailures != 0 {
		t.Errorf("recentFailures = %d after success, want 0", o.recentFailures)
	}
	if o.lastSuccess.IsZero() {
		t.Error("lastSuccess should be set")
	}
	cs.mu.Unlock()
}

func TestConnectState_Reset(t *testing.T) {
	cs := NewConnectState(DefaultConnectConfig())
	cs.RecordFailure("route1")
	cs.RecordSuccess("route2")
	cs.Reset()

	cs.mu.Lock()
	if len(cs.outcomes) != 0 {
		t.Errorf("outcomes should be empty after reset, got %d", len(cs.outcomes))
	}
	cs.mu.Unlock()
}

func TestSelectedRoute_String(t *testing.T) {
	sr := &SelectedRoute{
		Address:   "chat.signal.org",
		Port:      443,
		RouteInfo: RouteInfo{Description: "direct"},
	}
	s := sr.String()
	if s != "chat.signal.org:443 via direct" {
		t.Errorf("String() = %q", s)
	}
}
