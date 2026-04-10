package serialize

import (
	"testing"
)

func TestNewSerializer(t *testing.T) {
	s := NewSerializer()
	if s == nil {
		t.Fatal("NewSerializer returned nil")
	}

	// All fields should be nil by default
	if s.SignalMessage != nil {
		t.Fatal("SignalMessage should be nil")
	}
	if s.PreKeySignalMessage != nil {
		t.Fatal("PreKeySignalMessage should be nil")
	}
	if s.SenderKeyRecord != nil {
		t.Fatal("SenderKeyRecord should be nil")
	}
	if s.SenderKeyState != nil {
		t.Fatal("SenderKeyState should be nil")
	}
	if s.SenderKeyMessage != nil {
		t.Fatal("SenderKeyMessage should be nil")
	}
	if s.SenderKeyDistributionMessage != nil {
		t.Fatal("SenderKeyDistributionMessage should be nil")
	}
	if s.SignedPreKeyRecord != nil {
		t.Fatal("SignedPreKeyRecord should be nil")
	}
	if s.PreKeyRecord != nil {
		t.Fatal("PreKeyRecord should be nil")
	}
	if s.State != nil {
		t.Fatal("State should be nil")
	}
	if s.Session != nil {
		t.Fatal("Session should be nil")
	}
}
