package protocol

import (
	"testing"
)

func TestNewSenderKeyName(t *testing.T) {
	sender := NewSignalAddress("Alice", 1)
	skn := NewSenderKeyName("group1", sender)

	if skn.GroupID() != "group1" {
		t.Fatalf("expected group1, got %s", skn.GroupID())
	}
	if skn.Sender() != sender {
		t.Fatal("sender mismatch")
	}
}

func TestSenderKeyNameEmptyGroup(t *testing.T) {
	sender := NewSignalAddress("Bob", 2)
	skn := NewSenderKeyName("", sender)

	if skn.GroupID() != "" {
		t.Fatalf("expected empty group, got %s", skn.GroupID())
	}
	if skn.Sender().Name() != "Bob" {
		t.Fatal("sender name mismatch")
	}
	if skn.Sender().DeviceID() != 2 {
		t.Fatal("sender device ID mismatch")
	}
}
