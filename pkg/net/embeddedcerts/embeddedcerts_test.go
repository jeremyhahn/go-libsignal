// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package embeddedcerts

import (
	"testing"
	"time"
)

func TestSignalCAs_ParsedAndValid(t *testing.T) {
	certs, err := SignalCAs()
	if err != nil {
		t.Fatalf("SignalCAs() error: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("SignalCAs() returned no certificates")
	}
	for i, cert := range certs {
		if len(cert.Subject.String()) == 0 {
			t.Errorf("cert[%d]: empty Subject", i)
		}
		// Certificate must not have already expired.
		if cert.NotAfter.Before(time.Now()) {
			t.Errorf("cert[%d]: NotAfter %v is in the past", i, cert.NotAfter)
		}
	}
}

func TestGoogleProxyCAs_ParsedAndValid(t *testing.T) {
	certs, err := GoogleProxyCAs()
	if err != nil {
		t.Fatalf("GoogleProxyCAs() error: %v", err)
	}
	// Rust embeds 7 proxy certificates.
	if len(certs) != 7 {
		t.Fatalf("GoogleProxyCAs() = %d certificates, want 7", len(certs))
	}
	for i, cert := range certs {
		if len(cert.Subject.String()) == 0 {
			t.Errorf("cert[%d]: empty Subject", i)
		}
	}
}

func TestSignalCAs_NonNilRaw(t *testing.T) {
	certs, err := SignalCAs()
	if err != nil {
		t.Fatalf("SignalCAs(): %v", err)
	}
	for i, cert := range certs {
		if len(cert.Raw) == 0 {
			t.Errorf("cert[%d]: Raw DER is empty", i)
		}
	}
}

func TestGoogleProxyCAs_NonNilRaw(t *testing.T) {
	certs, err := GoogleProxyCAs()
	if err != nil {
		t.Fatalf("GoogleProxyCAs(): %v", err)
	}
	for i, cert := range certs {
		if len(cert.Raw) == 0 {
			t.Errorf("cert[%d]: Raw DER is empty", i)
		}
	}
}
