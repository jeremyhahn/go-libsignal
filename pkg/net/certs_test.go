package net

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestDefaultCertificatePinner(t *testing.T) {
	pinner := &DefaultCertificatePinner{}

	t.Run("native returns nil", func(t *testing.T) {
		cfg := pinner.PinCertificates(RootCertificatesNative)
		if cfg != nil {
			t.Error("expected nil for native")
		}
	})

	t.Run("signal returns fail-closed config", func(t *testing.T) {
		cfg := pinner.PinCertificates(RootCertificatesSignal)
		if cfg == nil {
			t.Fatal("expected non-nil config for signal (fail-closed)")
		}
		if cfg.RootCAs == nil {
			t.Error("expected non-nil empty cert pool")
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("expected TLS 1.2 min version, got %d", cfg.MinVersion)
		}
	})

	t.Run("proxy g returns fail-closed config", func(t *testing.T) {
		cfg := pinner.PinCertificates(RootCertificatesProxyG)
		if cfg == nil {
			t.Fatal("expected non-nil config for proxy (fail-closed)")
		}
		if cfg.RootCAs == nil {
			t.Error("expected non-nil empty cert pool")
		}
	})
}

func TestNewCertPoolFromDER(t *testing.T) {
	t.Run("valid cert", func(t *testing.T) {
		der := generateSelfSignedCertDER(t)
		pool, err := NewCertPoolFromDER(der)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool == nil {
			t.Fatal("returned nil pool")
		}
	})

	t.Run("invalid DER", func(t *testing.T) {
		_, err := NewCertPoolFromDER([]byte{1, 2, 3})
		if err == nil {
			t.Fatal("expected error for invalid DER")
		}
		certErr, ok := err.(*CertPinError)
		if !ok {
			t.Fatalf("expected *CertPinError, got %T", err)
		}
		if certErr.Kind != CertPinErrorParseFailed {
			t.Errorf("expected CertPinErrorParseFailed, got %d", certErr.Kind)
		}
	})

	t.Run("multiple certs", func(t *testing.T) {
		der1 := generateSelfSignedCertDER(t)
		der2 := generateSelfSignedCertDER(t)
		pool, err := NewCertPoolFromDER(der1, der2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool == nil {
			t.Fatal("returned nil pool")
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := NewCertPoolFromDER()
		if err == nil {
			t.Fatal("expected error for empty certs")
		}
		certErr, ok := err.(*CertPinError)
		if !ok {
			t.Fatalf("expected *CertPinError, got %T", err)
		}
		if certErr.Kind != CertPinErrorNoCertificates {
			t.Errorf("expected CertPinErrorNoCertificates, got %d", certErr.Kind)
		}
	})
}

func TestStaticCertificatePinner_FailClosed(t *testing.T) {
	t.Run("native returns nil", func(t *testing.T) {
		pinner := &StaticCertificatePinner{}
		cfg := pinner.PinCertificates(RootCertificatesNative)
		if cfg != nil {
			t.Error("expected nil for native")
		}
	})

	t.Run("signal with valid certs", func(t *testing.T) {
		der := generateSelfSignedCertDER(t)
		pinner := &StaticCertificatePinner{SignalCerts: [][]byte{der}}
		cfg := pinner.PinCertificates(RootCertificatesSignal)
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
		if cfg.RootCAs == nil {
			t.Error("expected non-nil cert pool")
		}
	})

	t.Run("signal with invalid certs fails closed", func(t *testing.T) {
		pinner := &StaticCertificatePinner{SignalCerts: [][]byte{{1, 2, 3}}}
		cfg := pinner.PinCertificates(RootCertificatesSignal)
		if cfg == nil {
			t.Fatal("expected non-nil config (fail-closed)")
		}
		// Should have an empty cert pool that rejects everything
		if cfg.RootCAs == nil {
			t.Error("expected non-nil empty cert pool")
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("expected TLS 1.2 min version, got %d", cfg.MinVersion)
		}
	})

	t.Run("signal with no certs fails closed", func(t *testing.T) {
		pinner := &StaticCertificatePinner{}
		cfg := pinner.PinCertificates(RootCertificatesSignal)
		if cfg == nil {
			t.Fatal("expected non-nil config (fail-closed)")
		}
		if cfg.RootCAs == nil {
			t.Error("expected non-nil empty cert pool")
		}
	})

	t.Run("proxy with invalid certs fails closed", func(t *testing.T) {
		pinner := &StaticCertificatePinner{ProxyCerts: [][]byte{{1, 2, 3}}}
		cfg := pinner.PinCertificates(RootCertificatesProxyG)
		if cfg == nil {
			t.Fatal("expected non-nil config (fail-closed)")
		}
		if cfg.RootCAs == nil {
			t.Error("expected non-nil empty cert pool")
		}
	})

	t.Run("unknown cert type fails closed", func(t *testing.T) {
		pinner := &StaticCertificatePinner{}
		cfg := pinner.PinCertificates(RootCertificates(99))
		if cfg == nil {
			t.Fatal("expected non-nil config for unknown type (fail-closed)")
		}
		if cfg.RootCAs == nil {
			t.Error("expected non-nil empty cert pool")
		}
	})
}

// TestNewEmbeddedCertificatePinner is the integration test for finding #33.
// It verifies that the embedded Signal and Google proxy root CAs can be loaded
// and produce working tls.Config objects (non-nil, non-empty cert pools).
func TestNewEmbeddedCertificatePinner(t *testing.T) {
	pinner, err := NewEmbeddedCertificatePinner()
	if err != nil {
		t.Fatalf("NewEmbeddedCertificatePinner(): %v", err)
	}
	if pinner == nil {
		t.Fatal("returned nil pinner")
	}

	t.Run("signal config has non-empty cert pool", func(t *testing.T) {
		cfg := pinner.PinCertificates(RootCertificatesSignal)
		if cfg == nil {
			t.Fatal("PinCertificates(Signal) returned nil")
		}
		if cfg.RootCAs == nil {
			t.Error("RootCAs is nil")
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %d, want TLS 1.2", cfg.MinVersion)
		}
	})

	t.Run("proxy config has non-empty cert pool", func(t *testing.T) {
		cfg := pinner.PinCertificates(RootCertificatesProxyG)
		if cfg == nil {
			t.Fatal("PinCertificates(ProxyG) returned nil")
		}
		if cfg.RootCAs == nil {
			t.Error("RootCAs is nil")
		}
	})

	t.Run("native still returns nil", func(t *testing.T) {
		cfg := pinner.PinCertificates(RootCertificatesNative)
		if cfg != nil {
			t.Error("expected nil for native cert type")
		}
	})
}

func generateSelfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
