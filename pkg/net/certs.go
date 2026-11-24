// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/net/embeddedcerts"
)

// RootCertificates represents the set of root certificates to use when
// establishing TLS connections to Signal services.
type RootCertificates int

const (
	// RootCertificatesNative uses the system's native certificate store.
	RootCertificatesNative RootCertificates = iota
	// RootCertificatesSignal uses Signal's pinned root certificates.
	RootCertificatesSignal
	// RootCertificatesProxyG uses the Google proxy root certificates
	// (GIAG2 + pki.goog roots).
	RootCertificatesProxyG
)

// CertPinErrorKind categorizes certificate pinning errors.
type CertPinErrorKind int

const (
	// CertPinErrorNoCertificates indicates no certificates were provided.
	CertPinErrorNoCertificates CertPinErrorKind = iota
	// CertPinErrorParseFailed indicates a DER certificate could not be parsed.
	CertPinErrorParseFailed
	// CertPinErrorPoolCreationFailed indicates the certificate pool could not be created.
	CertPinErrorPoolCreationFailed
)

// CertPinError represents an error during certificate pinning operations.
type CertPinError struct {
	Kind CertPinErrorKind
	Err  error
}

func (e *CertPinError) Error() string {
	switch e.Kind {
	case CertPinErrorNoCertificates:
		return "certpin: no certificates provided"
	case CertPinErrorParseFailed:
		return fmt.Sprintf("certpin: failed to parse DER certificate: %v", e.Err)
	case CertPinErrorPoolCreationFailed:
		return fmt.Sprintf("certpin: failed to create certificate pool: %v", e.Err)
	default:
		if e.Err != nil {
			return fmt.Sprintf("certpin: %v", e.Err)
		}
		return "certpin: unknown error"
	}
}

func (e *CertPinError) Unwrap() error {
	return e.Err
}

// CertificatePinner provides certificate pinning functionality for Signal
// service connections. Implementations verify that the TLS certificate chain
// includes an expected root certificate.
//
// IMPORTANT: Production callers MUST provide their own CertificatePinner
// implementation with embedded Signal root certificates. The default
// implementation (DefaultCertificatePinner) does not embed any Signal or
// Google proxy root certificates and will reject all non-native TLS
// connections (fail-closed). See StaticCertificatePinner for the recommended
// production pattern using go:embed with DER certificate files.
type CertificatePinner interface {
	// PinCertificates returns a tls.Config configured with the appropriate
	// root certificate pool for the given RootCertificates type.
	// If certs is RootCertificatesNative, it returns nil (use system roots).
	PinCertificates(certs RootCertificates) *tls.Config
}

// DefaultCertificatePinner is a baseline CertificatePinner that deliberately
// FAILS CLOSED for Signal and proxy certificate types.
//
// SECURITY WARNING: This implementation does NOT embed any Signal root
// certificates. For RootCertificatesSignal and RootCertificatesProxyG, it
// returns a tls.Config with an empty certificate pool, which causes all TLS
// handshakes to fail. This is intentional: it prevents silent fallback to
// system roots when no pinned certificates are configured.
//
// For production use, callers MUST replace this with a StaticCertificatePinner
// (or custom implementation) that embeds the required DER certificates:
//   - Signal:  signal.cer
//   - Proxy G: GIAG2.cer, GSR2.cer, GSR4.cer, GTSR1.cer, GTSR2.cer,
//     GTSR3.cer, GTSR4.cer
//
// The Rust reference (libsignal/rust/net/src/certs.rs) embeds these
// certificates at compile time via include_bytes! and returns them from
// static constants SIGNAL_ROOT_CERTIFICATES and PROXY_G_ROOT_CERTIFICATES.
// Go callers should embed the same DER files using go:embed and construct
// a StaticCertificatePinner.
//
// Example:
//
//	//go:embed res/signal.cer
//	var signalRootCert []byte
//
//	pinner := &StaticCertificatePinner{
//	    SignalCerts: [][]byte{signalRootCert},
//	    ProxyCerts:  [][]byte{giag2, gsr2, gsr4, gtsr1, gtsr2, gtsr3, gtsr4},
//	}
type DefaultCertificatePinner struct{}

// PinCertificates returns a tls.Config based on the certificate type.
// For RootCertificatesNative, returns nil (use system roots).
// For RootCertificatesSignal and RootCertificatesProxyG, returns a config
// with an empty cert pool, which causes TLS handshake to FAIL rather than
// silently falling back to system roots (fail-closed).
//
// See DefaultCertificatePinner documentation for why this MUST be replaced
// in production.
func (d *DefaultCertificatePinner) PinCertificates(certs RootCertificates) *tls.Config {
	switch certs {
	case RootCertificatesNative:
		return nil
	default:
		// Fail-closed: return a config with an empty cert pool that rejects
		// all server certificates, rather than silently succeeding.
		return &tls.Config{
			RootCAs:    x509.NewCertPool(),
			MinVersion: tls.VersionTLS12,
		}
	}
}

// StaticCertificatePinner is a CertificatePinner that uses caller-provided
// DER-encoded root certificates for Signal and Google proxy connections.
// This is the recommended pattern for production use, where the caller
// embeds the DER certificate files using go:embed.
//
// The Rust reference embeds the following certificate files:
//   - Signal:  signal.cer
//   - Proxy G: GIAG2.cer, GSR2.cer, GSR4.cer, GTSR1.cer, GTSR2.cer,
//     GTSR3.cer, GTSR4.cer
type StaticCertificatePinner struct {
	// SignalCerts contains DER-encoded root certificates for Signal services.
	SignalCerts [][]byte
	// ProxyCerts contains DER-encoded root certificates for Google proxy
	// connections (GIAG2 + pki.goog roots).
	ProxyCerts [][]byte
}

// PinCertificates returns a tls.Config configured with the appropriate
// pinned root certificate pool. For RootCertificatesNative, returns nil
// to use the system certificate store.
func (p *StaticCertificatePinner) PinCertificates(certs RootCertificates) *tls.Config {
	switch certs {
	case RootCertificatesNative:
		return nil
	case RootCertificatesSignal:
		pool, err := NewCertPoolFromDER(p.SignalCerts...)
		if err != nil {
			// Fail-closed: return config with empty pool that rejects all certs
			// rather than returning nil which falls back to system roots.
			return &tls.Config{
				RootCAs:    x509.NewCertPool(),
				MinVersion: tls.VersionTLS12,
			}
		}
		return &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
	case RootCertificatesProxyG:
		pool, err := NewCertPoolFromDER(p.ProxyCerts...)
		if err != nil {
			// Fail-closed: return config with empty pool that rejects all certs
			// rather than returning nil which falls back to system roots.
			return &tls.Config{
				RootCAs:    x509.NewCertPool(),
				MinVersion: tls.VersionTLS12,
			}
		}
		return &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
	default:
		// Unknown certificate type: fail-closed.
		return &tls.Config{
			RootCAs:    x509.NewCertPool(),
			MinVersion: tls.VersionTLS12,
		}
	}
}

// EmbeddedPinnerError is returned when the embedded certificates cannot be
// loaded during NewEmbeddedCertificatePinner construction.
type EmbeddedPinnerError struct {
	// Err is the underlying error from the embeddedcerts package.
	Err error
}

func (e *EmbeddedPinnerError) Error() string {
	return "net: failed to load embedded certificates: " + e.Err.Error()
}

func (e *EmbeddedPinnerError) Unwrap() error {
	return e.Err
}

// NewEmbeddedCertificatePinner returns a StaticCertificatePinner pre-loaded
// with the Signal and Google proxy root CA certificates embedded at compile
// time by the embeddedcerts subpackage.
//
// This is the recommended production CertificatePinner. It mirrors the Rust
// libsignal SIGNAL_ROOT_CERTIFICATES and PROXY_G_ROOT_CERTIFICATES constants
// defined in rust/net/src/certs.rs.
func NewEmbeddedCertificatePinner() (*StaticCertificatePinner, error) {
	signalCAs, err := embeddedcerts.SignalCAs()
	if err != nil {
		return nil, &EmbeddedPinnerError{Err: err}
	}
	proxyCAs, err := embeddedcerts.GoogleProxyCAs()
	if err != nil {
		return nil, &EmbeddedPinnerError{Err: err}
	}

	signalDERs := make([][]byte, len(signalCAs))
	for i, c := range signalCAs {
		signalDERs[i] = c.Raw
	}
	proxyDERs := make([][]byte, len(proxyCAs))
	for i, c := range proxyCAs {
		proxyDERs[i] = c.Raw
	}

	return &StaticCertificatePinner{
		SignalCerts: signalDERs,
		ProxyCerts:  proxyDERs,
	}, nil
}

// NewCertPoolFromDER creates an x509.CertPool from one or more DER-encoded
// certificates. This is a helper for building certificate pools from embedded
// certificate data.
func NewCertPoolFromDER(certs ...[]byte) (*x509.CertPool, error) {
	if len(certs) == 0 {
		return nil, &CertPinError{Kind: CertPinErrorNoCertificates}
	}
	pool := x509.NewCertPool()
	for _, der := range certs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &CertPinError{Kind: CertPinErrorParseFailed, Err: err}
		}
		pool.AddCert(cert)
	}
	return pool, nil
}
