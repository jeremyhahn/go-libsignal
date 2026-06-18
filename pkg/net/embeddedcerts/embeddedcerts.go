// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

// Package embeddedcerts provides the Signal and Google proxy root CA
// certificates that Rust libsignal embeds at compile time via include_bytes!
// in rust/net/src/certs.rs. The DER files are byte-identical copies from the
// Rust source tree at rust/net/res/*.cer.
//
// Rust reference: rust/net/src/certs.rs SIGNAL_ROOT_CERTIFICATES and
// PROXY_G_ROOT_CERTIFICATES.
package embeddedcerts

import (
	"crypto/x509"
	_ "embed"
)

// EmbeddedCertError is returned when an embedded certificate cannot be parsed.
type EmbeddedCertError struct {
	// Name is the filename of the certificate that failed to parse.
	Name string
	// Err is the underlying parse error.
	Err error
}

func (e *EmbeddedCertError) Error() string {
	return "embeddedcerts: failed to parse " + e.Name + ": " + e.Err.Error()
}

func (e *EmbeddedCertError) Unwrap() error {
	return e.Err
}

// Embedded DER certificate bytes. These are the same files embedded by the
// Rust crate at rust/net/res/*.cer via include_bytes!.

//go:embed res/signal.cer
var signalCERBytes []byte

//go:embed res/GIAG2.cer
var giag2CERBytes []byte

//go:embed res/GSR2.cer
var gsr2CERBytes []byte

//go:embed res/GSR4.cer
var gsr4CERBytes []byte

//go:embed res/GTSR1.cer
var gtsr1CERBytes []byte

//go:embed res/GTSR2.cer
var gtsr2CERBytes []byte

//go:embed res/GTSR3.cer
var gtsr3CERBytes []byte

//go:embed res/GTSR4.cer
var gtsr4CERBytes []byte

// parseDER parses a single DER-encoded certificate, returning a typed error on failure.
func parseDER(name string, der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &EmbeddedCertError{Name: name, Err: err}
	}
	return cert, nil
}

// SignalCAs returns the Signal root CA certificates embedded at compile time.
// These correspond to SIGNAL_ROOT_CERTIFICATES in the Rust crate.
//
// Rust reference: rust/net/src/certs.rs SIGNAL_ROOT_CERTIFICATES (signal.cer)
func SignalCAs() ([]*x509.Certificate, error) {
	cert, err := parseDER("signal.cer", signalCERBytes)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

// GoogleProxyCAs returns the Google proxy root CA certificates embedded at
// compile time (GIAG2 + pki.goog roots). These correspond to
// PROXY_G_ROOT_CERTIFICATES in the Rust crate.
//
// Rust reference: rust/net/src/certs.rs PROXY_G_ROOT_CERTIFICATES
func GoogleProxyCAs() ([]*x509.Certificate, error) {
	entries := []struct {
		name string
		der  []byte
	}{
		{"GIAG2.cer", giag2CERBytes},
		{"GSR2.cer", gsr2CERBytes},
		{"GSR4.cer", gsr4CERBytes},
		{"GTSR1.cer", gtsr1CERBytes},
		{"GTSR2.cer", gtsr2CERBytes},
		{"GTSR3.cer", gtsr3CERBytes},
		{"GTSR4.cer", gtsr4CERBytes},
	}
	certs := make([]*x509.Certificate, 0, len(entries))
	for _, e := range entries {
		cert, err := parseDER(e.name, e.der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
