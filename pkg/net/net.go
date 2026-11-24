// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

// Package net provides the networking layer for the Signal protocol library.
//
// It defines types and interfaces for communicating with Signal's backend
// services including the chat service, Contact Discovery Service (CDSI),
// and Secure Value Recovery (SVR). The package handles environment
// configuration (production vs staging), authentication, WebSocket transport,
// enclave attestation, and certificate pinning.
//
// This is primarily an interface layer. Concrete transport implementations
// are expected to be provided by callers.
package net

import "fmt"

// Environment represents a Signal server deployment environment.
type Environment int

const (
	// EnvironmentProduction is the production Signal server environment.
	EnvironmentProduction Environment = iota
	// EnvironmentStaging is the staging Signal server environment.
	EnvironmentStaging
)

// String returns the string representation of the environment.
func (e Environment) String() string {
	switch e {
	case EnvironmentProduction:
		return "production"
	case EnvironmentStaging:
		return "staging"
	default:
		return fmt.Sprintf("Environment(%d)", int(e))
	}
}

// IpType represents the type of IP protocol used for a connection.
type IpType int

const (
	// IpTypeUnknown indicates the IP type is not known.
	IpTypeUnknown IpType = iota
	// IpTypeIPv4 indicates an IPv4 connection.
	IpTypeIPv4
	// IpTypeIPv6 indicates an IPv6 connection.
	IpTypeIPv6
)
