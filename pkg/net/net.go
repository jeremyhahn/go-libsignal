// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

// Package net defines the interfaces and configuration for Signal's chat, CDSI and SVR services; callers supply the transports.
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
