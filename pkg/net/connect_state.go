// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ConnectConfig contains configuration for connection state management.
type ConnectConfig struct {
	// ConnectTimeout is the maximum time allowed for each connection attempt.
	ConnectTimeout time.Duration
	// NetworkInterfacePollInterval is how often to check for network
	// interface changes.
	NetworkInterfacePollInterval time.Duration
	// MaxConnectionAttempts is the maximum number of connection attempts
	// before giving up.
	MaxConnectionAttempts int
	// CooldownMaxDelay is the maximum delay between connection attempts
	// when backing off.
	CooldownMaxDelay time.Duration
}

// DefaultConnectConfig returns the suggested connection configuration.
func DefaultConnectConfig() ConnectConfig {
	return ConnectConfig{
		ConnectTimeout:               10 * time.Second,
		NetworkInterfacePollInterval: 100 * time.Millisecond,
		MaxConnectionAttempts:        5,
		CooldownMaxDelay:             30 * time.Second,
	}
}

// RouteInfo describes the route taken to connect to a service endpoint.
type RouteInfo struct {
	// RouteType identifies the kind of route (direct, proxy-f, proxy-g).
	RouteType string
	// Description is a human-readable summary of the route.
	Description string
}

// String returns the description of the route.
func (r RouteInfo) String() string {
	return r.Description
}

// ConnectionResources holds the shared resources needed to establish
// connections to Signal services. It references the connection state,
// DNS resolver, and network change notification channel.
type ConnectionResources struct {
	// ConnectState holds the connection routing and outcome tracking state.
	ConnectState *ConnectState
	// ConfirmationHeaderName is the header to check for server identity
	// confirmation. Empty if not applicable.
	ConfirmationHeaderName string
}

// ConnectState manages the state for establishing connections to Signal
// services. It tracks connection outcomes for route selection and
// provides the transport connector for establishing new connections.
type ConnectState struct {
	mu     sync.Mutex
	config ConnectConfig

	// outcomes tracks recent connection outcomes per route for
	// adaptive route selection.
	outcomes map[string]*routeOutcomes
}

// routeOutcomes tracks connection outcomes for a single route.
type routeOutcomes struct {
	recentFailures int
	lastFailure    time.Time
	lastSuccess    time.Time
}

// NewConnectState creates a new ConnectState with the given configuration.
func NewConnectState(config ConnectConfig) *ConnectState {
	return &ConnectState{
		config:   config,
		outcomes: make(map[string]*routeOutcomes),
	}
}

// RecordSuccess records a successful connection to the given route.
func (cs *ConnectState) RecordSuccess(route string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	o := cs.getOrCreateOutcomes(route)
	o.recentFailures = 0
	o.lastSuccess = time.Now()
}

// RecordFailure records a failed connection attempt to the given route.
func (cs *ConnectState) RecordFailure(route string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	o := cs.getOrCreateOutcomes(route)
	o.recentFailures++
	o.lastFailure = time.Now()
}

// getOrCreateOutcomes returns the outcomes for a route, creating a new
// entry if needed. Must be called with cs.mu held.
func (cs *ConnectState) getOrCreateOutcomes(route string) *routeOutcomes {
	o, ok := cs.outcomes[route]
	if !ok {
		o = &routeOutcomes{}
		cs.outcomes[route] = o
	}
	return o
}

// Reset clears all recorded connection outcomes. This should be called
// when the network state changes (e.g., switching between WiFi and
// cellular).
func (cs *ConnectState) Reset() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.outcomes = make(map[string]*routeOutcomes)
}

// NetworkChangeNotifier provides notifications when the network state
// changes. Implementations should send on the channel whenever the
// device's network connectivity changes (e.g., WiFi to cellular).
type NetworkChangeNotifier interface {
	// Changes returns a channel that receives a value whenever the
	// network state changes. The channel should never be closed.
	Changes() <-chan struct{}
}

// Connector establishes connections to a specific route type.
// Implementations handle the transport-level details of connecting
// through direct or proxied routes.
type Connector interface {
	// Connect establishes a connection to the given address.
	Connect(ctx context.Context, address string, port uint16) (WebSocketConnection, error)
}

// RouteSelector selects the best route for connecting to a service.
type RouteSelector interface {
	// SelectRoute returns the next route to try for connecting to the
	// service identified by the given domain config.
	SelectRoute(ctx context.Context, config *DomainConfig) (*SelectedRoute, error)
}

// SelectedRoute contains the connection parameters for a selected route.
type SelectedRoute struct {
	// Address is the target host to connect to (may differ from the
	// logical hostname if using a proxy).
	Address string
	// Port is the target port.
	Port uint16
	// SNI is the TLS Server Name Indication value.
	SNI string
	// HTTPHost is the HTTP Host header value.
	HTTPHost string
	// PathPrefix is prepended to request paths (for proxy routes).
	PathPrefix string
	// RouteInfo describes the selected route.
	RouteInfo RouteInfo
}

// String returns a human-readable description of the selected route.
func (r *SelectedRoute) String() string {
	return fmt.Sprintf("%s:%d via %s", r.Address, r.Port, r.RouteInfo.Description)
}
