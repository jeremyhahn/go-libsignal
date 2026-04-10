// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"net"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
)

// Well-known Signal service header names and WebSocket close codes.
const (
	// TimestampHeaderName is the header that indicates a response came from
	// the Signal chat server (not a proxy or load balancer).
	TimestampHeaderName = "x-signal-timestamp"

	// AlertHeaderName is the header used for server-originating alerts.
	AlertHeaderName = "x-signal-alert"

	// ConnectionInvalidatedCloseCode is the WebSocket close code sent when
	// the server invalidates a connection.
	ConnectionInvalidatedCloseCode = 4401

	// ConnectedElsewhereCloseCode is the WebSocket close code sent when
	// the device connects from another location.
	ConnectedElsewhereCloseCode = 4409
)

// Well-known WebSocket paths for the chat service.
const (
	// ChatWebSocketPath is the WebSocket path for the authenticated chat service.
	ChatWebSocketPath = "/v1/websocket/"
	// ChatProvisioningPath is the WebSocket path for provisioning.
	ChatProvisioningPath = "/v1/websocket/provisioning/"
)

// DefaultHTTPSPort is the default port used for Signal service connections.
const DefaultHTTPSPort = 443

// DomainConfig describes a target network resource (e.g., chat.signal.org)
// with connection parameters and static fallback IP addresses.
type DomainConfig struct {
	// Connect contains the connection-level configuration.
	Connect ConnectionConfig
	// IPv4 contains static fallback IPv4 addresses for DNS resolution failure.
	IPv4 []net.IP
	// IPv6 contains static fallback IPv6 addresses for DNS resolution failure.
	IPv6 []net.IP
}

// ConnectionConfig contains the parameters needed to connect to a Signal
// service endpoint.
type ConnectionConfig struct {
	// Hostname is the domain name of the resource.
	Hostname string
	// Port is the TCP port for the resource.
	Port uint16
	// Certs specifies which root certificates to use for TLS.
	Certs RootCertificates
	// ConfirmationHeaderName is a header to look for that indicates
	// the response came from the actual resource, not a proxy.
	// Empty string means no confirmation header is expected.
	ConfirmationHeaderName string
	// Proxy contains optional proxy configuration for domain fronting.
	Proxy *ConnectionProxyConfig
}

// ConnectionProxyConfig contains configuration for connecting through a
// domain-fronting proxy.
type ConnectionProxyConfig struct {
	// PathPrefix is prepended to request paths when going through the proxy.
	PathPrefix string
	// Configs contains the proxy configurations (typically two: Fastly and Google).
	Configs [2]ProxyConfig
}

// ProxyConfig describes a single domain-fronting proxy.
type ProxyConfig struct {
	// RouteType identifies the proxy type (e.g., "proxy-f" for Fastly,
	// "proxy-g" for Google).
	RouteType string
	// HTTPHost is the value of the HTTP Host header sent to the proxy.
	HTTPHost string
	// SNIList contains domain names used for DNS resolution and TLS SNI.
	SNIList []string
	// Certs specifies which root certificates to use for TLS with this proxy.
	Certs RootCertificates
}

// WSConfig contains WebSocket-specific configuration for a connection.
type WSConfig struct {
	// LocalIdleTimeout is how long to wait before sending a keepalive ping
	// when no messages have been sent.
	LocalIdleTimeout time.Duration
	// RemoteIdlePingTimeout is how long to wait for a pong response before
	// considering the connection dead.
	RemoteIdlePingTimeout time.Duration
	// RemoteIdleDisconnectTimeout is how long to wait with no messages from
	// the remote end before disconnecting.
	RemoteIdleDisconnectTimeout time.Duration
}

// DefaultWSConfig returns the recommended WebSocket configuration for
// general enclave connections.
func DefaultWSConfig() WSConfig {
	return WSConfig{
		LocalIdleTimeout:            30 * time.Second,
		RemoteIdlePingTimeout:       3 * time.Second,
		RemoteIdleDisconnectTimeout: 30 * time.Second,
	}
}

// Env contains the complete configuration for connecting to a Signal server
// environment (production or staging).
type Env struct {
	// CDSI is the Contact Discovery Service enclave endpoint.
	CDSI EnclaveEndpoint
	// SVR2 is the primary Secure Value Recovery v2 enclave endpoint.
	SVR2 EnclaveEndpoint
	// SVRB contains the Secure Value Recovery B (backup) enclave endpoints.
	SVRB SvrBEnv
	// ChatDomainConfig is the domain configuration for the chat service.
	ChatDomainConfig DomainConfig
	// ExperimentalChatH2DomainConfig is the domain configuration for the
	// experimental HTTP/2-based chat service.
	ExperimentalChatH2DomainConfig DomainConfig
}

// SvrBEnv contains the current and previous SVRB enclave endpoints.
// Multiple endpoints support enclave rotation.
type SvrBEnv struct {
	// Current contains the currently active SVRB endpoints.
	Current []*EnclaveEndpoint
	// Previous contains previously active SVRB endpoints that are still
	// used for migration/restore.
	Previous []*EnclaveEndpoint
}

// CurrentAndPrevious returns all SVRB endpoints, current first.
func (s *SvrBEnv) CurrentAndPrevious() []*EnclaveEndpoint {
	result := make([]*EnclaveEndpoint, 0, len(s.Current)+len(s.Previous))
	result = append(result, s.Current...)
	result = append(result, s.Previous...)
	return result
}

// Production configuration constants.
var (
	domainConfigChat = DomainConfig{
		Connect: ConnectionConfig{
			Hostname:               "chat.signal.org",
			Port:                   DefaultHTTPSPort,
			Certs:                  RootCertificatesSignal,
			ConfirmationHeaderName: TimestampHeaderName,
			Proxy: &ConnectionProxyConfig{
				PathPrefix: "/service",
				Configs:    [2]ProxyConfig{proxyConfigFProd, proxyConfigG},
			},
		},
		IPv4: []net.IP{
			net.ParseIP("76.223.92.165"),
			net.ParseIP("13.248.212.111"),
		},
		IPv6: []net.IP{
			net.ParseIP("2600:9000:a507:ab6d:4ce3:2f58:25d7:9cbf"),
			net.ParseIP("2600:9000:a61f:527c:d5eb:a431:5239:3232"),
		},
	}

	domainConfigExperimentalChatH2 = DomainConfig{
		Connect: ConnectionConfig{
			Hostname:               "grpc.chat.signal.org",
			Port:                   DefaultHTTPSPort,
			Certs:                  RootCertificatesSignal,
			ConfirmationHeaderName: TimestampHeaderName,
			Proxy:                  domainConfigChat.Connect.Proxy,
		},
	}

	domainConfigChatStaging = DomainConfig{
		Connect: ConnectionConfig{
			Hostname:               "chat.staging.signal.org",
			Port:                   DefaultHTTPSPort,
			Certs:                  RootCertificatesSignal,
			ConfirmationHeaderName: TimestampHeaderName,
			Proxy: &ConnectionProxyConfig{
				PathPrefix: "/service-staging",
				Configs:    [2]ProxyConfig{proxyConfigFStaging, proxyConfigG},
			},
		},
		IPv4: []net.IP{
			net.ParseIP("76.223.72.142"),
			net.ParseIP("13.248.206.115"),
		},
		IPv6: []net.IP{
			net.ParseIP("2600:9000:a507:ab6d:7b25:2580:8bd6:3b93"),
			net.ParseIP("2600:9000:a61f:527c:2215:cd9:bac6:a2f8"),
		},
	}

	domainConfigExperimentalChatH2Staging = DomainConfig{
		Connect: ConnectionConfig{
			Hostname:               "grpc.chat.staging.signal.org",
			Port:                   DefaultHTTPSPort,
			Certs:                  RootCertificatesSignal,
			ConfirmationHeaderName: TimestampHeaderName,
			Proxy:                  domainConfigChatStaging.Connect.Proxy,
		},
	}

	domainConfigCDSI = DomainConfig{
		Connect: ConnectionConfig{
			Hostname: "cdsi.signal.org",
			Port:     DefaultHTTPSPort,
			Certs:    RootCertificatesSignal,
			Proxy: &ConnectionProxyConfig{
				PathPrefix: "/cdsi",
				Configs:    [2]ProxyConfig{proxyConfigFProd, proxyConfigG},
			},
		},
		IPv4: []net.IP{net.ParseIP("40.122.45.194")},
		IPv6: []net.IP{net.ParseIP("2603:1030:7::1")},
	}

	domainConfigCDSIStaging = DomainConfig{
		Connect: ConnectionConfig{
			Hostname: "cdsi.staging.signal.org",
			Port:     DefaultHTTPSPort,
			Certs:    RootCertificatesSignal,
			Proxy: &ConnectionProxyConfig{
				PathPrefix: "/cdsi-staging",
				Configs:    [2]ProxyConfig{proxyConfigFStaging, proxyConfigG},
			},
		},
		IPv4: []net.IP{net.ParseIP("104.43.162.137")},
		IPv6: []net.IP{net.ParseIP("2603:1030:7::732")},
	}

	domainConfigSVR2 = DomainConfig{
		Connect: ConnectionConfig{
			Hostname: "svr2.signal.org",
			Port:     DefaultHTTPSPort,
			Certs:    RootCertificatesSignal,
			Proxy: &ConnectionProxyConfig{
				PathPrefix: "/svr2",
				Configs:    [2]ProxyConfig{proxyConfigFProd, proxyConfigG},
			},
		},
		IPv4: []net.IP{
			net.ParseIP("20.236.21.158"),
			net.ParseIP("20.104.52.125"),
			net.ParseIP("20.9.45.98"),
			net.ParseIP("20.66.40.69"),
			net.ParseIP("20.119.62.85"),
			net.ParseIP("20.65.43.198"),
			net.ParseIP("13.84.216.212"),
		},
		IPv6: []net.IP{
			net.ParseIP("2603:1030:20e:33::6"),
			net.ParseIP("2603:1030:408:3::1d"),
			net.ParseIP("2603:1030:b:2a::12"),
			net.ParseIP("2603:1030:803:4::65"),
			net.ParseIP("2a01:111:f100:3000::a83e:1208"),
			net.ParseIP("2603:1030:c04:1e::31c"),
			net.ParseIP("2603:1030:f00::17"),
		},
	}

	domainConfigSVR2Staging = DomainConfig{
		Connect: ConnectionConfig{
			Hostname: "svr2.staging.signal.org",
			Port:     DefaultHTTPSPort,
			Certs:    RootCertificatesSignal,
			Proxy: &ConnectionProxyConfig{
				PathPrefix: "/svr2-staging",
				Configs:    [2]ProxyConfig{proxyConfigFStaging, proxyConfigG},
			},
		},
		IPv4: []net.IP{
			net.ParseIP("104.43.134.192"),
			net.ParseIP("20.253.229.239"),
			net.ParseIP("157.55.188.67"),
			net.ParseIP("20.127.86.118"),
			net.ParseIP("20.186.175.196"),
		},
		IPv6: []net.IP{
			net.ParseIP("2603:1030:20e:31::20e"),
			net.ParseIP("2603:1030:403:29::7f"),
			net.ParseIP("2603:1030:b:2c::26"),
			net.ParseIP("2603:1030:800:5::bfee:ab23"),
			net.ParseIP("2603:1030:a04:16::3a"),
		},
	}

	domainConfigSVRBProd = DomainConfig{
		Connect: ConnectionConfig{
			Hostname: "svrb.signal.org",
			Port:     DefaultHTTPSPort,
			Certs:    RootCertificatesSignal,
			Proxy: &ConnectionProxyConfig{
				PathPrefix: "/svrb",
				Configs:    [2]ProxyConfig{proxyConfigFProd, proxyConfigG},
			},
		},
		IPv4: []net.IP{
			net.ParseIP("4.151.136.48"),
			net.ParseIP("20.232.191.209"),
			net.ParseIP("135.119.74.80"),
			net.ParseIP("172.200.87.186"),
			net.ParseIP("20.63.12.55"),
			net.ParseIP("20.66.41.177"),
			net.ParseIP("20.114.45.6"),
		},
		IPv6: []net.IP{
			net.ParseIP("2603:1030:20c:6::166"),
			net.ParseIP("2603:1030:408:6::e5"),
			net.ParseIP("2603:1030:7:5::22"),
			net.ParseIP("2a01:111:f100:4001::4625:a047"),
			net.ParseIP("2a01:111:f100:3000::a83e:14da"),
			net.ParseIP("2603:1030:c02:5::632"),
			net.ParseIP("2603:1030:f00:3::27"),
		},
	}

	domainConfigSVRBStaging = DomainConfig{
		Connect: ConnectionConfig{
			Hostname: "svrb.staging.signal.org",
			Port:     DefaultHTTPSPort,
			Certs:    RootCertificatesSignal,
			Proxy: &ConnectionProxyConfig{
				PathPrefix: "/svrb-staging",
				Configs:    [2]ProxyConfig{proxyConfigFStaging, proxyConfigG},
			},
		},
		IPv4: []net.IP{
			net.ParseIP("20.45.59.200"),
			net.ParseIP("132.196.9.248"),
			net.ParseIP("52.225.216.56"),
			net.ParseIP("20.66.46.240"),
			net.ParseIP("172.178.57.240"),
		},
		IPv6: []net.IP{
			net.ParseIP("2a01:111:f100:2004::8975:6ea4"),
			net.ParseIP("2603:1030:408:7::31"),
			net.ParseIP("2603:1030:b:29::8f"),
			net.ParseIP("2603:1030:800:5::bfee:ab24"),
			net.ParseIP("2603:1030:a04:26::82"),
		},
	}
)

// Proxy configurations.
var (
	proxyConfigFProd = ProxyConfig{
		RouteType: "proxy-f",
		HTTPHost:  "reflector-signal.global.ssl.fastly.net",
		SNIList: []string{
			"github.githubassets.com",
			"pinterest.com",
			"www.redditstatic.com",
		},
		Certs: RootCertificatesNative,
	}

	proxyConfigFStaging = ProxyConfig{
		RouteType: "proxy-f",
		HTTPHost:  "reflector-staging-signal.global.ssl.fastly.net",
		SNIList: []string{
			"github.githubassets.com",
			"pinterest.com",
			"www.redditstatic.com",
		},
		Certs: RootCertificatesNative,
	}

	proxyConfigG = ProxyConfig{
		RouteType: "proxy-g",
		HTTPHost:  "reflector-nrgwuv7kwq-uc.a.run.app",
		SNIList: []string{
			"www.google.com",
			"android.clients.google.com",
			"clients3.google.com",
			"clients4.google.com",
			"googlemail.com",
		},
		Certs: RootCertificatesProxyG,
	}
)

// Endpoint parameters for enclave connections.
var (
	endpointParamsCDSIProd = EndpointParams{
		MrEnclave:  MrEnclave{Value: attest.EnclaveIDCDSIProd, Kind: EnclaveKindCDSI},
		RaftConfig: nil,
	}
	endpointParamsCDSIStaging = EndpointParams{
		MrEnclave:  MrEnclave{Value: attest.EnclaveIDCDSIStaging, Kind: EnclaveKindCDSI},
		RaftConfig: nil,
	}
	endpointParamsSVR2_2026Q1Prod = EndpointParams{
		MrEnclave:  MrEnclave{Value: attest.EnclaveIDSVR2_2026Q1Prod, Kind: EnclaveKindSvrSgx},
		RaftConfig: attest.RaftConfigSVR2_2026Q1Prod,
	}
	endpointParamsSVR2_2026Q1Staging = EndpointParams{
		MrEnclave:  MrEnclave{Value: attest.EnclaveIDSVR2_2026Q1Staging, Kind: EnclaveKindSvrSgx},
		RaftConfig: attest.RaftConfigSVR2_2026Q1Staging,
	}
	endpointParamsSVRB_2026Q1Prod = EndpointParams{
		MrEnclave:  MrEnclave{Value: attest.EnclaveIDSVRB_2026Q1Prod, Kind: EnclaveKindSvrSgx},
		RaftConfig: attest.RaftConfigSVRB_2026Q1Prod,
	}
	endpointParamsSVRB_2025Q3Prod = EndpointParams{
		MrEnclave:  MrEnclave{Value: attest.EnclaveIDSVRB_2025Q3Prod, Kind: EnclaveKindSvrSgx},
		RaftConfig: attest.RaftConfigSVRB_2025Q3Prod,
	}
	endpointParamsSVRB_2026Q1Staging = EndpointParams{
		MrEnclave:  MrEnclave{Value: attest.EnclaveIDSVRB_2026Q1Staging, Kind: EnclaveKindSvrSgx},
		RaftConfig: attest.RaftConfigSVRB_2026Q1Staging,
	}
)

// Production returns the production environment configuration.
func Production() *Env {
	wsConfig := DefaultWSConfig()
	return &Env{
		ChatDomainConfig:               domainConfigChat,
		ExperimentalChatH2DomainConfig: domainConfigExperimentalChatH2,
		CDSI: EnclaveEndpoint{
			DomainConfig: domainConfigCDSI,
			WSConfig:     wsConfig,
			Params:       endpointParamsCDSIProd,
		},
		SVR2: EnclaveEndpoint{
			DomainConfig: domainConfigSVR2,
			WSConfig:     wsConfig,
			Params:       endpointParamsSVR2_2026Q1Prod,
		},
		SVRB: SvrBEnv{
			Current: []*EnclaveEndpoint{
				{
					DomainConfig: domainConfigSVRBProd,
					WSConfig:     wsConfig,
					Params:       endpointParamsSVRB_2026Q1Prod,
				},
			},
			Previous: []*EnclaveEndpoint{
				{
					DomainConfig: domainConfigSVRBProd,
					WSConfig:     wsConfig,
					Params:       endpointParamsSVRB_2025Q3Prod,
				},
			},
		},
	}
}

// Staging returns the staging environment configuration.
func Staging() *Env {
	wsConfig := DefaultWSConfig()
	return &Env{
		ChatDomainConfig:               domainConfigChatStaging,
		ExperimentalChatH2DomainConfig: domainConfigExperimentalChatH2Staging,
		CDSI: EnclaveEndpoint{
			DomainConfig: domainConfigCDSIStaging,
			WSConfig:     wsConfig,
			Params:       endpointParamsCDSIStaging,
		},
		SVR2: EnclaveEndpoint{
			DomainConfig: domainConfigSVR2Staging,
			WSConfig:     wsConfig,
			Params:       endpointParamsSVR2_2026Q1Staging,
		},
		SVRB: SvrBEnv{
			Current: []*EnclaveEndpoint{
				{
					DomainConfig: domainConfigSVRBStaging,
					WSConfig:     wsConfig,
					Params:       endpointParamsSVRB_2026Q1Staging,
				},
			},
			Previous: nil,
		},
	}
}

// EnvForEnvironment returns the Env configuration for the given environment.
func EnvForEnvironment(env Environment) *Env {
	switch env {
	case EnvironmentProduction:
		return Production()
	case EnvironmentStaging:
		return Staging()
	default:
		return Production()
	}
}
