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

// TLSVersion identifies a minimum TLS protocol version.
// Mirrors Rust net::env::SslVersion.
type TLSVersion int

const (
	// TLSVersion12 requires TLS 1.2 or higher.
	TLSVersion12 TLSVersion = iota
	// TLSVersion13 requires TLS 1.3 or higher.
	TLSVersion13
)

// HTTPVersion identifies which version of HTTP the endpoint speaks.
// Mirrors Rust net::env::HttpVersion.
type HTTPVersion int

const (
	// HTTPVersion1_1 selects HTTP/1.1.
	HTTPVersion1_1 HTTPVersion = iota
	// HTTPVersion2 selects HTTP/2.
	HTTPVersion2
)

// ConnectionConfig contains the parameters needed to connect to a Signal
// service endpoint.
//
// Rust ref: rust/net/src/env.rs — ConnectionConfig.
type ConnectionConfig struct {
	// Hostname is the domain name of the resource.
	Hostname string
	// Port is the TCP port for the resource.
	Port uint16
	// Certs specifies which root certificates to use for TLS.
	Certs RootCertificates
	// MinTLSVersion is the minimum TLS version to require.
	// nil means no specific version is enforced (permissive mode).
	// Rust sets Some(TLS1_3) for all production Signal endpoints.
	MinTLSVersion *TLSVersion
	// HTTPVersion selects the expected HTTP protocol version.
	// nil means the endpoint is not HTTP (e.g., a raw WebSocket).
	// Rust sets Http1_1 for most endpoints; Http2 for the experimental H2 chat endpoint.
	HTTPVersion *HTTPVersion
	// ConfirmationHeaderName is a header to look for that indicates
	// the response came from the actual resource, not a proxy.
	// Empty string means no confirmation header is expected.
	ConfirmationHeaderName string
	// Proxy contains optional proxy configuration for domain fronting.
	Proxy *ConnectionProxyConfig
}

// KeyTransConfig holds the raw key material for Signal's key-transparency tree.
// All values are 32-byte Ed25519 public key bytes.
//
// Rust ref: rust/net/src/env.rs — KeyTransConfig.
type KeyTransConfig struct {
	// SigningKeyMaterial is the Ed25519 signing key for the tree head signature.
	SigningKeyMaterial [32]byte
	// VRFKeyMaterial is the Ed25519 VRF public key.
	VRFKeyMaterial [32]byte
	// AuditorKeyMaterials contains one or more Ed25519 auditor public keys.
	// Signal production uses three auditor keys.
	AuditorKeyMaterials [][32]byte
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
//
// Rust ref: rust/net/src/env.rs — Env.
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
	// KeyTrans holds the key-transparency verification key material for this
	// environment. Corresponds to keytrans_config in the Rust Env struct.
	KeyTrans KeyTransConfig
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

// newTLSVersion allocates a fresh *TLSVersion so that each ConnectionConfig
// literal gets an independent pointer. This prevents callers from mutating a
// single shared instance and accidentally affecting all other configs that
// share the same backing value.
func newTLSVersion(v TLSVersion) *TLSVersion { return &v }

// newHTTPVersion allocates a fresh *HTTPVersion for the same reason as
// newTLSVersion: every ConnectionConfig must own its pointer independently.
func newHTTPVersion(v HTTPVersion) *HTTPVersion { return &v }

// KeyTrans configuration constants — verbatim hex literals from Rust
// rust/net/src/env.rs KEYTRANS_*_PROD / KEYTRANS_*_STAGING.

// KeyTransConfigProduction holds the key-transparency verification keys for
// the Signal production environment.
//
// Rust ref: rust/net/src/env.rs — KEYTRANS_CONFIG_PROD.
var KeyTransConfigProduction = KeyTransConfig{
	SigningKeyMaterial: [32]byte{
		0xa3, 0x97, 0x30, 0x67, 0x98, 0x43, 0x82, 0xcf,
		0xa8, 0x9e, 0xc2, 0x6d, 0x7c, 0xc1, 0x76, 0x68,
		0x0a, 0xef, 0xe9, 0x2b, 0x3d, 0x2e, 0xba, 0x85,
		0x15, 0x9d, 0xad, 0x0b, 0x83, 0x54, 0xb6, 0x22,
	},
	VRFKeyMaterial: [32]byte{
		0x38, 0x49, 0xcf, 0x11, 0x6c, 0x7b, 0xc9, 0xae,
		0xf5, 0xf1, 0x3f, 0x0c, 0x61, 0xa7, 0xc2, 0x46,
		0xe5, 0xba, 0xde, 0x4e, 0xb7, 0xe1, 0xc7, 0xb0,
		0xef, 0xca, 0xcd, 0xd8, 0xc1, 0xe6, 0xa6, 0xff,
	},
	AuditorKeyMaterials: [][32]byte{
		{
			0x2d, 0x97, 0x36, 0x08, 0xe9, 0x09, 0xa0, 0x9e,
			0x12, 0xcb, 0xdb, 0xd2, 0x1a, 0xd5, 0x87, 0x75,
			0xfd, 0x72, 0xfe, 0x10, 0x34, 0xa5, 0xa0, 0x79,
			0xf2, 0x65, 0x41, 0xd5, 0x76, 0x4c, 0xe1, 0x7f,
		},
		{
			0x2f, 0x21, 0x7a, 0x86, 0xcd, 0x2d, 0xbc, 0x95,
			0xd4, 0x6a, 0x84, 0x42, 0x09, 0x42, 0xa9, 0x58,
			0x77, 0xb3, 0x72, 0x3f, 0x63, 0x4b, 0xc6, 0x4b,
			0xb9, 0xe4, 0x06, 0x79, 0x6d, 0xf7, 0x46, 0xef,
		},
		{
			0x7f, 0xe5, 0xd9, 0x1d, 0xe2, 0x35, 0x18, 0x84,
			0x86, 0xd8, 0xfb, 0x83, 0x6a, 0x6d, 0xa3, 0x7e,
			0x62, 0x5e, 0x2b, 0x10, 0xeb, 0x6d, 0x14, 0x41,
			0x85, 0xb9, 0x36, 0x4c, 0xc8, 0x3c, 0xbb, 0xb6,
		},
	},
}

// KeyTransConfigStaging holds the key-transparency verification keys for
// the Signal staging environment.
//
// Rust ref: rust/net/src/env.rs — KEYTRANS_CONFIG_STAGING.
var KeyTransConfigStaging = KeyTransConfig{
	SigningKeyMaterial: [32]byte{
		0xac, 0x0d, 0xe1, 0xfd, 0x7f, 0x33, 0x55, 0x2b,
		0xbe, 0xb6, 0xeb, 0xc1, 0x2b, 0x9d, 0x4e, 0xa1,
		0x0b, 0xf5, 0xf0, 0x25, 0xc4, 0x50, 0x73, 0xd3,
		0xfb, 0x5f, 0x56, 0x48, 0x95, 0x5a, 0x74, 0x9e,
	},
	VRFKeyMaterial: [32]byte{
		0xec, 0x3a, 0x26, 0x82, 0x37, 0xcf, 0x5c, 0x47,
		0x11, 0x5c, 0xf2, 0x22, 0x40, 0x5d, 0x5f, 0x90,
		0xcc, 0x63, 0x3e, 0xbe, 0x05, 0xca, 0xf8, 0x2c,
		0x0d, 0xd5, 0xac, 0xf9, 0xd3, 0x41, 0xda, 0xdb,
	},
	AuditorKeyMaterials: [][32]byte{
		{
			0x11, 0x23, 0xb1, 0x3e, 0xe3, 0x24, 0x79, 0xae,
			0x6a, 0xf5, 0x73, 0x9e, 0x5d, 0x68, 0x7b, 0x51,
			0x55, 0x9a, 0xbf, 0x76, 0x84, 0x12, 0x05, 0x11,
			0xf6, 0x8c, 0xde, 0x7a, 0x21, 0xa0, 0xe7, 0x55,
		},
		{
			0xbd, 0x1e, 0x26, 0xa0, 0xfb, 0xdb, 0xfa, 0x92,
			0x34, 0x86, 0xcc, 0xc9, 0x29, 0x6f, 0x42, 0x27,
			0xdb, 0x49, 0x0b, 0x4a, 0xdd, 0x29, 0xf5, 0x50,
			0x77, 0x75, 0x17, 0x1e, 0xa0, 0xfb, 0x7a, 0x4e,
		},
		{
			0x09, 0x3e, 0xe4, 0x2d, 0x95, 0x50, 0x2b, 0x3e,
			0x81, 0xf4, 0xe6, 0x04, 0x17, 0x9c, 0x82, 0xc1,
			0x49, 0xff, 0xfb, 0x96, 0x16, 0x76, 0x42, 0xb9,
			0xeb, 0x81, 0xb0, 0x3d, 0x6e, 0x2d, 0xd6, 0x36,
		},
	},
}

// Production configuration constants.
var (
	domainConfigChat = DomainConfig{
		Connect: ConnectionConfig{
			Hostname:               "chat.signal.org",
			Port:                   DefaultHTTPSPort,
			Certs:                  RootCertificatesSignal,
			MinTLSVersion:          newTLSVersion(TLSVersion13),
			HTTPVersion:            newHTTPVersion(HTTPVersion1_1),
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
			MinTLSVersion:          newTLSVersion(TLSVersion13),
			HTTPVersion:            newHTTPVersion(HTTPVersion2),
			ConfirmationHeaderName: TimestampHeaderName,
			Proxy:                  domainConfigChat.Connect.Proxy,
		},
	}

	domainConfigChatStaging = DomainConfig{
		Connect: ConnectionConfig{
			Hostname:               "chat.staging.signal.org",
			Port:                   DefaultHTTPSPort,
			Certs:                  RootCertificatesSignal,
			MinTLSVersion:          newTLSVersion(TLSVersion13),
			HTTPVersion:            newHTTPVersion(HTTPVersion1_1),
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
			MinTLSVersion:          newTLSVersion(TLSVersion13),
			HTTPVersion:            newHTTPVersion(HTTPVersion2),
			ConfirmationHeaderName: TimestampHeaderName,
			Proxy:                  domainConfigChatStaging.Connect.Proxy,
		},
	}

	domainConfigCDSI = DomainConfig{
		Connect: ConnectionConfig{
			Hostname:      "cdsi.signal.org",
			Port:          DefaultHTTPSPort,
			Certs:         RootCertificatesSignal,
			MinTLSVersion: newTLSVersion(TLSVersion13),
			HTTPVersion:   newHTTPVersion(HTTPVersion1_1),
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
			Hostname:      "cdsi.staging.signal.org",
			Port:          DefaultHTTPSPort,
			Certs:         RootCertificatesSignal,
			MinTLSVersion: newTLSVersion(TLSVersion13),
			HTTPVersion:   newHTTPVersion(HTTPVersion1_1),
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
			Hostname:      "svr2.signal.org",
			Port:          DefaultHTTPSPort,
			Certs:         RootCertificatesSignal,
			MinTLSVersion: newTLSVersion(TLSVersion13),
			HTTPVersion:   newHTTPVersion(HTTPVersion1_1),
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
			Hostname:      "svr2.staging.signal.org",
			Port:          DefaultHTTPSPort,
			Certs:         RootCertificatesSignal,
			MinTLSVersion: newTLSVersion(TLSVersion13),
			HTTPVersion:   newHTTPVersion(HTTPVersion1_1),
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
			Hostname:      "svrb.signal.org",
			Port:          DefaultHTTPSPort,
			Certs:         RootCertificatesSignal,
			MinTLSVersion: newTLSVersion(TLSVersion13),
			HTTPVersion:   newHTTPVersion(HTTPVersion1_1),
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
			Hostname:      "svrb.staging.signal.org",
			Port:          DefaultHTTPSPort,
			Certs:         RootCertificatesSignal,
			MinTLSVersion: newTLSVersion(TLSVersion13),
			HTTPVersion:   newHTTPVersion(HTTPVersion1_1),
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

// cloneDomainConfig returns a DomainConfig that is a deep copy of src with
// independent allocations for every pointer and slice field:
//   - MinTLSVersion and HTTPVersion are freshly-allocated pointers.
//   - Connect.Proxy is a freshly-allocated *ConnectionProxyConfig (value copy).
//   - IPv4 and IPv6 are independent slice copies (new backing arrays).
//
// This ensures each returned Env is fully isolated: mutating any field of one
// Env cannot affect another Env or the package-level configuration constants.
func cloneDomainConfig(src DomainConfig) DomainConfig {
	dst := src
	if src.Connect.MinTLSVersion != nil {
		dst.Connect.MinTLSVersion = newTLSVersion(*src.Connect.MinTLSVersion)
	}
	if src.Connect.HTTPVersion != nil {
		dst.Connect.HTTPVersion = newHTTPVersion(*src.Connect.HTTPVersion)
	}
	if src.Connect.Proxy != nil {
		proxy := *src.Connect.Proxy
		dst.Connect.Proxy = &proxy
	}
	dst.IPv4 = append([]net.IP(nil), src.IPv4...)
	dst.IPv6 = append([]net.IP(nil), src.IPv6...)
	return dst
}

// deepCopyKeyTransConfig returns a KeyTransConfig whose AuditorKeyMaterials
// slice is a freshly-allocated copy of the one in src. SigningKeyMaterial and
// VRFKeyMaterial are fixed-size arrays and are copied by value automatically.
// Without this deep copy, assigning a KeyTransConfig by value would share the
// backing array of AuditorKeyMaterials with the package-level constant,
// allowing a caller to silently corrupt the global default for all future
// calls to Production() / Staging().
func deepCopyKeyTransConfig(src KeyTransConfig) KeyTransConfig {
	auditors := make([][32]byte, len(src.AuditorKeyMaterials))
	copy(auditors, src.AuditorKeyMaterials)
	return KeyTransConfig{
		SigningKeyMaterial:  src.SigningKeyMaterial,
		VRFKeyMaterial:      src.VRFKeyMaterial,
		AuditorKeyMaterials: auditors,
	}
}

// Production returns the production environment configuration.
// Each call returns an independent Env; callers may mutate the returned value
// without affecting other calls or the package-level configuration constants.
func Production() *Env {
	wsConfig := DefaultWSConfig()
	return &Env{
		ChatDomainConfig:               cloneDomainConfig(domainConfigChat),
		ExperimentalChatH2DomainConfig: cloneDomainConfig(domainConfigExperimentalChatH2),
		CDSI: EnclaveEndpoint{
			DomainConfig: cloneDomainConfig(domainConfigCDSI),
			WSConfig:     wsConfig,
			Params:       endpointParamsCDSIProd,
		},
		SVR2: EnclaveEndpoint{
			DomainConfig: cloneDomainConfig(domainConfigSVR2),
			WSConfig:     wsConfig,
			Params:       endpointParamsSVR2_2026Q1Prod,
		},
		SVRB: SvrBEnv{
			Current: []*EnclaveEndpoint{
				{
					DomainConfig: cloneDomainConfig(domainConfigSVRBProd),
					WSConfig:     wsConfig,
					Params:       endpointParamsSVRB_2026Q1Prod,
				},
			},
			Previous: []*EnclaveEndpoint{
				{
					DomainConfig: cloneDomainConfig(domainConfigSVRBProd),
					WSConfig:     wsConfig,
					Params:       endpointParamsSVRB_2025Q3Prod,
				},
			},
		},
		KeyTrans: deepCopyKeyTransConfig(KeyTransConfigProduction),
	}
}

// Staging returns the staging environment configuration.
// Each call returns an independent Env; callers may mutate the returned value
// without affecting other calls or the package-level configuration constants.
func Staging() *Env {
	wsConfig := DefaultWSConfig()
	return &Env{
		ChatDomainConfig:               cloneDomainConfig(domainConfigChatStaging),
		ExperimentalChatH2DomainConfig: cloneDomainConfig(domainConfigExperimentalChatH2Staging),
		CDSI: EnclaveEndpoint{
			DomainConfig: cloneDomainConfig(domainConfigCDSIStaging),
			WSConfig:     wsConfig,
			Params:       endpointParamsCDSIStaging,
		},
		SVR2: EnclaveEndpoint{
			DomainConfig: cloneDomainConfig(domainConfigSVR2Staging),
			WSConfig:     wsConfig,
			Params:       endpointParamsSVR2_2026Q1Staging,
		},
		SVRB: SvrBEnv{
			Current: []*EnclaveEndpoint{
				{
					DomainConfig: cloneDomainConfig(domainConfigSVRBStaging),
					WSConfig:     wsConfig,
					Params:       endpointParamsSVRB_2026Q1Staging,
				},
			},
			Previous: nil,
		},
		KeyTrans: deepCopyKeyTransConfig(KeyTransConfigStaging),
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
