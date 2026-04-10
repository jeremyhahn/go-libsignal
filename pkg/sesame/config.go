package sesame

import (
	"fmt"
	"time"
)

const (
	// DefaultMaxSend is the default maximum duration since session creation
	// before a session must no longer be used for encryption. Per Sesame spec
	// section 4.2: 30 days.
	DefaultMaxSend = 30 * 24 * time.Hour

	// DefaultMaxRecv is the default maximum duration since session creation
	// before a session may be deleted. Per Sesame spec section 4.2: 90 days.
	DefaultMaxRecv = 90 * 24 * time.Hour

	// DefaultMaxLatency is the default maximum expected message latency.
	// Per Sesame spec section 4.2: 14 days.
	DefaultMaxLatency = 14 * 24 * time.Hour

	// DefaultMaxInactiveSessions is the maximum number of inactive sessions
	// per device. Per Sesame spec section 3.2, sessions may be deleted from
	// the tail end if the list grows too large.
	DefaultMaxInactiveSessions = 40

	// DefaultMaxSendRetries is the maximum number of iterations in the
	// send loop before giving up. Per Sesame spec section 3.3, the send
	// process is iterative with server feedback.
	DefaultMaxSendRetries = 3

	// DefaultMaxDevicesPerUser is the maximum number of devices that may
	// be registered for a single user. This bounds memory consumption and
	// prevents resource exhaustion from unbounded device registration.
	DefaultMaxDevicesPerUser = 20

	// DefaultMaxUsers is the maximum number of user records that may be
	// stored simultaneously. This bounds memory consumption and prevents
	// resource exhaustion from unbounded user registration.
	DefaultMaxUsers = 1000
)

// Config holds the timing parameters for session lifecycle management.
// Per section 4.2 of the Sesame specification, these values control when
// sessions expire and when stale records are cleaned up.
type Config struct {
	// MaxSend is the maximum duration since session creation. If exceeded, the
	// session must no longer be used for encryption and shall be moved to inactive.
	MaxSend time.Duration

	// MaxRecv is the maximum duration since session creation. If exceeded,
	// the session may be deleted. Must satisfy: MaxRecv > MaxSend + 2*MaxLatency.
	MaxRecv time.Duration

	// MaxLatency is the maximum expected message delivery latency. Stale
	// records are deleted after this duration elapses from when they were
	// marked stale.
	MaxLatency time.Duration

	// MaxInactiveSessions is the maximum number of inactive sessions per device.
	// If the inactive list grows beyond this limit, sessions are deleted from
	// the tail end per Sesame spec section 3.2.
	MaxInactiveSessions int

	// MaxSendRetries is the maximum number of iterations in the send loop
	// per Sesame spec section 3.3. The send process is iterative and may
	// need to restart when the server reports device list changes.
	MaxSendRetries int

	// MaxDevicesPerUser is the maximum number of devices allowed per user.
	// Prevents resource exhaustion from unbounded device registration.
	MaxDevicesPerUser int

	// MaxUsers is the maximum number of user records that may be stored.
	// Prevents resource exhaustion from unbounded user creation.
	MaxUsers int
}

// DefaultConfig returns a Config with the specification default values:
// MaxSend=30 days, MaxRecv=90 days, MaxLatency=14 days, MaxInactiveSessions=40,
// MaxSendRetries=3.
func DefaultConfig() *Config {
	return &Config{
		MaxSend:             DefaultMaxSend,
		MaxRecv:             DefaultMaxRecv,
		MaxLatency:          DefaultMaxLatency,
		MaxInactiveSessions: DefaultMaxInactiveSessions,
		MaxSendRetries:      DefaultMaxSendRetries,
		MaxDevicesPerUser:   DefaultMaxDevicesPerUser,
		MaxUsers:            DefaultMaxUsers,
	}
}

// Validate checks that the configuration satisfies the Sesame specification
// constraint: MaxRecv > MaxSend + 2*MaxLatency. It also verifies that all
// durations are positive.
func (c *Config) Validate() error {
	if c.MaxSend <= 0 {
		return NewInvalidConfigError("MaxSend must be positive")
	}
	if c.MaxRecv <= 0 {
		return NewInvalidConfigError("MaxRecv must be positive")
	}
	if c.MaxLatency <= 0 {
		return NewInvalidConfigError("MaxLatency must be positive")
	}
	if c.MaxInactiveSessions <= 0 {
		return NewInvalidConfigError("MaxInactiveSessions must be positive")
	}
	if c.MaxSendRetries <= 0 {
		return NewInvalidConfigError("MaxSendRetries must be positive")
	}
	if c.MaxDevicesPerUser <= 0 {
		return NewInvalidConfigError("MaxDevicesPerUser must be positive")
	}
	if c.MaxUsers <= 0 {
		return NewInvalidConfigError("MaxUsers must be positive")
	}

	minMaxRecv := c.MaxSend + 2*c.MaxLatency
	if c.MaxRecv <= minMaxRecv {
		return NewInvalidConfigError(
			fmt.Sprintf("MaxRecv (%v) must be greater than MaxSend + 2*MaxLatency (%v)",
				c.MaxRecv, minMaxRecv),
		)
	}

	return nil
}
