// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// Auth represents a username/password combination for Signal service
// authentication.
//
// When returned by the chat server's /auth endpoints:
//   - username is "hex(uid)"
//   - password is "timestamp:hex(otp(uid, timestamp, secret))"
type Auth struct {
	Username string
	Password string
}

// otpLength is the hex-encoded OTP truncation length.
const otpLength = 20

// AuthFromUIDAndSecret creates an Auth from a 16-byte UID and a 32-byte
// shared secret. The password is derived as a time-based OTP using
// HMAC-SHA256.
func AuthFromUIDAndSecret(uid [16]byte, secret [32]byte) Auth {
	// Zeroize the secret copy after HMAC computation to prevent
	// sensitive material from lingering on the stack/heap.
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()

	username := hex.EncodeToString(uid[:])
	password := computeOTP(username, secret[:], time.Now())
	return Auth{
		Username: username,
		Password: password,
	}
}

// computeOTP computes a time-based one-time password for the given username
// and secret. The result is formatted as "timestamp:hex(hmac)[:20]".
func computeOTP(username string, secret []byte, now time.Time) string {
	ts := now.Unix()
	macInput := fmt.Sprintf("%s:%d", username, ts)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(macInput))
	digest := mac.Sum(nil)

	khex := hex.EncodeToString(digest)
	if len(khex) > otpLength {
		khex = khex[:otpLength]
	}
	return fmt.Sprintf("%d:%s", ts, khex)
}

// BasicAuthHeader returns the HTTP Authorization header value for basic
// authentication using the Auth credentials.
func (a *Auth) BasicAuthHeader() string {
	return "Basic " + basicAuth(a.Username, a.Password)
}

// SetAuthHeader sets the Authorization header on the given HTTP request.
func (a *Auth) SetAuthHeader(req *http.Request) {
	req.SetBasicAuth(a.Username, a.Password)
}

// basicAuth encodes username and password in base64 for HTTP basic auth.
func basicAuth(username, password string) string {
	// Use the standard library encoding via a temporary request.
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		// Should never fail with well-formed static inputs, but handle gracefully.
		return ""
	}
	req.SetBasicAuth(username, password)
	// Extract just the encoded part after "Basic ".
	auth := req.Header.Get("Authorization")
	if len(auth) > 6 {
		return auth[6:]
	}
	return ""
}
