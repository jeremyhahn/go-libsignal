package net

import "fmt"

// CdsiSerializeError is returned when a CDSI fixed-length serialization or
// deserialization operation fails.
type CdsiSerializeError struct {
	// Field identifies which DTO field caused the error.
	Field string
	// Msg describes the failure.
	Msg string
}

func (e *CdsiSerializeError) Error() string {
	return fmt.Sprintf("cdsi: serialize error on %s: %s", e.Field, e.Msg)
}

// ErrCdsiNoTokenInResponseType is the typed error for a missing CDSI token.
type ErrCdsiNoTokenInResponseType struct{}

func (e *ErrCdsiNoTokenInResponseType) Error() string {
	return "cdsi: no token in response"
}

// ErrChatDisconnectedType is the typed error for operations on a disconnected chat connection.
type ErrChatDisconnectedType struct{}

func (e *ErrChatDisconnectedType) Error() string {
	return "chat: connection is disconnected"
}

// ErrMissingRaftConfig indicates that an SGX enclave handshake was attempted
// without the required raft configuration.
type ErrMissingRaftConfig struct{}

func (e *ErrMissingRaftConfig) Error() string {
	return "net: raft config must be present for SGX enclave"
}

// ErrRequestConnectionMismatch indicates a mismatch between the number
// of backup requests and the number of established connections.
type ErrRequestConnectionMismatch struct {
	Requests    int
	Connections int
}

func (e *ErrRequestConnectionMismatch) Error() string {
	return fmt.Sprintf("net: backup has %d requests but %d connections", e.Requests, e.Connections)
}

// ErrNoServerResponse indicates that no response was received from a
// specific server in a multi-server operation.
type ErrNoServerResponse struct {
	ServerIndex int
}

func (e *ErrNoServerResponse) Error() string {
	return fmt.Sprintf("net: no response from server %d", e.ServerIndex)
}
