// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

package net

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/svr"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// BackupConnectionDelay is the stagger delay between initiating parallel
// connections to multiple SVRB backends, avoiding a thundering herd.
const BackupConnectionDelay = 50 * time.Millisecond

// SvrBErrorKind categorizes SVRB-specific errors.
type SvrBErrorKind int

const (
	// SvrBErrorConnect indicates a connection-level failure.
	SvrBErrorConnect SvrBErrorKind = iota
	// SvrBErrorRateLimited indicates the server is rate-limiting requests.
	SvrBErrorRateLimited
	// SvrBErrorService indicates a network/WebSocket error after connection.
	SvrBErrorService
	// SvrBErrorProtocol indicates a protocol-level error after establishing
	// a connection.
	SvrBErrorProtocol
	// SvrBErrorAttestation indicates enclave attestation failure.
	SvrBErrorAttestation
	// SvrBErrorRestoreFailed indicates the restore failed, possibly due to
	// an invalid password or share set.
	SvrBErrorRestoreFailed
	// SvrBErrorDataMissing indicates the data was never backed up or all
	// restore attempts have been exhausted.
	SvrBErrorDataMissing
	// SvrBErrorAllConnectionAttemptsFailed indicates no connection attempt
	// succeeded before timeout.
	SvrBErrorAllConnectionAttemptsFailed
	// SvrBErrorPreviousBackupDataInvalid indicates the previous backup data
	// could not be parsed.
	SvrBErrorPreviousBackupDataInvalid
	// SvrBErrorMetadataInvalid indicates the backup metadata could not be
	// parsed.
	SvrBErrorMetadataInvalid
	// SvrBErrorDecryption indicates a decryption failure.
	SvrBErrorDecryption
)

// SvrBError represents an error from SVRB operations.
type SvrBError struct {
	// Kind categorizes the error.
	Kind SvrBErrorKind
	// TriesRemaining is set when Kind is SvrBErrorRestoreFailed.
	TriesRemaining uint32
	// RetryAfter is set when Kind is SvrBErrorRateLimited.
	RetryAfter time.Duration
	// Err is the underlying error.
	Err error
}

// Error returns the error string.
func (e *SvrBError) Error() string {
	switch e.Kind {
	case SvrBErrorConnect:
		return fmt.Sprintf("svrb: connection error: %v", e.Err)
	case SvrBErrorRateLimited:
		return fmt.Sprintf("svrb: rate limited, retry after %v", e.RetryAfter)
	case SvrBErrorService:
		return fmt.Sprintf("svrb: network error: %v", e.Err)
	case SvrBErrorProtocol:
		return fmt.Sprintf("svrb: protocol error: %v", e.Err)
	case SvrBErrorAttestation:
		return fmt.Sprintf("svrb: attestation failed: %v", e.Err)
	case SvrBErrorRestoreFailed:
		return fmt.Sprintf("svrb: restore failed, %d tries remaining", e.TriesRemaining)
	case SvrBErrorDataMissing:
		return "svrb: data missing"
	case SvrBErrorAllConnectionAttemptsFailed:
		return "svrb: all connection attempts failed"
	case SvrBErrorPreviousBackupDataInvalid:
		return "svrb: previous backup data invalid"
	case SvrBErrorMetadataInvalid:
		return "svrb: metadata invalid"
	case SvrBErrorDecryption:
		return fmt.Sprintf("svrb: decryption error: %v", e.Err)
	default:
		if e.Err != nil {
			return fmt.Sprintf("svrb: %v", e.Err)
		}
		return "svrb: unknown error"
	}
}

// Unwrap returns the underlying error.
func (e *SvrBError) Unwrap() error {
	return e.Err
}

// Is implements errors.Is matching by kind.
func (e *SvrBError) Is(target error) bool {
	t, ok := target.(*SvrBError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// prioritizeError returns the higher-priority error of two SVRB errors.
// The priority order (highest first) is:
//  1. Structural errors (PreviousBackupDataInvalid, MetadataInvalid)
//  2. Data errors (Decryption)
//  3. Connection errors (Attestation, Protocol, RateLimited, Service,
//     Connect, AllConnectionAttemptsFailed)
//  4. Content errors (RestoreFailed, DataMissing)
func prioritizeError(first, second *SvrBError) *SvrBError {
	priorityOf := func(e *SvrBError) int {
		switch e.Kind {
		case SvrBErrorPreviousBackupDataInvalid:
			return 12
		case SvrBErrorMetadataInvalid:
			return 11
		case SvrBErrorDecryption:
			return 10
		case SvrBErrorAttestation:
			return 9
		case SvrBErrorProtocol:
			return 8
		case SvrBErrorRateLimited:
			return 7
		case SvrBErrorService:
			return 6
		case SvrBErrorConnect:
			return 5
		case SvrBErrorAllConnectionAttemptsFailed:
			return 4
		case SvrBErrorRestoreFailed:
			return 3
		case SvrBErrorDataMissing:
			return 2
		default:
			return 0
		}
	}

	if priorityOf(first) >= priorityOf(second) {
		return first
	}
	return second
}

// svrBErrorFromSvrError converts an SvrError to an SvrBError.
func svrBErrorFromSvrError(e *SvrError) *SvrBError {
	switch e.Kind {
	case SvrErrorWebSocketConnect:
		return &SvrBError{Kind: SvrBErrorConnect, Err: e.Err}
	case SvrErrorRateLimited:
		return &SvrBError{Kind: SvrBErrorRateLimited, RetryAfter: e.RetryAfter}
	case SvrErrorWebSocket:
		return &SvrBError{Kind: SvrBErrorService, Err: e.Err}
	case SvrErrorProtocol:
		return &SvrBError{Kind: SvrBErrorProtocol, Err: e.Err}
	case SvrErrorAttestation:
		return &SvrBError{Kind: SvrBErrorAttestation, Err: e.Err}
	case SvrErrorAllAttemptsFailed:
		return &SvrBError{Kind: SvrBErrorAllConnectionAttemptsFailed}
	default:
		return &SvrBError{Kind: SvrBErrorService, Err: e}
	}
}

// svrBErrorFromSvrLogicError converts an svr.Error to an SvrBError.
func svrBErrorFromSvrLogicError(err error) *SvrBError {
	e, ok := err.(*svr.Error)
	if !ok {
		return &SvrBError{Kind: SvrBErrorProtocol, Err: err}
	}

	if e.Is(svr.ErrBadData) || e.Is(svr.ErrBadResponse) || e.Is(svr.ErrNoUsableVersion) {
		return &SvrBError{Kind: SvrBErrorProtocol, Err: e}
	}
	if s := e.Status(); s == svr.StatusMissing {
		return &SvrBError{Kind: SvrBErrorDataMissing}
	}
	tries := e.TriesRemaining()
	if tries > 0 {
		return &SvrBError{Kind: SvrBErrorRestoreFailed, TriesRemaining: tries}
	}
	return &SvrBError{Kind: SvrBErrorProtocol, Err: e}
}

// SvrBTransport abstracts the network transport for a single SVRB server
// connection. It combines the attested Noise-protocol encryption with the
// underlying WebSocket transport to provide encrypted send/receive over
// the network. Implementations are responsible for encrypting via the
// Noise session before sending over the wire, and decrypting received
// wire bytes through the Noise session.
type SvrBTransport interface {
	// SendBytes encrypts and sends a request to the server.
	SendBytes(ctx context.Context, data []byte) error
	// ReceiveBytes receives and decrypts a response from the server.
	ReceiveBytes(ctx context.Context) ([]byte, error)
	// HandshakeHash returns the Noise handshake hash for channel binding.
	HandshakeHash() []byte
	// Close closes the underlying transport.
	Close() error
}

// SvrBPreparer prepares OPRF backup data for SVRB operations.
type SvrBPreparer interface {
	// Prepare creates an OPRF backup request set for the given password.
	// maxTries sets the server-side rate limit for restore attempts.
	// The returned OPRFBackup4 contains serialized requests ready to send
	// to each server and the derived output key.
	Prepare(password []byte, maxTries uint32) (*svr.OPRFBackup4, error)
}

// SvrBBackuper finalizes a prepared backup by sending requests to servers.
type SvrBBackuper interface {
	// Finalize sends the backup requests to all connected servers and
	// waits for acknowledgment.
	Finalize(ctx context.Context, backup *svr.OPRFBackup4) error
}

// SvrBRestorer restores a secret from SVRB servers using a password.
type SvrBRestorer interface {
	// Restore performs a two-phase OPRF restore, returning the encryption
	// key secret.
	Restore(ctx context.Context, password []byte) (*secret.Secret, error)
}

// SvrBQuerier queries the SVRB servers for the number of tries remaining.
type SvrBQuerier interface {
	// Query returns the minimum number of tries remaining across all
	// servers.
	Query(ctx context.Context) (uint32, error)
}

// SvrBRemover removes backup data from SVRB servers.
type SvrBRemover interface {
	// Remove deletes the backup from all connected servers. Connection
	// failures to individual servers are tolerated as long as at least
	// one server is reachable.
	Remove(ctx context.Context) error
}

// SvrBClient combines all SVRB operations into a single interface.
type SvrBClient interface {
	SvrBPreparer
	SvrBBackuper
	SvrBRestorer
	SvrBQuerier
	SvrBRemover
}

// SvrBConnector establishes connections to SVRB enclave backends.
type SvrBConnector interface {
	// Connect establishes attested connections to the SVRB servers and
	// returns connection results. Each result corresponds to one server.
	Connect(ctx context.Context) ([]SvrBConnectionResult, error)
}

// SvrBConnectionResult represents the outcome of a single SVRB server
// connection attempt. Either Transport is set (on success) or Err is
// set (on failure).
type SvrBConnectionResult struct {
	// ServerID is the numeric identifier for this server.
	ServerID uint64
	// Transport is the attested transport, nil on failure.
	Transport SvrBTransport
	// Err is the error if the connection attempt failed.
	Err error
}

// SvrBNetClient implements SvrBClient using an SvrBConnector for network
// transport and the svr package for cryptographic operations.
type SvrBNetClient struct {
	connector SvrBConnector
	serverIDs []uint64
}

// NewSvrBNetClient creates a new SVRB network client using the given
// connector and server IDs. The server IDs must match the IDs expected
// by the SVRB enclave backends.
func NewSvrBNetClient(connector SvrBConnector, serverIDs []uint64) *SvrBNetClient {
	ids := make([]uint64, len(serverIDs))
	copy(ids, serverIDs)
	return &SvrBNetClient{
		connector: connector,
		serverIDs: ids,
	}
}

// Prepare creates an OPRF backup request set for the given password.
// maxTries sets the server-side rate limit for restore attempts (must be > 0).
func (c *SvrBNetClient) Prepare(password []byte, maxTries uint32) (*svr.OPRFBackup4, error) {
	return svr.NewOPRFBackup4(c.serverIDs, password, maxTries)
}

// Finalize sends backup requests to all connected servers. It establishes
// connections, sends each request to its corresponding server, and collects
// responses.
func (c *SvrBNetClient) Finalize(ctx context.Context, backup *svr.OPRFBackup4) error {
	transports, connErrs, err := c.connectAll(ctx)
	if err != nil {
		return err
	}
	defer closeTransports(transports)

	// Fail immediately if any connection failed.
	if firstErr := firstConnectionError(connErrs); firstErr != nil {
		return firstErr
	}

	if len(backup.Requests) != len(transports) {
		return &SvrBError{
			Kind: SvrBErrorProtocol,
			Err:  &ErrRequestConnectionMismatch{Requests: len(backup.Requests), Connections: len(transports)},
		}
	}

	responses, err := sendAll(ctx, transports, backup.Requests)
	if err != nil {
		return err
	}

	if _, err := svr.FinalizeBackup4(responses); err != nil {
		return svrBErrorFromSvrLogicError(err)
	}
	return nil
}

// Restore performs a two-phase OPRF restore to recover the encryption key.
func (c *SvrBNetClient) Restore(ctx context.Context, password []byte) (*secret.Secret, error) {

	transports, connErrs, err := c.connectAll(ctx)
	if err != nil {
		return nil, err
	}
	defer closeTransports(transports)

	if firstErr := firstConnectionError(connErrs); firstErr != nil {
		return nil, firstErr
	}

	// Phase 1: create restore1 and send blinded points.
	restore1, err := svr.NewRestore1(c.serverIDs, password)
	if err != nil {
		return nil, svrBErrorFromSvrLogicError(err)
	}
	defer restore1.Zeroize()

	responses1, err := sendAll(ctx, transports, restore1.Requests)
	if err != nil {
		return nil, err
	}

	// Collect handshake hashes from the attested connections for channel
	// binding in the Schnorr proof.
	handshakeHashes := make([][]byte, len(transports))
	for i, t := range transports {
		handshakeHashes[i] = t.HandshakeHash()
	}

	// Phase 2: process phase 1 responses, generate phase 2 requests.
	restore2, err := restore1.Restore2(responses1, handshakeHashes)
	if err != nil {
		return nil, svrBErrorFromSvrLogicError(err)
	}
	defer restore2.Zeroize()

	responses2, err := sendAll(ctx, transports, restore2.Requests)
	if err != nil {
		return nil, err
	}

	output, err := restore2.Restore(responses2)
	if err != nil {
		return nil, svrBErrorFromSvrLogicError(err)
	}

	return output, nil
}

// Query returns the minimum tries remaining across all servers.
func (c *SvrBNetClient) Query(ctx context.Context) (uint32, error) {
	transports, connErrs, err := c.connectAll(ctx)
	if err != nil {
		return 0, err
	}
	defer closeTransports(transports)

	if firstErr := firstConnectionError(connErrs); firstErr != nil {
		return 0, firstErr
	}

	q := svr.Query4{}
	requests, err := q.RequestsN(len(transports))
	if err != nil {
		return 0, &SvrBError{Kind: SvrBErrorProtocol, Err: err}
	}

	responses, err := sendAll(ctx, transports, requests)
	if err != nil {
		return 0, err
	}

	tries, err := q.Finalize(responses)
	if err != nil {
		return 0, svrBErrorFromSvrLogicError(err)
	}
	return tries, nil
}

// Remove deletes backup data from all servers. Connection failures to
// individual servers are tolerated as long as at least one server is
// reachable.
func (c *SvrBNetClient) Remove(ctx context.Context) error {
	transports, connErrs, err := c.connectAll(ctx)
	if err != nil {
		return err
	}
	defer closeTransports(transports)

	if len(transports) == 0 {
		// All connection attempts failed; return the first error.
		return firstConnectionError(connErrs)
	}

	// For remove, we ignore individual connection failures and proceed
	// with whatever connections we have.
	r := svr.Remove4{}
	requests, err := r.RequestsN(len(transports))
	if err != nil {
		return &SvrBError{Kind: SvrBErrorProtocol, Err: err}
	}

	_, err = sendAll(ctx, transports, requests)
	return err
}

// connectAll establishes connections to all SVRB servers using the
// connector. It returns the successful transports and any errors
// separately.
func (c *SvrBNetClient) connectAll(ctx context.Context) ([]SvrBTransport, []*SvrBError, error) {
	results, err := c.connector.Connect(ctx)
	if err != nil {
		return nil, nil, &SvrBError{Kind: SvrBErrorAllConnectionAttemptsFailed, Err: err}
	}

	transports := make([]SvrBTransport, 0, len(results))
	errs := make([]*SvrBError, 0)

	for _, r := range results {
		if r.Err != nil {
			svrErr, ok := r.Err.(*SvrError)
			if ok {
				errs = append(errs, svrBErrorFromSvrError(svrErr))
			} else {
				errs = append(errs, &SvrBError{Kind: SvrBErrorConnect, Err: r.Err})
			}
		} else {
			transports = append(transports, r.Transport)
		}
	}

	return transports, errs, nil
}

// sendAll sends one request to each transport in parallel and collects
// the responses. It returns an error if any send or receive fails.
func sendAll(ctx context.Context, transports []SvrBTransport, requests [][]byte) ([][]byte, error) {
	type result struct {
		index int
		data  []byte
		err   error
	}

	var wg sync.WaitGroup
	results := make([]result, len(transports))

	for i := range transports {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			data, err := runInteraction(ctx, transports[idx], requests[idx])
			results[idx] = result{index: idx, data: data, err: err}
		}(i)
	}

	wg.Wait()

	responses := make([][]byte, len(transports))
	for _, r := range results {
		if r.err != nil {
			return nil, &SvrBError{Kind: SvrBErrorService, Err: r.err}
		}
		if r.data == nil {
			return nil, &SvrBError{
				Kind: SvrBErrorProtocol,
				Err:  &ErrNoServerResponse{ServerIndex: r.index},
			}
		}
		responses[r.index] = r.data
	}

	return responses, nil
}

// runInteraction sends a request on the transport and reads back the
// response.
func runInteraction(ctx context.Context, transport SvrBTransport, request []byte) ([]byte, error) {
	if err := transport.SendBytes(ctx, request); err != nil {
		return nil, err
	}
	return transport.ReceiveBytes(ctx)
}

// firstConnectionError returns the first error from a list of connection
// errors, or nil if there are none.
func firstConnectionError(errs []*SvrBError) *SvrBError {
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// closeTransports closes all transports, ignoring errors.
func closeTransports(transports []SvrBTransport) {
	for _, t := range transports {
		if t != nil {
			_ = t.Close()
		}
	}
}
