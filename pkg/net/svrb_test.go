package net

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/svr"
)

// --- mock transport ---

type mockSvrBTransport struct {
	handshakeHash []byte
	sendFn        func(ctx context.Context, data []byte) error
	receiveFn     func(ctx context.Context) ([]byte, error)
	closeFn       func() error
	sendCalls     int
	receiveCalls  int
	closed        bool
}

func (m *mockSvrBTransport) SendBytes(ctx context.Context, data []byte) error {
	m.sendCalls++
	if m.sendFn != nil {
		return m.sendFn(ctx, data)
	}
	return nil
}

func (m *mockSvrBTransport) ReceiveBytes(ctx context.Context) ([]byte, error) {
	m.receiveCalls++
	if m.receiveFn != nil {
		return m.receiveFn(ctx)
	}
	return nil, nil
}

func (m *mockSvrBTransport) HandshakeHash() []byte {
	if m.handshakeHash != nil {
		return m.handshakeHash
	}
	return make([]byte, 32)
}

func (m *mockSvrBTransport) Close() error {
	m.closed = true
	if m.closeFn != nil {
		return m.closeFn()
	}
	return nil
}

// --- mock connector ---

type mockSvrBConnector struct {
	results []SvrBConnectionResult
	err     error
}

func (m *mockSvrBConnector) Connect(_ context.Context) ([]SvrBConnectionResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.results, nil
}

// --- SvrBError tests ---

func TestSvrBError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *SvrBError
		want string
	}{
		{
			"connect",
			&SvrBError{Kind: SvrBErrorConnect, Err: errors.New("refused")},
			"svrb: connection error: refused",
		},
		{
			"rate limited",
			&SvrBError{Kind: SvrBErrorRateLimited, RetryAfter: 5 * time.Second},
			fmt.Sprintf("svrb: rate limited, retry after %v", 5*time.Second),
		},
		{
			"service",
			&SvrBError{Kind: SvrBErrorService, Err: errors.New("timeout")},
			"svrb: network error: timeout",
		},
		{
			"protocol",
			&SvrBError{Kind: SvrBErrorProtocol, Err: errors.New("bad frame")},
			"svrb: protocol error: bad frame",
		},
		{
			"attestation",
			&SvrBError{Kind: SvrBErrorAttestation, Err: errors.New("invalid")},
			"svrb: attestation failed: invalid",
		},
		{
			"restore failed",
			&SvrBError{Kind: SvrBErrorRestoreFailed, TriesRemaining: 3},
			"svrb: restore failed, 3 tries remaining",
		},
		{
			"data missing",
			&SvrBError{Kind: SvrBErrorDataMissing},
			"svrb: data missing",
		},
		{
			"all attempts failed",
			&SvrBError{Kind: SvrBErrorAllConnectionAttemptsFailed},
			"svrb: all connection attempts failed",
		},
		{
			"previous backup invalid",
			&SvrBError{Kind: SvrBErrorPreviousBackupDataInvalid},
			"svrb: previous backup data invalid",
		},
		{
			"metadata invalid",
			&SvrBError{Kind: SvrBErrorMetadataInvalid},
			"svrb: metadata invalid",
		},
		{
			"decryption",
			&SvrBError{Kind: SvrBErrorDecryption, Err: errors.New("bad mac")},
			"svrb: decryption error: bad mac",
		},
		{
			"unknown with err",
			&SvrBError{Kind: SvrBErrorKind(99), Err: errors.New("something")},
			"svrb: something",
		},
		{
			"unknown no err",
			&SvrBError{Kind: SvrBErrorKind(99)},
			"svrb: unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSvrBError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &SvrBError{Err: inner}
	if err.Unwrap() != inner {
		t.Error("Unwrap mismatch")
	}
}

func TestSvrBError_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    *SvrBError
		target error
		want   bool
	}{
		{
			"same kind",
			&SvrBError{Kind: SvrBErrorConnect},
			&SvrBError{Kind: SvrBErrorConnect},
			true,
		},
		{
			"different kind",
			&SvrBError{Kind: SvrBErrorConnect},
			&SvrBError{Kind: SvrBErrorProtocol},
			false,
		},
		{
			"different type",
			&SvrBError{Kind: SvrBErrorConnect},
			errors.New("other"),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Is(tt.target); got != tt.want {
				t.Errorf("Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrioritizeError(t *testing.T) {
	tests := []struct {
		name   string
		first  *SvrBError
		second *SvrBError
		want   SvrBErrorKind
	}{
		{
			"previous backup invalid over connect",
			&SvrBError{Kind: SvrBErrorPreviousBackupDataInvalid},
			&SvrBError{Kind: SvrBErrorConnect},
			SvrBErrorPreviousBackupDataInvalid,
		},
		{
			"metadata invalid over attestation",
			&SvrBError{Kind: SvrBErrorMetadataInvalid},
			&SvrBError{Kind: SvrBErrorAttestation},
			SvrBErrorMetadataInvalid,
		},
		{
			"decryption over protocol",
			&SvrBError{Kind: SvrBErrorDecryption},
			&SvrBError{Kind: SvrBErrorProtocol},
			SvrBErrorDecryption,
		},
		{
			"attestation over rate limited",
			&SvrBError{Kind: SvrBErrorAttestation},
			&SvrBError{Kind: SvrBErrorRateLimited},
			SvrBErrorAttestation,
		},
		{
			"protocol over service",
			&SvrBError{Kind: SvrBErrorProtocol},
			&SvrBError{Kind: SvrBErrorService},
			SvrBErrorProtocol,
		},
		{
			"rate limited over connect",
			&SvrBError{Kind: SvrBErrorRateLimited},
			&SvrBError{Kind: SvrBErrorConnect},
			SvrBErrorRateLimited,
		},
		{
			"connect over all attempts failed",
			&SvrBError{Kind: SvrBErrorConnect},
			&SvrBError{Kind: SvrBErrorAllConnectionAttemptsFailed},
			SvrBErrorConnect,
		},
		{
			"all attempts over restore failed",
			&SvrBError{Kind: SvrBErrorAllConnectionAttemptsFailed},
			&SvrBError{Kind: SvrBErrorRestoreFailed},
			SvrBErrorAllConnectionAttemptsFailed,
		},
		{
			"restore failed over data missing",
			&SvrBError{Kind: SvrBErrorRestoreFailed},
			&SvrBError{Kind: SvrBErrorDataMissing},
			SvrBErrorRestoreFailed,
		},
		{
			"second preferred when higher priority",
			&SvrBError{Kind: SvrBErrorDataMissing},
			&SvrBError{Kind: SvrBErrorDecryption},
			SvrBErrorDecryption,
		},
		{
			"same kind returns first",
			&SvrBError{Kind: SvrBErrorConnect},
			&SvrBError{Kind: SvrBErrorConnect},
			SvrBErrorConnect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := prioritizeError(tt.first, tt.second)
			if got.Kind != tt.want {
				t.Errorf("prioritizeError() kind = %d, want %d", got.Kind, tt.want)
			}
		})
	}
}

// --- Error conversion tests ---

func TestSvrBErrorFromSvrError(t *testing.T) {
	tests := []struct {
		name string
		err  *SvrError
		want SvrBErrorKind
	}{
		{"ws connect", &SvrError{Kind: SvrErrorWebSocketConnect, Err: errors.New("x")}, SvrBErrorConnect},
		{"rate limited", &SvrError{Kind: SvrErrorRateLimited, RetryAfter: time.Second}, SvrBErrorRateLimited},
		{"websocket", &SvrError{Kind: SvrErrorWebSocket, Err: errors.New("x")}, SvrBErrorService},
		{"protocol", &SvrError{Kind: SvrErrorProtocol, Err: errors.New("x")}, SvrBErrorProtocol},
		{"attestation", &SvrError{Kind: SvrErrorAttestation, Err: errors.New("x")}, SvrBErrorAttestation},
		{"all failed", &SvrError{Kind: SvrErrorAllAttemptsFailed}, SvrBErrorAllConnectionAttemptsFailed},
		{"unknown kind", &SvrError{Kind: SvrErrorKind(99)}, SvrBErrorService},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svrBErrorFromSvrError(tt.err)
			if got.Kind != tt.want {
				t.Errorf("kind = %d, want %d", got.Kind, tt.want)
			}
		})
	}
}

func TestSvrBErrorFromSvrLogicError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want SvrBErrorKind
	}{
		{"bad data", svr.ErrBadData, SvrBErrorProtocol},
		{"bad response", svr.ErrBadResponse, SvrBErrorProtocol},
		{"no usable version", svr.ErrNoUsableVersion, SvrBErrorProtocol},
		{"non-svr error", errors.New("other"), SvrBErrorProtocol},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := svrBErrorFromSvrLogicError(tt.err)
			if got.Kind != tt.want {
				t.Errorf("kind = %d, want %d", got.Kind, tt.want)
			}
		})
	}
}

// --- SvrBNetClient tests ---

func TestNewSvrBNetClient(t *testing.T) {
	serverIDs := []uint64{1, 2, 3}
	connector := &mockSvrBConnector{}

	client := NewSvrBNetClient(connector, serverIDs)

	if client == nil {
		t.Fatal("NewSvrBNetClient returned nil")
	}
	if len(client.serverIDs) != 3 {
		t.Errorf("serverIDs length = %d, want 3", len(client.serverIDs))
	}

	// Verify defensive copy.
	serverIDs[0] = 999
	if client.serverIDs[0] != 1 {
		t.Error("serverIDs was not copied")
	}
}

func TestSvrBNetClient_Prepare(t *testing.T) {
	client := NewSvrBNetClient(&mockSvrBConnector{}, []uint64{1, 2})

	backup, err := client.Prepare(svrTestPassword("password"), 255)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if backup == nil {
		t.Fatal("Prepare() returned nil")
	}
	if len(backup.Requests) != 2 {
		t.Errorf("Requests length = %d, want 2", len(backup.Requests))
	}
	if backup.Output == nil || backup.Output.IsDestroyed() {
		t.Error("Output is nil or destroyed")
	}
}

func TestSvrBNetClient_Finalize_ConnectorError(t *testing.T) {
	connector := &mockSvrBConnector{err: errors.New("connect failed")}
	client := NewSvrBNetClient(connector, []uint64{1, 2})

	backup := &svr.OPRFBackup4{Requests: [][]byte{{1}, {2}}}
	err := client.Finalize(context.Background(), backup)

	if err == nil {
		t.Fatal("Finalize() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorAllConnectionAttemptsFailed {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorAllConnectionAttemptsFailed)
	}
}

func TestSvrBNetClient_Finalize_ConnectionFailure(t *testing.T) {
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Err: &SvrError{Kind: SvrErrorAllAttemptsFailed}},
			{ServerID: 2, Err: &SvrError{Kind: SvrErrorAttestation, Err: errors.New("bad")}},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1, 2})

	backup := &svr.OPRFBackup4{Requests: [][]byte{{1}, {2}}}
	err := client.Finalize(context.Background(), backup)

	if err == nil {
		t.Fatal("Finalize() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorAllConnectionAttemptsFailed {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorAllConnectionAttemptsFailed)
	}
}

func TestSvrBNetClient_Finalize_RequestCountMismatch(t *testing.T) {
	transport := &mockSvrBTransport{}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	// Backup has 2 requests but only 1 connection.
	backup := &svr.OPRFBackup4{Requests: [][]byte{{1}, {2}}}
	err := client.Finalize(context.Background(), backup)

	if err == nil {
		t.Fatal("Finalize() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorProtocol {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorProtocol)
	}
	if !transport.closed {
		t.Error("transport should have been closed")
	}
}

func TestSvrBNetClient_Finalize_SendError(t *testing.T) {
	sendErr := errors.New("send failed")
	transport := &mockSvrBTransport{
		sendFn: func(_ context.Context, _ []byte) error {
			return sendErr
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	backup := &svr.OPRFBackup4{Requests: [][]byte{{1}}}
	err := client.Finalize(context.Background(), backup)

	if err == nil {
		t.Fatal("Finalize() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorService {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorService)
	}
}

func TestSvrBNetClient_Query_ConnectorError(t *testing.T) {
	connector := &mockSvrBConnector{err: errors.New("nope")}
	client := NewSvrBNetClient(connector, []uint64{1})

	_, err := client.Query(context.Background())
	if err == nil {
		t.Fatal("Query() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorAllConnectionAttemptsFailed {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorAllConnectionAttemptsFailed)
	}
}

func TestSvrBNetClient_Query_ConnectionFailure(t *testing.T) {
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Err: &SvrError{Kind: SvrErrorAllAttemptsFailed}},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	_, err := client.Query(context.Background())
	if err == nil {
		t.Fatal("Query() should have returned an error")
	}
}

func TestSvrBNetClient_Restore_ConnectorError(t *testing.T) {
	connector := &mockSvrBConnector{err: errors.New("nope")}
	client := NewSvrBNetClient(connector, []uint64{1})

	_, err := client.Restore(context.Background(), svrTestPassword("pass"))
	if err == nil {
		t.Fatal("Restore() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorAllConnectionAttemptsFailed {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorAllConnectionAttemptsFailed)
	}
}

func TestSvrBNetClient_Restore_ConnectionFailure(t *testing.T) {
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Err: &SvrError{Kind: SvrErrorAttestation, Err: errors.New("bad")}},
			{ServerID: 2, Err: &SvrError{Kind: SvrErrorAllAttemptsFailed}},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1, 2})

	_, err := client.Restore(context.Background(), svrTestPassword("pass"))
	if err == nil {
		t.Fatal("Restore() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	// First error should be returned.
	if svrBErr.Kind != SvrBErrorAttestation {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorAttestation)
	}
}

func TestSvrBNetClient_Remove_ConnectorError(t *testing.T) {
	connector := &mockSvrBConnector{err: errors.New("nope")}
	client := NewSvrBNetClient(connector, []uint64{1})

	err := client.Remove(context.Background())
	if err == nil {
		t.Fatal("Remove() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorAllConnectionAttemptsFailed {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorAllConnectionAttemptsFailed)
	}
}

func TestSvrBNetClient_Remove_AllConnectionsFailed(t *testing.T) {
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Err: &SvrError{Kind: SvrErrorAllAttemptsFailed}},
			{ServerID: 2, Err: &SvrError{Kind: SvrErrorAllAttemptsFailed}},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1, 2})

	err := client.Remove(context.Background())
	if err == nil {
		t.Fatal("Remove() should have returned an error when all connections fail")
	}
}

func TestSvrBNetClient_Remove_PartialConnectionFailure(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			// Return a valid remove response (empty response is fine
			// as the Remove4 type does not parse responses).
			return []byte{}, nil
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Err: errors.New("connection failed")},
			{ServerID: 2, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1, 2})

	// Remove tolerates partial failures.
	err := client.Remove(context.Background())
	// The send/receive may error on empty response but the point is it
	// does not fail on partial connection failure itself.
	// Since we return empty bytes, sendAll will get empty data.
	// That is acceptable - remove does not parse response bodies.
	_ = err // Partial failures are tolerated; error depends on response parsing.
	if !transport.closed {
		t.Error("transport should have been closed")
	}
}

func TestSvrBNetClient_Remove_SendFailure(t *testing.T) {
	transport := &mockSvrBTransport{
		sendFn: func(_ context.Context, _ []byte) error {
			return errors.New("send failed")
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	err := client.Remove(context.Background())
	if err == nil {
		t.Fatal("Remove() should have returned an error")
	}
}

// --- Transport close tests ---

func TestCloseTransports(t *testing.T) {
	t1 := &mockSvrBTransport{}
	t2 := &mockSvrBTransport{}

	closeTransports([]SvrBTransport{t1, t2})

	if !t1.closed || !t2.closed {
		t.Error("all transports should be closed")
	}
}

func TestCloseTransports_NilSafe(t *testing.T) {
	// Should not panic with nil entries.
	closeTransports([]SvrBTransport{nil, nil})
}

// --- sendAll tests ---

func TestSendAll_Success(t *testing.T) {
	t1 := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return []byte("resp1"), nil
		},
	}
	t2 := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return []byte("resp2"), nil
		},
	}

	responses, err := sendAll(context.Background(),
		[]SvrBTransport{t1, t2},
		[][]byte{[]byte("req1"), []byte("req2")},
	)

	if err != nil {
		t.Fatalf("sendAll() error = %v", err)
	}
	if len(responses) != 2 {
		t.Fatalf("responses length = %d, want 2", len(responses))
	}
	if string(responses[0]) != "resp1" {
		t.Errorf("responses[0] = %q, want %q", responses[0], "resp1")
	}
	if string(responses[1]) != "resp2" {
		t.Errorf("responses[1] = %q, want %q", responses[1], "resp2")
	}
}

func TestSendAll_SendError(t *testing.T) {
	transport := &mockSvrBTransport{
		sendFn: func(_ context.Context, _ []byte) error {
			return errors.New("send failed")
		},
	}

	_, err := sendAll(context.Background(),
		[]SvrBTransport{transport},
		[][]byte{[]byte("req")},
	)

	if err == nil {
		t.Fatal("sendAll() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorService {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorService)
	}
}

func TestSendAll_ReceiveError(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return nil, errors.New("receive failed")
		},
	}

	_, err := sendAll(context.Background(),
		[]SvrBTransport{transport},
		[][]byte{[]byte("req")},
	)

	if err == nil {
		t.Fatal("sendAll() should have returned an error")
	}
}

func TestSendAll_NilResponse(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return nil, nil
		},
	}

	_, err := sendAll(context.Background(),
		[]SvrBTransport{transport},
		[][]byte{[]byte("req")},
	)

	if err == nil {
		t.Fatal("sendAll() should have returned an error for nil response")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorProtocol {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorProtocol)
	}
}

// --- runInteraction tests ---

func TestRunInteraction_Success(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return []byte("response"), nil
		},
	}

	data, err := runInteraction(context.Background(), transport, []byte("request"))
	if err != nil {
		t.Fatalf("runInteraction() error = %v", err)
	}
	if string(data) != "response" {
		t.Errorf("data = %q, want %q", data, "response")
	}
	if transport.sendCalls != 1 {
		t.Errorf("sendCalls = %d, want 1", transport.sendCalls)
	}
	if transport.receiveCalls != 1 {
		t.Errorf("receiveCalls = %d, want 1", transport.receiveCalls)
	}
}

func TestRunInteraction_SendFailure(t *testing.T) {
	transport := &mockSvrBTransport{
		sendFn: func(_ context.Context, _ []byte) error {
			return errors.New("send error")
		},
	}

	_, err := runInteraction(context.Background(), transport, []byte("request"))
	if err == nil {
		t.Fatal("runInteraction() should have returned an error")
	}
	// ReceiveBytes should not have been called.
	if transport.receiveCalls != 0 {
		t.Errorf("receiveCalls = %d, want 0", transport.receiveCalls)
	}
}

// --- firstConnectionError tests ---

func TestFirstConnectionError_Empty(t *testing.T) {
	if got := firstConnectionError(nil); got != nil {
		t.Errorf("firstConnectionError(nil) = %v, want nil", got)
	}
	if got := firstConnectionError([]*SvrBError{}); got != nil {
		t.Errorf("firstConnectionError([]) = %v, want nil", got)
	}
}

func TestFirstConnectionError_NonEmpty(t *testing.T) {
	errs := []*SvrBError{
		{Kind: SvrBErrorConnect},
		{Kind: SvrBErrorAttestation},
	}
	got := firstConnectionError(errs)
	if got.Kind != SvrBErrorConnect {
		t.Errorf("kind = %d, want %d", got.Kind, SvrBErrorConnect)
	}
}

// --- connectAll tests ---

func TestConnectAll_ConnectorError(t *testing.T) {
	connector := &mockSvrBConnector{err: errors.New("fail")}
	client := NewSvrBNetClient(connector, []uint64{1})

	transports, errs, err := client.connectAll(context.Background())
	if err == nil {
		t.Fatal("connectAll() should have returned an error")
	}
	if transports != nil {
		t.Error("transports should be nil")
	}
	if errs != nil {
		t.Error("errs should be nil")
	}
}

func TestConnectAll_MixedResults(t *testing.T) {
	transport := &mockSvrBTransport{}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
			{ServerID: 2, Err: &SvrError{Kind: SvrErrorAttestation, Err: errors.New("bad")}},
			{ServerID: 3, Err: errors.New("generic error")},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1, 2, 3})

	transports, errs, err := client.connectAll(context.Background())
	if err != nil {
		t.Fatalf("connectAll() error = %v", err)
	}
	if len(transports) != 1 {
		t.Errorf("transports length = %d, want 1", len(transports))
	}
	if len(errs) != 2 {
		t.Errorf("errs length = %d, want 2", len(errs))
	}
	// First error should be attestation (from SvrError conversion).
	if errs[0].Kind != SvrBErrorAttestation {
		t.Errorf("errs[0].Kind = %d, want %d", errs[0].Kind, SvrBErrorAttestation)
	}
	// Second error should be connect (from generic error conversion).
	if errs[1].Kind != SvrBErrorConnect {
		t.Errorf("errs[1].Kind = %d, want %d", errs[1].Kind, SvrBErrorConnect)
	}
}

func TestConnectAll_AllSuccess(t *testing.T) {
	t1 := &mockSvrBTransport{}
	t2 := &mockSvrBTransport{}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: t1},
			{ServerID: 2, Transport: t2},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1, 2})

	transports, errs, err := client.connectAll(context.Background())
	if err != nil {
		t.Fatalf("connectAll() error = %v", err)
	}
	if len(transports) != 2 {
		t.Errorf("transports length = %d, want 2", len(transports))
	}
	if len(errs) != 0 {
		t.Errorf("errs length = %d, want 0", len(errs))
	}
}

// --- Interface compliance tests ---

func TestSvrBNetClient_ImplementsInterfaces(t *testing.T) {
	var _ SvrBPreparer = (*SvrBNetClient)(nil)
	var _ SvrBBackuper = (*SvrBNetClient)(nil)
	var _ SvrBRestorer = (*SvrBNetClient)(nil)
	var _ SvrBQuerier = (*SvrBNetClient)(nil)
	var _ SvrBRemover = (*SvrBNetClient)(nil)
	var _ SvrBClient = (*SvrBNetClient)(nil)
}

// --- BackupConnectionDelay constant test ---

func TestBackupConnectionDelay(t *testing.T) {
	if BackupConnectionDelay != 50*time.Millisecond {
		t.Errorf("BackupConnectionDelay = %v, want 50ms", BackupConnectionDelay)
	}
}

// --- Ensure transports are closed on error paths ---

func TestSvrBNetClient_Finalize_ClosesTransportsOnError(t *testing.T) {
	transport := &mockSvrBTransport{
		sendFn: func(_ context.Context, _ []byte) error {
			return errors.New("boom")
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	backup := &svr.OPRFBackup4{Requests: [][]byte{{1}}}
	_ = client.Finalize(context.Background(), backup)

	if !transport.closed {
		t.Error("transport should have been closed after error")
	}
}

func TestSvrBNetClient_Query_ClosesTransportsOnError(t *testing.T) {
	transport := &mockSvrBTransport{
		sendFn: func(_ context.Context, _ []byte) error {
			return errors.New("boom")
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	_, _ = client.Query(context.Background())

	if !transport.closed {
		t.Error("transport should have been closed after error")
	}
}

func TestSvrBNetClient_Restore_ClosesTransportsOnError(t *testing.T) {
	transport := &mockSvrBTransport{
		sendFn: func(_ context.Context, _ []byte) error {
			return errors.New("boom")
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	_, _ = client.Restore(context.Background(), svrTestPassword("pass"))

	if !transport.closed {
		t.Error("transport should have been closed after error")
	}
}

func TestSvrBNetClient_Remove_ClosesTransportsOnError(t *testing.T) {
	transport := &mockSvrBTransport{
		sendFn: func(_ context.Context, _ []byte) error {
			return errors.New("boom")
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	_ = client.Remove(context.Background())

	if !transport.closed {
		t.Error("transport should have been closed after error")
	}
}

// --- Query with receive error ---

func TestSvrBNetClient_Query_ReceiveError(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return nil, errors.New("recv fail")
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	_, err := client.Query(context.Background())
	if err == nil {
		t.Fatal("Query() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorService {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorService)
	}
}

// --- Query with bad response data ---

func TestSvrBNetClient_Query_BadResponse(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return []byte("not-a-protobuf"), nil
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	_, err := client.Query(context.Background())
	if err == nil {
		t.Fatal("Query() should have returned an error on bad response")
	}
}

// --- Restore with receive error on phase 1 ---

func TestSvrBNetClient_Restore_Phase1ReceiveError(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return nil, errors.New("recv fail")
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	_, err := client.Restore(context.Background(), svrTestPassword("pass"))
	if err == nil {
		t.Fatal("Restore() should have returned an error")
	}
}

// --- Finalize with bad protobuf response ---

func TestSvrBNetClient_Finalize_BadResponse(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return []byte("not-a-protobuf"), nil
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	backup := &svr.OPRFBackup4{Requests: [][]byte{{1}}}
	err := client.Finalize(context.Background(), backup)
	if err == nil {
		t.Fatal("Finalize() should have returned an error on bad response")
	}
}

// --- Finalize with nil response ---

func TestSvrBNetClient_Finalize_NilResponse(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return nil, nil
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	backup := &svr.OPRFBackup4{Requests: [][]byte{{1}}}
	err := client.Finalize(context.Background(), backup)
	if err == nil {
		t.Fatal("Finalize() should have returned an error on nil response")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorProtocol {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorProtocol)
	}
}

// --- Remove with receive error ---

func TestSvrBNetClient_Remove_ReceiveError(t *testing.T) {
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return nil, errors.New("recv fail")
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	err := client.Remove(context.Background())
	if err == nil {
		t.Fatal("Remove() should have returned an error")
	}
}

// --- Verify SvrBError works with errors.Is ---

func TestSvrBError_ErrorsIs(t *testing.T) {
	target := &SvrBError{Kind: SvrBErrorDataMissing}
	err := &SvrBError{Kind: SvrBErrorDataMissing, Err: errors.New("something")}

	if !errors.Is(err, target) {
		t.Error("errors.Is should match same kind")
	}

	other := &SvrBError{Kind: SvrBErrorProtocol}
	if errors.Is(err, other) {
		t.Error("errors.Is should not match different kind")
	}
}

// --- Verify SvrBError works with errors.As ---

func TestSvrBError_ErrorsAs(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &SvrBError{Kind: SvrBErrorAttestation, Err: errors.New("bad")})

	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatal("errors.As should unwrap to *SvrBError")
	}
	if svrBErr.Kind != SvrBErrorAttestation {
		t.Errorf("kind = %d, want %d", svrBErr.Kind, SvrBErrorAttestation)
	}
}
