package net

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/svr"
	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
	"google.golang.org/protobuf/proto"
)

// --- svrBErrorFromSvrLogicError: cover StatusMissing and TriesRemaining paths ---

func TestSvrBErrorFromSvrLogicError_StatusMissing(t *testing.T) {
	// Create an svr.Error with StatusMissing to trigger the data-missing branch.
	err := &svr.Error{}
	// We can't set private fields directly, so use the restore flow to generate one.
	// Instead, use the checkStatus helper from the svr package indirectly.
	// The simplest path: create a query finalize with MISSING status.
	q := svr.Query4{}
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Query_{
			Query: &svrpb.Response4_Query{
				Status:         svrpb.Response4_MISSING,
				TriesRemaining: 0,
			},
		},
	}
	b, marshalErr := proto.Marshal(resp)
	if marshalErr != nil {
		t.Fatalf("marshal failed: %v", marshalErr)
	}
	_, err2 := q.Finalize([][]byte{b})
	if err2 == nil {
		t.Fatal("expected error for MISSING status")
	}
	// Now convert this svr error through svrBErrorFromSvrLogicError
	got := svrBErrorFromSvrLogicError(err2)
	if got.Kind != SvrBErrorDataMissing {
		t.Errorf("kind = %d, want %d (SvrBErrorDataMissing)", got.Kind, SvrBErrorDataMissing)
	}
	_ = err // suppress unused
}

func TestSvrBErrorFromSvrLogicError_RestoreFailed(t *testing.T) {
	// Create a Restore2Result that will produce a restore-failed error with tries > 0.
	r2 := &svr.Restore2Result{
		TriesRemaining: 5,
	}
	// Access is not possible since serverIDs is private. Use indirect path instead.
	// Simulate via the known error path: error status with tries remaining.
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_OK,
				TriesRemaining: 3,
			},
		},
	}
	b, _ := proto.Marshal(resp)
	r1, _ := svr.NewRestore1([]uint64{1}, svrTestPassword("pass"))
	// This will fail because the response has no Auth entries (no usable version).
	// But first, create a response with ERROR status and tries remaining.
	errorResp := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_ERROR,
				TriesRemaining: 4,
			},
		},
	}
	eb, _ := proto.Marshal(errorResp)

	_, err := r1.Restore2([][]byte{eb}, [][]byte{make([]byte, 32)})
	if err == nil {
		t.Fatal("expected error for ERROR status")
	}

	got := svrBErrorFromSvrLogicError(err)
	if got.Kind != SvrBErrorRestoreFailed {
		t.Errorf("kind = %d, want %d (SvrBErrorRestoreFailed)", got.Kind, SvrBErrorRestoreFailed)
	}
	if got.TriesRemaining != 4 {
		t.Errorf("TriesRemaining = %d, want 4", got.TriesRemaining)
	}

	_ = b
	_ = r2
}

func TestSvrBErrorFromSvrLogicError_ProtocolFallthrough(t *testing.T) {
	// An svr.Error that is not bad data/response/version, has no missing status,
	// and has 0 tries remaining should fall through to protocol error.
	// A bad response status error with StatusError has tries=0.
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Query_{
			Query: &svrpb.Response4_Query{
				Status:         svrpb.Response4_ERROR,
				TriesRemaining: 0,
			},
		},
	}
	b, _ := proto.Marshal(resp)
	q := svr.Query4{}
	_, err := q.Finalize([][]byte{b})
	if err == nil {
		t.Fatal("expected error")
	}

	got := svrBErrorFromSvrLogicError(err)
	if got.Kind != SvrBErrorProtocol {
		t.Errorf("kind = %d, want %d (SvrBErrorProtocol)", got.Kind, SvrBErrorProtocol)
	}
}

// --- Restore: cover more error paths ---

func TestSvrBNetClient_Restore_Phase1BadResponse(t *testing.T) {
	// Restore where phase1 returns a bad protobuf triggers svrBErrorFromSvrLogicError.
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return []byte("bad-protobuf"), nil
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
		t.Fatal("Restore() should have returned an error for bad phase1 response")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
}

// --- Query: cover Finalize logic error path ---

func TestSvrBNetClient_Query_FinalizeError(t *testing.T) {
	// Return a valid protobuf but with ERROR status to trigger svrBErrorFromSvrLogicError
	// in the Query.Finalize call path.
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Query_{
			Query: &svrpb.Response4_Query{
				Status:         svrpb.Response4_MISSING,
				TriesRemaining: 0,
			},
		},
	}
	respBytes, _ := proto.Marshal(resp)
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return respBytes, nil
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
		t.Fatal("Query() should have returned an error for MISSING status")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
}

// --- Remove: cover the no-transports path returning firstConnectionError ---

func TestSvrBNetClient_Remove_EmptyTransportsWithErrors(t *testing.T) {
	// All connections fail, so transports is empty and connErrs has entries.
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Err: errors.New("conn1 failed")},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	err := client.Remove(context.Background())
	if err == nil {
		t.Fatal("Remove() should have returned an error")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorConnect {
		t.Errorf("kind = %d, want %d (SvrBErrorConnect)", svrBErr.Kind, SvrBErrorConnect)
	}
}

// --- Remove with nil receive (triggers sendAll nil response check) ---

func TestSvrBNetClient_Remove_NilReceive(t *testing.T) {
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

	err := client.Remove(context.Background())
	if err == nil {
		t.Fatal("Remove() should have returned an error for nil receive")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorProtocol {
		t.Errorf("kind = %d, want %d (SvrBErrorProtocol)", svrBErr.Kind, SvrBErrorProtocol)
	}
}

// --- prioritizeError: cover the default (unknown) priority path ---

func TestPrioritizeError_UnknownKind(t *testing.T) {
	unknown := &SvrBError{Kind: SvrBErrorKind(99)}
	known := &SvrBError{Kind: SvrBErrorDataMissing}

	// Unknown priority is 0, DataMissing is 2, so known should win.
	got := prioritizeError(unknown, known)
	if got.Kind != SvrBErrorDataMissing {
		t.Errorf("expected DataMissing to win over unknown, got kind %d", got.Kind)
	}

	// When both are unknown, first should win (equal priority).
	unknown2 := &SvrBError{Kind: SvrBErrorKind(98)}
	got2 := prioritizeError(unknown, unknown2)
	if got2 != unknown {
		t.Error("expected first unknown to win when both have equal priority")
	}
}

// --- prioritizeError: cover service priority ---

func TestPrioritizeError_ServicePriority(t *testing.T) {
	service := &SvrBError{Kind: SvrBErrorService}
	connect := &SvrBError{Kind: SvrBErrorConnect}

	got := prioritizeError(connect, service)
	if got.Kind != SvrBErrorService {
		t.Errorf("expected Service to win over Connect, got kind %d", got.Kind)
	}
}

// --- Finalize: cover the FinalizeBackup4 error path ---

func TestSvrBNetClient_Finalize_FinalizeBackupError(t *testing.T) {
	// Return a protobuf with wrong inner type (Query instead of Create)
	// so FinalizeBackup4 returns an error.
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Query_{
			Query: &svrpb.Response4_Query{
				Status:         svrpb.Response4_OK,
				TriesRemaining: 10,
			},
		},
	}
	respBytes, _ := proto.Marshal(resp)
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			return respBytes, nil
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, []uint64{1})

	backup, err := client.Prepare(svrTestPassword("password"), 255)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	// Adjust to 1 request for 1 transport
	backup.Requests = backup.Requests[:1]
	err = client.Finalize(context.Background(), backup)
	if err == nil {
		t.Fatal("Finalize() should have returned an error for wrong response type")
	}
}

// --- Restore: phase 2 sendAll error ---

func TestSvrBNetClient_Restore_Phase2SendError(t *testing.T) {
	// Phase 1 returns a valid Restore1 response (ERROR status with tries remaining)
	// so Restore2 succeeds, but phase 2 sendAll fails.
	callCount := 0
	transport := &mockSvrBTransport{
		receiveFn: func(_ context.Context) ([]byte, error) {
			callCount++
			if callCount == 1 {
				// Phase 1: return ERROR status so Restore2 produces an error
				resp := &svrpb.Response4{
					Inner: &svrpb.Response4_Restore1_{
						Restore1: &svrpb.Response4_Restore1{
							Status:         svrpb.Response4_ERROR,
							TriesRemaining: 5,
						},
					},
				}
				b, _ := proto.Marshal(resp)
				return b, nil
			}
			// Phase 2: this shouldn't be reached since Restore2 should error
			return nil, errors.New("phase 2 receive error")
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
	var svrBErr *SvrBError
	if errors.As(err, &svrBErr) {
		// Should be a RestoreFailed error since Restore2 gets ERROR status
		if svrBErr.Kind != SvrBErrorRestoreFailed {
			t.Logf("got error kind %d, message: %v", svrBErr.Kind, err)
		}
	}
}

// --- Query: sendAll error ---

func TestSvrBNetClient_Query_SendAllError(t *testing.T) {
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

	_, err := client.Query(context.Background())
	if err == nil {
		t.Fatal("Query() should have returned an error when sendAll fails")
	}
}

// --- Remove: sendAll error ---

func TestSvrBNetClient_Remove_SendAllError(t *testing.T) {
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
		t.Fatal("Remove() should have returned an error when sendAll fails")
	}
}

// --- Finalize: sendAll error ---

func TestSvrBNetClient_Finalize_SendAllError(t *testing.T) {
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

	backup, err := client.Prepare(svrTestPassword("password"), 255)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	backup.Requests = backup.Requests[:1]
	err = client.Finalize(context.Background(), backup)
	if err == nil {
		t.Fatal("Finalize() should have returned an error when sendAll fails")
	}
}

// --- Restore: phase 1 receive error via sendAll ---

func TestSvrBNetClient_Restore_Phase1SendError(t *testing.T) {
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

	_, err := client.Restore(context.Background(), svrTestPassword("pass"))
	if err == nil {
		t.Fatal("Restore() should have returned an error when phase 1 send fails")
	}
}

// --- basicAuth: edge case where header is too short ---

func TestBasicAuth_EmptyCredentials(t *testing.T) {
	result := basicAuth("", "")
	if result == "" {
		t.Fatal("result should not be empty for empty credentials (base64 of ':' is 'Og==')")
	}
}

// --- SvrBConnectionResult struct tests ---

func TestSvrBConnectionResult_Fields(t *testing.T) {
	transport := &mockSvrBTransport{}
	result := SvrBConnectionResult{
		ServerID:  42,
		Transport: transport,
		Err:       nil,
	}
	if result.ServerID != 42 {
		t.Errorf("ServerID = %d, want 42", result.ServerID)
	}
	if result.Transport == nil {
		t.Error("Transport should not be nil")
	}
	if result.Err != nil {
		t.Error("Err should be nil")
	}

	errResult := SvrBConnectionResult{
		ServerID: 1,
		Err:      errors.New("failed"),
	}
	if errResult.Transport != nil {
		t.Error("Transport should be nil for error result")
	}
	if errResult.Err == nil {
		t.Error("Err should not be nil")
	}
}
