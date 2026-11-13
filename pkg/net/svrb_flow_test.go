package net

import (
	"context"
	"crypto/sha512"
	"errors"
	"sort"
	"sync"
	"testing"

	"github.com/gtank/ristretto255"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr"
	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// svrTestPassword builds an SVR password fixture of the length production
// uses. Signal always passes BackupKey.DeriveForwardSecrecyPassword output,
// which is 32 bytes (docs/backup/account-keys.md), and HKDF under the FIPS
// 140-3 gate rejects keys shorter than 112 bits (docs/FIPS.md).
func svrTestPassword(label string) []byte {
	pw := make([]byte, 32)
	copy(pw, label)
	return pw
}

// svrTestServerVersion holds a single version's data for a test server.
type svrTestServerVersion struct {
	authCommitment        *ristretto255.Element
	oprfSecretshare       *ristretto255.Scalar
	encryptionSecretshare [32]byte
	zeroSecretshare       *ristretto255.Scalar
}

// svrTestServer simulates a single SVR4 server for net-level testing.
type svrTestServer struct {
	mu              sync.Mutex
	tries           uint32
	versions        map[uint32]*svrTestServerVersion
	restore1Blinded []byte
}

func newSvrTestServer() *svrTestServer {
	return &svrTestServer{versions: make(map[uint32]*svrTestServerVersion)}
}

func (s *svrTestServer) hashedUserID() [64]byte {
	var h [64]byte
	for i := range h {
		h[i] = 1
	}
	return h
}

func (s *svrTestServer) handleCreate(reqBytes []byte) []byte {
	req := &svrpb.Request4{}
	if err := proto.Unmarshal(reqBytes, req); err != nil {
		panic("decode Request4: " + err.Error())
	}
	inner, ok := req.Inner.(*svrpb.Request4_Create_)
	if !ok {
		panic("not Create")
	}
	cr := inner.Create

	s.mu.Lock()
	defer s.mu.Unlock()

	s.versions = make(map[uint32]*svrTestServerVersion)

	oprfShare := decodeScalarHelper(cr.OprfSecretshare)
	zeroShare := decodeScalarHelper(cr.ZeroSecretshare)
	authCommit := decodeElementHelper(cr.AuthCommitment)
	var encShare [32]byte
	copy(encShare[:], cr.EncryptionSecretshare)

	s.versions[cr.Version] = &svrTestServerVersion{
		authCommitment:        authCommit,
		oprfSecretshare:       oprfShare,
		encryptionSecretshare: encShare,
		zeroSecretshare:       zeroShare,
	}
	s.tries = cr.MaxTries

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Create_{
			Create: &svrpb.Response4_Create{
				Status:         svrpb.Response4_OK,
				TriesRemaining: s.tries,
			},
		},
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		panic("marshal Response4: " + err.Error())
	}
	return b
}

func (s *svrTestServer) handleRestore1(reqBytes []byte) []byte {
	req := &svrpb.Request4{}
	if err := proto.Unmarshal(reqBytes, req); err != nil {
		panic("decode Request4: " + err.Error())
	}
	inner, ok := req.Inner.(*svrpb.Request4_Restore1_)
	if !ok {
		panic("not Restore1")
	}
	r1 := inner.Restore1

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tries--
	s.restore1Blinded = r1.Blinded

	uid := s.hashedUserID()
	userHashPt, err := ristretto255.NewIdentityElement().SetUniformBytes(uid[:])
	if err != nil {
		panic("set uniform bytes for userHashPt: " + err.Error())
	}
	blinded := decodeElementHelper(r1.Blinded)

	versionKeys := make([]uint32, 0, len(s.versions))
	for v := range s.versions {
		versionKeys = append(versionKeys, v)
	}
	sort.Slice(versionKeys, func(i, j int) bool { return versionKeys[i] < versionKeys[j] })

	auths := make([]*svrpb.Response4_Restore1_Auth, 0, len(s.versions))
	for _, version := range versionKeys {
		state := s.versions[version]
		part1 := ristretto255.NewIdentityElement().ScalarMult(state.oprfSecretshare, blinded)
		part2 := ristretto255.NewIdentityElement().ScalarMult(state.zeroSecretshare, userHashPt)
		element := ristretto255.NewIdentityElement().Add(part1, part2)

		auths = append(auths, &svrpb.Response4_Restore1_Auth{
			Version: version,
			Element: element.Bytes(),
		})
	}

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_OK,
				TriesRemaining: s.tries,
				Auth:           auths,
			},
		},
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		panic("marshal Response4: " + err.Error())
	}
	return b
}

func (s *svrTestServer) handleRestore2(reqBytes []byte, handshakeHash []byte) []byte {
	req := &svrpb.Request4{}
	if err := proto.Unmarshal(reqBytes, req); err != nil {
		panic("decode Request4: " + err.Error())
	}
	inner, ok := req.Inner.(*svrpb.Request4_Restore2_)
	if !ok {
		panic("not Restore2")
	}
	r2 := inner.Restore2

	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.versions[r2.Version]
	if !ok {
		panic("version not set")
	}

	authScalar := decodeScalarHelper(r2.AuthScalar)
	authPoint := decodeElementHelper(r2.AuthPoint)

	h := sha512.New()
	h.Write(r2.AuthPoint)
	h.Write(s.restore1Blinded)
	h.Write(handshakeHash)
	challengeBytes := h.Sum(nil)
	challenge, err := new(ristretto255.Scalar).SetUniformBytes(challengeBytes)
	if err != nil {
		panic("set uniform bytes for challenge: " + err.Error())
	}

	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(authScalar)
	rhs := ristretto255.NewIdentityElement().ScalarMult(challenge, state.authCommitment)
	rhs.Add(rhs, authPoint)

	if lhs.Equal(rhs) != 1 {
		panic("Schnorr proof verification failed")
	}

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore2_{
			Restore2: &svrpb.Response4_Restore2{
				Status:                svrpb.Response4_OK,
				EncryptionSecretshare: state.encryptionSecretshare[:],
			},
		},
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		panic("marshal Response4: " + err.Error())
	}
	return b
}

func (s *svrTestServer) handleQuery() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Query_{
			Query: &svrpb.Response4_Query{
				Status:         svrpb.Response4_OK,
				TriesRemaining: s.tries,
			},
		},
	}
	b, _ := proto.Marshal(resp)
	return b
}

func (s *svrTestServer) handleRemove() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.versions = make(map[uint32]*svrTestServerVersion)
	s.tries = 0

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Remove_{
			Remove: &svrpb.Response4_Remove{},
		},
	}
	b, _ := proto.Marshal(resp)
	return b
}

func decodeScalarHelper(data []byte) *ristretto255.Scalar {
	s, err := new(ristretto255.Scalar).SetCanonicalBytes(data)
	if err != nil {
		panic("decode scalar: " + err.Error())
	}
	return s
}

func decodeElementHelper(data []byte) *ristretto255.Element {
	e, err := ristretto255.NewIdentityElement().SetCanonicalBytes(data)
	if err != nil {
		panic("decode element: " + err.Error())
	}
	return e
}

// svrTestTransport wraps a test server to provide an SvrBTransport that handles
// the SVR4 protocol by dispatching to the test server's request handlers.
type svrTestTransport struct {
	server        *svrTestServer
	handshakeHash []byte
	phase         int
	closed        bool
	lastRequest   []byte
}

func (t *svrTestTransport) SendBytes(_ context.Context, data []byte) error {
	t.lastRequest = data
	return nil
}

func (t *svrTestTransport) ReceiveBytes(_ context.Context) ([]byte, error) {
	req := &svrpb.Request4{}
	if err := proto.Unmarshal(t.lastRequest, req); err != nil {
		return nil, err
	}

	switch req.Inner.(type) {
	case *svrpb.Request4_Create_:
		return t.server.handleCreate(t.lastRequest), nil
	case *svrpb.Request4_Restore1_:
		t.phase = 1
		return t.server.handleRestore1(t.lastRequest), nil
	case *svrpb.Request4_Restore2_:
		t.phase = 2
		return t.server.handleRestore2(t.lastRequest, t.handshakeHash), nil
	case *svrpb.Request4_Query_:
		return t.server.handleQuery(), nil
	case *svrpb.Request4_Remove_:
		return t.server.handleRemove(), nil
	default:
		return nil, errors.New("unknown request type")
	}
}

func (t *svrTestTransport) HandshakeHash() []byte {
	return t.handshakeHash
}

func (t *svrTestTransport) Close() error {
	t.closed = true
	return nil
}

// --- Full Restore flow test ---

func TestSvrBNetClient_Restore_FullSuccessFlow(t *testing.T) {
	serverIDs := []uint64{1}
	password := svrTestPassword("my-password")

	server := newSvrTestServer()
	handshakeHash := makeTestBytes(32, 0xAA)

	// First, create a backup on the server.
	backup, err := svr.NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}
	server.handleCreate(backup.Requests[0])

	// Set up a connector that returns a transport wired to the test server.
	transport := &svrTestTransport{
		server:        server,
		handshakeHash: handshakeHash,
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, serverIDs)

	// Perform restore.
	got, err := client.Restore(context.Background(), password)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	if !secrettest.Same(t, got, backup.Output) {
		t.Fatalf("restored secret does not match backup output")
	}

	if !transport.closed {
		t.Error("transport should have been closed after Restore")
	}
}

func TestSvrBNetClient_Restore_MultiServerSuccess(t *testing.T) {
	serverIDs := []uint64{1, 2, 3}
	password := svrTestPassword("multi-server-password")

	servers := make([]*svrTestServer, len(serverIDs))
	transports := make([]SvrBTransport, len(serverIDs))
	results := make([]SvrBConnectionResult, len(serverIDs))

	backup, err := svr.NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}

	for i := range serverIDs {
		servers[i] = newSvrTestServer()
		servers[i].handleCreate(backup.Requests[i])

		transport := &svrTestTransport{
			server:        servers[i],
			handshakeHash: makeTestBytes(32, byte(i+1)),
		}
		transports[i] = transport
		results[i] = SvrBConnectionResult{
			ServerID:  serverIDs[i],
			Transport: transport,
		}
	}

	connector := &mockSvrBConnector{results: results}
	client := NewSvrBNetClient(connector, serverIDs)

	got, err := client.Restore(context.Background(), password)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	if !secrettest.Same(t, got, backup.Output) {
		t.Fatalf("restored secret does not match backup output")
	}
}

// --- Full Finalize flow test ---

func TestSvrBNetClient_Finalize_FullSuccessFlow(t *testing.T) {
	serverIDs := []uint64{1}
	password := svrTestPassword("finalize-password")

	server := newSvrTestServer()

	backup, err := svr.NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}

	transport := &svrTestTransport{
		server:        server,
		handshakeHash: makeTestBytes(32, 0xBB),
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, serverIDs)

	err = client.Finalize(context.Background(), backup)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	if !transport.closed {
		t.Error("transport should have been closed")
	}
}

// --- Full Query flow test ---

func TestSvrBNetClient_Query_FullSuccessFlow(t *testing.T) {
	serverIDs := []uint64{1}
	password := svrTestPassword("query-password")

	server := newSvrTestServer()

	// Create a backup first so the server has state.
	backup, err := svr.NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}
	server.handleCreate(backup.Requests[0])

	transport := &svrTestTransport{
		server:        server,
		handshakeHash: makeTestBytes(32, 0xCC),
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, serverIDs)

	tries, err := client.Query(context.Background())
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if tries != 10 {
		t.Errorf("Query() tries = %d, want 10", tries)
	}
}

// --- Full Remove flow test ---

func TestSvrBNetClient_Remove_FullSuccessFlow(t *testing.T) {
	serverIDs := []uint64{1}
	password := svrTestPassword("remove-password")

	server := newSvrTestServer()

	backup, err := svr.NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}
	server.handleCreate(backup.Requests[0])

	transport := &svrTestTransport{
		server:        server,
		handshakeHash: makeTestBytes(32, 0xDD),
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, serverIDs)

	err = client.Remove(context.Background())
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
}

// --- SvrSgxHandshaker nil raft config ---

func TestSvrSgxHandshaker_NilRaftConfig_SvrbFlow(t *testing.T) {
	h := &SvrSgxHandshaker{}
	params := &EndpointParams{
		MrEnclave:  MrEnclave{Value: make([]byte, 32)},
		RaftConfig: nil,
	}
	_, err := h.NewHandshake(params, []byte("msg"))
	if err == nil {
		t.Fatal("expected error for nil raft config")
	}
}

// --- basicAuth: short Authorization header ---

func TestBasicAuth_ValidCredentials(t *testing.T) {
	result := basicAuth("user", "pass")
	if result == "" {
		t.Fatal("basicAuth should return non-empty for valid credentials")
	}
}

// --- Restore: phase 2 restore.Restore error ---

func TestSvrBNetClient_Restore_Phase2RestoreError(t *testing.T) {
	// Set up a transport that returns valid phase1 and valid phase2 responses,
	// but phase2 returns wrong encryption share size to trigger Restore error.
	serverIDs := []uint64{1}
	password := svrTestPassword("test-password")

	backup, err := svr.NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}

	server := newSvrTestServer()
	server.handleCreate(backup.Requests[0])

	callCount := 0
	transport := &mockSvrBTransport{
		handshakeHash: makeTestBytes(32, 0xEE),
		sendFn:        func(_ context.Context, _ []byte) error { return nil },
		receiveFn: func(_ context.Context) ([]byte, error) {
			callCount++
			if callCount == 1 {
				// Phase 1: return valid restore1 response from server
				r1, _ := svr.NewRestore1(serverIDs, password)
				return server.handleRestore1(r1.Requests[0]), nil
			}
			// Phase 2: return a response with wrong encryption share size
			resp := &svrpb.Response4{
				Inner: &svrpb.Response4_Restore2_{
					Restore2: &svrpb.Response4_Restore2{
						Status:                svrpb.Response4_OK,
						EncryptionSecretshare: []byte{1, 2, 3}, // wrong size
					},
				},
			}
			b, _ := proto.Marshal(resp)
			return b, nil
		},
	}
	connector := &mockSvrBConnector{
		results: []SvrBConnectionResult{
			{ServerID: 1, Transport: transport},
		},
	}
	client := NewSvrBNetClient(connector, serverIDs)

	_, err = client.Restore(context.Background(), password)
	if err == nil {
		t.Fatal("Restore() should have returned an error for wrong encryption share size")
	}
	var svrBErr *SvrBError
	if !errors.As(err, &svrBErr) {
		t.Fatalf("expected *SvrBError, got %T", err)
	}
	if svrBErr.Kind != SvrBErrorProtocol {
		t.Errorf("kind = %d, want %d (SvrBErrorProtocol)", svrBErr.Kind, SvrBErrorProtocol)
	}
}

func makeTestBytes(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}
