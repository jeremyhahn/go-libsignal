package svr

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"sort"
	"testing"

	"github.com/gtank/ristretto255"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

// testServerVersion holds a single version's data for a test server.
type testServerVersion struct {
	authCommitment        *ristretto255.Element
	oprfSecretshare       *ristretto255.Scalar
	encryptionSecretshare [32]byte
	zeroSecretshare       *ristretto255.Scalar
}

// testServer simulates a single SVR4 server for testing.
type testServer struct {
	tries           uint32
	versions        map[uint32]*testServerVersion
	restore1Blinded []byte
}

func newTestServer() *testServer {
	return &testServer{
		versions: make(map[uint32]*testServerVersion),
	}
}

// hashedUserID returns a constant 64-byte "hash" for the single test user.
func (s *testServer) hashedUserID() [64]byte {
	var h [64]byte
	for i := range h {
		h[i] = 1
	}
	return h
}

func (s *testServer) create(reqBytes []byte) {
	req := &svrpb.Request4{}
	if err := proto.Unmarshal(reqBytes, req); err != nil {
		panic("decode Request4: " + err.Error())
	}
	inner, ok := req.Inner.(*svrpb.Request4_Create_)
	if !ok {
		panic("not Create")
	}
	cr := inner.Create

	s.versions = make(map[uint32]*testServerVersion)

	oprfShare, err := decodeScalar(cr.OprfSecretshare)
	if err != nil {
		panic("decode oprf_secretshare: " + err.Error())
	}
	zeroShare, err := decodeScalar(cr.ZeroSecretshare)
	if err != nil {
		panic("decode zero_secretshare: " + err.Error())
	}
	authCommit, err := decodeElement(cr.AuthCommitment)
	if err != nil {
		panic("decode auth_commitment: " + err.Error())
	}
	var encShare [32]byte
	copy(encShare[:], cr.EncryptionSecretshare)

	s.versions[cr.Version] = &testServerVersion{
		authCommitment:        authCommit,
		oprfSecretshare:       oprfShare,
		encryptionSecretshare: encShare,
		zeroSecretshare:       zeroShare,
	}
	s.tries = cr.MaxTries
}

func (s *testServer) restore1(reqBytes []byte) []byte {
	req := &svrpb.Request4{}
	if err := proto.Unmarshal(reqBytes, req); err != nil {
		panic("decode Request4: " + err.Error())
	}
	inner, ok := req.Inner.(*svrpb.Request4_Restore1_)
	if !ok {
		panic("not Restore1")
	}
	r1 := inner.Restore1

	if s.tries == 0 {
		panic("no tries remaining")
	}
	s.tries--
	s.restore1Blinded = r1.Blinded

	uid := s.hashedUserID()
	userHashPt, err := ristretto255.NewIdentityElement().SetUniformBytes(uid[:])
	if err != nil {
		panic("set uniform bytes for userHashPt: " + err.Error())
	}
	blinded, err := decodeElement(r1.Blinded)
	if err != nil {
		panic("decode blinded: " + err.Error())
	}

	versionKeys := make([]uint32, 0, len(s.versions))
	for v := range s.versions {
		versionKeys = append(versionKeys, v)
	}
	sort.Slice(versionKeys, func(i, j int) bool { return versionKeys[i] < versionKeys[j] })

	auths := make([]*svrpb.Response4_Restore1_Auth, 0, len(s.versions))
	for _, version := range versionKeys {
		state := s.versions[version]
		// element = blinded * oprf_secretshare + userHashPt * zero_secretshare
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

func (s *testServer) restore2(reqBytes []byte, handshakeHash []byte) []byte {
	req := &svrpb.Request4{}
	if err := proto.Unmarshal(reqBytes, req); err != nil {
		panic("decode Request4: " + err.Error())
	}
	inner, ok := req.Inner.(*svrpb.Request4_Restore2_)
	if !ok {
		panic("not Restore2")
	}
	r2 := inner.Restore2

	state, ok := s.versions[r2.Version]
	if !ok {
		panic("version not set")
	}

	authScalar, err := decodeScalar(r2.AuthScalar)
	if err != nil {
		panic("decode auth_scalar: " + err.Error())
	}
	authPoint, err := decodeElement(r2.AuthPoint)
	if err != nil {
		panic("decode auth_point: " + err.Error())
	}

	// Verify Schnorr proof: g^authScalar == authCommitment^challenge + authPoint
	// challenge = Scalar::from_uniform_bytes(SHA-512(authPoint || blinded || handshakeHash))
	h := sha512.New()
	h.Write(r2.AuthPoint)
	h.Write(s.restore1Blinded)
	h.Write(handshakeHash)
	challengeBytes := h.Sum(nil)
	challenge, err := new(ristretto255.Scalar).SetUniformBytes(challengeBytes)
	if err != nil {
		panic("set uniform bytes for challenge: " + err.Error())
	}

	// lhs = g * authScalar
	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(authScalar)

	// rhs = authCommitment * challenge + authPoint
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

func TestFullCreateRestore(t *testing.T) {
	serverIDs := []uint64{1, 2, 3}
	password := make([]byte, 67)
	for i := range password {
		password[i] = 2
	}

	backup, err := NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}

	servers := make([]*testServer, len(serverIDs))
	for i := range servers {
		servers[i] = newTestServer()
	}
	for i, req := range backup.Requests {
		servers[i].create(req)
	}

	handshakeHashes := [][]byte{
		makeBytes(32, 1),
		makeBytes(32, 2),
		makeBytes(32, 3),
	}

	restore1, err := NewRestore1(serverIDs, password)
	if err != nil {
		t.Fatalf("NewRestore1 failed: %v", err)
	}

	restore1Responses := make([][]byte, len(serverIDs))
	for i, req := range restore1.Requests {
		restore1Responses[i] = servers[i].restore1(req)
	}

	restore2, err := restore1.Restore2(restore1Responses, handshakeHashes)
	if err != nil {
		t.Fatalf("Restore2 failed: %v", err)
	}

	restore2Responses := make([][]byte, len(serverIDs))
	for i, req := range restore2.Requests {
		restore2Responses[i] = servers[i].restore2(req, handshakeHashes[i])
	}

	got, err := restore2.Restore(restore2Responses)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	if !bytes.Equal(got.Bytes(), backup.Output.Bytes()) {
		t.Fatal("restored secret does not match backup output")
	}
}

func TestFullCreateRestoreSingleServer(t *testing.T) {
	serverIDs := []uint64{42}
	password := []byte("my-password")

	backup, err := NewOPRFBackup4(serverIDs, password, 5)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}

	server := newTestServer()
	server.create(backup.Requests[0])

	handshakeHashes := [][]byte{makeBytes(32, 0xAA)}

	restore1, err := NewRestore1(serverIDs, password)
	if err != nil {
		t.Fatalf("NewRestore1 failed: %v", err)
	}
	r1Resp := [][]byte{server.restore1(restore1.Requests[0])}

	restore2, err := restore1.Restore2(r1Resp, handshakeHashes)
	if err != nil {
		t.Fatalf("Restore2 failed: %v", err)
	}
	r2Resp := [][]byte{server.restore2(restore2.Requests[0], handshakeHashes[0])}

	got, err := restore2.Restore(r2Resp)
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	if !bytes.Equal(got.Bytes(), backup.Output.Bytes()) {
		t.Fatal("restored secret does not match backup output")
	}
}

func TestRestore1BadInputs(t *testing.T) {
	t.Run("empty server IDs", func(t *testing.T) {
		_, err := NewRestore1(nil, []byte("pass"))
		if err == nil {
			t.Fatal("expected error for empty server IDs")
		}
	})

	t.Run("response count mismatch", func(t *testing.T) {
		r1, err := NewRestore1([]uint64{1, 2}, []byte("pass"))
		if err != nil {
			t.Fatalf("NewRestore1 failed: %v", err)
		}
		_, err = r1.Restore2([][]byte{{}}, [][]byte{{}, {}})
		if err == nil {
			t.Fatal("expected error for response count mismatch")
		}
	})

	t.Run("handshake hash count mismatch", func(t *testing.T) {
		r1, err := NewRestore1([]uint64{1, 2}, []byte("pass"))
		if err != nil {
			t.Fatalf("NewRestore1 failed: %v", err)
		}
		_, err = r1.Restore2([][]byte{{}, {}}, [][]byte{{}})
		if err == nil {
			t.Fatal("expected error for handshake hash count mismatch")
		}
	})
}

func TestRestore2BadInputs(t *testing.T) {
	t.Run("response count mismatch", func(t *testing.T) {
		r2 := &Restore2Result{
			serverIDs: []uint64{1, 2},
		}
		_, err := r2.Restore([][]byte{{}})
		if err == nil {
			t.Fatal("expected error for response count mismatch")
		}
		var svrErr *Error
		if !errors.As(err, &svrErr) {
			t.Fatalf("expected *Error, got %T", err)
		}
	})

	t.Run("bad protobuf response", func(t *testing.T) {
		r2 := &Restore2Result{
			serverIDs: []uint64{1},
		}
		_, err := r2.Restore([][]byte{{0xff}})
		if err == nil {
			t.Fatal("expected error for bad protobuf")
		}
	})

	t.Run("wrong response type", func(t *testing.T) {
		r2 := &Restore2Result{
			serverIDs: []uint64{1},
		}
		resp := &svrpb.Response4{
			Inner: &svrpb.Response4_Query_{
				Query: &svrpb.Response4_Query{},
			},
		}
		b, _ := proto.Marshal(resp)
		_, err := r2.Restore([][]byte{b})
		if err == nil {
			t.Fatal("expected error for wrong response type")
		}
	})

	t.Run("error status", func(t *testing.T) {
		r2 := &Restore2Result{
			serverIDs:      []uint64{1},
			TriesRemaining: 3,
		}
		resp := &svrpb.Response4{
			Inner: &svrpb.Response4_Restore2_{
				Restore2: &svrpb.Response4_Restore2{
					Status: svrpb.Response4_ERROR,
				},
			},
		}
		b, _ := proto.Marshal(resp)
		_, err := r2.Restore([][]byte{b})
		if err == nil {
			t.Fatal("expected error for ERROR status")
		}
		var svrErr *Error
		if !errors.As(err, &svrErr) {
			t.Fatalf("expected *Error, got %T", err)
		}
		if svrErr.TriesRemaining() != 3 {
			t.Fatalf("tries remaining = %d, want 3", svrErr.TriesRemaining())
		}
	})

	t.Run("wrong encryption share size", func(t *testing.T) {
		r2 := &Restore2Result{
			serverIDs: []uint64{1},
			authPoint: ristretto255.NewIdentityElement(),
		}
		resp := &svrpb.Response4{
			Inner: &svrpb.Response4_Restore2_{
				Restore2: &svrpb.Response4_Restore2{
					Status:                svrpb.Response4_OK,
					EncryptionSecretshare: []byte{1, 2, 3},
				},
			},
		}
		b, _ := proto.Marshal(resp)
		_, err := r2.Restore([][]byte{b})
		if err == nil {
			t.Fatal("expected error for wrong share size")
		}
	})
}

func TestRestore1ErrorStatus(t *testing.T) {
	r1, err := NewRestore1([]uint64{1}, []byte("pass"))
	if err != nil {
		t.Fatalf("NewRestore1 failed: %v", err)
	}

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_ERROR,
				TriesRemaining: 2,
			},
		},
	}
	b, _ := proto.Marshal(resp)

	_, err = r1.Restore2([][]byte{b}, [][]byte{makeBytes(32, 0)})
	if err == nil {
		t.Fatal("expected error for ERROR status")
	}
	var svrErr *Error
	if !errors.As(err, &svrErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if svrErr.TriesRemaining() != 2 {
		t.Fatalf("tries remaining = %d, want 2", svrErr.TriesRemaining())
	}
}

func TestRestore1NoUsableVersion(t *testing.T) {
	r1, err := NewRestore1([]uint64{1, 2}, []byte("pass"))
	if err != nil {
		t.Fatalf("NewRestore1 failed: %v", err)
	}

	resp1 := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_OK,
				TriesRemaining: 5,
				Auth: []*svrpb.Response4_Restore1_Auth{
					{Version: 1, Element: ristretto255.NewIdentityElement().Bytes()},
				},
			},
		},
	}
	resp2 := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_OK,
				TriesRemaining: 5,
				Auth: []*svrpb.Response4_Restore1_Auth{
					{Version: 2, Element: ristretto255.NewIdentityElement().Bytes()},
				},
			},
		},
	}
	b1, _ := proto.Marshal(resp1)
	b2, _ := proto.Marshal(resp2)

	_, err = r1.Restore2([][]byte{b1, b2}, [][]byte{makeBytes(32, 0), makeBytes(32, 0)})
	if !errors.Is(err, ErrNoUsableVersion) {
		t.Fatalf("expected ErrNoUsableVersion, got %v", err)
	}
}

func TestOPRFBackup4BadInputs(t *testing.T) {
	t.Run("empty server IDs", func(t *testing.T) {
		_, err := NewOPRFBackup4(nil, []byte("pass"), 10)
		if err == nil {
			t.Fatal("expected error for empty server IDs")
		}
	})

	t.Run("zero max tries", func(t *testing.T) {
		_, err := NewOPRFBackup4([]uint64{1}, []byte("pass"), 0)
		if err == nil {
			t.Fatal("expected error for zero max tries")
		}
	})
}

func TestEncryptionKeyKnownVector(t *testing.T) {
	sEnc := make([]byte, 32)
	kAuth := makeBytes(32, 1)
	got := encryptionKey(sEnc, kAuth)
	defer got.Destroy()
	want := []byte{
		0xfd, 0x8d, 0x53, 0xd8, 0x11, 0x52, 0x8b, 0xa9,
		0x51, 0x07, 0x59, 0xec, 0x66, 0x5d, 0xac, 0xf3,
		0x1b, 0x74, 0x7f, 0x5a, 0x94, 0xa5, 0x8f, 0x4b,
		0x84, 0xf5, 0xd5, 0xf4, 0x04, 0x58, 0xb9, 0xe8,
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("encryptionKey mismatch:\n  got:  %x\n  want: %x", got.Bytes(), want)
	}
}

func TestMultipleRestoresFromSameBackup(t *testing.T) {
	serverIDs := []uint64{1, 2}
	password := []byte("consistent-password")

	backup, err := NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}

	servers := make([]*testServer, len(serverIDs))
	for i := range servers {
		servers[i] = newTestServer()
		servers[i].create(backup.Requests[i])
	}

	handshakeHashes := [][]byte{makeBytes(32, 0xA), makeBytes(32, 0xB)}

	// Do two separate restores and verify both produce the same output.
	for attempt := 0; attempt < 2; attempt++ {
		r1, err := NewRestore1(serverIDs, password)
		if err != nil {
			t.Fatalf("attempt %d: NewRestore1 failed: %v", attempt, err)
		}
		r1Resp := make([][]byte, len(serverIDs))
		for i, req := range r1.Requests {
			r1Resp[i] = servers[i].restore1(req)
		}
		r2, err := r1.Restore2(r1Resp, handshakeHashes)
		if err != nil {
			t.Fatalf("attempt %d: Restore2 failed: %v", attempt, err)
		}
		r2Resp := make([][]byte, len(serverIDs))
		for i, req := range r2.Requests {
			r2Resp[i] = servers[i].restore2(req, handshakeHashes[i])
		}
		got, err := r2.Restore(r2Resp)
		if err != nil {
			t.Fatalf("attempt %d: Restore failed: %v", attempt, err)
		}
		if !bytes.Equal(got.Bytes(), backup.Output.Bytes()) {
			t.Fatalf("attempt %d: restored secret does not match backup output", attempt)
		}
	}
}

// makeBytes creates a byte slice of the given length filled with the given value.
func makeBytes(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}
