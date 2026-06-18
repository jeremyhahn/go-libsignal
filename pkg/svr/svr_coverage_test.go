package svr

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gtank/ristretto255"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

// --- RestoreFull tests ---

func TestRestoreFull_EmptyServerIDs(t *testing.T) {
	_, err := RestoreFull(nil, []byte("pass"), nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty server IDs")
	}
}

func TestRestoreFull_Restore2Error(t *testing.T) {
	serverIDs := []uint64{1}
	password := []byte("pass")

	// Create restore1 responses with ERROR status
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_ERROR,
				TriesRemaining: 2,
			},
		},
	}
	b, _ := proto.Marshal(resp)

	_, err := RestoreFull(
		serverIDs, password,
		[][]byte{b},
		[][]byte{make([]byte, 32)},
		func(requests [][]byte) ([][]byte, error) {
			return nil, errors.New("should not be called")
		},
	)
	if err == nil {
		t.Fatal("expected error for ERROR status in Restore2")
	}
}

func TestRestoreFull_SendRequestsError(t *testing.T) {
	serverIDs := []uint64{1}
	password := []byte("pass")

	backup, err := NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}

	server := newTestServer()
	server.create(backup.Requests[0])

	r1, _ := NewRestore1(serverIDs, password)
	restore1Resp := [][]byte{server.restore1(r1.Requests[0])}
	hashes := [][]byte{make([]byte, 32)}

	sendErr := errors.New("send failed")
	_, err = RestoreFull(
		serverIDs, password,
		restore1Resp,
		hashes,
		func(requests [][]byte) ([][]byte, error) {
			return nil, sendErr
		},
	)
	if err == nil {
		t.Fatal("expected error when sendRequests fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected sendErr, got %v", err)
	}
}

func TestRestoreFull_Restore2PhaseError(t *testing.T) {
	serverIDs := []uint64{1}
	password := []byte("pass")

	backup, err := NewOPRFBackup4(serverIDs, password, 10)
	if err != nil {
		t.Fatalf("NewOPRFBackup4 failed: %v", err)
	}

	server := newTestServer()
	server.create(backup.Requests[0])

	r1, _ := NewRestore1(serverIDs, password)
	restore1Resp := [][]byte{server.restore1(r1.Requests[0])}
	hashes := [][]byte{make([]byte, 32)}

	_, err = RestoreFull(
		serverIDs, password,
		restore1Resp,
		hashes,
		func(requests [][]byte) ([][]byte, error) {
			// Return a response with wrong inner type
			resp := &svrpb.Response4{
				Inner: &svrpb.Response4_Query_{
					Query: &svrpb.Response4_Query{},
				},
			}
			b, _ := proto.Marshal(resp)
			return [][]byte{b}, nil
		},
	)
	if err == nil {
		t.Fatal("expected error for wrong response type in phase 2")
	}
}

// --- NewBackup4 zero maxTries ---

func TestNewBackup4_ZeroMaxTries(t *testing.T) {
	var secret Secret
	_, err := NewBackup4(secret, 0)
	if err == nil {
		t.Fatal("expected error for zero maxTries")
	}
}

// --- NewBackup4 success ---

func TestNewBackup4_Success(t *testing.T) {
	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0x01}, 32))
	backup, err := NewBackup4(secret, 5)
	if err != nil {
		t.Fatalf("NewBackup4 failed: %v", err)
	}
	if backup == nil {
		t.Fatal("NewBackup4 returned nil")
	}
	if backup.MaxTries != 5 {
		t.Errorf("MaxTries = %d, want 5", backup.MaxTries)
	}
	if backup.Secret != secret {
		t.Error("Secret mismatch")
	}
	if len(backup.Entropy) != 32 {
		t.Errorf("Entropy length = %d, want 32", len(backup.Entropy))
	}
	if len(backup.RequestID) != 32 {
		t.Errorf("RequestID length = %d, want 32", len(backup.RequestID))
	}
}

// --- DecryptSecret tampered ciphertext ---

func TestDecryptSecret_TamperedCiphertext(t *testing.T) {
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0x42}, 32))

	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0xAB}, 32))

	ct, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	// Tamper with the ciphertext
	ct[0] ^= 0xFF
	_, err = DecryptSecret(key, ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

// --- DecryptSecret wrong key ---

func TestDecryptSecret_WrongKey(t *testing.T) {
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0x42}, 32))

	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0xAB}, 32))

	ct, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	var wrongKey [32]byte
	copy(wrongKey[:], bytes.Repeat([]byte{0x99}, 32))
	_, err = DecryptSecret(wrongKey, ct)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

// --- Restore2.Restore bad element in Restore1 ---

func TestRestore1_Restore2_BadElementInAuth(t *testing.T) {
	r1, _ := NewRestore1([]uint64{1}, []byte("pass"))

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_OK,
				TriesRemaining: 5,
				Auth: []*svrpb.Response4_Restore1_Auth{
					{Version: 1, Element: []byte{0xFF, 0xFF}}, // invalid element
				},
			},
		},
	}
	b, _ := proto.Marshal(resp)
	_, err := r1.Restore2([][]byte{b}, [][]byte{make([]byte, 32)})
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("expected ErrBadResponse, got %v", err)
	}
}

// --- FinalizeBackup4: bad response ---

func TestFinalizeBackup4_BadProtobuf(t *testing.T) {
	_, err := FinalizeBackup4([][]byte{{0xFF, 0xFF}})
	if !errors.Is(err, ErrBadData) {
		t.Fatalf("expected ErrBadData, got %v", err)
	}
}

func TestFinalizeBackup4_WrongInnerType(t *testing.T) {
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Query_{
			Query: &svrpb.Response4_Query{},
		},
	}
	b, _ := proto.Marshal(resp)
	_, err := FinalizeBackup4([][]byte{b})
	if !errors.Is(err, ErrBadData) {
		t.Fatalf("expected ErrBadData, got %v", err)
	}
}

func TestFinalizeBackup4_ErrorStatus(t *testing.T) {
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Create_{
			Create: &svrpb.Response4_Create{
				Status:         svrpb.Response4_ERROR,
				TriesRemaining: 5,
			},
		},
	}
	b, _ := proto.Marshal(resp)
	_, err := FinalizeBackup4([][]byte{b})
	if err == nil {
		t.Fatal("expected error for ERROR status")
	}
}

func TestFinalizeBackup4_EmptyResponses(t *testing.T) {
	_, err := FinalizeBackup4(nil)
	if !errors.Is(err, ErrBadData) {
		t.Fatalf("expected ErrBadData, got %v", err)
	}
}

func TestFinalizeBackup4_Success(t *testing.T) {
	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Create_{
			Create: &svrpb.Response4_Create{
				Status:         svrpb.Response4_OK,
				TriesRemaining: 10,
			},
		},
	}
	b, _ := proto.Marshal(resp)
	tries, err := FinalizeBackup4([][]byte{b})
	if err != nil {
		t.Fatalf("FinalizeBackup4 failed: %v", err)
	}
	if tries != 10 {
		t.Errorf("tries = %d, want 10", tries)
	}
}

// --- EncryptSecret/DecryptSecret roundtrip ---

func TestEncryptDecryptSecret_Roundtrip(t *testing.T) {
	var key [32]byte
	copy(key[:], bytes.Repeat([]byte{0x42}, 32))

	var secret Secret
	copy(secret[:], bytes.Repeat([]byte{0xAB}, 32))

	ct, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	got, err := DecryptSecret(key, ct)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}
	if got != secret {
		t.Error("decrypted secret does not match original")
	}
}

// --- authsWithVersion: missing version in one response ---

func TestAuthsWithVersion_MissingVersion(t *testing.T) {
	r1, _ := NewRestore1([]uint64{1, 2}, []byte("pass"))

	// First response has version 5, second has version 6 only.
	// authsWithVersion(5, ...) should fail because server 2 lacks version 5.
	responses := []*svrpb.Response4_Restore1{
		{
			Auth: []*svrpb.Response4_Restore1_Auth{
				{Version: 5, Element: ristretto255.NewIdentityElement().Bytes()},
			},
		},
		{
			Auth: []*svrpb.Response4_Restore1_Auth{
				{Version: 6, Element: ristretto255.NewIdentityElement().Bytes()},
			},
		},
	}

	_, err := r1.authsWithVersion(5, responses)
	if !errors.Is(err, ErrNoUsableVersion) {
		t.Fatalf("expected ErrNoUsableVersion, got %v", err)
	}
}

// --- Restore1.Restore2: bad protobuf in response ---

func TestRestore1_Restore2_BadProtobuf(t *testing.T) {
	r1, _ := NewRestore1([]uint64{1}, []byte("pass"))
	_, err := r1.Restore2([][]byte{{0xFF, 0xFF}}, [][]byte{make([]byte, 32)})
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("expected ErrBadResponse, got %v", err)
	}
}

// --- Restore1.Restore2: wrong inner type ---

func TestRestore1_Restore2_WrongInnerType(t *testing.T) {
	r1, _ := NewRestore1([]uint64{1}, []byte("pass"))

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Query_{
			Query: &svrpb.Response4_Query{},
		},
	}
	b, _ := proto.Marshal(resp)
	_, err := r1.Restore2([][]byte{b}, [][]byte{make([]byte, 32)})
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("expected ErrBadResponse, got %v", err)
	}
}

// --- Restore1.Restore2: MISSING status with no tries (no triesRemaining set) ---

func TestRestore1_Restore2_MissingStatus(t *testing.T) {
	r1, _ := NewRestore1([]uint64{1}, []byte("pass"))

	resp := &svrpb.Response4{
		Inner: &svrpb.Response4_Restore1_{
			Restore1: &svrpb.Response4_Restore1{
				Status:         svrpb.Response4_MISSING,
				TriesRemaining: 0,
			},
		},
	}
	b, _ := proto.Marshal(resp)
	_, err := r1.Restore2([][]byte{b}, [][]byte{make([]byte, 32)})
	if err == nil {
		t.Fatal("expected error for MISSING status")
	}
}

// --- bytesXORingTo: single element ---

func TestBytesXORingTo_SingleElement(t *testing.T) {
	target := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	shares := bytesXORingTo(1, target)
	if len(shares) != 1 {
		t.Fatalf("got %d shares, want 1", len(shares))
	}
	if !bytes.Equal(shares[0], target) {
		t.Error("single share should equal target")
	}
}

// --- kdf: nil input2 ---

func TestKDF_NilInput2(t *testing.T) {
	info := []byte("test")
	input1 := []byte("data")

	a := kdf32(info, input1, nil)
	b := kdf32(info, input1, nil)
	if a != b {
		t.Fatal("kdf32 with nil input2 should be deterministic")
	}
}

// --- randomScalar: produces non-zero scalars ---

func TestRandomScalar_NonZero(t *testing.T) {
	s := randomScalar()
	if s.Equal(ristretto255.NewScalar()) == 1 {
		t.Error("random scalar should not be zero (extremely unlikely)")
	}
}

// --- scalarsSummingTo: n=1 should return target ---

func TestScalarsSummingTo_SingleElement(t *testing.T) {
	target := randomScalar()
	shares := scalarsSummingTo(1, target)
	if len(shares) != 1 {
		t.Fatalf("got %d shares, want 1", len(shares))
	}
	if shares[0].Equal(target) != 1 {
		t.Error("single share should equal target")
	}
}

// --- checkStatus: OK returns nil ---

func TestCheckStatus_OK(t *testing.T) {
	err := checkStatus(svrpb.Response4_OK)
	if err != nil {
		t.Fatalf("expected nil for OK status, got %v", err)
	}
}

// --- checkStatus: non-OK returns error with correct status ---

func TestCheckStatus_NonOK(t *testing.T) {
	statuses := []svrpb.Response4_Status{
		svrpb.Response4_ERROR,
		svrpb.Response4_MISSING,
		svrpb.Response4_INVALID_REQUEST,
		svrpb.Response4_RESTORE1_MISSING,
		svrpb.Response4_VERSION_MISMATCH,
	}
	for _, s := range statuses {
		err := checkStatus(s)
		if err == nil {
			t.Errorf("expected error for status %v", s)
		}
		var svrErr *Error
		if !errors.As(err, &svrErr) {
			t.Errorf("expected *Error for status %v, got %T", s, err)
		}
	}
}

// --- Error.Status and Error.TriesRemaining ---

func TestError_StatusAndTriesRemaining(t *testing.T) {
	e := newBadResponseStatusError(StatusMissing)
	if e.Status() != StatusMissing {
		t.Errorf("Status() = %v, want %v", e.Status(), StatusMissing)
	}

	e2 := newRestoreFailedError(7)
	if e2.TriesRemaining() != 7 {
		t.Errorf("TriesRemaining() = %d, want 7", e2.TriesRemaining())
	}
}

// --- authCommitments: deterministic for same inputs ---

func TestAuthCommitments_Deterministic(t *testing.T) {
	serverIDs := []uint64{1, 2}
	input := passwordToUniformInput([]byte("password"))
	kOprf := randomScalar()
	ap := authPt(&input, kOprf)

	c1 := authCommitments(serverIDs, &input, ap)
	c2 := authCommitments(serverIDs, &input, ap)

	for i := range c1 {
		if c1[i].scalar.Equal(c2[i].scalar) != 1 {
			t.Fatalf("scalar %d mismatch", i)
		}
		if c1[i].point.Equal(c2[i].point) != 1 {
			t.Fatalf("point %d mismatch", i)
		}
	}
}

// --- authSecret: deterministic ---

func TestAuthSecret_Deterministic(t *testing.T) {
	input := passwordToUniformInput([]byte("pass"))
	pt := ristretto255.NewIdentityElement().ScalarBaseMult(randomScalar())

	a := authSecret(&input, pt)
	defer a.Destroy()
	b := authSecret(&input, pt)
	defer b.Destroy()
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("authSecret should be deterministic")
	}
}

// --- inputHashPt: deterministic ---

func TestInputHashPt_Deterministic(t *testing.T) {
	input := passwordToUniformInput([]byte("test"))
	pt1 := inputHashPt(&input)
	pt2 := inputHashPt(&input)
	if pt1.Equal(pt2) != 1 {
		t.Error("inputHashPt should be deterministic")
	}
}

// --- Query4.RequestsN: n=0 returns empty ---

func TestQuery4_RequestsN_Zero(t *testing.T) {
	q := Query4{}
	reqs, err := q.RequestsN(0)
	if err != nil {
		t.Fatalf("RequestsN(0) error = %v", err)
	}
	if len(reqs) != 0 {
		t.Errorf("got %d requests, want 0", len(reqs))
	}
}

// --- Remove4.RequestsN: n=0 returns empty ---

func TestRemove4_RequestsN_Zero(t *testing.T) {
	r := Remove4{}
	reqs, err := r.RequestsN(0)
	if err != nil {
		t.Fatalf("RequestsN(0) error = %v", err)
	}
	if len(reqs) != 0 {
		t.Errorf("got %d requests, want 0", len(reqs))
	}
}

// --- uint64ToBeBytes edge cases ---

func TestUint64ToBeBytes_Zero(t *testing.T) {
	got := uint64ToBeBytes(0)
	want := [8]byte{}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestUint64ToBeBytes_MaxValue(t *testing.T) {
	got := uint64ToBeBytes(0xFFFFFFFFFFFFFFFF)
	want := [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
