package svr

import (
	"math"

	"github.com/gtank/ristretto255"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// OPRFBackup4 represents a v4 SVR backup using the OPRF protocol. It generates
// per-server secret shares for the OPRF key, encryption key, and zero key,
// along with authentication commitments, then produces serialized protobuf
// requests to send to each server.
type OPRFBackup4 struct {
	// Requests contains one serialized Request4 per server.
	Requests [][]byte
	// Output is the derived encryption key that the client uses to encrypt
	// its secret before storing it. It is held in guarded memory and must be
	// destroyed by the caller via Zeroize() when no longer needed.
	Output *secret.Secret
}

// Zeroize destroys the guarded encryption key. This method is idempotent.
func (b *OPRFBackup4) Zeroize() {
	if b.Output != nil {
		b.Output.Destroy()
	}
}

// NewOPRFBackup4 creates a new OPRF-based backup request set for the given
// servers. The password is used to derive the OPRF input, and maxTries sets
// the server-side rate limit for restore attempts.
func NewOPRFBackup4(serverIDs []uint64, password []byte, maxTries uint32) (*OPRFBackup4, error) {
	if len(serverIDs) == 0 {
		return nil, ErrBadData
	}
	if maxTries == 0 {
		return nil, ErrBadData
	}

	n := len(serverIDs)
	input := passwordToUniformInput(password)
	defer crypto.ZeroizeArray64(&input)
	inputSecret, err := secret.New(input[:])
	if err != nil {
		return nil, &Error{kind: errBadData}
	}
	defer inputSecret.Destroy()

	// Recover the input as a fixed array for functions that require *[64]byte.
	inputPtr := (*[64]byte)(inputSecret.Bytes())

	kOprf := randomScalar()
	defer zeroScalar(kOprf)

	sEnc, err := secret.NewRandom(32)
	if err != nil {
		return nil, &Error{kind: errBadData}
	}
	defer sEnc.Destroy()

	oprfShares := scalarsSummingTo(n, kOprf)
	defer zeroizeScalars(oprfShares)
	encShares := bytesXORingTo(n, sEnc.Bytes())
	zeroSc := ristretto255.NewScalar() // zero
	zeroShares := scalarsSummingTo(n, zeroSc)
	defer zeroizeScalars(zeroShares)

	ap := authPt(inputPtr, kOprf)
	commitments := authCommitments(serverIDs, inputPtr, ap)
	defer zeroizeCommitments(commitments)

	// Random version identifier for this backup.
	versionSecret, err := secret.NewRandom(4)
	if err != nil {
		return nil, &Error{kind: errBadData}
	}
	versionBytes := versionSecret.Bytes()
	version := uint32(versionBytes[0]) | uint32(versionBytes[1])<<8 |
		uint32(versionBytes[2])<<16 | uint32(versionBytes[3])<<24
	versionSecret.Destroy()

	kAuth := authSecret(inputPtr, ap)
	output := encryptionKey(sEnc.Bytes(), kAuth.Bytes())
	kAuth.Destroy()

	requests := make([][]byte, n)
	for i := 0; i < n; i++ {
		req := &svrpb.Request4{
			Inner: &svrpb.Request4_Create_{
				Create: &svrpb.Request4_Create{
					Version:               version,
					MaxTries:              maxTries,
					OprfSecretshare:       oprfShares[i].Bytes(),
					AuthCommitment:        commitments[i].point.Bytes(),
					EncryptionSecretshare: encShares[i],
					ZeroSecretshare:       zeroShares[i].Bytes(),
				},
			},
		}
		b, err := proto.Marshal(req)
		if err != nil {
			return nil, ErrBadData
		}
		requests[i] = b
	}

	return &OPRFBackup4{
		Requests: requests,
		Output:   output,
	}, nil
}

// FinalizeBackup4 processes server responses to backup requests. It verifies
// that all servers returned OK status and returns the minimum tries remaining.
func FinalizeBackup4(responses [][]byte) (uint32, error) {
	if len(responses) == 0 {
		return 0, ErrBadData
	}
	minTries := uint32(math.MaxUint32)
	for _, b := range responses {
		resp := &svrpb.Response4{}
		if err := proto.Unmarshal(b, resp); err != nil {
			return 0, ErrBadData
		}
		inner, ok := resp.Inner.(*svrpb.Response4_Create_)
		if !ok || inner == nil {
			return 0, ErrBadData
		}
		cr := inner.Create
		if err := checkStatus(cr.GetStatus()); err != nil {
			return 0, err
		}
		if cr.GetTriesRemaining() < minTries {
			minTries = cr.GetTriesRemaining()
		}
	}
	return minTries, nil
}
