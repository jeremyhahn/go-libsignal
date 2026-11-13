package svr

import (
	"crypto/sha512"
	"sort"

	"github.com/gtank/ristretto255"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
	ucrypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// Restore1 is the first phase of a two-phase SVR restore. It sends a blinded
// point to each server and receives back OPRF evaluations and auth elements
// for version negotiation. The input is held in guarded memory and must be
// destroyed via Zeroize() when no longer needed.
type Restore1 struct {
	serverIDs []uint64
	input     *secret.Secret
	blind     *ristretto255.Scalar

	// Requests contains one serialized Request4 per server.
	Requests [][]byte
}

// Zeroize destroys the guarded input secret and overwrites the blinding
// scalar. This method is idempotent.
func (r *Restore1) Zeroize() {
	if r.input != nil {
		r.input.Destroy()
	}
	zeroScalar(r.blind)
}

// NewRestore1 creates a new first-phase restore request set for the given
// servers. The password is used to derive the OPRF input. A random blinding
// scalar is generated internally.
func NewRestore1(serverIDs []uint64, password []byte) (*Restore1, error) {
	if len(serverIDs) == 0 {
		return nil, ErrBadData
	}

	blind := randomScalar()
	input := passwordToUniformInput(password)
	defer ucrypto.ZeroizeArray64(&input)
	inputSecret, err := secret.New(input[:])
	if err != nil {
		return nil, &Error{kind: errBadData}
	}
	// blinded = inputHashPt(input) * blind, with the input borrowed.
	var blinded *ristretto255.Element
	if err := withInput(inputSecret, func(inputPtr *[64]byte) error {
		blinded = ristretto255.NewIdentityElement().ScalarMult(blind, inputHashPt(inputPtr))
		return nil
	}); err != nil {
		inputSecret.Destroy()
		return nil, &Error{kind: errBadData}
	}
	blindedBytes := blinded.Bytes()

	requests := make([][]byte, len(serverIDs))
	for i := range serverIDs {
		req := &svrpb.Request4{
			Inner: &svrpb.Request4_Restore1_{
				Restore1: &svrpb.Request4_Restore1{
					Blinded: blindedBytes,
				},
			},
		}
		b, err := proto.Marshal(req)
		if err != nil {
			inputSecret.Destroy()
			return nil, ErrBadData
		}
		requests[i] = b
	}

	return &Restore1{
		serverIDs: serverIDs,
		input:     inputSecret,
		blind:     blind,
		Requests:  requests,
	}, nil
}

// Restore2 processes the first-phase responses and produces second-phase
// requests containing Schnorr-like authentication proofs.
//
// responses1 contains the serialized Response4 from each server.
// handshakeHashes contains the TLS handshake hash for each server connection,
// used as a channel binding in the Schnorr proof.
func (r *Restore1) Restore2(responses1 [][]byte, handshakeHashes [][]byte) (*Restore2Result, error) {
	n := len(r.serverIDs)
	if len(responses1) != n || len(handshakeHashes) != n {
		return nil, newNumServersError(n, len(responses1))
	}

	// Parse all Restore1 responses.
	parsed := make([]*svrpb.Response4_Restore1, n)
	for i, b := range responses1 {
		resp := &svrpb.Response4{}
		if err := proto.Unmarshal(b, resp); err != nil {
			return nil, ErrBadResponse
		}
		inner, ok := resp.Inner.(*svrpb.Response4_Restore1_)
		if !ok || inner == nil {
			return nil, ErrBadResponse
		}
		parsed[i] = inner.Restore1
	}

	// Determine tries_remaining from responses that would have decremented.
	var triesRemaining *uint32
	for _, rr := range parsed {
		status := rr.GetStatus()
		if status == svrpb.Response4_OK || status == svrpb.Response4_ERROR {
			tr := rr.GetTriesRemaining()
			if triesRemaining == nil || tr < *triesRemaining {
				trCopy := tr
				triesRemaining = &trCopy
			}
		}
	}

	// Check all statuses are OK.
	for _, rr := range parsed {
		if err := checkStatus(rr.GetStatus()); err != nil {
			if triesRemaining != nil {
				return nil, newRestoreFailedError(*triesRemaining)
			}
			return nil, err
		}
	}

	// Find a version present in all responses.
	version, err := r.versionToUse(parsed)
	if err != nil {
		return nil, err
	}

	// Get one Auth per response for the chosen version.
	auths, err := r.authsWithVersion(version, parsed)
	if err != nil {
		return nil, err
	}

	// Sum the OPRF elements from all servers:
	//   SUM = sum(P * k_i + H * z_i) = P * k_oprf + H * 0 = P * k_oprf
	sum := ristretto255.NewIdentityElement()
	for _, auth := range auths {
		elem, err := decodeElement(auth.GetElement())
		if err != nil {
			return nil, ErrBadResponse
		}
		sum.Add(sum, elem)
	}

	// Unblind: auth_pt = SUM * (1/blind)
	blindInv := ristretto255.NewScalar().Invert(r.blind)
	defer zeroScalar(blindInv)
	ap := ristretto255.NewIdentityElement().ScalarMult(blindInv, sum)

	// Recompute auth commitments for the Schnorr proof.
	// The input is borrowed for the commitments and the blinded point.
	var commitments []authCommitment
	var blindedPt *ristretto255.Element
	if err := withInput(r.input, func(inputPtr *[64]byte) error {
		commitments = authCommitments(r.serverIDs, inputPtr, ap)
		blindedPt = ristretto255.NewIdentityElement().ScalarMult(r.blind, inputHashPt(inputPtr))
		return nil
	}); err != nil {
		return nil, &Error{kind: errBadData}
	}
	defer zeroizeCommitments(commitments)

	// Random nonce for the Schnorr proof.
	randScalar := randomScalar()
	defer zeroScalar(randScalar)
	proofPt := ristretto255.NewIdentityElement().ScalarBaseMult(randScalar)
	proofPtBytes := proofPt.Bytes()

	// The blinded point bytes for the hash.
	blindedPtBytes := blindedPt.Bytes()

	requests := make([][]byte, n)
	for i := range r.serverIDs {
		// Compute the Schnorr challenge: H(proofPt || blindedPt || handshakeHash)
		h := sha512.New()
		h.Write(proofPtBytes)
		h.Write(blindedPtBytes)
		h.Write(handshakeHashes[i])
		challengeBytes := h.Sum(nil)
		challenge, cerr := ristretto255.NewScalar().SetUniformBytes(challengeBytes)
		if cerr != nil {
			return nil, &Error{kind: errBadData}
		}

		// proof_scalar = sk * challenge + rand
		proofScalar := ristretto255.NewScalar().Multiply(commitments[i].scalar, challenge)
		proofScalar.Add(proofScalar, randScalar)

		req := &svrpb.Request4{
			Inner: &svrpb.Request4_Restore2_{
				Restore2: &svrpb.Request4_Restore2{
					AuthPoint:  proofPtBytes,
					AuthScalar: proofScalar.Bytes(),
					Version:    version,
				},
			},
		}
		b, err := proto.Marshal(req)
		if err != nil {
			return nil, ErrBadData
		}
		requests[i] = b
	}

	tr := uint32(0)
	if triesRemaining != nil {
		tr = *triesRemaining
	}

	// Clone the input secret so Restore2Result owns its own copy.
	inputClone, err := r.input.Clone()
	if err != nil {
		return nil, &Error{kind: errBadData}
	}

	return &Restore2Result{
		serverIDs:      r.serverIDs,
		input:          inputClone,
		authPoint:      ap,
		TriesRemaining: tr,
		Requests:       requests,
	}, nil
}

// versionToUse finds a version number that appears in every response.
func (r *Restore1) versionToUse(responses []*svrpb.Response4_Restore1) (uint32, error) {
	counts := make(map[uint32]int)
	for _, resp := range responses {
		for _, auth := range resp.GetAuth() {
			counts[auth.GetVersion()]++
		}
	}

	// Find a version present in all responses. Use sorted keys for
	// deterministic behavior.
	versions := make([]uint32, 0, len(counts))
	for v := range counts {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	for _, v := range versions {
		if counts[v] == len(r.serverIDs) {
			return v, nil
		}
	}
	return 0, ErrNoUsableVersion
}

// authsWithVersion extracts one Auth from each response for the given version.
// Returns an error if any response lacks an Auth with that version.
func (r *Restore1) authsWithVersion(version uint32, responses []*svrpb.Response4_Restore1) ([]*svrpb.Response4_Restore1_Auth, error) {
	out := make([]*svrpb.Response4_Restore1_Auth, 0, len(responses))
	for _, resp := range responses {
		for _, auth := range resp.GetAuth() {
			if auth.GetVersion() == version {
				out = append(out, auth)
				break
			}
		}
	}
	if len(out) != len(responses) {
		return nil, ErrNoUsableVersion
	}
	return out, nil
}

// Restore2Result is the second phase of a two-phase SVR restore. It holds the
// second-phase requests and, after processing server responses, reconstructs
// the original encryption key. The input is held in guarded memory and must
// be destroyed via Zeroize() when no longer needed.
type Restore2Result struct {
	serverIDs []uint64
	input     *secret.Secret
	authPoint *ristretto255.Element

	// TriesRemaining is the minimum tries remaining from the first phase.
	TriesRemaining uint32

	// Requests contains one serialized Request4 per server.
	Requests [][]byte
}

// Zeroize destroys the guarded input secret. This method is idempotent.
func (r *Restore2Result) Zeroize() {
	if r.input != nil {
		r.input.Destroy()
	}
}

// Restore processes the second-phase responses and reconstructs the encryption
// key by XOR-combining the encryption secret shares from all servers. The
// returned secret is in guarded memory and must be destroyed by the caller
// when no longer needed.
func (r *Restore2Result) Restore(responses2 [][]byte) (*secret.Secret, error) {
	n := len(r.serverIDs)
	if len(responses2) != n {
		return nil, newNumServersError(n, len(responses2))
	}

	parsed := make([]*svrpb.Response4_Restore2, n)
	for i, b := range responses2 {
		resp := &svrpb.Response4{}
		if err := proto.Unmarshal(b, resp); err != nil {
			return nil, ErrBadResponse
		}
		inner, ok := resp.Inner.(*svrpb.Response4_Restore2_)
		if !ok || inner == nil {
			return nil, ErrBadResponse
		}
		parsed[i] = inner.Restore2
	}

	// Check all statuses are OK.
	for _, rr := range parsed {
		if err := checkStatus(rr.GetStatus()); err != nil {
			return nil, newRestoreFailedError(r.TriesRemaining)
		}
	}

	// XOR all encryption secret shares together in guarded memory.
	sEncBuf := make([]byte, 32)
	for _, resp := range parsed {
		share := resp.GetEncryptionSecretshare()
		if len(share) != 32 {
			return nil, ErrBadResponse
		}
		arrXOR(share, sEncBuf)
	}
	sEnc, err := secret.New(sEncBuf)
	if err != nil {
		return nil, &Error{kind: errBadData}
	}
	defer sEnc.Destroy()

	var kAuth *secret.Secret
	if err := withInput(r.input, func(inputPtr *[64]byte) error {
		kAuth = authSecret(inputPtr, r.authPoint)
		return nil
	}); err != nil {
		return nil, &Error{kind: errBadData}
	}
	defer kAuth.Destroy()
	return encryptionKeyFromSecrets(sEnc, kAuth), nil
}

// RestoreFull performs a complete two-phase restore as a convenience wrapper.
// It takes the first-phase responses and handshake hashes, produces second-
// phase requests via a callback, and returns the final encryption key in
// guarded memory. The caller must destroy the returned secret when done.
//
// The sendRequests callback receives the second-phase requests and must return
// the corresponding server responses.
func RestoreFull(
	serverIDs []uint64,
	password []byte,
	responses1 [][]byte,
	handshakeHashes [][]byte,
	sendRequests func(requests [][]byte) ([][]byte, error),
) (*secret.Secret, error) {
	r1, err := NewRestore1(serverIDs, password)
	if err != nil {
		return nil, err
	}
	defer r1.Zeroize()

	r2, err := r1.Restore2(responses1, handshakeHashes)
	if err != nil {
		return nil, err
	}
	defer r2.Zeroize()

	responses2, err := sendRequests(r2.Requests)
	if err != nil {
		return nil, err
	}

	return r2.Restore(responses2)
}
