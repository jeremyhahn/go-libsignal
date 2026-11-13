package spqr

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// ChainStartInfo is the HKDF info string for session initialization.
	// Note the double space before "Start" which matches the Rust reference.
	// Verified byte-identical to signalapp/SparsePostQuantumRatchet v1.5.1
	// at src/chain.rs:334.
	ChainStartInfo = "Signal PQ Ratchet V1 Chain  Start"
	// ChainAddEpochInfo is the HKDF info string for adding a new epoch.
	// Verified byte-identical to SparsePostQuantumRatchet v1.5.1
	// src/chain.rs:360.
	ChainAddEpochInfo = "Signal PQ Ratchet V1 Chain Add Epoch"
	// ChainNextInfo is the HKDF info label for chain key stepping.
	// The full info is: counter_be32 || ChainNextInfo.
	// Verified byte-identical to SparsePostQuantumRatchet v1.5.1
	// src/chain.rs:237.
	ChainNextInfo = "Signal PQ Ratchet V1 Chain Next"

	// kdfOutputLen is the total output length: RK(32) + CKs(32) + CKr(32).
	kdfOutputLen = 96
	// keyLen is the length of each derived key.
	keyLen = 32
	// sckaCKOutputLen is the total output length for KdfSckaCK: nextCK(32) + MK(32).
	sckaCKOutputLen = 64
)

// zeroSalt returns a fresh 32-byte zero slice for use as HKDF salt.
// A function is used instead of a package-level variable to prevent
// accidental mutation of shared state.
func zeroSalt() []byte {
	return make([]byte, 32)
}

// KdfSckaInit derives the initial root key, send chain key, and receive chain
// key from a shared secret using HKDF-SHA256 with a zero salt.
func KdfSckaInit(sharedSecret []byte) (rk, cks, ckr *secret.Secret, err error) {
	if len(sharedSecret) == 0 {
		return nil, nil, nil, &ErrInvalidInput{
			Field:  "sharedSecret",
			Reason: "must not be empty",
		}
	}

	output, err := kdf.DeriveSecrets(sharedSecret, zeroSalt(), []byte(ChainStartInfo), kdfOutputLen)
	if err != nil {
		return nil, nil, nil, err
	}

	// Split inside locked memory; splitLocked wipes output.
	keys, err := splitLocked(output, 3)
	if err != nil {
		return nil, nil, nil, err
	}
	return keys[0], keys[1], keys[2], nil
}

// KdfSckaRK derives a new root key, send chain key, and receive chain key
// from the current root key and an SCKA output using HKDF-SHA256.
func KdfSckaRK(rk *secret.Secret, sckaOutput []byte) (newRK, newCKs, newCKr *secret.Secret, err error) {
	if rk == nil || rk.IsDestroyed() {
		return nil, nil, nil, &ErrInvalidInput{
			Field:  "rk",
			Reason: "must not be empty",
		}
	}
	if len(sckaOutput) == 0 {
		return nil, nil, nil, &ErrInvalidInput{
			Field:  "sckaOutput",
			Reason: "must not be empty",
		}
	}

	var output []byte
	err = rk.WithBytes(func(rkBytes []byte) error {
		if len(rkBytes) != keyLen {
			return &ErrInvalidInput{Field: "rk", Reason: fmt.Sprintf("want %d bytes, got %d", keyLen, len(rkBytes))}
		}
		var dErr error
		output, dErr = kdf.DeriveSecrets(sckaOutput, rkBytes, []byte(ChainAddEpochInfo), kdfOutputLen)
		return dErr
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Split inside locked memory; splitLocked wipes output.
	keys, err := splitLocked(output, 3)
	if err != nil {
		return nil, nil, nil, err
	}
	return keys[0], keys[1], keys[2], nil
}

// KdfSckaCK derives a next chain key and message key from the current chain
// key and counter using HKDF-SHA256, matching the Rust reference implementation.
//
// HKDF parameters (aligned with Rust libsignal):
//   - salt:  zeros(32)
//   - ikm:   chain_key (32 bytes)
//   - info:  counter_be32 || "Signal PQ Ratchet V1 Chain Next"
//   - length: 64
//
// Output split: nextCK(32) || mk(32)
func KdfSckaCK(ck *secret.Secret, ctr uint32) (mk, nextCK *secret.Secret, err error) {
	if ck == nil || ck.IsDestroyed() {
		return nil, nil, &ErrInvalidInput{
			Field:  "ck",
			Reason: "must not be empty",
		}
	}

	// Build info: counter_be32 || ChainNextInfo
	ctrBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ctrBytes, ctr)
	info := slices.Concat(ctrBytes, []byte(ChainNextInfo))

	var output []byte
	err = ck.WithBytes(func(ckBytes []byte) error {
		if len(ckBytes) != keyLen {
			return &ErrInvalidInput{Field: "ck", Reason: fmt.Sprintf("want %d bytes, got %d", keyLen, len(ckBytes))}
		}
		var dErr error
		output, dErr = kdf.DeriveSecrets(ckBytes, zeroSalt(), info, sckaCKOutputLen)
		return dErr
	})
	if err != nil {
		return nil, nil, err
	}

	// Split: nextCK(first 32) || mk(last 32), matching Rust reference.
	// Split inside locked memory; splitLocked wipes output.
	keys, err := splitLocked(output, 2)
	if err != nil {
		return nil, nil, err
	}
	return keys[1], keys[0], nil
}

// splitLocked moves a KDF output into a locked scratch region at once,
// wiping output, and splits it there into n keyLen-byte secrets. Each
// secret.New moves its segment locked region to locked region, so no
// unprotected copy of a segment exists during the split.
func splitLocked(output []byte, n int) (_ []*secret.Secret, err error) {
	defer crypto.Zeroize(output)
	if len(output) != n*keyLen {
		return nil, &ErrInvalidInput{Field: "kdf output", Reason: "unexpected length"}
	}
	scratch, err := secret.NewEmpty(len(output))
	if err != nil {
		return nil, err
	}
	defer scratch.Destroy()

	keys := make([]*secret.Secret, 0, n)
	err = scratch.WithBytes(func(b []byte) error {
		copy(b, output)
		crypto.Zeroize(output)
		for i := 0; i < n; i++ {
			k, nErr := secret.New(b[i*keyLen : (i+1)*keyLen])
			if nErr != nil {
				return nErr
			}
			keys = append(keys, k)
		}
		return nil
	})
	if err != nil {
		for _, k := range keys {
			k.Destroy()
		}
		return nil, err
	}
	return keys, nil
}
