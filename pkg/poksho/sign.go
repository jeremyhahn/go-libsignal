package poksho

import "github.com/gtank/ristretto255"

// Sign produces a Schnorr-style proof of knowledge of the discrete log of
// publicKey with respect to the Ristretto255 base point. The resulting
// signature is binding to message and is generated using the supplied
// 32-byte synthetic randomness.
//
// Mirrors Rust libsignal's poksho::sign at rust/poksho/src/sign.rs. The
// output bytes are byte-identical between the two implementations for
// the same inputs.
//
// Use this for signatures issued by ServerSecretParams; the receiver
// validates with Verify (or zkgroup's higher-level wrappers).
func Sign(privateKey *ristretto255.Scalar, publicKey *ristretto255.Element, message, randomness []byte) ([]byte, error) {
	st := NewStatement()
	st.Add("public_key", [][2]string{{"private_key", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("private_key", privateKey)

	pointArgs := NewPointArgs()
	pointArgs.Add("public_key", publicKey)

	return st.Prove(scalarArgs, pointArgs, message, randomness)
}

// Verify checks a Schnorr-style proof produced by Sign. It returns nil on
// success and *ErrPokshoVerificationFailure (or another typed proof
// error) when the signature does not match.
//
// Mirrors Rust libsignal's poksho::verify_signature at
// rust/poksho/src/sign.rs.
func Verify(signature []byte, publicKey *ristretto255.Element, message []byte) error {
	st := NewStatement()
	st.Add("public_key", [][2]string{{"private_key", "G"}})

	pointArgs := NewPointArgs()
	pointArgs.Add("public_key", publicKey)

	return st.VerifyProof(signature, pointArgs, message)
}
