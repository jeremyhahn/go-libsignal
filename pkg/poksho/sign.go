package poksho

import "github.com/gtank/ristretto255"

// Sign returns a Schnorr-style proof of knowledge of publicKey's discrete log, bound to message, byte-identical to Rust poksho::sign.
func Sign(privateKey *ristretto255.Scalar, publicKey *ristretto255.Element, message, randomness []byte) ([]byte, error) {
	st := NewStatement()
	st.Add("public_key", [][2]string{{"private_key", "G"}})

	scalarArgs := NewScalarArgs()
	scalarArgs.Add("private_key", privateKey)

	pointArgs := NewPointArgs()
	pointArgs.Add("public_key", publicKey)

	return st.Prove(scalarArgs, pointArgs, message, randomness)
}

// Verify checks a Sign signature, returning *ErrPokshoVerificationFailure or another typed error on mismatch.
func Verify(signature []byte, publicKey *ristretto255.Element, message []byte) error {
	st := NewStatement()
	st.Add("public_key", [][2]string{{"private_key", "G"}})

	pointArgs := NewPointArgs()
	pointArgs.Add("public_key", publicKey)

	return st.VerifyProof(signature, pointArgs, message)
}
