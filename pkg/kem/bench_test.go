package kem

import "testing"

// BenchmarkMLKEM768KeyGen measures ML-KEM-768 key-pair generation.
func BenchmarkMLKEM768KeyGen(b *testing.B) {
	scheme := NewMLKEM768KEM()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scheme.Generate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLKEM768Encapsulate measures ML-KEM-768 encapsulation (shared secret + ciphertext).
func BenchmarkMLKEM768Encapsulate(b *testing.B) {
	scheme := NewMLKEM768KEM()
	kp, err := scheme.Generate()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := scheme.Encapsulate(kp.Public)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMLKEM768Decapsulate measures ML-KEM-768 decapsulation.
func BenchmarkMLKEM768Decapsulate(b *testing.B) {
	scheme := NewMLKEM768KEM()
	kp, err := scheme.Generate()
	if err != nil {
		b.Fatal(err)
	}
	_, ct, err := scheme.Encapsulate(kp.Public)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scheme.Decapsulate(kp.Secret, ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}
