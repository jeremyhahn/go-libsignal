package kdf

import "testing"

// BenchmarkDeriveSecrets measures HKDF-SHA256 key derivation (combined extract+expand).
func BenchmarkDeriveSecrets(b *testing.B) {
	ikm := make([]byte, 32)
	salt := make([]byte, 32)
	info := []byte("Signal_bench_info")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DeriveSecrets(ikm, salt, info, 64)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkExtract measures the HKDF extract step (HMAC-SHA256 PRK computation).
func BenchmarkExtract(b *testing.B) {
	ikm := make([]byte, 32)
	salt := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Extract(ikm, salt)
	}
}

// BenchmarkExpand measures the HKDF expand step given a pre-computed PRK.
func BenchmarkExpand(b *testing.B) {
	ikm := make([]byte, 32)
	salt := make([]byte, 32)
	prk := Extract(ikm, salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Expand(prk, []byte("Signal_bench_info"), 64)
		if err != nil {
			b.Fatal(err)
		}
	}
}
