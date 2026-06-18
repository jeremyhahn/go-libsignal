package ecc

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/logger"
)

// noopLogger satisfies logger.Loggable and discards all output.
// Installed by TestMain so benchmark runs stay clean of debug lines.
type noopLogger struct{}

func (noopLogger) Debug(caller, message string)   {}
func (noopLogger) Info(caller, message string)    {}
func (noopLogger) Warning(caller, message string) {}
func (noopLogger) Error(caller, message string)   {}
func (noopLogger) Configure(settings string)      {}

func TestMain(m *testing.M) {
	var l logger.Loggable = noopLogger{}
	logger.Setup(&l)
	os.Exit(m.Run())
}

// BenchmarkGenerateKeyPair measures X25519 key-pair generation.
func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCalculateSignature measures XEdDSA sign over a 64-byte message.
func BenchmarkCalculateSignature(b *testing.B) {
	kp, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 64)
	priv := kp.PrivateKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CalculateSignature(priv, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifySignature measures XEdDSA verify over a 64-byte message.
func BenchmarkVerifySignature(b *testing.B) {
	kp, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 64)
	sig, err := CalculateSignature(kp.PrivateKey(), msg)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifySignature(kp.PublicKey(), msg, sig)
	}
}
