//go:build !fips140only

package sealed

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// destroyBeforeCopy makes every copyFromSecret source destroyed just before
// its borrow, as a concurrent enclave wipe would. It returns a counter of
// the borrows it hit and restores the no-op hook when the test ends.
func destroyBeforeCopy(t *testing.T) *int {
	t.Helper()
	hits := new(int)
	prev := beforeCopyBorrow
	beforeCopyBorrow = func(s *secret.Secret) {
		*hits++
		s.Destroy()
	}
	t.Cleanup(func() { beforeCopyBorrow = prev })
	return hits
}

func newBorrowTestUSMC(t *testing.T, senderUUID string, senderStore interface {
	GetIdentityKeyPair() *identity.KeyPair
}) *UnidentifiedSenderMessageContent {
	t.Helper()
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)
	senderCert, err := NewSenderCertificate(
		senderUUID, nil,
		senderStore.GetIdentityKeyPair().PublicKey().PublicKey(),
		1, 9999999999,
		serverCert, serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}
	usmc, err := NewUnidentifiedSenderMessageContent(2, senderCert, []byte("borrow"), ContentHintDefault, nil)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent: %v", err)
	}
	return usmc
}

func TestSealedSenderV1_DestroyedSourceFails(t *testing.T) {
	aliceStore := newTestIdentityStore(t)
	bobStore := newTestIdentityStore(t)
	bobAddress := protocol.NewSignalAddress("bob-uuid", 1)
	if _, err := aliceStore.SaveIdentity(bobAddress, identity.NewKey(bobStore.GetIdentityKeyPair().PublicKey().PublicKey())); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	usmc := newBorrowTestUSMC(t, "alice-uuid", aliceStore)

	// A valid ciphertext, made before the hook is installed, for the
	// decrypt half.
	ciphertext, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC: %v", err)
	}

	hits := destroyBeforeCopy(t)

	t.Run("encrypt", func(t *testing.T) {
		*hits = 0
		out, err := SealedSenderEncryptFromUSMC(bobAddress, usmc, aliceStore)
		if !errors.Is(err, secret.ErrSecretDestroyed) {
			t.Fatalf("err = %v, want ErrSecretDestroyed", err)
		}
		if out != nil {
			t.Fatal("encrypt returned a ciphertext from a destroyed key")
		}
		if *hits == 0 {
			t.Fatal("copyFromSecret was not reached")
		}
	})

	t.Run("decrypt", func(t *testing.T) {
		*hits = 0
		out, err := SealedSenderDecryptToUSMC(ciphertext, bobStore)
		if !errors.Is(err, secret.ErrSecretDestroyed) {
			t.Fatalf("err = %v, want ErrSecretDestroyed", err)
		}
		if out != nil {
			t.Fatal("decrypt returned a message from a destroyed key")
		}
		if *hits == 0 {
			t.Fatal("copyFromSecret was not reached")
		}
	})
}

func TestSealedSenderV2_DestroyedSourceFails(t *testing.T) {
	aliceStore, bobStore, _, bobAddress, bobSession, _ := setupV2Session(t)
	usmc := newBorrowTestUSMC(t, "9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a", aliceStore)

	addrs := []*protocol.SignalAddress{bobAddress}
	sessions := []*record.Session{bobSession}
	ciphertext, err := SealedSenderMultiRecipientEncrypt(addrs, sessions, nil, usmc, aliceStore)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt: %v", err)
	}
	bobServiceId, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobAddress.Name())
	if err != nil {
		t.Fatalf("ServiceIdFromString: %v", err)
	}

	hits := destroyBeforeCopy(t)

	t.Run("encrypt", func(t *testing.T) {
		*hits = 0
		out, err := SealedSenderMultiRecipientEncrypt(addrs, sessions, nil, usmc, aliceStore)
		if !errors.Is(err, secret.ErrSecretDestroyed) {
			t.Fatalf("err = %v, want ErrSecretDestroyed", err)
		}
		if out != nil {
			t.Fatal("encrypt returned a ciphertext from a destroyed key")
		}
		if *hits == 0 {
			t.Fatal("copyFromSecret was not reached")
		}
	})

	t.Run("decrypt", func(t *testing.T) {
		*hits = 0
		out, err := SealedSenderV2DecryptToUSMC(ciphertext, bobServiceId, bobStore)
		if !errors.Is(err, secret.ErrSecretDestroyed) {
			t.Fatalf("err = %v, want ErrSecretDestroyed", err)
		}
		if out != nil {
			t.Fatal("decrypt returned a message from a destroyed key")
		}
		if *hits == 0 {
			t.Fatal("copyFromSecret was not reached")
		}
	})
}

// TestCopyFromSecret_WrongLengthFails covers the length check: a source
// shorter than dst is refused and dst is wiped.
func TestCopyFromSecret_WrongLengthFails(t *testing.T) {
	src, err := secret.New([]byte{1, 2, 3})
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer src.Destroy()

	dst := []byte{0xAA, 0xAA, 0xAA, 0xAA}
	if err := copyFromSecret(dst, src); !errors.Is(err, ErrKeyMaterialLength) {
		t.Fatalf("err = %v, want ErrKeyMaterialLength", err)
	}
	for i, b := range dst {
		if b != 0 {
			t.Fatalf("dst[%d] = %#x, want 0", i, b)
		}
	}
}
