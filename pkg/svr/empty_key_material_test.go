package svr

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// TestEncryptionKeyFromSecrets_EmptyInputs checks that the encryption key
// is never derived from an sEnc or kAuth that holds no material.
func TestEncryptionKeyFromSecrets_EmptyInputs(t *testing.T) {
	newLive := func() *secret.Secret {
		s, err := secret.New(make([]byte, 32))
		if err != nil {
			t.Fatalf("secret.New: %v", err)
		}
		return s
	}
	sEnc, kAuth := newLive(), newLive()
	defer sEnc.Destroy()
	defer kAuth.Destroy()

	for name, in := range map[string][2]*secret.Secret{
		"nil sEnc":   {nil, kAuth},
		"zero kAuth": {sEnc, {}},
		"both nil":   {nil, nil},
	} {
		func() {
			defer func() {
				r := recover()
				msg, _ := r.(string)
				if !strings.Contains(msg, errEmptyKeyMaterial.Error()) {
					t.Errorf("%s: want a panic with %v, got %v", name, errEmptyKeyMaterial, r)
				}
			}()
			encryptionKeyFromSecrets(in[0], in[1])
		}()
	}

	out := encryptionKeyFromSecrets(sEnc, kAuth)
	if out == nil {
		t.Fatal("live inputs: want a key")
	}
	out.Destroy()
}
