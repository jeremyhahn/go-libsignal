package accountkeys

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func TestErrInvalidACILength_Error(t *testing.T) {
	e := &ErrInvalidACILength{Length: 8}
	msg := e.Error()
	if !strings.Contains(msg, "16") {
		t.Errorf("expected message to mention 16, got: %s", msg)
	}
	if !strings.Contains(msg, "8") {
		t.Errorf("expected message to mention 8, got: %s", msg)
	}
}

func TestErrGeneratingRandomEntropy_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("rng fail")
	e := &ErrGeneratingRandomEntropy{Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "rng fail") {
		t.Errorf("expected inner error in message, got: %s", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should expose inner error")
	}
}

func TestErrEntropyPoolLength_Error(t *testing.T) {
	e := &ErrEntropyPoolLength{Expected: 64, Got: 10}
	msg := e.Error()
	if !strings.Contains(msg, "64") {
		t.Errorf("expected 64 in message, got: %s", msg)
	}
	if !strings.Contains(msg, "10") {
		t.Errorf("expected 10 in message, got: %s", msg)
	}
}

func TestErrEntropyPoolInvalidChar_Error(t *testing.T) {
	e := &ErrEntropyPoolInvalidChar{Position: 42}
	msg := e.Error()
	if !strings.Contains(msg, "42") {
		t.Errorf("expected position 42 in message, got: %s", msg)
	}
}

func TestErrSecuringSecret_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("alloc failed")
	e := &ErrSecuringSecret{Operation: "SVR key", Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "SVR key") {
		t.Errorf("expected operation in message, got: %s", msg)
	}
	if !strings.Contains(msg, "alloc failed") {
		t.Errorf("expected inner error in message, got: %s", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should expose inner error")
	}
}

func TestErrInvalidSaltLength_Error(t *testing.T) {
	e := &ErrInvalidSaltLength{Expected: 32, Got: 16}
	msg := e.Error()
	if !strings.Contains(msg, "32") {
		t.Errorf("expected 32 in message, got: %s", msg)
	}
	if !strings.Contains(msg, "16") {
		t.Errorf("expected 16 in message, got: %s", msg)
	}
}

func TestErrEmptyPIN_Error(t *testing.T) {
	e := &ErrEmptyPIN{}
	msg := e.Error()
	if !strings.Contains(msg, "empty") {
		t.Errorf("expected 'empty' in message, got: %s", msg)
	}
}

func TestErrGeneratingSalt_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("os.Read failed")
	e := &ErrGeneratingSalt{Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "os.Read failed") {
		t.Errorf("expected inner error in message, got: %s", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should expose inner error")
	}
}

func TestErrInvalidPHCString_ErrorAndUnwrap(t *testing.T) {
	t.Run("with inner error", func(t *testing.T) {
		inner := errors.New("bad format")
		e := &ErrInvalidPHCString{Err: inner}
		msg := e.Error()
		if !strings.Contains(msg, "bad format") {
			t.Errorf("expected inner error in message, got: %s", msg)
		}
		if !errors.Is(e, inner) {
			t.Error("Unwrap should expose inner error")
		}
	})

	t.Run("without inner error", func(t *testing.T) {
		e := &ErrInvalidPHCString{}
		msg := e.Error()
		if !strings.Contains(msg, "invalid PHC string") {
			t.Errorf("expected 'invalid PHC string' in message, got: %s", msg)
		}
	})
}

func TestErrPHCInvalidSaltEncoding_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("base64 decode error")
	e := &ErrPHCInvalidSaltEncoding{Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "base64 decode error") {
		t.Errorf("expected inner error in message, got: %s", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should expose inner error")
	}
}

func TestErrPHCInvalidHashEncoding_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("hash decode error")
	e := &ErrPHCInvalidHashEncoding{Err: inner}
	msg := e.Error()
	if !strings.Contains(msg, "hash decode error") {
		t.Errorf("expected inner error in message, got: %s", msg)
	}
	if !errors.Is(e, inner) {
		t.Error("Unwrap should expose inner error")
	}
}

func TestErrPHCInvalidFormat_Error(t *testing.T) {
	e := &ErrPHCInvalidFormat{}
	msg := e.Error()
	if !strings.Contains(msg, "invalid PHC string format") {
		t.Errorf("expected 'invalid PHC string format' in message, got: %s", msg)
	}
}

// TestErrorsAsTypes verifies the error types are distinguishable via errors.As.
func TestErrorsAsTypes(t *testing.T) {
	// Trigger ErrEntropyPoolLength via Validate.
	pool := AccountEntropyPool("tooshort")
	err := pool.Validate()
	var lenErr *ErrEntropyPoolLength
	if !errors.As(err, &lenErr) {
		t.Errorf("expected ErrEntropyPoolLength, got: %T", err)
	}

	// Trigger ErrEntropyPoolInvalidChar via Validate.
	invalidPool := AccountEntropyPool(strings.Repeat("A", 64))
	err = invalidPool.Validate()
	var charErr *ErrEntropyPoolInvalidChar
	if !errors.As(err, &charErr) {
		t.Errorf("expected ErrEntropyPoolInvalidChar, got: %T", err)
	}

	// Trigger ErrInvalidSaltLength via HashPin.
	_, err = HashPin("pin", make([]byte, 5))
	var saltErr *ErrInvalidSaltLength
	if !errors.As(err, &saltErr) {
		t.Errorf("expected ErrInvalidSaltLength, got: %T", err)
	}
	if saltErr.Got != 5 {
		t.Errorf("expected Got=5, got: %d", saltErr.Got)
	}

	// Trigger ErrEmptyPIN via HashPin.
	_, err = HashPin("  ", make([]byte, 32))
	var pinErr *ErrEmptyPIN
	if !errors.As(err, &pinErr) {
		t.Errorf("expected ErrEmptyPIN, got: %T", err)
	}

	// Trigger ErrInvalidACILength via DeriveBackupId.
	pool64 := AccountEntropyPool(strings.Repeat("a", 64))
	bk, bkErr := pool64.DeriveBackupKey()
	if bkErr != nil {
		t.Fatalf("unexpected error deriving backup key: %v", bkErr)
	}
	defer bk.Destroy()

	// Use the backup_forward_secrecy BackupKey to trigger ErrInvalidACILength.
	rawKey := [BackupKeyLength]byte{}
	copy(rawKey[:], secrettest.Bytes(bk))
	backupKey := NewBackupKey(rawKey)
	defer backupKey.Zeroize()

	_, err = backupKey.DeriveBackupId([]byte{1, 2, 3})
	var aciErr *ErrInvalidACILength
	if !errors.As(err, &aciErr) {
		t.Errorf("expected ErrInvalidACILength, got: %T", err)
	}
	if aciErr.Length != 3 {
		t.Errorf("expected Length=3, got: %d", aciErr.Length)
	}

	// Trigger ErrInvalidPHCString via VerifyLocalPinHash.
	_, err = VerifyLocalPinHash("pin", "not-a-phc-string")
	var phcErr *ErrInvalidPHCString
	if !errors.As(err, &phcErr) {
		t.Errorf("expected ErrInvalidPHCString, got: %T", err)
	}
}
