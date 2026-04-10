package backup

import (
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/accountkeys"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

const fakeAccountEntropyPool = "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l"

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func fakeACI() protocol.ServiceId {
	var uuid [16]byte
	copy(uuid[:], mustDecodeHex("659aa5f4a28dfcc11ea1b997537a3d95"))
	return protocol.NewACI(uuid)
}

func TestDeriveBackupKey(t *testing.T) {
	pool := accountkeys.AccountEntropyPool(fakeAccountEntropyPool)
	bk, err := DeriveBackupKey(pool)
	if err != nil {
		t.Fatalf("DeriveBackupKey: %v", err)
	}
	defer bk.Zeroize()

	expected := mustDecodeHex("ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985")
	if hex.EncodeToString(bk.key.Bytes()) != hex.EncodeToString(expected) {
		t.Errorf("backup key mismatch:\n  got  %x\n  want %x", bk.key.Bytes(), expected)
	}
}

func TestDeriveBackupID(t *testing.T) {
	pool := accountkeys.AccountEntropyPool(fakeAccountEntropyPool)
	bk, err := DeriveBackupKey(pool)
	if err != nil {
		t.Fatalf("DeriveBackupKey: %v", err)
	}
	defer bk.Zeroize()

	id, err := bk.DeriveBackupID(fakeACI())
	if err != nil {
		t.Fatalf("DeriveBackupID: %v", err)
	}

	expected := mustDecodeHex("8a624fbc45379043f39f1391cddc5fe8")
	if hex.EncodeToString(id.id[:]) != hex.EncodeToString(expected) {
		t.Errorf("backup ID mismatch:\n  got  %x\n  want %x", id.id, expected)
	}
}

func TestDeriveMessageBackupKeyLegacy(t *testing.T) {
	pool := accountkeys.AccountEntropyPool(fakeAccountEntropyPool)
	bk, err := DeriveBackupKey(pool)
	if err != nil {
		t.Fatalf("DeriveBackupKey: %v", err)
	}
	defer bk.Zeroize()

	id, err := bk.DeriveBackupID(fakeACI())
	if err != nil {
		t.Fatalf("DeriveBackupID: %v", err)
	}

	mk, err := DeriveMessageBackupKey(bk, id, nil)
	if err != nil {
		t.Fatalf("DeriveMessageBackupKey: %v", err)
	}
	defer mk.Zeroize()

	expectedHMAC := mustDecodeHex("f425e22a607c529717e1e1b29f9fe139f9d1c7e7d01e371c7753c544a3026649")
	expectedAES := mustDecodeHex("e143f4ad5668d8bfed2f88562f0693f53bda2c0e55c9d71730f30e24695fd6df")

	if hex.EncodeToString(mk.HMACKey.Bytes()) != hex.EncodeToString(expectedHMAC) {
		t.Errorf("HMAC key mismatch:\n  got  %x\n  want %x", mk.HMACKey.Bytes(), expectedHMAC)
	}
	if hex.EncodeToString(mk.AESKey.Bytes()) != hex.EncodeToString(expectedAES) {
		t.Errorf("AES key mismatch:\n  got  %x\n  want %x", mk.AESKey.Bytes(), expectedAES)
	}
}

func TestDeriveMessageBackupKeyWithForwardSecrecy(t *testing.T) {
	pool := accountkeys.AccountEntropyPool(fakeAccountEntropyPool)
	bk, err := DeriveBackupKey(pool)
	if err != nil {
		t.Fatalf("DeriveBackupKey: %v", err)
	}
	defer bk.Zeroize()

	id, err := bk.DeriveBackupID(fakeACI())
	if err != nil {
		t.Fatalf("DeriveBackupID: %v", err)
	}

	token := mustDecodeHex("69207061737320746865206b6e69666520746f207468652061786f6c6f746c21")
	mk, err := DeriveMessageBackupKey(bk, id, token)
	if err != nil {
		t.Fatalf("DeriveMessageBackupKey: %v", err)
	}
	defer mk.Zeroize()

	expectedHMAC := mustDecodeHex("20e6ab57b87e051f3e695e953cf8a261dd307e4f92ae2921673f1d397e07887b")
	expectedAES := mustDecodeHex("602af6ecfc09d695a8d58da9f18225e967979c5e03543ca0224a03cca3d9735e")

	if hex.EncodeToString(mk.HMACKey.Bytes()) != hex.EncodeToString(expectedHMAC) {
		t.Errorf("HMAC key mismatch:\n  got  %x\n  want %x", mk.HMACKey.Bytes(), expectedHMAC)
	}
	if hex.EncodeToString(mk.AESKey.Bytes()) != hex.EncodeToString(expectedAES) {
		t.Errorf("AES key mismatch:\n  got  %x\n  want %x", mk.AESKey.Bytes(), expectedAES)
	}
}
