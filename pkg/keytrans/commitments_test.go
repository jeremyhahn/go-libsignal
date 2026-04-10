package keytrans

import (
	"testing"
)

func TestCommit(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		searchKey := []byte("test-key")
		data := []byte("test-data")
		nonce := &[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		c1 := Commit(searchKey, data, nonce)
		c2 := Commit(searchKey, data, nonce)

		if len(c1) != 32 {
			t.Fatalf("expected 32 byte commitment, got %d", len(c1))
		}
		for i := range c1 {
			if c1[i] != c2[i] {
				t.Fatal("same inputs should produce same commitment")
			}
		}
	})

	t.Run("different data produces different commitment", func(t *testing.T) {
		searchKey := []byte("test-key")
		nonce := &[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		c1 := Commit(searchKey, []byte("data1"), nonce)
		c2 := Commit(searchKey, []byte("data2"), nonce)

		same := true
		for i := range c1 {
			if c1[i] != c2[i] {
				same = false
				break
			}
		}
		if same {
			t.Fatal("different data should produce different commitments")
		}
	})

	t.Run("different nonce produces different commitment", func(t *testing.T) {
		searchKey := []byte("test-key")
		data := []byte("test-data")
		nonce1 := &[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		nonce2 := &[16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

		c1 := Commit(searchKey, data, nonce1)
		c2 := Commit(searchKey, data, nonce2)

		same := true
		for i := range c1 {
			if c1[i] != c2[i] {
				same = false
				break
			}
		}
		if same {
			t.Fatal("different nonces should produce different commitments")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		searchKey := []byte("test-key")
		nonce := &[16]byte{}
		c := Commit(searchKey, nil, nonce)
		if len(c) != 32 {
			t.Fatalf("expected 32 byte commitment, got %d", len(c))
		}
	})
}

func TestVerifyCommitment(t *testing.T) {
	searchKey := []byte("test-key")
	data := []byte("test-data")
	nonce := &[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	t.Run("valid commitment verifies", func(t *testing.T) {
		commitment := Commit(searchKey, data, nonce)
		if !VerifyCommitment(searchKey, commitment, data, nonce) {
			t.Fatal("valid commitment should verify")
		}
	})

	t.Run("wrong data fails", func(t *testing.T) {
		commitment := Commit(searchKey, data, nonce)
		if VerifyCommitment(searchKey, commitment, []byte("wrong"), nonce) {
			t.Fatal("wrong data should fail verification")
		}
	})

	t.Run("wrong nonce fails", func(t *testing.T) {
		commitment := Commit(searchKey, data, nonce)
		wrongNonce := &[16]byte{0}
		if VerifyCommitment(searchKey, commitment, data, wrongNonce) {
			t.Fatal("wrong nonce should fail verification")
		}
	})

	t.Run("wrong search key fails", func(t *testing.T) {
		commitment := Commit(searchKey, data, nonce)
		if VerifyCommitment([]byte("wrong-key"), commitment, data, nonce) {
			t.Fatal("wrong search key should fail verification")
		}
	})

	t.Run("tampered commitment fails", func(t *testing.T) {
		commitment := Commit(searchKey, data, nonce)
		commitment[0] ^= 0xFF
		if VerifyCommitment(searchKey, commitment, data, nonce) {
			t.Fatal("tampered commitment should fail verification")
		}
	})
}
