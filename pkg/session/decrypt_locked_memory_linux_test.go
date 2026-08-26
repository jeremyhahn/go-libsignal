//go:build linux && !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 5 tests in this file exercise X25519: each establishes a real session pair
// before measuring the locked memory a decrypt leaves behind. FIPS 140-3 does
// not approve that, but the X3DH specification (section 2.1) and the Double
// Ratchet specification (section 5.2) require it, so the fips140only build tag
// drops this file from the FIPS gate. `make test` and `make coverage` still
// run it.

package session_test

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
)

// A decrypt runs on a clone of the session state so that a failure can be
// rolled back, and that clone holds guarded buffers of its own. go-enclave
// reclaims nothing on its own, so a clone that is thrown away without being
// released costs the process locked memory permanently — and a peer can force
// that with any message that fails to decrypt. Nothing in go-enclave
// reports how many locked buffers a process holds, so this test reads the
// kernel's own accounting, VmLck in /proc/self/status, which is exactly the
// resource being consumed. The measurement is Linux-only.

// decryptAttempts is how many messages each test feeds through the cipher.
// Enough that even the smallest possible leak — one locked page per message —
// lands at twice the tolerance, few enough that a whole-clone leak still fits
// inside a default RLIMIT_MEMLOCK while it is being measured.
const decryptAttempts = 64

// lockedMemoryGrowthToleranceKB absorbs page-granularity noise from the
// allocations the runtime makes around the measurement.
const lockedMemoryGrowthToleranceKB = 128

func lockedMemoryKB(t *testing.T) int {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("read /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "VmLck:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("unexpected VmLck line: %q", line)
		}
		locked, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("parse VmLck from %q: %v", line, err)
		}
		return locked
	}
	t.Fatal("/proc/self/status has no VmLck line")
	return 0
}

// replayedMessage returns a message from Alice that Bob has already accepted.
// Decrypting it again is rejected as a duplicate, which is the cheapest way to
// drive the rollback path an attacker can drive: every replay clones Bob's
// session state, fails, and throws the clone away.
func replayedMessage(t *testing.T, aliceCipher *session.Cipher, bobCipher *session.Cipher,
	serializer *serialize.Serializer) *protocol.SignalMessage {
	t.Helper()

	encrypted, err := aliceCipher.Encrypt([]byte("replayed"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := encrypted.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	message, err := protocol.NewSignalMessageFromBytes(raw, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewSignalMessageFromBytes: %v", err)
	}
	if _, err := bobCipher.Decrypt(message); err != nil {
		t.Fatalf("first Decrypt: %v", err)
	}
	return message
}

func TestFailedDecryptDoesNotStrandLockedMemory(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	message := replayedMessage(t, aliceCipher, bobCipher, serializer)

	attempt := func() {
		if _, err := bobCipher.Decrypt(message); err == nil {
			t.Fatal("expected the replayed message to be rejected")
		}
	}

	// One attempt outside the measurement, so any one-off allocation made on
	// the way in is not counted as growth.
	attempt()

	before := lockedMemoryKB(t)
	for i := 0; i < decryptAttempts; i++ {
		attempt()
	}
	if growth := lockedMemoryKB(t) - before; growth > lockedMemoryGrowthToleranceKB {
		t.Errorf("locked memory grew by %d kB over %d failed decryptions (tolerance %d kB): the discarded working state is being abandoned",
			growth, decryptAttempts, lockedMemoryGrowthToleranceKB)
	}
}

func TestSuccessfulDecryptKeepsCommittedState(t *testing.T) {
	// The discard must not fire on the success path: the committed state owns
	// the clone's guarded material and the session has to keep working.
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// A failed decrypt in between must leave the session able to carry on.
	replayed := replayedMessage(t, aliceCipher, bobCipher, serializer)
	if _, err := bobCipher.Decrypt(replayed); err == nil {
		t.Fatal("expected the replayed message to be rejected")
	}

	for round := 0; round < 3; round++ {
		plaintext := []byte("round " + strconv.Itoa(round))
		encrypted, err := aliceCipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("round %d Encrypt: %v", round, err)
		}
		raw, err := encrypted.Serialize()
		if err != nil {
			t.Fatalf("round %d Serialize: %v", round, err)
		}
		message, err := protocol.NewSignalMessageFromBytes(raw, serializer.SignalMessage)
		if err != nil {
			t.Fatalf("round %d NewSignalMessageFromBytes: %v", round, err)
		}
		decrypted, err := bobCipher.Decrypt(message)
		if err != nil {
			t.Fatalf("round %d Decrypt: %v", round, err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("round %d: decrypted %q, want %q", round, decrypted, plaintext)
		}
	}
}

// encryptedBytes returns Alice's next message in its serialized form.
func encryptedBytes(t *testing.T, aliceCipher *session.Cipher, plaintext string) []byte {
	t.Helper()
	encrypted, err := aliceCipher.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := encrypted.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return raw
}

func parseSignalMessage(t *testing.T, raw []byte, serializer *serialize.Serializer) *protocol.SignalMessage {
	t.Helper()
	message, err := protocol.NewSignalMessageFromBytes(raw, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewSignalMessageFromBytes: %v", err)
	}
	return message
}

// tamperCipherText alters one character of the base64 ciphertext, leaving the
// ratchet key, the counter and the message's shape untouched. The result still
// parses and still routes to the same message key, but cannot be
// authenticated.
func tamperCipherText(t *testing.T, raw []byte) []byte {
	t.Helper()
	const field = `"CipherText":"`
	start := bytes.Index(raw, []byte(field))
	if start < 0 {
		t.Fatalf("serialized message has no %s field: %s", field, raw)
	}
	value := start + len(field)
	tampered := append([]byte(nil), raw...)
	if tampered[value] == 'A' {
		tampered[value] = 'B'
	} else {
		tampered[value] = 'A'
	}
	return tampered
}

// A message that matches a stored skipped message key takes those keys out of
// the clone before it authenticates them, so the clone's own cleanup no longer
// covers them. An attacker only has to replay a captured message with a
// corrupted ciphertext to drive that path.
func TestFailedSkippedKeyDecryptDoesNotStrandLockedMemory(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	first := encryptedBytes(t, aliceCipher, "first")
	second := encryptedBytes(t, aliceCipher, "second")

	// Bob accepts the second message, which stores the first one's message key
	// as a skipped key.
	if _, err := bobCipher.Decrypt(parseSignalMessage(t, second, serializer)); err != nil {
		t.Fatalf("Decrypt of the second message: %v", err)
	}

	tampered := parseSignalMessage(t, tamperCipherText(t, first), serializer)
	attempt := func() {
		if _, err := bobCipher.Decrypt(tampered); err == nil {
			t.Fatal("expected the corrupted message to be rejected")
		}
	}

	attempt()

	before := lockedMemoryKB(t)
	for i := 0; i < decryptAttempts; i++ {
		attempt()
	}
	if growth := lockedMemoryKB(t) - before; growth > lockedMemoryGrowthToleranceKB {
		t.Errorf("locked memory grew by %d kB over %d failed skipped-key decryptions (tolerance %d kB): the removed message keys are being abandoned",
			growth, decryptAttempts, lockedMemoryGrowthToleranceKB)
	}
}

// A committed decrypt hands the clone's guarded objects to the session state
// and leaves that state's previous ones with no owner, so normal traffic must
// not accumulate locked memory either.
func TestSuccessfulDecryptDoesNotStrandLockedMemory(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	// Encrypt everything up front: the measurement is of what accepting a
	// message costs Bob, not of what producing one costs Alice.
	messages := make([]*protocol.SignalMessage, decryptAttempts+1)
	for i := range messages {
		messages[i] = parseSignalMessage(t, encryptedBytes(t, aliceCipher, "accepted"), serializer)
	}

	accept := func(message *protocol.SignalMessage) {
		plaintext, err := bobCipher.Decrypt(message)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(plaintext) != "accepted" {
			t.Fatalf("decrypted %q, want %q", plaintext, "accepted")
		}
	}

	accept(messages[0])

	before := lockedMemoryKB(t)
	for _, message := range messages[1:] {
		accept(message)
	}
	if growth := lockedMemoryKB(t) - before; growth > lockedMemoryGrowthToleranceKB {
		t.Errorf("locked memory grew by %d kB over %d accepted messages (tolerance %d kB): the state the commit superseded is being abandoned",
			growth, decryptAttempts, lockedMemoryGrowthToleranceKB)
	}
}

// A back-and-forth conversation exercises what a one-way stream does not: a
// ratchet step on every turn, which replaces the sender chain, the root key and
// the chain keys on both sides.
func TestConversationDoesNotStrandLockedMemory(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	_, _, aliceCipher, bobCipher := setupSessionPair(t, serializer)

	turn := func(from, to *session.Cipher, plaintext string) {
		message := parseSignalMessage(t, encryptedBytes(t, from, plaintext), serializer)
		decrypted, err := to.Decrypt(message)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(decrypted) != plaintext {
			t.Fatalf("decrypted %q, want %q", decrypted, plaintext)
		}
	}

	exchange := func() {
		turn(aliceCipher, bobCipher, "from alice")
		turn(bobCipher, aliceCipher, "from bob")
	}

	exchange()

	before := lockedMemoryKB(t)
	for i := 0; i < decryptAttempts; i++ {
		exchange()
	}
	if growth := lockedMemoryKB(t) - before; growth > lockedMemoryGrowthToleranceKB {
		t.Errorf("locked memory grew by %d kB over %d exchanges (tolerance %d kB): the material each ratchet step supersedes is being abandoned",
			growth, decryptAttempts, lockedMemoryGrowthToleranceKB)
	}
}
