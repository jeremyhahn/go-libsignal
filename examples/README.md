# go-libsignal Examples

Runnable end-to-end examples demonstrating the Signal Protocol in Go.
Each example is a single self-contained `main.go` that uses freshly generated keys on every run.

## Prerequisites

All examples require `GOWORK=off` because the parent `go.work` file pins a newer
toolchain than this module's `go.mod`.

## Examples

### simple-session

Minimal Alice-to-Bob single-message exchange via X3DH key agreement and Double Ratchet.
Alice generates a pre-key bundle, Bob processes it to establish the session, Alice encrypts
"Hello, Bob!" as a `PreKeySignalMessage`, Bob decrypts and prints the plaintext.

```
GOWORK=off go run ./examples/simple-session/
```

Expected output:
```
Alice -> Bob: Hello, Bob!
```

### sealed-sender

Alice sends a Sealed Sender V1 message to Bob. A trust-root key pair and server certificate
are generated in memory. Alice's `SenderCertificate` is signed by the server key. After
establishing a session via X3DH (PQXDH), Alice encrypts with `SealedSenderEncrypt` and Bob
decrypts with `SealedSenderDecryptWithKyber`, recovering both the plaintext and Alice's UUID.

```
GOWORK=off go run ./examples/sealed-sender/
```

Expected output:
```
Bob received from alice-00000000-0000-0000-0000-000000000001: Hello, Bob! This is sealed.
```

### group-messaging

Alice creates a SenderKey group, distributes a `SenderKeyDistributionMessage` to Bob and
Charlie, then encrypts "Hello, group!" with `GroupCipher.Encrypt`. Bob and Charlie each
independently decrypt the ciphertext via their own `GroupCipher.Decrypt` instances.

```
GOWORK=off go run ./examples/group-messaging/
```

Expected output:
```
Bob received from Alice: Hello, group!
Charlie received from Alice: Hello, group!
```
