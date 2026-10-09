# go-libsignal Documentation

> **Status: REFERENCE** · Last verified: 2026-10-09
> Index of the documents under `docs/`; each describes go-libsignal code owned by this repository.

## Architecture

- [Overview](architecture/overview.md)
- [Security model](architecture/security-model.md)
- [Design patterns](architecture/design-patterns.md)

## Protocol

- [Message types](protocol/message-types.md)
- [Serialization](protocol/serialization.md)
- [Sealed sender](protocol/sealed-sender.md)

## Sessions

- [Double Ratchet](sessions/double-ratchet.md)
- [Session cipher and builder](sessions/cipher.md)
- [Session state management](sessions/state-management.md)
- [Sesame](sessions/sesame.md)

## Groups

- [SenderKey](groups/senderkey.md)

## Post-quantum

- [Triple Ratchet](post-quantum/triple-ratchet.md)
- [SPQR](post-quantum/spqr.md)
- [ML-KEM Braid](post-quantum/mlkem-braid.md)

## Crypto

- [Cipher primitives](crypto/primitives.md)
- [KEM](crypto/kem.md)
- [Elliptic curves](crypto/ecc.md)
- [Key derivation and memory protection](crypto/key-management.md)
- [FIPS 140-3 posture](FIPS.md)

## Identity

- [Key transparency](identity/key-transparency.md)
- [Safety number fingerprints](identity/fingerprints.md)
- [Usernames](identity/usernames.md)

## Credentials

- [Poksho](credentials/poksho.md)
- [ZK credentials](credentials/zk-credentials.md)
- [ZK groups](credentials/zkgroup.md)

## Backup and recovery

- [Message backup](backup/message-backup.md)
- [Account keys](backup/account-keys.md)
- [Secure Value Recovery](backup/svr.md)
- [Device transfer](backup/device-transfer.md)
- [Media sanitization](backup/media.md)

## Network

- [Attestation](network/attestation.md)
- [Transport](network/transport.md)

## Maintainer

- [Bumping the pinned Rust libsignal commit](maintainer/bumping-rust-rev.md)

## Reference papers

- [X3DH](references/x3dh.pdf)
- [PQXDH](references/pqxdh.pdf)
- [Double Ratchet](references/doubleratchet.pdf)
- [XEdDSA](references/xeddsa.pdf)
- [Sesame](references/sesame.pdf)
- [ML-KEM Braid](references/mlkembraid.pdf)
