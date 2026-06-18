// wire_emitter: deterministic wire-format fixture generator for go-libsignal interop.
//
// Rust source: tests/interop/rust/src/bin/wire_emitter.rs (libsignal v0.92.2)
// Upstream pin: 98915c442d
//
// Usage: wire_emitter --out <DIR>
//
// Writes six JSON fixture files under <DIR>:
//   sealed_sender_v1.json
//   sealed_sender_v2_received.json
//   sealed_sender_v2_multi.json
//   senderkey_distribution.json
//   senderkey_message.json
//   fingerprint.json
//
// All randomness is sourced from ChaCha20Rng seeded at 0xC0DECAFE so that
// re-running the binary produces byte-identical JSON.

use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result};
use clap::Parser;
use libsignal_protocol::{
    Aci, ContentHint, CiphertextMessageType, DeviceId, Fingerprint, GenericSignedPreKey,
    IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemIdentityKeyStore, InMemSenderKeyStore,
    InMemSignalProtocolStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PlaintextContent, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeyStore, PreKeySignalMessage,
    ProtocolAddress, SealedSenderV2SentMessage, SenderCertificate, ServerCertificate, ServiceId,
    SessionStore, SignalMessage, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
    UnidentifiedSenderMessageContent, create_sender_key_distribution_message,
    group_encrypt, kem, process_prekey_bundle, sealed_sender_encrypt_from_usmc,
    sealed_sender_multi_recipient_encrypt,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use spqr::{initial_state, send, ChainParams, Direction, Params, Version};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "wire_emitter", about = "Emit deterministic wire-format fixtures for go-libsignal")]
struct Cli {
    /// Output directory for the six wire/* JSON fixture files.
    #[arg(long)]
    out: String,
    /// Optional path for the messagebackup/frame_aes.json fixture (C2). When
    /// supplied, also emits AES-256-CBC+PKCS7 vectors using the same `aes`
    /// and `cbc` crates that rust/message-backup/src/export.rs uses, so the
    /// fixture bytes are sourced from Rust rather than Go.
    #[arg(long)]
    frame_aes_out: Option<String>,
}

// ---------------------------------------------------------------------------
// JSON schema types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Fixture {
    source: &'static str,
    rust_rev: &'static str,
    purpose: &'static str,
    vectors: Vec<Vector>,
}

#[derive(Serialize)]
struct Vector {
    name: String,
    inputs: serde_json::Value,
    expected: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RUST_REV: &str = "98915c442d";

const ALICE_UUID: &str = "11111111-1111-1111-1111-111111111111";
const BOB_UUID: &str = "22222222-2222-2222-2222-222222222222";
const CAROL_UUID: &str = "33333333-3333-3333-3333-333333333333";
const DAVE_UUID: &str = "44444444-4444-4444-4444-444444444444";

const ALICE_DEVICE: u8 = 1;
const BOB_DEVICE: u8 = 1;
const CAROL_DEVICE: u8 = 1;
const DAVE_DEVICE: u8 = 1;

// Fixed certificate expiry — well in the future, irrelevant for wire format.
const CERT_EXPIRY_MS: u64 = 4_102_444_800_000; // 2100-01-01 00:00:00 UTC

// Fixed plaintext for all encryption fixtures.
const PLAINTEXT: &[u8] = b"wave-d-fixture-plaintext";

// Shared SPQR auth key — must match the value the Go consumer uses so both
// sides derive identical chain keys. Identical to the live harness AUTH_KEY in
// tests/interop/rust/src/main.rs.
const SPQR_AUTH_KEY: &[u8; 32] = b"interop-shared-auth-key-32bytes!";

// Deterministic seed for the SPQR send RNG. The pq_ratchet wire message embeds
// freshly generated KEM/ratchet material, so reproducibility requires a fixed
// RNG seed independent of the shared fixture RNG.
const SPQR_SEND_SEED: u64 = 0x5051_5253;

// ---------------------------------------------------------------------------
// Helper: build an InMemSignalProtocolStore with seeded identity key pair.
// ---------------------------------------------------------------------------

fn make_store(rng: &mut ChaCha20Rng) -> Result<InMemSignalProtocolStore> {
    let identity_key = IdentityKeyPair::generate(rng);
    InMemSignalProtocolStore::new(identity_key, 1234).context("InMemSignalProtocolStore::new")
}

// ---------------------------------------------------------------------------
// Helper: create a PreKeyBundle and persist the key material in `store`,
// returning the bundle for the remote side to consume.
// ---------------------------------------------------------------------------

async fn create_and_store_prekey_bundle(
    store: &mut InMemSignalProtocolStore,
    rng: &mut ChaCha20Rng,
) -> Result<PreKeyBundle> {
    let pre_key_pair = KeyPair::generate(rng);
    let signed_pre_key_pair = KeyPair::generate(rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);

    let identity_kp = store.identity_store.get_identity_key_pair().await?;

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = identity_kp
        .private_key()
        .calculate_signature(&signed_pre_key_public, rng)?;

    let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
    let kyber_pre_key_signature = identity_kp
        .private_key()
        .calculate_signature(&kyber_pre_key_public, rng)?;

    let pre_key_id: PreKeyId = 1u32.into();
    let signed_pre_key_id: SignedPreKeyId = 1u32.into();
    let kyber_pre_key_id: KyberPreKeyId = 1u32.into();
    let device_id = DeviceId::new(BOB_DEVICE).unwrap();

    let registration_id = store.identity_store.get_local_registration_id().await?;
    let identity_key = *identity_kp.identity_key();

    let bundle = PreKeyBundle::new(
        registration_id,
        device_id,
        Some((pre_key_id, pre_key_pair.public_key)),
        signed_pre_key_id,
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        kyber_pre_key_id,
        kyber_pre_key_pair.public_key.clone(),
        kyber_pre_key_signature.to_vec(),
        identity_key,
    )?;

    let ts = Timestamp::from_epoch_millis(1_000_000);

    store
        .pre_key_store
        .save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key_pair))
        .await?;

    store
        .signed_pre_key_store
        .save_signed_pre_key(
            signed_pre_key_id,
            &SignedPreKeyRecord::new(
                signed_pre_key_id,
                ts,
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
        )
        .await?;

    store
        .kyber_pre_key_store
        .save_kyber_pre_key(
            kyber_pre_key_id,
            &KyberPreKeyRecord::new(
                kyber_pre_key_id,
                ts,
                &kyber_pre_key_pair,
                &kyber_pre_key_signature,
            ),
        )
        .await?;

    Ok(bundle)
}

// ---------------------------------------------------------------------------
// D1 — Sealed Sender v1
// ---------------------------------------------------------------------------
//
// Rust source: rust/protocol/src/sealed_sender.rs — sealed_sender_encrypt_from_usmc
//
// All key material is derived from the shared RNG so the output is fully
// reproducible. The fixture records raw private-key bytes so the Go side can
// reconstruct the exact same keys.

async fn emit_sealed_sender_v1(rng: &mut ChaCha20Rng) -> Result<Fixture> {
    use libsignal_protocol::CiphertextMessageType;

    // Key material.
    let trust_root_kp = KeyPair::generate(rng);
    let server_key_kp = KeyPair::generate(rng);
    let alice_identity = IdentityKeyPair::generate(rng);
    let bob_identity = IdentityKeyPair::generate(rng);

    // Server certificate.
    let server_cert = ServerCertificate::new(
        1,
        server_key_kp.public_key,
        &trust_root_kp.private_key,
        rng,
    )?;

    // Sender certificate.
    let alice_device_id = DeviceId::new(ALICE_DEVICE).unwrap();
    let expires = Timestamp::from_epoch_millis(CERT_EXPIRY_MS);
    let sender_cert = SenderCertificate::new(
        ALICE_UUID.to_string(),
        Some("+14151111111".to_string()),
        alice_identity.public_key().clone(),
        alice_device_id,
        expires,
        server_cert,
        &server_key_kp.private_key,
        rng,
    )?;

    // Alice's identity store knows Bob's public identity key.
    let mut alice_identity_store = InMemIdentityKeyStore::new(alice_identity, 1001);
    let bob_address = ProtocolAddress::new(
        BOB_UUID.to_string(),
        DeviceId::new(BOB_DEVICE).unwrap(),
    );
    alice_identity_store
        .save_identity(&bob_address, &IdentityKey::new(bob_identity.public_key().clone()))
        .await?;

    // Build USMC with plaintext content type.
    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::Plaintext,
        sender_cert.clone(),
        PLAINTEXT.to_vec(),
        ContentHint::Default,
        None,
    )?;

    // Encrypt.
    let ciphertext =
        sealed_sender_encrypt_from_usmc(&bob_address, &usmc, &alice_identity_store, rng).await?;

    let inputs = serde_json::json!({
        "trust_root_private_key": hex::encode(trust_root_kp.private_key.serialize()),
        "trust_root_public_key":  hex::encode(trust_root_kp.public_key.serialize()),
        "server_key_private_key": hex::encode(server_key_kp.private_key.serialize()),
        "server_key_public_key":  hex::encode(server_key_kp.public_key.serialize()),
        "alice_identity_private": hex::encode(alice_identity.private_key().serialize()),
        "alice_identity_public":  hex::encode(alice_identity.public_key().serialize()),
        "bob_identity_private":   hex::encode(bob_identity.private_key().serialize()),
        "bob_identity_public":    hex::encode(bob_identity.public_key().serialize()),
        "alice_uuid":             ALICE_UUID,
        "alice_device_id":        ALICE_DEVICE,
        "alice_e164":             "+14151111111",
        "bob_uuid":               BOB_UUID,
        "bob_device_id":          BOB_DEVICE,
        "cert_expiry_ms":         CERT_EXPIRY_MS,
        "plaintext":              hex::encode(PLAINTEXT),
        "sender_cert_serialized": hex::encode(sender_cert.serialized()?),
    });

    let expected = serde_json::json!({
        "ciphertext": hex::encode(&ciphertext),
    });

    Ok(Fixture {
        source: "rust/protocol/src/sealed_sender.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "Sealed Sender v1: encrypt a fixed plaintext and produce the wire-format ciphertext bytes.",
        vectors: vec![Vector {
            name: "sealed_sender_v1_encrypt".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// D2 — Sealed Sender v2 received-format (single recipient Bob)
// D3 — Sealed Sender v2 multi-recipient (3 recipients: Bob, Carol, Dave)
//
// Rust source: rust/protocol/src/sealed_sender.rs — sealed_sender_multi_recipient_encrypt,
//              SealedSenderV2SentMessage::received_message_parts_for_recipient
// ---------------------------------------------------------------------------

async fn emit_sealed_sender_v2(rng: &mut ChaCha20Rng) -> Result<(Fixture, Fixture)> {
    use libsignal_protocol::CiphertextMessageType;

    // ---- Sender ----
    let mut alice_store = make_store(rng)?;

    // ---- Recipients ----
    let mut bob_store = make_store(rng)?;
    let mut carol_store = make_store(rng)?;
    let mut dave_store = make_store(rng)?;

    let bob_address = ProtocolAddress::new(BOB_UUID.to_string(), DeviceId::new(BOB_DEVICE).unwrap());
    let carol_address = ProtocolAddress::new(CAROL_UUID.to_string(), DeviceId::new(CAROL_DEVICE).unwrap());
    let dave_address = ProtocolAddress::new(DAVE_UUID.to_string(), DeviceId::new(DAVE_DEVICE).unwrap());

    // Build prekey bundles and establish sessions for all three recipients.
    let bob_bundle = create_and_store_prekey_bundle(&mut bob_store, rng).await?;
    let carol_bundle = create_and_store_prekey_bundle(&mut carol_store, rng).await?;
    let dave_bundle = create_and_store_prekey_bundle(&mut dave_store, rng).await?;

    process_prekey_bundle(
        &bob_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle,
        SystemTime::UNIX_EPOCH,
        rng,
    )
    .await?;
    process_prekey_bundle(
        &carol_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &carol_bundle,
        SystemTime::UNIX_EPOCH,
        rng,
    )
    .await?;
    process_prekey_bundle(
        &dave_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &dave_bundle,
        SystemTime::UNIX_EPOCH,
        rng,
    )
    .await?;

    // Capture identity keys for fixture inputs.
    let alice_identity = alice_store.identity_store.get_identity_key_pair().await?;
    let bob_identity = bob_store.identity_store.get_identity_key_pair().await?;
    let carol_identity = carol_store.identity_store.get_identity_key_pair().await?;
    let dave_identity = dave_store.identity_store.get_identity_key_pair().await?;

    // ---- Certificates ----
    let trust_root_kp = KeyPair::generate(rng);
    let server_key_kp = KeyPair::generate(rng);
    let server_cert = ServerCertificate::new(
        1,
        server_key_kp.public_key,
        &trust_root_kp.private_key,
        rng,
    )?;
    let alice_device_id = DeviceId::new(ALICE_DEVICE).unwrap();
    let expires = Timestamp::from_epoch_millis(CERT_EXPIRY_MS);
    let sender_cert = SenderCertificate::new(
        ALICE_UUID.to_string(),
        Some("+14151111111".to_string()),
        alice_identity.public_key().clone(),
        alice_device_id,
        expires,
        server_cert,
        &server_key_kp.private_key,
        rng,
    )?;

    // ---- USMC ----
    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::Plaintext,
        sender_cert.clone(),
        PLAINTEXT.to_vec(),
        ContentHint::Default,
        None,
    )?;

    // ---- Load sessions for multi-recipient encrypt ----
    let bob_session = alice_store
        .session_store
        .load_session(&bob_address)
        .await?
        .expect("session established above");
    let carol_session = alice_store
        .session_store
        .load_session(&carol_address)
        .await?
        .expect("session established above");
    let dave_session = alice_store
        .session_store
        .load_session(&dave_address)
        .await?
        .expect("session established above");

    let destinations = [&bob_address, &carol_address, &dave_address];
    let sessions = [&bob_session, &carol_session, &dave_session];

    let sent_message = sealed_sender_multi_recipient_encrypt(
        &destinations,
        &sessions,
        std::iter::empty::<ServiceId>(),
        &usmc,
        &alice_store.identity_store,
        rng,
    )
    .await?;

    // ---- Parse sent message → per-recipient received messages ----
    let parsed = SealedSenderV2SentMessage::parse(&sent_message)?;

    let bob_service_id = ServiceId::from(Aci::from_uuid_bytes(
        *Uuid::parse_str(BOB_UUID).unwrap().as_bytes(),
    ));
    let carol_service_id = ServiceId::from(Aci::from_uuid_bytes(
        *Uuid::parse_str(CAROL_UUID).unwrap().as_bytes(),
    ));
    let dave_service_id = ServiceId::from(Aci::from_uuid_bytes(
        *Uuid::parse_str(DAVE_UUID).unwrap().as_bytes(),
    ));

    let bob_received: Vec<u8> = parsed
        .recipients
        .get(&bob_service_id)
        .map(|r| parsed.received_message_parts_for_recipient(r).as_ref().concat())
        .unwrap_or_default();
    let carol_received: Vec<u8> = parsed
        .recipients
        .get(&carol_service_id)
        .map(|r| parsed.received_message_parts_for_recipient(r).as_ref().concat())
        .unwrap_or_default();
    let dave_received: Vec<u8> = parsed
        .recipients
        .get(&dave_service_id)
        .map(|r| parsed.received_message_parts_for_recipient(r).as_ref().concat())
        .unwrap_or_default();

    let common_inputs = serde_json::json!({
        "alice_identity_private": hex::encode(alice_identity.private_key().serialize()),
        "alice_identity_public":  hex::encode(alice_identity.public_key().serialize()),
        "alice_uuid":             ALICE_UUID,
        "alice_device_id":        ALICE_DEVICE,
        "alice_e164":             "+14151111111",
        "bob_identity_private":   hex::encode(bob_identity.private_key().serialize()),
        "bob_identity_public":    hex::encode(bob_identity.public_key().serialize()),
        "bob_uuid":               BOB_UUID,
        "bob_device_id":          BOB_DEVICE,
        "carol_identity_public":  hex::encode(carol_identity.public_key().serialize()),
        "carol_uuid":             CAROL_UUID,
        "carol_device_id":        CAROL_DEVICE,
        "dave_identity_public":   hex::encode(dave_identity.public_key().serialize()),
        "dave_uuid":              DAVE_UUID,
        "dave_device_id":         DAVE_DEVICE,
        "trust_root_public_key":  hex::encode(trust_root_kp.public_key.serialize()),
        "cert_expiry_ms":         CERT_EXPIRY_MS,
        "plaintext":              hex::encode(PLAINTEXT),
        "sender_cert_serialized": hex::encode(sender_cert.serialized()?),
    });

    // D2: received-format for Bob (first recipient).
    let d2 = Fixture {
        source: "rust/protocol/src/sealed_sender.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "Sealed Sender v2 received-format: per-recipient received-message bytes for a single recipient.",
        vectors: vec![Vector {
            name: "sealed_sender_v2_bob_received".to_string(),
            inputs: common_inputs.clone(),
            expected: serde_json::json!({
                "bob_received_message": hex::encode(&bob_received),
            }),
        }],
    };

    // D3: full sent message + all three received messages.
    let d3 = Fixture {
        source: "rust/protocol/src/sealed_sender.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "Sealed Sender v2 multi-recipient: full sent-message bytes and per-recipient received-message bytes for 3 recipients.",
        vectors: vec![Vector {
            name: "sealed_sender_v2_multi_3recipients".to_string(),
            inputs: common_inputs,
            expected: serde_json::json!({
                "sent_message":           hex::encode(&sent_message),
                "bob_received_message":   hex::encode(&bob_received),
                "carol_received_message": hex::encode(&carol_received),
                "dave_received_message":  hex::encode(&dave_received),
            }),
        }],
    };

    Ok((d2, d3))
}

// ---------------------------------------------------------------------------
// D4 — SenderKeyDistributionMessage
// D5 — SenderKeyMessage
//
// Rust source: rust/protocol/src/group_cipher.rs — create_sender_key_distribution_message,
//              group_encrypt
// ---------------------------------------------------------------------------

async fn emit_sender_key(rng: &mut ChaCha20Rng) -> Result<(Fixture, Fixture)> {

    // Fixed distribution ID — stable across runs.
    let distribution_id = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();

    let alice_address = ProtocolAddress::new(
        ALICE_UUID.to_string(),
        DeviceId::new(ALICE_DEVICE).unwrap(),
    );
    let mut alice_sender_key_store = InMemSenderKeyStore::new();

    // create_sender_key_distribution_message initialises fresh key material.
    let skdm = create_sender_key_distribution_message(
        &alice_address,
        distribution_id,
        &mut alice_sender_key_store,
        rng,
    )
    .await?;

    let skdm_serialized = skdm.serialized().to_vec();

    let signing_key_pub = skdm.signing_key()?;
    let chain_key_bytes = skdm.chain_key()?;

    let d4_inputs = serde_json::json!({
        "alice_uuid":             ALICE_UUID,
        "alice_device_id":        ALICE_DEVICE,
        "distribution_id":        distribution_id.to_string(),
        "message_version":        skdm.message_version(),
        "chain_id":               skdm.chain_id()?,
        "iteration":              skdm.iteration()?,
        "chain_key":              hex::encode(chain_key_bytes),
        "signing_key_public":     hex::encode(signing_key_pub.serialize()),
    });

    let d4 = Fixture {
        source: "rust/protocol/src/group_cipher.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "SenderKeyDistributionMessage: serialized bytes for a freshly-created sender key chain.",
        vectors: vec![Vector {
            name: "senderkey_distribution_message".to_string(),
            inputs: d4_inputs,
            expected: serde_json::json!({
                "serialized": hex::encode(&skdm_serialized),
            }),
        }],
    };

    // Encrypt one message with the sender key.
    let skm = group_encrypt(
        &mut alice_sender_key_store,
        &alice_address,
        distribution_id,
        PLAINTEXT,
        rng,
    )
    .await?;

    let skm_serialized = skm.serialized().to_vec();

    let d5_inputs = serde_json::json!({
        "alice_uuid":       ALICE_UUID,
        "alice_device_id":  ALICE_DEVICE,
        "distribution_id":  distribution_id.to_string(),
        "plaintext":        hex::encode(PLAINTEXT),
        // The Go consumer must first call process_sender_key_distribution_message
        // using the skdm from the d4 fixture.
        "senderkey_distribution_serialized": hex::encode(&skdm_serialized),
    });

    let d5 = Fixture {
        source: "rust/protocol/src/group_cipher.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "SenderKeyMessage: ciphertext bytes produced by group_encrypt for a fixed plaintext.",
        vectors: vec![Vector {
            name: "senderkey_message".to_string(),
            inputs: d5_inputs,
            expected: serde_json::json!({
                "serialized": hex::encode(&skm_serialized),
            }),
        }],
    };

    Ok((d4, d5))
}

// ---------------------------------------------------------------------------
// D6 — DisplayableFingerprint + ScannableFingerprint
//
// Rust source: rust/protocol/src/fingerprint.rs — Fingerprint::new
//
// We use the exact same pinned test-vector keys from the Rust mod test to
// serve as a regression anchor for the Go fingerprint package.
// ---------------------------------------------------------------------------

fn emit_fingerprint(rng: &mut ChaCha20Rng) -> Result<Fixture> {
    use libsignal_protocol::FingerprintError;

    fn map_fperr(e: FingerprintError) -> anyhow::Error {
        anyhow::anyhow!("FingerprintError: {e}")
    }

    // Pinned test-vector keys from Rust fingerprint.rs mod test.
    const ALICE_IDENTITY_BYTES: &[u8] = &[
        0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7,
        0xc0, 0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc, 0xca, 0x5c, 0xe1,
        0x3c, 0x70, 0x64, 0xd8, 0x68,
    ];
    const BOB_IDENTITY_BYTES: &[u8] = &[
        0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d,
        0x4d, 0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02, 0xb5, 0xc0, 0xdb,
        0xd9, 0x6f, 0xda, 0x90, 0x7b,
    ];

    // Generated key pair from the seeded RNG (includes private keys for Go round-trip testing).
    let alice_kp = IdentityKeyPair::generate(rng);
    let bob_kp = IdentityKeyPair::generate(rng);

    let alice_stable_id = "+14152222222";
    let bob_stable_id = "+14153333333";
    let iterations: u32 = 5200;

    // Decode pinned keys.
    let alice_id_key = IdentityKey::decode(ALICE_IDENTITY_BYTES)?;
    let bob_id_key = IdentityKey::decode(BOB_IDENTITY_BYTES)?;

    // v1 fingerprints (Alice's perspective).
    let alice_fprint_v1 = Fingerprint::new(
        1,
        iterations,
        alice_stable_id.as_bytes(),
        &alice_id_key,
        bob_stable_id.as_bytes(),
        &bob_id_key,
    )
    .map_err(map_fperr)?;

    // v1 fingerprints (Bob's perspective — same display string, different scannable).
    let bob_fprint_v1 = Fingerprint::new(
        1,
        iterations,
        bob_stable_id.as_bytes(),
        &bob_id_key,
        alice_stable_id.as_bytes(),
        &alice_id_key,
    )
    .map_err(map_fperr)?;

    // v2 fingerprints.
    let alice_fprint_v2 = Fingerprint::new(
        2,
        iterations,
        alice_stable_id.as_bytes(),
        &alice_id_key,
        bob_stable_id.as_bytes(),
        &bob_id_key,
    )
    .map_err(map_fperr)?;

    let bob_fprint_v2 = Fingerprint::new(
        2,
        iterations,
        bob_stable_id.as_bytes(),
        &bob_id_key,
        alice_stable_id.as_bytes(),
        &alice_id_key,
    )
    .map_err(map_fperr)?;

    // v2 fingerprint for the rng-derived keys.
    let alice_gen_fprint_v2 = Fingerprint::new(
        2,
        iterations,
        alice_stable_id.as_bytes(),
        alice_kp.identity_key(),
        bob_stable_id.as_bytes(),
        bob_kp.identity_key(),
    )
    .map_err(map_fperr)?;

    let inputs = serde_json::json!({
        // Pinned upstream test keys (public only).
        "alice_identity_public": hex::encode(ALICE_IDENTITY_BYTES),
        "bob_identity_public":   hex::encode(BOB_IDENTITY_BYTES),
        "alice_stable_id":       alice_stable_id,
        "bob_stable_id":         bob_stable_id,
        "iterations":            iterations,
        // Generated keys with private keys for round-trip testing.
        "alice_generated_private": hex::encode(alice_kp.private_key().serialize()),
        "alice_generated_public":  hex::encode(alice_kp.public_key().serialize()),
        "bob_generated_private":   hex::encode(bob_kp.private_key().serialize()),
        "bob_generated_public":    hex::encode(bob_kp.public_key().serialize()),
    });

    let expected = serde_json::json!({
        // v1 results.
        "displayable_v1":         alice_fprint_v1.display.to_string(),
        "alice_scannable_v1_hex": hex::encode(alice_fprint_v1.scannable.serialize().map_err(map_fperr)?),
        "bob_scannable_v1_hex":   hex::encode(bob_fprint_v1.scannable.serialize().map_err(map_fperr)?),
        // v2 results.
        "displayable_v2":         alice_fprint_v2.display.to_string(),
        "alice_scannable_v2_hex": hex::encode(alice_fprint_v2.scannable.serialize().map_err(map_fperr)?),
        "bob_scannable_v2_hex":   hex::encode(bob_fprint_v2.scannable.serialize().map_err(map_fperr)?),
        // Generated-key v2 fingerprint.
        "alice_generated_displayable_v2":    alice_gen_fprint_v2.display.to_string(),
        "alice_generated_scannable_v2_hex":  hex::encode(alice_gen_fprint_v2.scannable.serialize().map_err(map_fperr)?),
    });

    Ok(Fixture {
        source: "rust/protocol/src/fingerprint.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "DisplayableFingerprint and ScannableFingerprint for pinned alice/bob identity keys at 5200 iterations, versions 1 and 2.",
        vectors: vec![Vector {
            name: "fingerprint_v1_and_v2".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// K1 — Kyber-1024 KAT (Known-Answer Test)
//
// Emits a single deterministic (pk, sk, ct, expected_ss) tuple for Kyber-1024
// using the ChaCha20-seeded RNG so that re-running the binary produces
// byte-identical JSON. The shared secret is obtained by encapsulating against
// the public key and then cross-checked via decapsulate to confirm correctness.
//
// TODO: run `make interop-wire-emit` to regenerate
//       tests/interop/fixtures/kem/kyber1024_kat.json after any upstream
//       libsignal revision bump (RUST_REV).
//
// Rust reference: rust/protocol/src/kem.rs — KeyPair::generate, PublicKey::encapsulate,
//                 SecretKey::decapsulate (libsignal v0.92.2, RUST_REV 98915c442d).
// ---------------------------------------------------------------------------

fn emit_kyber1024_kat(rng: &mut ChaCha20Rng) -> Result<Fixture> {
    // Generate a deterministic key pair from the seeded RNG.
    let kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);

    // Serialize public and secret keys (both include the 0x08 type-byte prefix).
    let pk_serialized = kp.public_key.serialize();
    let sk_serialized = kp.secret_key.serialize();

    // Encapsulate: produces a shared secret and a serialized ciphertext.
    let (ss, ct_serialized) = kp.public_key.encapsulate(rng)
        .context("Kyber-1024 encapsulate failed")?;

    // Cross-check: decapsulate with the secret key and verify agreement.
    let ss_check = kp.secret_key.decapsulate(&ct_serialized)
        .context("Kyber-1024 decapsulate failed")?;
    anyhow::ensure!(
        ss.as_ref() == ss_check.as_ref(),
        "KAT self-check failed: encapsulate/decapsulate shared secrets differ"
    );

    let inputs = serde_json::json!({
        // pk_hex / sk_hex include the 0x08 Kyber1024 type-byte prefix so that
        // the Go consumer can pass them directly to DeserializePublicKey /
        // NewSecretKey after stripping the leading byte.
        "pk_hex": hex::encode(pk_serialized.as_ref()),
        "sk_hex": hex::encode(sk_serialized.as_ref()),
        "ct_hex": hex::encode(ct_serialized.as_ref()),
    });

    let expected = serde_json::json!({
        "ss_hex": hex::encode(ss.as_ref()),
    });

    Ok(Fixture {
        source: "rust/protocol/src/kem.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "Kyber-1024 KAT: deterministic (pk, sk, ct, expected_ss) tuple produced \
                  by Rust libsignal. Go consumer must verify \
                  Decapsulate(ct, sk) == expected_ss.",
        vectors: vec![Vector {
            name: "kyber1024_kat".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// P1 — SignalMessage wire vector
//
// Rust source: rust/protocol/src/protocol.rs — SignalMessage::new (line 79)
//
// SignalMessage::new(
//     message_version: u8,
//     mac_key: &[u8],
//     addresses: Option<(&ProtocolAddress, &ProtocolAddress)>,
//     sender_ratchet_key: PublicKey,
//     counter: u32,
//     previous_counter: u32,
//     ciphertext: &[u8],
//     sender_identity_key: &IdentityKey,
//     receiver_identity_key: &IdentityKey,
//     pq_ratchet: &[u8],
// ) -> Result<Self>
//
// All key material derived from the shared seeded RNG for full reproducibility.
// pq_ratchet = [] (no SPQR active), addresses = None (backward-compat).
// ---------------------------------------------------------------------------

fn emit_signal_message(rng: &mut ChaCha20Rng) -> Result<Fixture> {
    // Fixed 32-byte MAC key — read from seeded RNG.
    let mut mac_key = [0u8; 32];
    rand::RngCore::fill_bytes(rng, &mut mac_key);

    // Fixed 20-byte ciphertext body.
    let mut ciphertext = [0u8; 20];
    rand::RngCore::fill_bytes(rng, &mut ciphertext);

    // Key pairs from seeded RNG.
    let ratchet_kp = KeyPair::generate(rng);
    let sender_identity_kp = IdentityKeyPair::generate(rng);
    let receiver_identity_kp = IdentityKeyPair::generate(rng);

    let msg = SignalMessage::new(
        3, // message_version = 3 (pre-Kyber) — Go accepts 3 and 4
        &mac_key,
        None, // no address binding — backward compat
        ratchet_kp.public_key,
        42,
        41,
        &ciphertext,
        sender_identity_kp.identity_key(),
        receiver_identity_kp.identity_key(),
        b"", // pq_ratchet empty
    )?;

    let serialized = msg.serialized().to_vec();

    let inputs = serde_json::json!({
        "message_version":        3,
        "mac_key":                hex::encode(mac_key),
        "sender_ratchet_public":  hex::encode(ratchet_kp.public_key.serialize()),
        "sender_identity_private": hex::encode(sender_identity_kp.private_key().serialize()),
        "sender_identity_public": hex::encode(sender_identity_kp.public_key().serialize()),
        "receiver_identity_private": hex::encode(receiver_identity_kp.private_key().serialize()),
        "receiver_identity_public": hex::encode(receiver_identity_kp.public_key().serialize()),
        "counter":                42u32,
        "previous_counter":       41u32,
        "ciphertext":             hex::encode(ciphertext),
    });

    let expected = serde_json::json!({
        "serialized": hex::encode(&serialized),
        "mac_tag":    hex::encode(&serialized[serialized.len() - 8..]),
    });

    Ok(Fixture {
        source: "rust/protocol/src/protocol.rs:79 SignalMessage::new (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "SignalMessage wire vector: fixed (mac_key, ratchet_key, identity_keys, ciphertext) \
                  tuple. Go must parse with NewSignalMessageFromBytes, verify all fields round-trip, \
                  and VerifyMac with the supplied mac_key.",
        vectors: vec![Vector {
            name: "signal_message".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// P2 — PreKeySignalMessage wire vector
//
// Rust source: rust/protocol/src/protocol.rs — PreKeySignalMessage::new (line 352)
//
// PreKeySignalMessage::new(
//     message_version: u8,
//     registration_id: u32,
//     pre_key_id: Option<PreKeyId>,
//     signed_pre_key_id: SignedPreKeyId,
//     kyber_payload: Option<KyberPayload>,  // None → version 3 (pre-Kyber)
//     base_key: PublicKey,
//     identity_key: IdentityKey,
//     message: SignalMessage,
// ) -> Result<Self>
//
// Uses version 3 with kyber_payload = None so Go's NewPreKeySignalMessageFromBytes
// does not require a Kyber payload (PreKyberVersion branch).
// Inner SignalMessage constructed first, then wrapped.
// ---------------------------------------------------------------------------

fn emit_prekey_signal_message(rng: &mut ChaCha20Rng) -> Result<Fixture> {
    // Key material for the inner SignalMessage.
    let mut mac_key = [0u8; 32];
    rand::RngCore::fill_bytes(rng, &mut mac_key);

    let mut ciphertext = [0u8; 20];
    rand::RngCore::fill_bytes(rng, &mut ciphertext);

    let ratchet_kp = KeyPair::generate(rng);
    let sender_identity_kp = IdentityKeyPair::generate(rng);
    let receiver_identity_kp = IdentityKeyPair::generate(rng);

    // Inner SignalMessage.
    let inner = SignalMessage::new(
        3,
        &mac_key,
        None,
        ratchet_kp.public_key,
        7,
        6,
        &ciphertext,
        sender_identity_kp.identity_key(),
        receiver_identity_kp.identity_key(),
        b"",
    )?;

    // Key material for the PreKeySignalMessage envelope.
    let base_kp = KeyPair::generate(rng);
    let identity_kp = IdentityKeyPair::generate(rng);

    let pre_key_id: PreKeyId = 23u32.into();
    let signed_pre_key_id: libsignal_protocol::SignedPreKeyId = 42u32.into();
    let registration_id: u32 = 1234;

    let pksm = PreKeySignalMessage::new(
        3, // version 3 = pre-Kyber; no kyber_payload required
        registration_id,
        Some(pre_key_id),
        signed_pre_key_id,
        None, // kyber_payload = None
        base_kp.public_key,
        *identity_kp.identity_key(),
        inner,
    )?;

    let serialized = pksm.serialized().to_vec();

    let inputs = serde_json::json!({
        "message_version":         3,
        "registration_id":         registration_id,
        "pre_key_id":              23u32,
        "signed_pre_key_id":       42u32,
        "base_key_public":         hex::encode(base_kp.public_key.serialize()),
        "identity_key_public":     hex::encode(identity_kp.public_key().serialize()),
        // Inner SignalMessage inputs (for Go MAC verification):
        "mac_key":                 hex::encode(mac_key),
        "ratchet_key_public":      hex::encode(ratchet_kp.public_key.serialize()),
        "sender_identity_public":  hex::encode(sender_identity_kp.public_key().serialize()),
        "sender_identity_private": hex::encode(sender_identity_kp.private_key().serialize()),
        "receiver_identity_public": hex::encode(receiver_identity_kp.public_key().serialize()),
        "receiver_identity_private": hex::encode(receiver_identity_kp.private_key().serialize()),
        "inner_counter":           7u32,
        "inner_previous_counter":  6u32,
        "inner_ciphertext":        hex::encode(ciphertext),
    });

    let expected = serde_json::json!({
        "serialized": hex::encode(&serialized),
    });

    Ok(Fixture {
        source: "rust/protocol/src/protocol.rs:352 PreKeySignalMessage::new (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "PreKeySignalMessage wire vector (version 3, no Kyber payload). Go must parse \
                  with NewPreKeySignalMessageFromBytes, assert all fields round-trip, and verify \
                  the inner SignalMessage MAC with the supplied mac_key.",
        vectors: vec![Vector {
            name: "prekey_signal_message".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// P3 — DecryptionErrorMessage wire vector
//
// Rust source: rust/protocol/src/protocol.rs — DecryptionErrorMessage::for_original (line 881)
//
// DecryptionErrorMessage::for_original(
//     original_bytes: &[u8],
//     original_type: CiphertextMessageType,
//     original_timestamp: Timestamp,
//     original_sender_device_id: u32,
// ) -> Result<Self>
//
// Pass a SignalMessage as original_bytes with type Whisper so the constructor
// extracts the ratchet key. The extracted ratchet key appears in the fixture
// so Go can validate it matches.
// ---------------------------------------------------------------------------

fn emit_decryption_error_message(rng: &mut ChaCha20Rng) -> Result<Fixture> {
    // Build a minimal SignalMessage to serve as the "original encrypted message".
    let mut mac_key = [0u8; 32];
    rand::RngCore::fill_bytes(rng, &mut mac_key);

    let mut ciphertext = [0u8; 20];
    rand::RngCore::fill_bytes(rng, &mut ciphertext);

    let ratchet_kp = KeyPair::generate(rng);
    let sender_id_kp = IdentityKeyPair::generate(rng);
    let receiver_id_kp = IdentityKeyPair::generate(rng);

    let original_msg = SignalMessage::new(
        3,
        &mac_key,
        None,
        ratchet_kp.public_key,
        1,
        0,
        &ciphertext,
        sender_id_kp.identity_key(),
        receiver_id_kp.identity_key(),
        b"",
    )?;

    let original_bytes = original_msg.serialized().to_vec();
    let original_timestamp = Timestamp::from_epoch_millis(1_700_000_000_000);
    let original_device_id: u32 = 3;

    let dem = libsignal_protocol::DecryptionErrorMessage::for_original(
        &original_bytes,
        CiphertextMessageType::Whisper,
        original_timestamp,
        original_device_id,
    )?;

    let dem_serialized = dem.serialized().to_vec();

    // Wrap in PlaintextContent (matches Rust From<DecryptionErrorMessage> for PlaintextContent).
    let plaintext: PlaintextContent = dem.clone().into();
    let plaintext_serialized = plaintext.serialized().to_vec();

    let inputs = serde_json::json!({
        // Original SignalMessage inputs so Go can reconstruct and verify.
        "original_mac_key":        hex::encode(mac_key),
        "original_ratchet_public": hex::encode(ratchet_kp.public_key.serialize()),
        "original_sender_identity_public": hex::encode(sender_id_kp.public_key().serialize()),
        "original_receiver_identity_public": hex::encode(receiver_id_kp.public_key().serialize()),
        "original_message_hex":    hex::encode(&original_bytes),
        "original_timestamp_ms":   1_700_000_000_000u64,
        "original_device_id":      original_device_id,
        "original_type":           "Whisper",
    });

    let expected = serde_json::json!({
        "dem_serialized":          hex::encode(&dem_serialized),
        "ratchet_key_public":      hex::encode(ratchet_kp.public_key.serialize()),
        "timestamp_ms":            original_timestamp.epoch_millis(),
        "device_id":               original_device_id,
        "plaintext_content_serialized": hex::encode(&plaintext_serialized),
    });

    Ok(Fixture {
        source: "rust/protocol/src/protocol.rs:881 DecryptionErrorMessage::for_original (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "DecryptionErrorMessage wire vector. Go must DeserializeDecryptionErrorMessage \
                  and assert ratchet_key, timestamp, device_id. Also validates PlaintextContent \
                  wrapping via ExtractDecryptionErrorMessageFromSerializedContent.",
        vectors: vec![Vector {
            name: "decryption_error_message".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// P4 — PlaintextContent wire vector
//
// Rust source: rust/protocol/src/protocol.rs — From<DecryptionErrorMessage> for PlaintextContent
// (line 837); PlaintextContent::PLAINTEXT_CONTEXT_IDENTIFIER_BYTE = 0xC0,
// PADDING_BOUNDARY_BYTE = 0x80.
//
// PlaintextContent is constructed from a DecryptionErrorMessage via the From impl:
//   [0xC0] || proto::service::Content { decryption_error_message: dem_bytes } || [0x80]
//
// We reuse the same DEM from a fresh SignalMessage so the vector is independent
// of P3.
// ---------------------------------------------------------------------------

fn emit_plaintext_content(rng: &mut ChaCha20Rng) -> Result<Fixture> {
    // Build a distinct SignalMessage as the "original" for a fresh DEM.
    let mut mac_key = [0u8; 32];
    rand::RngCore::fill_bytes(rng, &mut mac_key);

    let mut ciphertext = [0u8; 16];
    rand::RngCore::fill_bytes(rng, &mut ciphertext);

    let ratchet_kp = KeyPair::generate(rng);
    let sender_id_kp = IdentityKeyPair::generate(rng);
    let receiver_id_kp = IdentityKeyPair::generate(rng);

    let original_msg = SignalMessage::new(
        3,
        &mac_key,
        None,
        ratchet_kp.public_key,
        5,
        4,
        &ciphertext,
        sender_id_kp.identity_key(),
        receiver_id_kp.identity_key(),
        b"",
    )?;

    let original_bytes = original_msg.serialized().to_vec();
    let ts = Timestamp::from_epoch_millis(1_600_000_000_000);

    let dem = libsignal_protocol::DecryptionErrorMessage::for_original(
        &original_bytes,
        CiphertextMessageType::Whisper,
        ts,
        2,
    )?;

    let plaintext: PlaintextContent = dem.into();
    let plaintext_serialized = plaintext.serialized().to_vec();

    // Validate wire-format invariants.
    anyhow::ensure!(
        plaintext_serialized[0] == 0xC0,
        "PlaintextContent must start with 0xC0"
    );
    anyhow::ensure!(
        *plaintext_serialized.last().unwrap() == 0x80,
        "PlaintextContent must end with 0x80"
    );

    let inputs = serde_json::json!({
        "identifier_byte": "0xC0",
        "padding_byte":    "0x80",
        "original_message_hex": hex::encode(&original_bytes),
        "original_timestamp_ms": ts.epoch_millis(),
        "original_device_id": 2u32,
    });

    let expected = serde_json::json!({
        "serialized":           hex::encode(&plaintext_serialized),
        "first_byte":           format!("{:#04x}", plaintext_serialized[0]),
        "last_byte":            format!("{:#04x}", plaintext_serialized.last().unwrap()),
        "body_hex":             hex::encode(&plaintext_serialized[1..]),
    });

    Ok(Fixture {
        source: "rust/protocol/src/protocol.rs:837 From<DecryptionErrorMessage> for PlaintextContent (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "PlaintextContent wire vector: identifier 0xC0 || Content proto body || padding 0x80. \
                  Go must parse with NewPlaintextContentFromBytes, assert identifier byte, \
                  and round-trip ExtractDecryptionErrorMessageFromSerializedContent.",
        vectors: vec![Vector {
            name: "plaintext_content".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// I1 — IdentityKeyPair serialize / try_from KAT
// ---------------------------------------------------------------------------

// emit_identity_key_pair emits a deterministic IdentityKeyPair fixture for
// verifying Go's NewKeyPairFromBytes / Serialize round-trip against Rust.
//
// Rust source: rust/protocol/src/identity_key.rs — IdentityKeyPair::serialize
//              and TryFrom<&[u8]> for IdentityKeyPair (libsignal v0.92.2).
fn emit_identity_key_pair(rng: &mut ChaCha20Rng) -> Result<Fixture> {
    let kp = IdentityKeyPair::generate(rng);
    let serialized = kp.serialize();

    let inputs = serde_json::json!({
        // public_hex: 33-byte DjbType-prefixed (0x05) Curve25519 public key.
        "public_hex":  hex::encode(kp.public_key().serialize().as_ref()),
        // private_hex: 32-byte raw Curve25519 scalar.
        "private_hex": hex::encode(&kp.private_key().serialize()[..]),
    });

    let expected = serde_json::json!({
        // serialized_hex: proto.Marshal of IdentityKeyPairStructure.
        "serialized_hex": hex::encode(serialized.as_ref()),
    });

    Ok(Fixture {
        source: "rust/protocol/src/identity_key.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "IdentityKeyPair serialization KAT: Rust IdentityKeyPair::serialize \
                  produces IdentityKeyPairStructure protobuf. Go must round-trip via \
                  NewKeyPairFromBytes(serialized_hex) and recover public_hex / private_hex.",
        vectors: vec![Vector {
            name: "identity_key_pair_kat".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// S1 — SPQR pq_ratchet field bytes
//
// Rust source: SparsePostQuantumRatchet crate v1.5.1 (tag v1.5.1) — spqr::send.
//
// The bytes produced here are exactly what rides in SignalMessage.pq_ratchet
// (proto field 5): the serialized post-quantum ratchet message. The Go side
// (pkg/spqr) consumes this format via spqr.Recv and must derive a byte-identical
// message key from the same auth_key + wire message.
//
// Flow (mirrors the live SPQR harness in src/main.rs, but baked into a static
// fixture so byte-compat is proven without invoking the Rust binary at test
// time):
//   1. initial_state(A2B, V1, V1, auth_key)         — sender state
//   2. send(state, seeded_rng)                       — first message
//        result.msg  = pq_ratchet wire bytes
//        result.key  = sender-derived message key
// Because MinVersion = V1, negotiation resolves on the first send, so result.key
// is non-empty. The Go consumer initializes a B2A receiver from the same
// auth_key, calls spqr.Recv(msg), and asserts the receiver key == result.key.
// ---------------------------------------------------------------------------

fn emit_spqr_pq_ratchet() -> Result<Fixture> {
    // Sender (A2B) initial state. MinVersion = V1 forces immediate negotiation
    // resolution so the very first send produces a non-empty message key.
    let sender_state = initial_state(Params {
        direction: Direction::A2B,
        version: Version::V1,
        min_version: Version::V1,
        auth_key: SPQR_AUTH_KEY,
        chain_params: ChainParams::default(),
    })
    .map_err(|e| anyhow::anyhow!("spqr::initial_state failed: {e:?}"))?;

    // Deterministic RNG so the embedded KEM/ratchet material is reproducible.
    let mut send_rng = ChaCha20Rng::seed_from_u64(SPQR_SEND_SEED);

    let result = send(&sender_state, &mut send_rng)
        .map_err(|e| anyhow::anyhow!("spqr::send failed: {e:?}"))?;

    let pq_ratchet_msg = result.msg;
    let sender_key = result
        .key
        .ok_or_else(|| anyhow::anyhow!("spqr::send produced no message key (negotiation did not resolve)"))?;

    anyhow::ensure!(
        !pq_ratchet_msg.is_empty(),
        "spqr::send produced an empty pq_ratchet message"
    );
    anyhow::ensure!(
        !sender_key.is_empty(),
        "spqr::send produced an empty message key (negotiation did not resolve)"
    );
    anyhow::ensure!(
        pq_ratchet_msg[0] == 0x01,
        "spqr pq_ratchet message must start with SCKA version byte 0x01, got {:#04x}",
        pq_ratchet_msg[0]
    );

    let inputs = serde_json::json!({
        // 32-byte shared auth key. The Go consumer initializes a B2A receiver
        // with this exact key (MinVersion = V1, MaxJump = 25000, MaxOOOKeys = 2000,
        // matching spqr ChainParams::default()).
        "auth_key_hex":   hex::encode(SPQR_AUTH_KEY),
        "direction":      "a2b",
        "version":        1u32,
        "min_version":    1u32,
        "max_jump":       25000u32,
        "max_ooo_keys":   2000u32,
        "send_seed":      SPQR_SEND_SEED,
    });

    let expected = serde_json::json!({
        // pq_ratchet_hex: the exact bytes carried in SignalMessage.pq_ratchet
        // (proto field 5). Go's spqr.Recv must accept these bytes.
        "pq_ratchet_hex": hex::encode(&pq_ratchet_msg),
        // sender_key_hex: the message key the sender derived for this message.
        // Go's receiver must derive the same key from spqr.Recv.
        "sender_key_hex": hex::encode(&sender_key),
    });

    Ok(Fixture {
        source: "SparsePostQuantumRatchet crate v1.5.1 — spqr::send (rides in SignalMessage.pq_ratchet, proto field 5)",
        rust_rev: RUST_REV,
        purpose: "SPQR pq_ratchet wire vector: the post-quantum ratchet message bytes carried in \
                  SignalMessage.pq_ratchet (proto field 5), emitted by the Rust SparsePostQuantumRatchet \
                  crate. Go's pkg/spqr.Recv must accept the bytes and derive a message key byte-identical \
                  to sender_key_hex from the same auth_key.",
        vectors: vec![Vector {
            name: "spqr_pq_ratchet_first_message".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// Z1 — GroupSendEndorsementsResponse wire vector
//
// Rust source: rust/zkgroup/src/api/groups/group_send_endorsement.rs —
//              GroupSendDerivedKeyPair::for_expiration + GroupSendEndorsementsResponse::issue
//              (libsignal v0.92.2, RUST_REV 98915c442d)
//
// All inputs are fully pinned (no RNG); the fixture is byte-identical on
// every invocation.
//
//   server_params         ServerSecretParams::generate([0x42; 32])
//   group_params          GroupSecretParams::generate([0x43; 32])
//   expiration            Timestamp::from_epoch_seconds(2 * SECONDS_PER_DAY)
//   issue_randomness      [0x44; 32]
//   members               Alice / Bob / Carol (UUIDs below)
//
// The Go consumer calls DeserializeGroupSendEndorsementsResponse on
// response_hex, then ReceiveWithServiceIDs to verify the endorsements.
// ---------------------------------------------------------------------------

fn emit_group_send_endorsements() -> Result<Fixture> {
    use zkgroup::groups::{GroupSendDerivedKeyPair, GroupSendEndorsementsResponse, GroupSecretParams};
    use zkgroup::{ServerSecretParams, SECONDS_PER_DAY};

    // Pinned seeds — deterministic, no RNG.
    let server_randomness: [u8; 32] = [0x42; 32];
    let group_randomness: [u8; 32] = [0x43; 32];
    let issue_randomness: [u8; 32] = [0x44; 32];

    // Fixed day-aligned expiration: exactly 2 days after the Unix epoch.
    let expiration = zkgroup::Timestamp::from_epoch_seconds(2 * SECONDS_PER_DAY);

    // Fixed member UUIDs (ACI) — reuse the top-level constants.
    let alice_bytes = *uuid::Uuid::parse_str(ALICE_UUID).unwrap().as_bytes();
    let bob_bytes = *uuid::Uuid::parse_str(BOB_UUID).unwrap().as_bytes();
    let carol_bytes = *uuid::Uuid::parse_str(CAROL_UUID).unwrap().as_bytes();

    let alice_aci = ServiceId::from(Aci::from_uuid_bytes(alice_bytes));
    let bob_aci = ServiceId::from(Aci::from_uuid_bytes(bob_bytes));
    let carol_aci = ServiceId::from(Aci::from_uuid_bytes(carol_bytes));

    // Server: generate params and derive the per-expiration key pair.
    let server_params = ServerSecretParams::generate(server_randomness);
    let server_public = server_params.get_public_params();

    let key_pair = GroupSendDerivedKeyPair::for_expiration(expiration, &server_params);

    // Group: generate secret params and encrypt the member service IDs.
    let group_params = GroupSecretParams::generate(group_randomness);
    let alice_ct = group_params.encrypt_service_id(alice_aci);
    let bob_ct = group_params.encrypt_service_id(bob_aci);
    let carol_ct = group_params.encrypt_service_id(carol_aci);

    // Issue the endorsement response.
    let response = GroupSendEndorsementsResponse::issue(
        [alice_ct, bob_ct, carol_ct],
        &key_pair,
        issue_randomness,
    );

    // Serialize to the bincode wire format used on the wire between the group
    // server and Signal clients.
    let response_bytes = zkgroup::serialize(&response);

    // Serialize server public params and group secret params so the Go
    // consumer can reconstruct the full verification context.
    let server_public_bytes = zkgroup::serialize(&server_public);
    let group_secret_bytes = zkgroup::serialize(&group_params);

    let inputs = serde_json::json!({
        "server_randomness_hex":    hex::encode(server_randomness),
        "group_randomness_hex":     hex::encode(group_randomness),
        "issue_randomness_hex":     hex::encode(issue_randomness),
        "expiration_secs":          expiration.epoch_seconds(),
        "alice_uuid":               ALICE_UUID,
        "bob_uuid":                 BOB_UUID,
        "carol_uuid":               CAROL_UUID,
        // Server public params — Go extracts the endorsement public key from this.
        "server_public_params_hex": hex::encode(&server_public_bytes),
        // Group secret params — Go uses this to call ReceiveWithServiceIDs.
        "group_secret_params_hex":  hex::encode(&group_secret_bytes),
    });

    let expected = serde_json::json!({
        // Wire bytes of zkgroup::serialize(&response):
        //   [0x00 reserved] || [LE u64 len(R)] || 32*R || [LE u64 len(proof)] || proof || [LE u64 expiration_secs]
        "response_hex": hex::encode(&response_bytes),
        "expiration_secs": expiration.epoch_seconds(),
    });

    Ok(Fixture {
        source: "rust/zkgroup/src/api/groups/group_send_endorsement.rs (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "GroupSendEndorsementsResponse wire vector: fixed (server_params, group_params, \
                  expiration, member_service_ids) tuple. response_hex is the output of \
                  zkgroup::serialize(&response) — byte-identical to the bincode wire format. \
                  Go consumer must DeserializeGroupSendEndorsementsResponse(response_hex) then \
                  ReceiveWithServiceIDs([Alice,Bob,Carol], now, group_secret_params, server_public_key) \
                  and verify len(received) == 3. Regenerate via `make interop-wire-emit`.",
        vectors: vec![Vector {
            name: "group_send_endorsements_response".to_string(),
            inputs,
            expected,
        }],
    })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    let out_dir = Path::new(&cli.out);
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating output directory {}", out_dir.display()))?;

    // Single seeded RNG for ALL fixtures — deterministic across runs.
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0DE_CAFE);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    // D1
    let d1 = rt.block_on(emit_sealed_sender_v1(&mut rng))?;
    write_fixture(out_dir, "sealed_sender_v1.json", &d1)?;
    eprintln!("  wrote sealed_sender_v1.json");

    // D2 + D3
    let (d2, d3) = rt.block_on(emit_sealed_sender_v2(&mut rng))?;
    write_fixture(out_dir, "sealed_sender_v2_received.json", &d2)?;
    eprintln!("  wrote sealed_sender_v2_received.json");
    write_fixture(out_dir, "sealed_sender_v2_multi.json", &d3)?;
    eprintln!("  wrote sealed_sender_v2_multi.json");

    // D4 + D5
    let (d4, d5) = rt.block_on(emit_sender_key(&mut rng))?;
    write_fixture(out_dir, "senderkey_distribution.json", &d4)?;
    eprintln!("  wrote senderkey_distribution.json");
    write_fixture(out_dir, "senderkey_message.json", &d5)?;
    eprintln!("  wrote senderkey_message.json");

    // D6
    let d6 = emit_fingerprint(&mut rng)?;
    write_fixture(out_dir, "fingerprint.json", &d6)?;
    eprintln!("  wrote fingerprint.json");

    // K1 — Kyber-1024 KAT (written under the kem/ subdirectory).
    let kem_dir = out_dir.join("kem");
    std::fs::create_dir_all(&kem_dir)
        .with_context(|| format!("creating kem output directory {}", kem_dir.display()))?;
    let k1 = emit_kyber1024_kat(&mut rng)?;
    write_fixture(&kem_dir, "kyber1024_kat.json", &k1)?;
    eprintln!("  wrote kem/kyber1024_kat.json");

    // P1 — SignalMessage
    let p1 = emit_signal_message(&mut rng)?;
    write_fixture(out_dir, "signal_message.json", &p1)?;
    eprintln!("  wrote signal_message.json");

    // P2 — PreKeySignalMessage
    let p2 = emit_prekey_signal_message(&mut rng)?;
    write_fixture(out_dir, "prekey_signal_message.json", &p2)?;
    eprintln!("  wrote prekey_signal_message.json");

    // P3 — DecryptionErrorMessage
    let p3 = emit_decryption_error_message(&mut rng)?;
    write_fixture(out_dir, "decryption_error_message.json", &p3)?;
    eprintln!("  wrote decryption_error_message.json");

    // P4 — PlaintextContent
    let p4 = emit_plaintext_content(&mut rng)?;
    write_fixture(out_dir, "plaintext_content.json", &p4)?;
    eprintln!("  wrote plaintext_content.json");

    // I1 — IdentityKeyPair KAT
    let i1 = emit_identity_key_pair(&mut rng)?;
    write_fixture(out_dir, "identity_key_pair.json", &i1)?;
    eprintln!("  wrote identity_key_pair.json");

    // S1 — SPQR pq_ratchet field bytes. Uses its own seeded RNG (independent of
    // the shared fixture RNG above) so the embedded KEM material is reproducible.
    let s1 = emit_spqr_pq_ratchet()?;
    write_fixture(out_dir, "spqr_pq_ratchet.json", &s1)?;
    eprintln!("  wrote spqr_pq_ratchet.json");

    // Z1 — GroupSendEndorsementsResponse wire vector. Uses no RNG (all inputs
    // are pinned constants); the JSON fixture is fully deterministic.
    let z1 = emit_group_send_endorsements()?;
    write_fixture(out_dir, "group_send_endorsements.json", &z1)?;
    eprintln!("  wrote group_send_endorsements.json");

    eprintln!("wire_emitter: all fixtures written to {}", out_dir.display());

    // C2 (optional, separate path because it lives under messagebackup/, not wire/).
    if let Some(ref aes_path) = cli.frame_aes_out {
        let c2 = emit_frame_aes_cbc()?;
        let path = Path::new(aes_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(&c2)
            .context("serializing frame_aes.json")?;
        std::fs::write(path, json + "\n")
            .with_context(|| format!("writing {}", path.display()))?;
        eprintln!("wire_emitter: messagebackup/frame_aes.json written to {}", path.display());
    }

    Ok(())
}

/// Emit the C2 frame_aes.json fixture using Rust's `aes` + `cbc` crates with
/// PKCS7 padding — the exact construction used by
/// rust/message-backup/src/export.rs::aes_cbc_encrypt.
fn emit_frame_aes_cbc() -> Result<Fixture> {
    use aes::Aes256;
    use cbc::Encryptor;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    let key: [u8; 32] = [0xaf; 32];
    let iv: [u8; 16] = [0xbb; 16];

    // Plaintexts pinned to match the existing fixture so the hex bytes are
    // byte-identical to the C2 fixture and the Go consumer test in
    // tests/interop/messagebackup_frame_aes_test.go is unchanged.
    let med: Vec<u8> = vec![0xab; 256];
    let long: Vec<u8> = (0..256u16).flat_map(|_| 0..=255u8).collect::<Vec<u8>>()[..1024].to_vec();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("aes_reader_round_trip_empty", Vec::new()),
        ("aes_reader_round_trip_short", b"abcdefghijklmnopqrstuvwxyz".to_vec()),
        ("aes_reader_round_trip_med",   med),
        ("aes_reader_round_trip_long",  long),
    ];

    let mut vectors = Vec::with_capacity(cases.len());
    for (name, plaintext) in cases.into_iter() {
        // CBC + PKCS7 needs at most one extra block of room for padding.
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(&plaintext);
        let cipher = Encryptor::<Aes256>::new(&key.into(), &iv.into());
        let ct_len = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("provided enough room for padding")
            .len();
        buf.truncate(ct_len);

        vectors.push(Vector {
            name: name.to_string(),
            inputs: serde_json::json!({
                "key_hex":       hex::encode(key),
                "iv_hex":        hex::encode(iv),
                "plaintext_hex": hex::encode(&plaintext),
            }),
            expected: serde_json::json!({
                "ciphertext_hex": hex::encode(&buf),
            }),
        });
    }

    Ok(Fixture {
        source: "rust/message-backup/src/export.rs::aes_cbc_encrypt (libsignal v0.92.2)",
        rust_rev: RUST_REV,
        purpose: "AES-256-CBC + PKCS7 frame encryption parity for message-backup. \
                  Ciphertext bytes emitted by Rust libsignal v0.92.2's aes/cbc crates, \
                  the same construction as rust/message-backup/src/export.rs.",
        vectors,
    })
}

fn write_fixture(out_dir: &Path, name: &str, fixture: &Fixture) -> Result<()> {
    let path = out_dir.join(name);
    let json = serde_json::to_string_pretty(fixture)
        .with_context(|| format!("serializing {name}"))?;
    std::fs::write(&path, json)
        .with_context(|| format!("writing {}", path.display()))
}
