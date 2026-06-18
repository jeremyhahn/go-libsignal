// interop_runner: live cross-implementation interop harness for go-libsignal.
//
// Rust source: tests/interop/rust/src/bin/interop_runner.rs
// Upstream pin: 98915c442d
//
// Reads newline-delimited JSON commands from stdin, writes JSON responses to stdout.
// Each command carries an optional "seed_hex" field to seed a ChaCha20Rng for
// deterministic output.
//
// Supported operations:
//   session_encrypt    — PQXDH + Double Ratchet encrypt → prekey_msg_hex
//   session_decrypt    — decrypt a Go-produced PreKeySignalMessage
//   sealed_v1_encrypt  — Sealed Sender v1 encrypt (USMC with Plaintext content)
//   sealed_v1_decrypt  — Sealed Sender v1 decrypt
//   sealed_v2_encrypt  — Sealed Sender v2 multi-recipient encrypt (2 recipients)
//   sealed_v2_decrypt  — Sealed Sender v2 per-recipient decrypt
//   sender_key_encrypt — group (SenderKey) encrypt
//   sender_key_decrypt — group (SenderKey) decrypt
//   backup_encrypt     — AES-256-CBC + PKCS7 frame encrypt with HMAC-SHA256
//   backup_decrypt     — AES-256-CBC + PKCS7 frame decrypt with HMAC-SHA256 verify

use std::io::{self, BufRead, Write};
use std::time::SystemTime;

use aes::Aes256;
use anyhow::{bail, Context, Result};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use libsignal_protocol::{
    Aci, ContentHint, CiphertextMessageType, DeviceId, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, InMemIdentityKeyStore, InMemSenderKeyStore, InMemSignalProtocolStore,
    KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress,
    SealedSenderV2SentMessage, SenderCertificate, ServerCertificate, ServiceId,
    SessionStore, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
    UnidentifiedSenderMessageContent,
    GenericSignedPreKey,
    create_sender_key_distribution_message, group_decrypt, group_encrypt, kem,
    message_decrypt_prekey, message_encrypt,
    process_prekey_bundle, sealed_sender_decrypt_to_usmc, sealed_sender_encrypt_from_usmc,
    sealed_sender_multi_recipient_encrypt,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Every command has "op" and optional "seed_hex".
#[derive(Deserialize)]
struct Command {
    op: String,
    seed_hex: Option<String>,
    #[serde(flatten)]
    params: serde_json::Value,
}

#[derive(Serialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(flatten)]
    fields: serde_json::Value,
}

fn ok(fields: serde_json::Value) -> Response {
    Response { error: None, fields }
}

fn err_resp(msg: impl std::fmt::Display) -> Response {
    Response {
        error: Some(format!("{:#}", msg)),
        fields: serde_json::json!({}),
    }
}

// ---------------------------------------------------------------------------
// RNG helper
// ---------------------------------------------------------------------------

fn rng_from_seed_hex(seed_hex: &Option<String>) -> Result<ChaCha20Rng> {
    let seed = match seed_hex.as_deref() {
        Some(h) => {
            let bytes = hex::decode(h).context("seed_hex: invalid hex")?;
            if bytes.is_empty() { bail!("seed_hex must not be empty"); }
            let mut arr = [0u8; 8];
            let n = bytes.len().min(8);
            arr[..n].copy_from_slice(&bytes[..n]);
            u64::from_le_bytes(arr)
        }
        None => 0xC0DE_CAFE_1234_5678,
    };
    Ok(ChaCha20Rng::seed_from_u64(seed))
}

// ---------------------------------------------------------------------------
// Helper: build an InMemSignalProtocolStore with a fresh generated identity.
// ---------------------------------------------------------------------------

fn make_store(rng: &mut ChaCha20Rng, registration_id: u32) -> Result<InMemSignalProtocolStore> {
    let identity = IdentityKeyPair::generate(rng);
    InMemSignalProtocolStore::new(identity, registration_id).context("InMemSignalProtocolStore::new")
}

// ---------------------------------------------------------------------------
// Helper: pre-populate pre-key material into store and return the bundle.
// All key material is derived from the seeded rng for determinism.
// ---------------------------------------------------------------------------

async fn setup_recipient_bundle(
    store: &mut InMemSignalProtocolStore,
    rng: &mut ChaCha20Rng,
) -> Result<(PreKeyBundle, libsignal_protocol::PrivateKey, libsignal_protocol::PrivateKey, Vec<u8>)> {
    let pre_key_pair      = KeyPair::generate(rng);
    let signed_pre_key_pair = KeyPair::generate(rng);
    let kyber_pre_key_pair  = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);

    let identity_kp = store.identity_store.get_identity_key_pair().await?;

    let spk_pub = signed_pre_key_pair.public_key.serialize();
    let spk_sig = identity_kp.private_key().calculate_signature(&spk_pub, rng)?;

    let kpk_pub = kyber_pre_key_pair.public_key.serialize();
    let kpk_sig = identity_kp.private_key().calculate_signature(&kpk_pub, rng)?;

    let pre_key_id:      PreKeyId      = 1u32.into();
    let spk_id:          SignedPreKeyId = 1u32.into();
    let kpk_id:          KyberPreKeyId  = 1u32.into();
    let device_id        = DeviceId::new(1).unwrap();
    let ts               = Timestamp::from_epoch_millis(1_000_000);
    let reg_id           = store.identity_store.get_local_registration_id().await?;
    let identity_key     = *identity_kp.identity_key();

    let bundle = PreKeyBundle::new(
        reg_id, device_id,
        Some((pre_key_id, pre_key_pair.public_key)),
        spk_id, signed_pre_key_pair.public_key, spk_sig.to_vec(),
        kpk_id, kyber_pre_key_pair.public_key.clone(), kpk_sig.to_vec(),
        identity_key,
    )?;

    // Capture private key bytes before moving into records.
    let pk_private  = pre_key_pair.private_key.clone();
    let spk_private = signed_pre_key_pair.private_key.clone();
    let kpk_private_bytes = kyber_pre_key_pair.secret_key.serialize().to_vec();

    store.pre_key_store.save_pre_key(
        pre_key_id,
        &PreKeyRecord::new(pre_key_id, &pre_key_pair),
    ).await?;
    store.signed_pre_key_store.save_signed_pre_key(
        spk_id,
        &SignedPreKeyRecord::new(spk_id, ts, &signed_pre_key_pair, &spk_sig),
    ).await?;
    store.kyber_pre_key_store.save_kyber_pre_key(
        kpk_id,
        &KyberPreKeyRecord::new(kpk_id, ts, &kyber_pre_key_pair, &kpk_sig),
    ).await?;

    Ok((bundle, pk_private, spk_private, kpk_private_bytes))
}

// ---------------------------------------------------------------------------
// op: session_encrypt
//
// Deterministically generates Alice and Bob's key material, establishes a
// PQXDH session (Alice → Bob) and encrypts a PreKeySignalMessage.
//
// Params:  plaintext_hex, seed_hex
// Returns: alice/bob identity keys, bob bundle key material, prekey_msg_hex
// ---------------------------------------------------------------------------

async fn op_session_encrypt(
    params: &serde_json::Value,
    rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let plaintext_hex = params["plaintext_hex"].as_str().unwrap_or("48656c6c6f");
    let plaintext = hex::decode(plaintext_hex).context("plaintext_hex")?;

    let alice_uuid = "11111111-1111-1111-1111-111111111111";
    let bob_uuid   = "22222222-2222-2222-2222-222222222222";
    let alice_addr = ProtocolAddress::new(alice_uuid.to_string(), DeviceId::new(1).unwrap());
    let bob_addr   = ProtocolAddress::new(bob_uuid.to_string(),   DeviceId::new(1).unwrap());

    let mut alice_store = make_store(rng, 1001)?;
    let mut bob_store   = make_store(rng, 1002)?;

    let (bob_bundle, pk_priv, spk_priv, kpk_priv_bytes) =
        setup_recipient_bundle(&mut bob_store, rng).await?;

    process_prekey_bundle(
        &bob_addr,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_bundle,
        SystemTime::UNIX_EPOCH,
        rng,
    ).await?;

    let ciphertext = message_encrypt(
        &plaintext,
        &bob_addr,
        &alice_addr,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::UNIX_EPOCH,
        rng,
    ).await?;

    let alice_identity = alice_store.identity_store.get_identity_key_pair().await?;
    let bob_identity   = bob_store.identity_store.get_identity_key_pair().await?;

    Ok(serde_json::json!({
        "alice_identity_private_hex": hex::encode(alice_identity.private_key().serialize()),
        "alice_identity_public_hex":  hex::encode(alice_identity.public_key().serialize()),
        "bob_identity_private_hex":   hex::encode(bob_identity.private_key().serialize()),
        "bob_identity_public_hex":    hex::encode(bob_identity.public_key().serialize()),
        "bob_registration_id":        bob_bundle.registration_id()?,
        "bob_pre_key_id":             u32::from(bob_bundle.pre_key_id()?.unwrap_or(PreKeyId::from(0u32))),
        "bob_pre_key_public_hex":     hex::encode(bob_bundle.pre_key_public()?.unwrap().serialize()),
        "bob_pre_key_private_hex":    hex::encode(pk_priv.serialize()),
        "bob_signed_pre_key_id":      u32::from(bob_bundle.signed_pre_key_id()?),
        "bob_signed_pre_key_public_hex": hex::encode(bob_bundle.signed_pre_key_public()?.serialize()),
        "bob_signed_pre_key_private_hex": hex::encode(spk_priv.serialize()),
        "bob_signed_pre_key_sig_hex": hex::encode(bob_bundle.signed_pre_key_signature()?),
        "bob_kyber_pre_key_id":       u32::from(bob_bundle.kyber_pre_key_id()?),
        "bob_kyber_pre_key_public_hex": hex::encode(bob_bundle.kyber_pre_key_public()?.serialize()),
        "bob_kyber_pre_key_private_hex": hex::encode(&kpk_priv_bytes),
        "bob_kyber_pre_key_sig_hex":  hex::encode(bob_bundle.kyber_pre_key_signature()?),
        "plaintext_hex":              plaintext_hex,
        "prekey_msg_hex":             hex::encode(ciphertext.serialize()),
        "alice_uuid":                 alice_uuid,
        "bob_uuid":                   bob_uuid,
    }))
}

// ---------------------------------------------------------------------------
// op: session_decrypt
//
// Decrypts a Go-produced PreKeySignalMessage using Bob's stored key material.
//
// Params:
//   prekey_msg_hex
//   bob_identity_private_hex, bob_registration_id
//   bob_pre_key_id, bob_pre_key_private_hex
//   bob_signed_pre_key_id, bob_signed_pre_key_private_hex, bob_signed_pre_key_sig_hex
//   bob_kyber_pre_key_id, bob_kyber_pre_key_public_hex, bob_kyber_pre_key_private_hex, bob_kyber_pre_key_sig_hex
//   alice_identity_public_hex, alice_uuid, bob_uuid
//
// Returns: plaintext_hex
// ---------------------------------------------------------------------------

async fn op_session_decrypt(
    params: &serde_json::Value,
    rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let prekey_msg_hex = params["prekey_msg_hex"].as_str().context("missing prekey_msg_hex")?;
    let bob_priv_hex   = params["bob_identity_private_hex"].as_str().context("missing bob_identity_private_hex")?;
    let bob_reg_id     = params["bob_registration_id"].as_u64().context("missing bob_registration_id")? as u32;
    let alice_pub_hex  = params["alice_identity_public_hex"].as_str().context("missing alice_identity_public_hex")?;
    let alice_uuid     = params["alice_uuid"].as_str().unwrap_or("11111111-1111-1111-1111-111111111111");
    let bob_uuid       = params["bob_uuid"].as_str().unwrap_or("22222222-2222-2222-2222-222222222222");

    let bob_priv = libsignal_protocol::PrivateKey::deserialize(&hex::decode(bob_priv_hex)?)?;
    let bob_pub  = bob_priv.public_key()?;
    let bob_identity = IdentityKeyPair::new(IdentityKey::new(bob_pub), bob_priv);
    let mut bob_store = InMemSignalProtocolStore::new(bob_identity, bob_reg_id)?;

    // One-time pre-key.
    let pk_id: PreKeyId = (params["bob_pre_key_id"].as_u64().context("missing bob_pre_key_id")? as u32).into();
    let pk_priv = libsignal_protocol::PrivateKey::deserialize(
        &hex::decode(params["bob_pre_key_private_hex"].as_str().context("missing bob_pre_key_private_hex")?)?,
    )?;
    let pk_pub = pk_priv.public_key()?;
    bob_store.pre_key_store.save_pre_key(pk_id, &PreKeyRecord::new(pk_id, &KeyPair::new(pk_pub, pk_priv))).await?;

    // Signed pre-key.
    let spk_id: SignedPreKeyId = (params["bob_signed_pre_key_id"].as_u64().context("missing bob_signed_pre_key_id")? as u32).into();
    let spk_priv = libsignal_protocol::PrivateKey::deserialize(
        &hex::decode(params["bob_signed_pre_key_private_hex"].as_str().context("missing bob_signed_pre_key_private_hex")?)?,
    )?;
    let spk_pub = spk_priv.public_key()?;
    let spk_sig = hex::decode(params["bob_signed_pre_key_sig_hex"].as_str().context("missing bob_signed_pre_key_sig_hex")?)?;
    let ts = Timestamp::from_epoch_millis(1_000_000);
    bob_store.signed_pre_key_store.save_signed_pre_key(
        spk_id,
        &SignedPreKeyRecord::new(spk_id, ts, &KeyPair::new(spk_pub, spk_priv), &spk_sig),
    ).await?;

    // Kyber pre-key.
    let kpk_id: KyberPreKeyId = (params["bob_kyber_pre_key_id"].as_u64().context("missing bob_kyber_pre_key_id")? as u32).into();
    let kpk_pub_bytes  = hex::decode(params["bob_kyber_pre_key_public_hex"].as_str().context("missing bob_kyber_pre_key_public_hex")?)?;
    let kpk_priv_bytes = hex::decode(params["bob_kyber_pre_key_private_hex"].as_str().context("missing bob_kyber_pre_key_private_hex")?)?;
    let kpk_sig        = hex::decode(params["bob_kyber_pre_key_sig_hex"].as_str().context("missing bob_kyber_pre_key_sig_hex")?)?;
    let kpk_pair = kem::KeyPair::from_public_and_private(&kpk_pub_bytes, &kpk_priv_bytes)
        .context("kyber KeyPair::from_public_and_private")?;
    bob_store.kyber_pre_key_store.save_kyber_pre_key(
        kpk_id,
        &KyberPreKeyRecord::new(kpk_id, ts, &kpk_pair, &kpk_sig),
    ).await?;

    // Trust Alice's identity.
    let alice_addr = ProtocolAddress::new(alice_uuid.to_string(), DeviceId::new(1).unwrap());
    let alice_pub  = libsignal_protocol::PublicKey::deserialize(&hex::decode(alice_pub_hex)?)?;
    bob_store.identity_store.save_identity(&alice_addr, &IdentityKey::new(alice_pub)).await?;

    let bob_addr = ProtocolAddress::new(bob_uuid.to_string(), DeviceId::new(1).unwrap());
    let prekey_bytes = hex::decode(prekey_msg_hex)?;
    let pksm = PreKeySignalMessage::try_from(prekey_bytes.as_ref())?;

    let plaintext = message_decrypt_prekey(
        &pksm,
        &alice_addr, // remote (sender) = Alice
        &bob_addr,   // local (us) = Bob
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        &mut bob_store.pre_key_store,
        &bob_store.signed_pre_key_store,
        &mut bob_store.kyber_pre_key_store,
        rng,
    ).await?;

    Ok(serde_json::json!({ "plaintext_hex": hex::encode(&plaintext) }))
}

// ---------------------------------------------------------------------------
// op: sealed_v1_encrypt
//
// Params:  plaintext_hex, seed_hex
// Returns: alice/bob identity keys, trust_root/server_key, sender_cert_hex,
//          ciphertext_hex, cert_expiry_ms
// ---------------------------------------------------------------------------

async fn op_sealed_v1_encrypt(
    params: &serde_json::Value,
    rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let plaintext_hex = params["plaintext_hex"].as_str().unwrap_or("48656c6c6f");
    let plaintext = hex::decode(plaintext_hex).context("plaintext_hex")?;
    const CERT_EXPIRY_MS: u64 = 4_102_444_800_000;

    let alice_uuid = "11111111-1111-1111-1111-111111111111";
    let bob_uuid   = "22222222-2222-2222-2222-222222222222";
    let alice_e164 = "+14151111111";

    let trust_root_kp  = KeyPair::generate(rng);
    let server_key_kp  = KeyPair::generate(rng);
    let alice_identity = IdentityKeyPair::generate(rng);
    let bob_identity   = IdentityKeyPair::generate(rng);

    let server_cert = ServerCertificate::new(1, server_key_kp.public_key, &trust_root_kp.private_key, rng)?;
    let expires = Timestamp::from_epoch_millis(CERT_EXPIRY_MS);
    let sender_cert = SenderCertificate::new(
        alice_uuid.to_string(), Some(alice_e164.to_string()),
        alice_identity.public_key().clone(),
        DeviceId::new(1).unwrap(), expires, server_cert,
        &server_key_kp.private_key, rng,
    )?;

    let bob_addr = ProtocolAddress::new(bob_uuid.to_string(), DeviceId::new(1).unwrap());
    let mut alice_id_store = InMemIdentityKeyStore::new(alice_identity.clone(), 1001);
    alice_id_store.save_identity(&bob_addr, &IdentityKey::new(bob_identity.public_key().clone())).await?;

    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::Plaintext,
        sender_cert.clone(),
        plaintext,
        ContentHint::Default,
        None,
    )?;

    let ciphertext = sealed_sender_encrypt_from_usmc(&bob_addr, &usmc, &alice_id_store, rng).await?;

    Ok(serde_json::json!({
        "alice_identity_private_hex": hex::encode(alice_identity.private_key().serialize()),
        "alice_identity_public_hex":  hex::encode(alice_identity.public_key().serialize()),
        "bob_identity_private_hex":   hex::encode(bob_identity.private_key().serialize()),
        "bob_identity_public_hex":    hex::encode(bob_identity.public_key().serialize()),
        "trust_root_private_hex":     hex::encode(trust_root_kp.private_key.serialize()),
        "trust_root_public_hex":      hex::encode(trust_root_kp.public_key.serialize()),
        "server_key_private_hex":     hex::encode(server_key_kp.private_key.serialize()),
        "server_key_public_hex":      hex::encode(server_key_kp.public_key.serialize()),
        "sender_cert_serialized_hex": hex::encode(sender_cert.serialized()?),
        "ciphertext_hex":             hex::encode(&ciphertext),
        "cert_expiry_ms":             CERT_EXPIRY_MS,
        "plaintext_hex":              plaintext_hex,
        "alice_uuid":                 alice_uuid,
        "bob_uuid":                   bob_uuid,
        "alice_e164":                 alice_e164,
    }))
}

// ---------------------------------------------------------------------------
// op: sealed_v1_decrypt
//
// Params:
//   ciphertext_hex, bob_identity_private_hex, alice_identity_public_hex,
//   alice_uuid, bob_uuid
//
// Returns: plaintext_hex, sender_uuid
// ---------------------------------------------------------------------------

async fn op_sealed_v1_decrypt(
    params: &serde_json::Value,
    _rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let ct_hex        = params["ciphertext_hex"].as_str().context("missing ciphertext_hex")?;
    let bob_priv_hex  = params["bob_identity_private_hex"].as_str().context("missing bob_identity_private_hex")?;
    let alice_pub_hex = params["alice_identity_public_hex"].as_str().context("missing alice_identity_public_hex")?;
    let alice_uuid    = params["alice_uuid"].as_str().unwrap_or("11111111-1111-1111-1111-111111111111");

    let bob_priv = libsignal_protocol::PrivateKey::deserialize(&hex::decode(bob_priv_hex)?)?;
    let bob_pub  = bob_priv.public_key()?;
    let bob_identity = IdentityKeyPair::new(IdentityKey::new(bob_pub), bob_priv);
    let mut bob_id_store = InMemIdentityKeyStore::new(bob_identity, 1002);

    let alice_addr = ProtocolAddress::new(alice_uuid.to_string(), DeviceId::new(1).unwrap());
    let alice_pub  = libsignal_protocol::PublicKey::deserialize(&hex::decode(alice_pub_hex)?)?;
    bob_id_store.save_identity(&alice_addr, &IdentityKey::new(alice_pub)).await?;

    let ct_bytes = hex::decode(ct_hex)?;
    let usmc = sealed_sender_decrypt_to_usmc(&ct_bytes, &bob_id_store).await?;

    Ok(serde_json::json!({
        "plaintext_hex": hex::encode(usmc.contents()?),
        "sender_uuid":   usmc.sender()?.sender_uuid()?,
    }))
}

// ---------------------------------------------------------------------------
// op: sealed_v2_encrypt
//
// Two-recipient (Bob + Carol) Sealed Sender v2 multi-recipient encrypt.
//
// Params:  plaintext_hex, seed_hex
// Returns: all key material + sent_message_hex, bob_received_hex, carol_received_hex
// ---------------------------------------------------------------------------

async fn op_sealed_v2_encrypt(
    params: &serde_json::Value,
    rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let plaintext_hex = params["plaintext_hex"].as_str().unwrap_or("48656c6c6f");
    let plaintext = hex::decode(plaintext_hex).context("plaintext_hex")?;
    const CERT_EXPIRY_MS: u64 = 4_102_444_800_000;

    let alice_uuid = "11111111-1111-1111-1111-111111111111";
    let bob_uuid   = "22222222-2222-2222-2222-222222222222";
    let carol_uuid = "33333333-3333-3333-3333-333333333333";
    let alice_e164 = "+14151111111";

    let bob_addr   = ProtocolAddress::new(bob_uuid.to_string(),   DeviceId::new(1).unwrap());
    let carol_addr = ProtocolAddress::new(carol_uuid.to_string(), DeviceId::new(1).unwrap());

    let mut alice_store = make_store(rng, 1001)?;
    let mut bob_store   = make_store(rng, 1002)?;
    let mut carol_store = make_store(rng, 1003)?;

    let (bob_bundle,   _, _, _) = setup_recipient_bundle(&mut bob_store,   rng).await?;
    let (carol_bundle, _, _, _) = setup_recipient_bundle(&mut carol_store, rng).await?;

    process_prekey_bundle(&bob_addr,   &mut alice_store.session_store, &mut alice_store.identity_store, &bob_bundle,   SystemTime::UNIX_EPOCH, rng).await?;
    process_prekey_bundle(&carol_addr, &mut alice_store.session_store, &mut alice_store.identity_store, &carol_bundle, SystemTime::UNIX_EPOCH, rng).await?;

    let alice_identity = alice_store.identity_store.get_identity_key_pair().await?;
    let bob_identity   = bob_store.identity_store.get_identity_key_pair().await?;
    let carol_identity = carol_store.identity_store.get_identity_key_pair().await?;

    let trust_root_kp = KeyPair::generate(rng);
    let server_key_kp = KeyPair::generate(rng);
    let server_cert = ServerCertificate::new(1, server_key_kp.public_key, &trust_root_kp.private_key, rng)?;
    let expires = Timestamp::from_epoch_millis(CERT_EXPIRY_MS);
    let sender_cert = SenderCertificate::new(
        alice_uuid.to_string(), Some(alice_e164.to_string()),
        alice_identity.public_key().clone(),
        DeviceId::new(1).unwrap(), expires, server_cert,
        &server_key_kp.private_key, rng,
    )?;

    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::Plaintext,
        sender_cert.clone(),
        plaintext,
        ContentHint::Default,
        None,
    )?;

    let bob_session   = alice_store.session_store.load_session(&bob_addr).await?.expect("bob session");
    let carol_session = alice_store.session_store.load_session(&carol_addr).await?.expect("carol session");
    let destinations  = [&bob_addr, &carol_addr];
    let sessions      = [&bob_session, &carol_session];

    let sent_message = sealed_sender_multi_recipient_encrypt(
        &destinations, &sessions,
        std::iter::empty::<ServiceId>(),
        &usmc, &alice_store.identity_store, rng,
    ).await?;

    let parsed = SealedSenderV2SentMessage::parse(&sent_message)?;

    let bob_service_id = ServiceId::from(Aci::from_uuid_bytes(
        *Uuid::parse_str(bob_uuid).unwrap().as_bytes(),
    ));
    let carol_service_id = ServiceId::from(Aci::from_uuid_bytes(
        *Uuid::parse_str(carol_uuid).unwrap().as_bytes(),
    ));

    let bob_received: Vec<u8> = parsed.recipients.get(&bob_service_id)
        .map(|r| parsed.received_message_parts_for_recipient(r).as_ref().concat())
        .unwrap_or_default();
    let carol_received: Vec<u8> = parsed.recipients.get(&carol_service_id)
        .map(|r| parsed.received_message_parts_for_recipient(r).as_ref().concat())
        .unwrap_or_default();

    Ok(serde_json::json!({
        "alice_identity_private_hex":  hex::encode(alice_identity.private_key().serialize()),
        "alice_identity_public_hex":   hex::encode(alice_identity.public_key().serialize()),
        "bob_identity_private_hex":    hex::encode(bob_identity.private_key().serialize()),
        "bob_identity_public_hex":     hex::encode(bob_identity.public_key().serialize()),
        "carol_identity_private_hex":  hex::encode(carol_identity.private_key().serialize()),
        "carol_identity_public_hex":   hex::encode(carol_identity.public_key().serialize()),
        "trust_root_public_hex":       hex::encode(trust_root_kp.public_key.serialize()),
        "sender_cert_serialized_hex":  hex::encode(sender_cert.serialized()?),
        "cert_expiry_ms":              CERT_EXPIRY_MS,
        "sent_message_hex":            hex::encode(&sent_message),
        "bob_received_hex":            hex::encode(&bob_received),
        "carol_received_hex":          hex::encode(&carol_received),
        "plaintext_hex":               plaintext_hex,
        "alice_uuid":                  alice_uuid,
        "bob_uuid":                    bob_uuid,
        "carol_uuid":                  carol_uuid,
        "alice_e164":                  alice_e164,
    }))
}

// ---------------------------------------------------------------------------
// op: sealed_v2_decrypt
//
// Params:
//   received_hex, recipient_identity_private_hex, alice_identity_public_hex,
//   alice_uuid, recipient_uuid
//
// Returns: plaintext_hex, sender_uuid
// ---------------------------------------------------------------------------

async fn op_sealed_v2_decrypt(
    params: &serde_json::Value,
    _rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let received_hex   = params["received_hex"].as_str().context("missing received_hex")?;
    let recip_priv_hex = params["recipient_identity_private_hex"].as_str().context("missing recipient_identity_private_hex")?;
    let alice_pub_hex  = params["alice_identity_public_hex"].as_str().context("missing alice_identity_public_hex")?;
    let alice_uuid     = params["alice_uuid"].as_str().unwrap_or("11111111-1111-1111-1111-111111111111");

    let recip_priv = libsignal_protocol::PrivateKey::deserialize(&hex::decode(recip_priv_hex)?)?;
    let recip_pub  = recip_priv.public_key()?;
    let recip_identity = IdentityKeyPair::new(IdentityKey::new(recip_pub), recip_priv);
    let mut recip_id_store = InMemIdentityKeyStore::new(recip_identity, 2000);

    let alice_addr = ProtocolAddress::new(alice_uuid.to_string(), DeviceId::new(1).unwrap());
    let alice_pub  = libsignal_protocol::PublicKey::deserialize(&hex::decode(alice_pub_hex)?)?;
    recip_id_store.save_identity(&alice_addr, &IdentityKey::new(alice_pub)).await?;

    let received_bytes = hex::decode(received_hex)?;
    let usmc = sealed_sender_decrypt_to_usmc(&received_bytes, &recip_id_store).await?;

    Ok(serde_json::json!({
        "plaintext_hex": hex::encode(usmc.contents()?),
        "sender_uuid":   usmc.sender()?.sender_uuid()?,
    }))
}

// ---------------------------------------------------------------------------
// op: sender_key_encrypt
//
// Params:  alice_uuid, distribution_id, plaintext_hex, seed_hex
// Returns: alice_uuid, distribution_id, skdm_hex, ciphertext_hex, plaintext_hex
// ---------------------------------------------------------------------------

async fn op_sender_key_encrypt(
    params: &serde_json::Value,
    rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let alice_uuid    = params["alice_uuid"].as_str().unwrap_or("11111111-1111-1111-1111-111111111111");
    let dist_id_str   = params["distribution_id"].as_str().unwrap_or("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    let plaintext_hex = params["plaintext_hex"].as_str().unwrap_or("48656c6c6f");
    let plaintext     = hex::decode(plaintext_hex).context("plaintext_hex")?;

    let distribution_id = Uuid::parse_str(dist_id_str).context("distribution_id")?;
    let alice_addr = ProtocolAddress::new(alice_uuid.to_string(), DeviceId::new(1).unwrap());
    let mut alice_store = InMemSenderKeyStore::new();

    let skdm = create_sender_key_distribution_message(&alice_addr, distribution_id, &mut alice_store, rng).await?;
    let skm  = group_encrypt(&mut alice_store, &alice_addr, distribution_id, &plaintext, rng).await?;

    Ok(serde_json::json!({
        "alice_uuid":       alice_uuid,
        "distribution_id":  dist_id_str,
        "skdm_hex":         hex::encode(skdm.serialized()),
        "ciphertext_hex":   hex::encode(skm.serialized()),
        "plaintext_hex":    plaintext_hex,
    }))
}

// ---------------------------------------------------------------------------
// op: sender_key_decrypt
//
// Params:
//   alice_uuid, distribution_id, skdm_hex, ciphertext_hex
//
// Returns: plaintext_hex
// ---------------------------------------------------------------------------

async fn op_sender_key_decrypt(
    params: &serde_json::Value,
    _rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let alice_uuid    = params["alice_uuid"].as_str().unwrap_or("11111111-1111-1111-1111-111111111111");
    let dist_id_str   = params["distribution_id"].as_str().context("missing distribution_id")?;
    let skdm_hex      = params["skdm_hex"].as_str().context("missing skdm_hex")?;
    let ct_hex        = params["ciphertext_hex"].as_str().context("missing ciphertext_hex")?;

    let distribution_id = Uuid::parse_str(dist_id_str).context("distribution_id")?;
    let alice_addr = ProtocolAddress::new(alice_uuid.to_string(), DeviceId::new(1).unwrap());
    let mut bob_store = InMemSenderKeyStore::new();

    let skdm_bytes = hex::decode(skdm_hex)?;
    let skdm = libsignal_protocol::SenderKeyDistributionMessage::try_from(skdm_bytes.as_ref())?;
    libsignal_protocol::process_sender_key_distribution_message(&alice_addr, &skdm, &mut bob_store).await?;

    let ct_bytes = hex::decode(ct_hex)?;
    let plaintext = group_decrypt(&ct_bytes, &mut bob_store, &alice_addr).await?;

    Ok(serde_json::json!({ "plaintext_hex": hex::encode(&plaintext) }))
}

// ---------------------------------------------------------------------------
// op: backup_encrypt
//
// AES-256-CBC + PKCS7 encryption matching the Go backup.EncryptFrames format.
// IV is deterministic from the seeded RNG if "iv_hex" is not provided.
//
// Params:  hmac_key_hex (32), aes_key_hex (32), plaintext_hex, [iv_hex], seed_hex
// Returns: iv_hex, ciphertext_hex, hmac_hex
// ---------------------------------------------------------------------------

fn op_backup_encrypt(
    params: &serde_json::Value,
    rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let hmac_key_hex  = params["hmac_key_hex"].as_str().context("missing hmac_key_hex")?;
    let aes_key_hex   = params["aes_key_hex"].as_str().context("missing aes_key_hex")?;
    let plaintext_hex = params["plaintext_hex"].as_str().context("missing plaintext_hex")?;

    let hmac_key:  Vec<u8> = hex::decode(hmac_key_hex)?;
    let aes_key:   Vec<u8> = hex::decode(aes_key_hex)?;
    let plaintext: Vec<u8> = hex::decode(plaintext_hex)?;

    let iv: [u8; 16] = match params["iv_hex"].as_str() {
        Some(h) => {
            let b = hex::decode(h)?;
            if b.len() != 16 { bail!("iv_hex must be 16 bytes"); }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        None => {
            let mut arr = [0u8; 16];
            rand::RngCore::fill_bytes(rng, &mut arr);
            arr
        }
    };

    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(&plaintext);
    let enc = cbc::Encryptor::<Aes256>::new(aes_key.as_slice().into(), &iv.into());
    let ct_len = enc.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| anyhow::anyhow!("AES-CBC: {:?}", e))?
        .len();
    buf.truncate(ct_len);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
        .map_err(|e| anyhow::anyhow!("HMAC: {e}"))?;
    mac.update(&iv);
    mac.update(&buf);
    let hmac_out = mac.finalize().into_bytes();

    Ok(serde_json::json!({
        "iv_hex":         hex::encode(iv),
        "ciphertext_hex": hex::encode(&buf),
        "hmac_hex":       hex::encode(hmac_out),
    }))
}

// ---------------------------------------------------------------------------
// op: backup_decrypt
//
// Params:  hmac_key_hex, aes_key_hex, iv_hex, ciphertext_hex, hmac_hex
// Returns: plaintext_hex
// ---------------------------------------------------------------------------

fn op_backup_decrypt(
    params: &serde_json::Value,
    _rng: &mut ChaCha20Rng,
) -> Result<serde_json::Value> {
    let hmac_key_hex = params["hmac_key_hex"].as_str().context("missing hmac_key_hex")?;
    let aes_key_hex  = params["aes_key_hex"].as_str().context("missing aes_key_hex")?;
    let iv_hex       = params["iv_hex"].as_str().context("missing iv_hex")?;
    let ct_hex       = params["ciphertext_hex"].as_str().context("missing ciphertext_hex")?;
    let hmac_hex     = params["hmac_hex"].as_str().context("missing hmac_hex")?;

    let hmac_key:      Vec<u8> = hex::decode(hmac_key_hex)?;
    let aes_key:       Vec<u8> = hex::decode(aes_key_hex)?;
    let iv_bytes:      Vec<u8> = hex::decode(iv_hex)?;
    let ciphertext:    Vec<u8> = hex::decode(ct_hex)?;
    let expected_hmac: Vec<u8> = hex::decode(hmac_hex)?;

    if iv_bytes.len() != 16 { bail!("iv must be 16 bytes"); }

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
        .map_err(|e| anyhow::anyhow!("HMAC: {e}"))?;
    mac.update(&iv_bytes);
    mac.update(&ciphertext);
    let actual = mac.finalize().into_bytes();
    if actual.as_slice() != expected_hmac.as_slice() {
        bail!("HMAC verification failed");
    }

    let mut buf = ciphertext.clone();
    let iv_arr: [u8; 16] = iv_bytes.try_into().unwrap();
    let dec = cbc::Decryptor::<Aes256>::new(aes_key.as_slice().into(), &iv_arr.into());
    let pt = dec.decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("AES-CBC: {:?}", e))?;

    Ok(serde_json::json!({ "plaintext_hex": hex::encode(pt) }))
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn dispatch(cmd: Command, rt: &tokio::runtime::Runtime) -> Response {
    let mut rng = match rng_from_seed_hex(&cmd.seed_hex) {
        Ok(r)  => r,
        Err(e) => return err_resp(e),
    };

    let result: Result<serde_json::Value> = match cmd.op.as_str() {
        "session_encrypt"    => rt.block_on(op_session_encrypt(&cmd.params, &mut rng)),
        "session_decrypt"    => rt.block_on(op_session_decrypt(&cmd.params, &mut rng)),
        "sealed_v1_encrypt"  => rt.block_on(op_sealed_v1_encrypt(&cmd.params, &mut rng)),
        "sealed_v1_decrypt"  => rt.block_on(op_sealed_v1_decrypt(&cmd.params, &mut rng)),
        "sealed_v2_encrypt"  => rt.block_on(op_sealed_v2_encrypt(&cmd.params, &mut rng)),
        "sealed_v2_decrypt"  => rt.block_on(op_sealed_v2_decrypt(&cmd.params, &mut rng)),
        "sender_key_encrypt" => rt.block_on(op_sender_key_encrypt(&cmd.params, &mut rng)),
        "sender_key_decrypt" => rt.block_on(op_sender_key_decrypt(&cmd.params, &mut rng)),
        "backup_encrypt"     => op_backup_encrypt(&cmd.params, &mut rng),
        "backup_decrypt"     => op_backup_decrypt(&cmd.params, &mut rng),
        other                => Err(anyhow::anyhow!("unknown op: {}", other)),
    };

    match result {
        Ok(fields) => ok(fields),
        Err(e)     => err_resp(e),
    }
}

// ---------------------------------------------------------------------------
// Entry point — newline-delimited JSON loop
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;

    let stdin  = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = line.context("reading stdin")?;
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let resp = match serde_json::from_str::<Command>(line) {
            Ok(cmd)  => dispatch(cmd, &rt),
            Err(e)   => err_resp(format!("JSON parse: {e}")),
        };
        let json = serde_json::to_string(&resp).context("serializing")?;
        writeln!(out, "{}", json).context("writing")?;
        out.flush().context("flush")?;
    }
    Ok(())
}
