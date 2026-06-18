// libsignal-interop: Rust CLI for SPQR wire-format interop testing.
//
// Subcommands:
//   spqr-init  --seed <u64> --direction <a2b|b2a>
//   spqr-send  --seed <u64> --state-hex <hex>
//   spqr-recv  --state-hex <hex> --msg-hex <hex>
//
// All subcommands emit JSON to stdout on success, or JSON {"error":"..."} to
// stderr with non-zero exit status on failure.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use spqr::{initial_state, recv, send, ChainParams, Direction, Params, Version};
use std::process;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "libsignal-interop", about = "SPQR wire-format interop harness")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize SPQR state; emits {"state_hex":"..."}.
    SpqrInit {
        /// Seed for ChaCha20Rng (unused for init, kept for API symmetry).
        #[arg(long)]
        seed: u64,
        /// Direction: a2b or b2a.
        #[arg(long)]
        direction: String,
    },
    /// Run one send step; emits {"state_hex":"...","key_hex":"...","msg_hex":"..."}.
    SpqrSend {
        /// Seed for ChaCha20Rng.
        #[arg(long)]
        seed: u64,
        /// Current serialized state as hex.
        #[arg(long)]
        state_hex: String,
    },
    /// Run one recv step; emits {"state_hex":"...","key_hex":"..."}.
    SpqrRecv {
        /// Current serialized state as hex.
        #[arg(long)]
        state_hex: String,
        /// Wire message as hex.
        #[arg(long)]
        msg_hex: String,
    },
}

// ---------------------------------------------------------------------------
// JSON output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct InitOutput {
    state_hex: String,
}

#[derive(Serialize)]
struct SendOutput {
    state_hex: String,
    key_hex: String,
    msg_hex: String,
}

#[derive(Serialize)]
struct RecvOutput {
    state_hex: String,
    key_hex: String,
}

#[derive(Serialize)]
struct ErrorOutput {
    error: String,
}

// ---------------------------------------------------------------------------
// Auth key: fixed shared secret used for all interop tests.
// Both sides (Rust and Go) must use the same auth_key so chain keys agree.
// ---------------------------------------------------------------------------
const AUTH_KEY: &[u8; 32] = b"interop-shared-auth-key-32bytes!";

// ---------------------------------------------------------------------------
// Direction helper
// ---------------------------------------------------------------------------

fn parse_direction(s: &str) -> Result<Direction> {
    match s.to_ascii_lowercase().as_str() {
        "a2b" => Ok(Direction::A2B),
        "b2a" => Ok(Direction::B2A),
        other => bail!("unknown direction {:?}; expected 'a2b' or 'b2a'", other),
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_spqr_init(direction_str: &str) -> Result<()> {
    let direction = parse_direction(direction_str)?;

    let state = initial_state(Params {
        direction,
        version: Version::V1,
        min_version: Version::V1,
        auth_key: AUTH_KEY,
        chain_params: ChainParams::default(),
    })
    .context("spqr::initial_state failed")?;

    let out = InitOutput {
        state_hex: hex::encode(&state),
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

fn cmd_spqr_send(seed: u64, state_hex: &str) -> Result<()> {
    let state_bytes = hex::decode(state_hex).context("state-hex is not valid hex")?;
    // ChaCha20Rng from rand_chacha 0.9 satisfies spqr v1.5.1's Rng + CryptoRng bounds.
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let result = send(&state_bytes, &mut rng).context("spqr::send failed")?;

    let out = SendOutput {
        state_hex: hex::encode(&result.state),
        key_hex: result
            .key
            .as_deref()
            .map(hex::encode)
            .unwrap_or_default(),
        msg_hex: hex::encode(&result.msg),
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

fn cmd_spqr_recv(state_hex: &str, msg_hex: &str) -> Result<()> {
    let state_bytes = hex::decode(state_hex).context("state-hex is not valid hex")?;
    let msg_bytes = hex::decode(msg_hex).context("msg-hex is not valid hex")?;

    let result = recv(&state_bytes, &msg_bytes).context("spqr::recv failed")?;

    let out = RecvOutput {
        state_hex: hex::encode(&result.state),
        key_hex: result
            .key
            .as_deref()
            .map(hex::encode)
            .unwrap_or_default(),
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::SpqrInit { seed: _, direction } => cmd_spqr_init(direction),
        Commands::SpqrSend { seed, state_hex } => cmd_spqr_send(*seed, state_hex),
        Commands::SpqrRecv { state_hex, msg_hex } => cmd_spqr_recv(state_hex, msg_hex),
    };

    if let Err(e) = result {
        let err_out = ErrorOutput {
            error: format!("{:#}", e),
        };
        eprintln!(
            "{}",
            serde_json::to_string(&err_out).unwrap_or_else(|_| format!(
                r#"{{"error":"{}"}}"#,
                e
            ))
        );
        process::exit(1);
    }
}
