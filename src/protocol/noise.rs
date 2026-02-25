use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::protocol::frame::Frame;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const HANDSHAKE_MAX_BYTES: usize = 1024;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;

#[derive(Debug)]
pub struct SecureChannel {
    stream: TcpStream,
    state: TransportState,
    session_id: String,
    remote_public_key: Vec<u8>,
    remote_fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct NoiseKeypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl SecureChannel {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn remote_public_key(&self) -> &[u8] {
        &self.remote_public_key
    }

    pub fn remote_fingerprint(&self) -> &str {
        &self.remote_fingerprint
    }

    pub async fn connect(addr: SocketAddr, local_private_key: &[u8]) -> Result<Self> {
        let mut stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("failed to connect to {addr}"))?;

        let mut handshake = build_initiator(local_private_key)?;
        let mut handshake_buffer = [0_u8; HANDSHAKE_MAX_BYTES];

        let message_len = handshake
            .write_message(&[], &mut handshake_buffer)
            .context("failed to create initiator handshake message #1")?;
        write_prefixed(&mut stream, &handshake_buffer[..message_len]).await?;

        let response_2 = read_prefixed(&mut stream).await?;
        handshake
            .read_message(&response_2, &mut handshake_buffer)
            .context("failed to process responder handshake message #2")?;

        let message_3_len = handshake
            .write_message(&[], &mut handshake_buffer)
            .context("failed to create initiator handshake message #3")?;
        write_prefixed(&mut stream, &handshake_buffer[..message_3_len]).await?;

        let remote_public_key = handshake
            .get_remote_static()
            .map(ToOwned::to_owned)
            .context("responder static public key missing in Noise XX handshake")?;
        let remote_fingerprint = key_fingerprint(&remote_public_key);

        let session_id = derive_session_id(handshake.get_handshake_hash());
        let state = handshake
            .into_transport_mode()
            .context("failed to enter transport mode")?;

        Ok(Self {
            stream,
            state,
            session_id,
            remote_public_key,
            remote_fingerprint,
        })
    }

    pub async fn accept(mut stream: TcpStream, local_private_key: &[u8]) -> Result<Self> {
        let mut handshake = build_responder(local_private_key)?;
        let mut handshake_buffer = [0_u8; HANDSHAKE_MAX_BYTES];

        let request_1 = read_prefixed(&mut stream).await?;
        handshake
            .read_message(&request_1, &mut handshake_buffer)
            .context("failed to process initiator handshake message #1")?;

        let response_2_len = handshake
            .write_message(&[], &mut handshake_buffer)
            .context("failed to create responder handshake message #2")?;
        write_prefixed(&mut stream, &handshake_buffer[..response_2_len]).await?;

        let request_3 = read_prefixed(&mut stream).await?;
        handshake
            .read_message(&request_3, &mut handshake_buffer)
            .context("failed to process initiator handshake message #3")?;

        let remote_public_key = handshake
            .get_remote_static()
            .map(ToOwned::to_owned)
            .context("initiator static public key missing in Noise XX handshake")?;
        let remote_fingerprint = key_fingerprint(&remote_public_key);

        let session_id = derive_session_id(handshake.get_handshake_hash());
        let state = handshake
            .into_transport_mode()
            .context("failed to enter transport mode")?;

        Ok(Self {
            stream,
            state,
            session_id,
            remote_public_key,
            remote_fingerprint,
        })
    }

    pub async fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        let plain = frame.encode_plain();
        let mut encrypted = vec![0_u8; plain.len() + 16 + 64];
        let encrypted_len = self
            .state
            .write_message(&plain, &mut encrypted)
            .context("failed to encrypt frame")?;

        if encrypted_len == 0 || encrypted_len > MAX_FRAME_BYTES {
            bail!("invalid encrypted frame size: {encrypted_len}");
        }

        self.stream
            .write_u32(encrypted_len as u32)
            .await
            .context("failed to write frame length")?;
        self.stream
            .write_all(&encrypted[..encrypted_len])
            .await
            .context("failed to write frame payload")?;
        self.stream.flush().await.context("failed to flush frame")?;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> Result<Frame> {
        let encrypted_len = self
            .stream
            .read_u32()
            .await
            .context("failed to read frame length")? as usize;

        if encrypted_len == 0 || encrypted_len > MAX_FRAME_BYTES {
            bail!("encrypted frame too large: {encrypted_len}");
        }

        let mut encrypted = vec![0_u8; encrypted_len];
        self.stream
            .read_exact(&mut encrypted)
            .await
            .context("failed to read encrypted frame")?;

        let mut plain = vec![0_u8; encrypted_len + 64];
        let plain_len = self
            .state
            .read_message(&encrypted, &mut plain)
            .context("failed to decrypt frame")?;

        Frame::decode_plain(&plain[..plain_len]).context("failed to decode frame")
    }
}

pub fn generate_keypair() -> Result<NoiseKeypair> {
    let params = noise_params()?;
    let builder = Builder::new(params);
    let keypair = builder
        .generate_keypair()
        .context("failed to generate noise keypair")?;
    Ok(NoiseKeypair {
        private: keypair.private,
        public: keypair.public,
    })
}

pub fn generate_keypair_b64() -> Result<(String, String)> {
    let keypair = generate_keypair()?;
    Ok((
        STANDARD.encode(keypair.private),
        STANDARD.encode(keypair.public),
    ))
}

pub fn decode_key_b64(value: &str, label: &str) -> Result<Vec<u8>> {
    let decoded = STANDARD
        .decode(value)
        .with_context(|| format!("failed to decode base64 key for {label}"))?;
    if decoded.len() != 32 {
        bail!("invalid {label}: expected 32 bytes, got {}", decoded.len());
    }
    Ok(decoded)
}

pub fn key_fingerprint(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn load_keypair_file(path: &Path) -> Result<NoiseKeypair> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read keypair file {}", path.display()))?;
    parse_keypair_file(&content)
}

pub fn write_keypair_file(path: &Path, keypair: &NoiseKeypair, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        bail!(
            "keypair file already exists at {} (use --force to overwrite)",
            path.display()
        );
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create keypair directory {}", parent.display())
            })?;
        }
    }

    let content = format!(
        "# XDNS static Noise keypair\nprivate={}\npublic={}\n",
        STANDARD.encode(&keypair.private),
        STANDARD.encode(&keypair.public)
    );
    fs::write(path, content)
        .with_context(|| format!("failed to write keypair file {}", path.display()))
}

pub fn generate_and_write_keypair(path: &Path, overwrite: bool) -> Result<NoiseKeypair> {
    let keypair = generate_keypair()?;
    write_keypair_file(path, &keypair, overwrite)?;
    Ok(keypair)
}

pub fn load_or_generate_keypair(path: &Path) -> Result<(NoiseKeypair, bool)> {
    if path.exists() {
        return Ok((load_keypair_file(path)?, false));
    }
    Ok((generate_and_write_keypair(path, false)?, true))
}

fn parse_keypair_file(content: &str) -> Result<NoiseKeypair> {
    let mut private = None::<String>;
    let mut public = None::<String>;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim().to_string();
        match key {
            "private" => private = Some(value),
            "public" => public = Some(value),
            _ => {}
        }
    }

    let private = private.context("keypair file is missing `private=` line")?;
    let public = public.context("keypair file is missing `public=` line")?;
    Ok(NoiseKeypair {
        private: decode_key_b64(&private, "private")?,
        public: decode_key_b64(&public, "public")?,
    })
}

fn build_initiator(local_private_key: &[u8]) -> Result<HandshakeState> {
    let params = noise_params()?;
    Builder::new(params)
        .local_private_key(local_private_key)
        .build_initiator()
        .context("failed to build noise initiator")
}

fn build_responder(local_private_key: &[u8]) -> Result<HandshakeState> {
    let params = noise_params()?;
    Builder::new(params)
        .local_private_key(local_private_key)
        .build_responder()
        .context("failed to build noise responder")
}

fn noise_params() -> Result<NoiseParams> {
    NOISE_PATTERN
        .parse::<NoiseParams>()
        .context("failed to parse noise parameters")
}

fn derive_session_id(handshake_hash: &[u8]) -> String {
    let mut out = String::new();
    for byte in handshake_hash.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

async fn write_prefixed(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    if payload.len() > u16::MAX as usize {
        bail!("handshake message too large: {}", payload.len());
    }
    stream
        .write_u16(payload.len() as u16)
        .await
        .context("failed to write handshake length")?;
    stream
        .write_all(payload)
        .await
        .context("failed to write handshake payload")?;
    stream
        .flush()
        .await
        .context("failed to flush handshake payload")?;
    Ok(())
}

async fn read_prefixed(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let len = stream
        .read_u16()
        .await
        .context("failed to read handshake length")? as usize;
    if len == 0 || len > HANDSHAKE_MAX_BYTES {
        bail!("invalid handshake message length: {len}");
    }

    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("failed to read handshake payload")?;
    Ok(payload)
}
