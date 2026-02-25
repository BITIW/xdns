use anyhow::{Context, Result, bail};
use bytes::{Buf, BufMut, BytesMut};
use rand::{Rng, RngCore, thread_rng};

pub const FLAG_PADDED: u8 = 0x01;
const HEADER_LEN: usize = 14;
const MAX_PADDING_BYTES: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    DnsQuery = 1,
    DnsResponse = 2,
    Ping = 3,
    Pong = 4,
    BatchQuery = 5,
}

impl TryFrom<u8> for FrameKind {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::DnsQuery),
            2 => Ok(Self::DnsResponse),
            3 => Ok(Self::Ping),
            4 => Ok(Self::Pong),
            5 => Ok(Self::BatchQuery),
            _ => bail!("unknown frame kind: {value}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: FrameKind,
    pub flags: u8,
    pub request_id: u32,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode_plain(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        out.put_u8(self.kind as u8);
        out.put_u8(self.flags);
        out.put_u32(self.request_id);
        out.put_u64(self.sequence);
        out.extend_from_slice(&self.payload);
        out.to_vec()
    }

    pub fn decode_plain(input: &[u8]) -> Result<Self> {
        if input.len() < HEADER_LEN {
            bail!("frame too short: {}", input.len());
        }

        let mut bytes = input;
        let kind = FrameKind::try_from(bytes.get_u8())?;
        let flags = bytes.get_u8();
        let request_id = bytes.get_u32();
        let sequence = bytes.get_u64();
        let payload = bytes.to_vec();

        Ok(Self {
            kind,
            flags,
            request_id,
            sequence,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BatchItem {
    pub request_id: u32,
    pub payload: Vec<u8>,
}

pub fn encode_batch(items: &[BatchItem]) -> Result<Vec<u8>> {
    if items.len() > u16::MAX as usize {
        bail!("batch too large: {} items", items.len());
    }

    let mut out = BytesMut::new();
    out.put_u16(items.len() as u16);

    for item in items {
        if item.payload.len() > u16::MAX as usize {
            bail!("batch item payload too large: {}", item.payload.len());
        }
        out.put_u32(item.request_id);
        out.put_u16(item.payload.len() as u16);
        out.extend_from_slice(&item.payload);
    }

    Ok(out.to_vec())
}

pub fn decode_batch(input: &[u8]) -> Result<Vec<BatchItem>> {
    if input.len() < 2 {
        bail!("batch payload too short");
    }

    let mut bytes = input;
    let count = bytes.get_u16() as usize;
    let mut out = Vec::with_capacity(count);

    for _ in 0..count {
        if bytes.remaining() < 6 {
            bail!("truncated batch entry");
        }
        let request_id = bytes.get_u32();
        let payload_len = bytes.get_u16() as usize;
        if bytes.remaining() < payload_len {
            bail!("truncated batch payload");
        }

        let mut payload = vec![0_u8; payload_len];
        bytes.copy_to_slice(&mut payload);
        out.push(BatchItem {
            request_id,
            payload,
        });
    }

    if bytes.has_remaining() {
        bail!("unexpected trailing bytes in batch payload");
    }

    Ok(out)
}

pub fn add_padding(payload: &[u8], max_padding: usize) -> Result<(Vec<u8>, u8)> {
    if max_padding == 0 {
        return Ok((payload.to_vec(), 0));
    }

    if payload.len() > u16::MAX as usize {
        bail!("payload too large for padding header: {}", payload.len());
    }

    let padding_len = thread_rng().gen_range(0..=max_padding.min(MAX_PADDING_BYTES));
    let mut out = BytesMut::with_capacity(2 + payload.len() + padding_len);
    out.put_u16(payload.len() as u16);
    out.extend_from_slice(payload);

    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len];
        thread_rng().fill_bytes(&mut padding);
        out.extend_from_slice(&padding);
    }

    Ok((out.to_vec(), FLAG_PADDED))
}

pub fn strip_padding(flags: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload.to_vec());
    }

    if payload.len() < 2 {
        bail!("padded payload is missing length prefix");
    }

    let mut bytes = payload;
    let original_len = bytes.get_u16() as usize;
    if bytes.remaining() < original_len {
        bail!(
            "padded payload is truncated: expected {original_len} bytes, got {}",
            bytes.remaining()
        );
    }

    let mut out = vec![0_u8; original_len];
    bytes.copy_to_slice(&mut out);
    Ok(out)
}

pub fn with_optional_padding(payload: &[u8], max_padding: usize) -> Result<(Vec<u8>, u8)> {
    add_padding(payload, max_padding).context("failed to apply frame padding")
}
