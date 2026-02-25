use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::dns::wire;

#[derive(Debug, Clone)]
pub struct UpstreamResolver {
    upstream_addr: SocketAddr,
    timeout: Duration,
}

impl UpstreamResolver {
    pub fn new(upstream_addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            upstream_addr,
            timeout,
        }
    }

    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        let udp_response = self.resolve_udp(query).await?;
        if wire::is_truncated(&udp_response) {
            return self.resolve_tcp(query).await;
        }
        Ok(udp_response)
    }

    async fn resolve_udp(&self, query: &[u8]) -> Result<Vec<u8>> {
        let bind_addr = if self.upstream_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind UDP socket at {bind_addr}"))?;

        timeout(self.timeout, socket.send_to(query, self.upstream_addr))
            .await
            .context("upstream UDP send timed out")?
            .with_context(|| format!("failed to send UDP query to {}", self.upstream_addr))?;

        let mut buffer = vec![0_u8; u16::MAX as usize];
        let (response_len, _) = timeout(self.timeout, socket.recv_from(&mut buffer))
            .await
            .context("upstream UDP receive timed out")?
            .context("failed to receive UDP response")?;

        buffer.truncate(response_len);
        Ok(buffer)
    }

    async fn resolve_tcp(&self, query: &[u8]) -> Result<Vec<u8>> {
        let mut stream = timeout(self.timeout, TcpStream::connect(self.upstream_addr))
            .await
            .context("upstream TCP connect timed out")?
            .with_context(|| format!("failed to connect to upstream {}", self.upstream_addr))?;

        if query.len() > u16::MAX as usize {
            anyhow::bail!("query too large for DNS-over-TCP: {}", query.len());
        }

        timeout(self.timeout, stream.write_u16(query.len() as u16))
            .await
            .context("upstream TCP write length timed out")?
            .context("failed to write DNS-over-TCP request length")?;
        timeout(self.timeout, stream.write_all(query))
            .await
            .context("upstream TCP write payload timed out")?
            .context("failed to write DNS-over-TCP request payload")?;
        timeout(self.timeout, stream.flush())
            .await
            .context("upstream TCP flush timed out")?
            .context("failed to flush DNS-over-TCP request")?;

        let response_len = timeout(self.timeout, stream.read_u16())
            .await
            .context("upstream TCP read length timed out")?
            .context("failed to read DNS-over-TCP response length")?
            as usize;

        let mut response = vec![0_u8; response_len];
        timeout(self.timeout, stream.read_exact(&mut response))
            .await
            .context("upstream TCP read payload timed out")?
            .context("failed to read DNS-over-TCP response payload")?;
        Ok(response)
    }
}
