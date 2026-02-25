use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

use crate::dns::cache::DnsCache;
use crate::dns::wire;
use crate::protocol::frame::{
    BatchItem, Frame, FrameKind, encode_batch, strip_padding, with_optional_padding,
};
use crate::protocol::noise::SecureChannel;
use crate::protocol::replay::ReplayFilter;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub listen_udp: SocketAddr,
    pub listen_tcp: SocketAddr,
    pub server_addr: SocketAddr,
    pub client_private_key: Vec<u8>,
    pub server_fingerprint_file: PathBuf,
    pub request_timeout: Duration,
    pub keepalive_interval: Duration,
    pub cache_max_entries: usize,
    pub cache_max_ttl: u32,
    pub cache_negative_ttl: u32,
    pub max_padding: usize,
    pub batch_size: usize,
}

pub async fn run(config: ClientConfig) -> Result<()> {
    let cache = DnsCache::new(
        config.cache_max_entries,
        config.cache_max_ttl,
        config.cache_negative_ttl,
    );
    let (request_tx, request_rx) = mpsc::channel(1024);

    tokio::try_join!(
        run_connection_manager(config.clone(), request_rx),
        run_udp_listener(
            config.listen_udp,
            request_tx.clone(),
            cache.clone(),
            config.request_timeout
        ),
        run_tcp_listener(config.listen_tcp, request_tx, cache, config.request_timeout),
    )?;

    Ok(())
}

#[derive(Debug)]
struct PendingDnsRequest {
    query: Vec<u8>,
    response_tx: oneshot::Sender<Result<Vec<u8>>>,
}

struct ConnectionManager {
    config: ClientConfig,
    request_rx: mpsc::Receiver<PendingDnsRequest>,
    pending: HashMap<u32, oneshot::Sender<Result<Vec<u8>>>>,
    pinned_server_fingerprint: Option<String>,
    next_request_id: u32,
    next_sequence: u64,
    replay_filter: ReplayFilter,
}

async fn run_connection_manager(
    config: ClientConfig,
    request_rx: mpsc::Receiver<PendingDnsRequest>,
) -> Result<()> {
    let pinned_server_fingerprint = load_pinned_fingerprint(&config.server_fingerprint_file)?;
    let mut manager = ConnectionManager {
        config,
        request_rx,
        pending: HashMap::new(),
        pinned_server_fingerprint,
        next_request_id: 1,
        next_sequence: 1,
        replay_filter: ReplayFilter::new(128),
    };

    manager.run().await
}

impl ConnectionManager {
    async fn run(&mut self) -> Result<()> {
        loop {
            let mut channel = match SecureChannel::connect(
                self.config.server_addr,
                &self.config.client_private_key,
            )
            .await
            {
                Ok(channel) => channel,
                Err(error) => {
                    warn!(
                        "failed to connect to server {}: {error:#}",
                        self.config.server_addr
                    );
                    self.fail_all_pending(anyhow!("secure channel is not available"));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            if let Err(error) = self.validate_or_pin_server(channel.remote_fingerprint()) {
                warn!(
                    "server fingerprint validation failed for {}: {error:#}",
                    self.config.server_addr
                );
                self.fail_all_pending(anyhow!("server fingerprint mismatch"));
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            self.replay_filter = ReplayFilter::new(128);
            info!(
                "secure channel established to {} (session={}, fingerprint={})",
                self.config.server_addr,
                channel.session_id(),
                channel.remote_fingerprint()
            );

            let result = self.run_connected(&mut channel).await;
            if let Err(error) = result {
                warn!("secure channel closed: {error:#}");
            }
            self.fail_all_pending(anyhow!("secure channel disconnected"));

            if self.request_rx.is_closed() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn run_connected(&mut self, channel: &mut SecureChannel) -> Result<()> {
        let mut keepalive = interval(self.config.keepalive_interval);

        loop {
            tokio::select! {
                _ = keepalive.tick() => {
                    let frame = Frame {
                        kind: FrameKind::Ping,
                        flags: 0,
                        request_id: 0,
                        sequence: self.next_sequence(),
                        payload: Vec::new(),
                    };
                    channel.send_frame(&frame).await.context("failed to send keepalive ping")?;
                }
                request = self.request_rx.recv() => {
                    let Some(first_request) = request else {
                        return Ok(());
                    };

                    let mut batch = vec![first_request];
                    while batch.len() < self.config.batch_size {
                        match self.request_rx.try_recv() {
                            Ok(next) => batch.push(next),
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }

                    if batch.len() == 1 {
                        let request = batch.pop().expect("single batch item is present");
                        self.send_single(channel, request).await?;
                    } else {
                        self.send_batch(channel, batch).await?;
                    }
                }
                frame = channel.recv_frame() => {
                    let frame = frame?;
                    self.handle_incoming_frame(channel, frame).await?;
                }
            }
        }
    }

    async fn send_single(
        &mut self,
        channel: &mut SecureChannel,
        request: PendingDnsRequest,
    ) -> Result<()> {
        let request_id = self.next_request_id();
        let (payload, flags) = with_optional_padding(&request.query, self.config.max_padding)?;

        self.pending.insert(request_id, request.response_tx);
        let frame = Frame {
            kind: FrameKind::DnsQuery,
            flags,
            request_id,
            sequence: self.next_sequence(),
            payload,
        };

        if let Err(error) = channel.send_frame(&frame).await {
            self.fail_pending(request_id, anyhow!("failed to send DNS query: {error:#}"));
            return Err(error);
        }
        Ok(())
    }

    async fn send_batch(
        &mut self,
        channel: &mut SecureChannel,
        batch: Vec<PendingDnsRequest>,
    ) -> Result<()> {
        let mut items = Vec::with_capacity(batch.len());
        let mut request_ids = Vec::with_capacity(batch.len());

        for request in batch {
            let request_id = self.next_request_id();
            request_ids.push(request_id);
            self.pending.insert(request_id, request.response_tx);
            items.push(BatchItem {
                request_id,
                payload: request.query,
            });
        }

        let encoded_batch = match encode_batch(&items) {
            Ok(payload) => payload,
            Err(error) => {
                for request_id in request_ids {
                    self.fail_pending(
                        request_id,
                        anyhow!("failed to encode DNS batch payload: {error:#}"),
                    );
                }
                return Err(error);
            }
        };
        let (payload, flags) = with_optional_padding(&encoded_batch, self.config.max_padding)?;

        let frame = Frame {
            kind: FrameKind::BatchQuery,
            flags,
            request_id: 0,
            sequence: self.next_sequence(),
            payload,
        };

        if let Err(error) = channel.send_frame(&frame).await {
            for request_id in request_ids {
                self.fail_pending(
                    request_id,
                    anyhow!("failed to send DNS batch query: {error:#}"),
                );
            }
            return Err(error);
        }

        Ok(())
    }

    async fn handle_incoming_frame(
        &mut self,
        channel: &mut SecureChannel,
        frame: Frame,
    ) -> Result<()> {
        if let Err(error) = self.replay_filter.check_and_mark(frame.sequence) {
            debug!(
                "dropped replayed frame sequence {}: {error:#}",
                frame.sequence
            );
            return Ok(());
        }

        match frame.kind {
            FrameKind::DnsResponse => {
                let response = strip_padding(frame.flags, &frame.payload)?;
                if let Some(pending) = self.pending.remove(&frame.request_id) {
                    let _ = pending.send(Ok(response));
                } else {
                    debug!(
                        "received DNS response for unknown request {}",
                        frame.request_id
                    );
                }
            }
            FrameKind::Ping => {
                let pong = Frame {
                    kind: FrameKind::Pong,
                    flags: 0,
                    request_id: frame.request_id,
                    sequence: self.next_sequence(),
                    payload: Vec::new(),
                };
                channel
                    .send_frame(&pong)
                    .await
                    .context("failed to send pong")?;
            }
            FrameKind::Pong => {}
            FrameKind::DnsQuery | FrameKind::BatchQuery => {
                debug!("unexpected frame kind from server: {:?}", frame.kind);
            }
        }
        Ok(())
    }

    fn next_request_id(&mut self) -> u32 {
        let next = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        next
    }

    fn next_sequence(&mut self) -> u64 {
        let next = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);
        next
    }

    fn fail_pending(&mut self, request_id: u32, error: anyhow::Error) {
        if let Some(tx) = self.pending.remove(&request_id) {
            let _ = tx.send(Err(error));
        }
    }

    fn fail_all_pending(&mut self, error: anyhow::Error) {
        let message = error.to_string();
        for (_, tx) in self.pending.drain() {
            let _ = tx.send(Err(anyhow!(message.clone())));
        }
    }

    fn validate_or_pin_server(&mut self, remote_fingerprint: &str) -> Result<()> {
        match &self.pinned_server_fingerprint {
            Some(expected) if expected != remote_fingerprint => bail!(
                "pinned server fingerprint mismatch: expected {}, got {}",
                expected,
                remote_fingerprint
            ),
            Some(_) => Ok(()),
            None => {
                store_pinned_fingerprint(&self.config.server_fingerprint_file, remote_fingerprint)?;
                self.pinned_server_fingerprint = Some(remote_fingerprint.to_owned());
                info!(
                    "pinned new server fingerprint {} in {}",
                    remote_fingerprint,
                    self.config.server_fingerprint_file.display()
                );
                Ok(())
            }
        }
    }
}

async fn run_udp_listener(
    listen_addr: SocketAddr,
    request_tx: mpsc::Sender<PendingDnsRequest>,
    cache: DnsCache,
    request_timeout: Duration,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .with_context(|| format!("failed to bind UDP listener on {listen_addr}"))?,
    );
    info!("UDP DNS listener started on {listen_addr}");

    let mut buffer = vec![0_u8; u16::MAX as usize];
    loop {
        let (size, peer_addr) = socket
            .recv_from(&mut buffer)
            .await
            .with_context(|| format!("UDP receive failed on {listen_addr}"))?;
        let query = buffer[..size].to_vec();

        let socket = Arc::clone(&socket);
        let request_tx = request_tx.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            let response =
                resolve_dns_query(query.clone(), &request_tx, &cache, request_timeout).await;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    warn!("UDP query resolve error: {error:#}");
                    wire::build_servfail_response(&query)
                }
            };

            if response.is_empty() {
                return;
            }

            if let Err(error) = socket.send_to(&response, peer_addr).await {
                warn!("failed to send UDP response to {peer_addr}: {error}");
            }
        });
    }
}

async fn run_tcp_listener(
    listen_addr: SocketAddr,
    request_tx: mpsc::Sender<PendingDnsRequest>,
    cache: DnsCache,
    request_timeout: Duration,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind TCP listener on {listen_addr}"))?;
    info!("TCP DNS listener started on {listen_addr}");

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .with_context(|| format!("TCP accept failed on {listen_addr}"))?;
        let request_tx = request_tx.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_tcp_client(stream, request_tx, cache, request_timeout).await
            {
                debug!("TCP client {peer_addr} closed with error: {error:#}");
            }
        });
    }
}

async fn handle_tcp_client(
    mut stream: TcpStream,
    request_tx: mpsc::Sender<PendingDnsRequest>,
    cache: DnsCache,
    request_timeout: Duration,
) -> Result<()> {
    loop {
        let packet_len = match stream.read_u16().await {
            Ok(len) => len as usize,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error).context("failed to read DNS-over-TCP length"),
        };

        let mut query = vec![0_u8; packet_len];
        stream
            .read_exact(&mut query)
            .await
            .context("failed to read DNS-over-TCP payload")?;

        let response = resolve_dns_query(query.clone(), &request_tx, &cache, request_timeout)
            .await
            .unwrap_or_else(|_| wire::build_servfail_response(&query));
        if response.len() > u16::MAX as usize {
            return Err(anyhow!(
                "response exceeds DNS-over-TCP limit: {} bytes",
                response.len()
            ));
        }

        stream
            .write_u16(response.len() as u16)
            .await
            .context("failed to write DNS-over-TCP response length")?;
        stream
            .write_all(&response)
            .await
            .context("failed to write DNS-over-TCP response payload")?;
        stream
            .flush()
            .await
            .context("failed to flush DNS-over-TCP response")?;
    }
}

async fn resolve_dns_query(
    query: Vec<u8>,
    request_tx: &mpsc::Sender<PendingDnsRequest>,
    cache: &DnsCache,
    request_timeout: Duration,
) -> Result<Vec<u8>> {
    if let Some(response) = cache.get(&query).await {
        return Ok(response);
    }

    let response = send_over_transport(query.clone(), request_tx, request_timeout).await?;
    cache.insert(&query, &response).await;
    Ok(response)
}

async fn send_over_transport(
    query: Vec<u8>,
    request_tx: &mpsc::Sender<PendingDnsRequest>,
    request_timeout: Duration,
) -> Result<Vec<u8>> {
    let (response_tx, response_rx) = oneshot::channel();
    request_tx
        .send(PendingDnsRequest { query, response_tx })
        .await
        .context("failed to enqueue DNS request")?;

    timeout(request_timeout, response_rx)
        .await
        .with_context(|| format!("timed out after {:?}", request_timeout))?
        .context("response channel canceled")?
}

fn load_pinned_fingerprint(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read server fingerprint file {}", path.display()))?;
    let fingerprint = content.trim();
    if fingerprint.is_empty() {
        return Ok(None);
    }
    Ok(Some(fingerprint.to_owned()))
}

fn store_pinned_fingerprint(path: &Path, fingerprint: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create fingerprint directory {}",
                    parent.display()
                )
            })?;
        }
    }
    fs::write(path, format!("{fingerprint}\n"))
        .with_context(|| format!("failed to write server fingerprint file {}", path.display()))
}
