use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Error, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info};

use crate::dns::db::PersistentDnsCache;
use crate::dns::upstream::UpstreamResolver;
use crate::dns::wire;
use crate::protocol::frame::{
    BatchItem, Frame, FrameKind, decode_batch, strip_padding, with_optional_padding,
};
use crate::protocol::noise::SecureChannel;
use crate::protocol::replay::ReplayFilter;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub server_private_key: Vec<u8>,
    pub cache_db_path: PathBuf,
    pub cache_max_ttl: u32,
    pub cache_negative_ttl: u32,
    pub resolve_timeout: Duration,
    pub keepalive_interval: Duration,
    pub max_padding: usize,
}

#[derive(Debug)]
struct ResolvedResponse {
    request_id: u32,
    response: Vec<u8>,
}

pub async fn run(config: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind secure listener on {}", config.bind_addr))?;
    let resolver = Arc::new(UpstreamResolver::new(
        config.upstream_addr,
        config.resolve_timeout,
    ));
    let cache = Arc::new(
        PersistentDnsCache::open(
            config.cache_db_path.clone(),
            config.cache_max_ttl,
            config.cache_negative_ttl,
        )
        .await
        .with_context(|| {
            format!(
                "failed to initialize persistent DNS cache at {}",
                config.cache_db_path.display()
            )
        })?,
    );

    info!(
        "XDNS server listening on {}, upstream={}, sqlite_cache={}",
        config.bind_addr,
        config.upstream_addr,
        config.cache_db_path.display()
    );

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .with_context(|| format!("failed to accept client on {}", config.bind_addr))?;

        let config = config.clone();
        let resolver = Arc::clone(&resolver);
        let cache = Arc::clone(&cache);
        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, config, resolver, cache).await {
                log_hwaw_error(
                    "secure session processing crashed",
                    "server could not continue handling one client session",
                    &error,
                );
            }
        });
    }
}

async fn handle_client(
    stream: TcpStream,
    config: ServerConfig,
    resolver: Arc<UpstreamResolver>,
    cache: Arc<PersistentDnsCache>,
) -> Result<()> {
    let mut channel = SecureChannel::accept(stream, &config.server_private_key)
        .await
        .context("secure handshake failed")?;
    let client_fingerprint = channel.remote_fingerprint().to_owned();

    info!(
        "secure client connected (session={}, fingerprint={})",
        channel.session_id(),
        client_fingerprint
    );

    let mut replay = ReplayFilter::new(128);
    let mut next_sequence = 1_u64;
    let (resolved_tx, mut resolved_rx) = mpsc::channel::<ResolvedResponse>(1024);
    let mut keepalive = interval(config.keepalive_interval);

    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                let ping = Frame {
                    kind: FrameKind::Ping,
                    flags: 0,
                    request_id: 0,
                    sequence: next_sequence,
                    payload: Vec::new(),
                };
                next_sequence = next_sequence.wrapping_add(1).max(1);
                if let Err(error) = channel.send_frame(&ping).await {
                    if is_disconnect_error(&error) {
                        info!(
                            "secure client disconnected (session={}, fingerprint={})",
                            channel.session_id(),
                            client_fingerprint
                        );
                        return Ok(());
                    }
                    return Err(error).context("failed to send keepalive ping");
                }
            }
            maybe_response = resolved_rx.recv() => {
                let Some(resolved) = maybe_response else {
                    return Ok(());
                };
                let (payload, flags) = with_optional_padding(&resolved.response, config.max_padding)?;
                let frame = Frame {
                    kind: FrameKind::DnsResponse,
                    flags,
                    request_id: resolved.request_id,
                    sequence: next_sequence,
                    payload,
                };
                next_sequence = next_sequence.wrapping_add(1).max(1);
                if let Err(error) = channel.send_frame(&frame).await {
                    if is_disconnect_error(&error) {
                        info!(
                            "secure client disconnected (session={}, fingerprint={})",
                            channel.session_id(),
                            client_fingerprint
                        );
                        return Ok(());
                    }
                    return Err(error).context("failed to send DNS response");
                }
            }
            frame = channel.recv_frame() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => {
                        if is_disconnect_error(&error) {
                            info!(
                                "secure client disconnected (session={}, fingerprint={})",
                                channel.session_id(),
                                client_fingerprint
                            );
                            return Ok(());
                        }
                        return Err(error).context("failed to receive secure frame");
                    }
                };
                if let Err(error) = replay.check_and_mark(frame.sequence) {
                    debug!("dropped replayed frame sequence {}: {error:#}", frame.sequence);
                    continue;
                }

                match frame.kind {
                    FrameKind::DnsQuery => {
                        let query = match strip_padding(frame.flags, &frame.payload) {
                            Ok(query) => query,
                            Err(error) => {
                                log_hwaw_error(
                                    "frame payload decode failed",
                                    "server rejected a DNS query frame because padding was invalid",
                                    &error,
                                );
                                continue;
                            }
                        };
                        dispatch_query(
                            frame.request_id,
                            query,
                            client_fingerprint.clone(),
                            Arc::clone(&resolver),
                            Arc::clone(&cache),
                            resolved_tx.clone(),
                        );
                    }
                    FrameKind::BatchQuery => {
                        let payload = match strip_padding(frame.flags, &frame.payload) {
                            Ok(payload) => payload,
                            Err(error) => {
                                log_hwaw_error(
                                    "frame payload decode failed",
                                    "server rejected a batch frame because padding was invalid",
                                    &error,
                                );
                                continue;
                            }
                        };

                        let batch = match decode_batch(&payload) {
                            Ok(batch) => batch,
                            Err(error) => {
                                log_hwaw_error(
                                    "batch payload decode failed",
                                    "server could not unpack DNS batch requests",
                                    &error,
                                );
                                continue;
                            }
                        };

                        for BatchItem { request_id, payload } in batch {
                            dispatch_query(
                                request_id,
                                payload,
                                client_fingerprint.clone(),
                                Arc::clone(&resolver),
                                Arc::clone(&cache),
                                resolved_tx.clone(),
                            );
                        }
                    }
                    FrameKind::Ping => {
                        let pong = Frame {
                            kind: FrameKind::Pong,
                            flags: 0,
                            request_id: frame.request_id,
                            sequence: next_sequence,
                            payload: Vec::new(),
                        };
                        next_sequence = next_sequence.wrapping_add(1).max(1);
                        channel.send_frame(&pong).await.context("failed to send pong")?;
                    }
                    FrameKind::Pong => {}
                    FrameKind::DnsResponse => {
                        debug!(
                            "unexpected DnsResponse frame from fingerprint={}",
                            client_fingerprint
                        );
                    }
                }
            }
        }
    }
}

fn dispatch_query(
    request_id: u32,
    query: Vec<u8>,
    client_fingerprint: String,
    resolver: Arc<UpstreamResolver>,
    cache: Arc<PersistentDnsCache>,
    resolved_tx: mpsc::Sender<ResolvedResponse>,
) {
    tokio::spawn(async move {
        let query_label =
            wire::question_name(&query).unwrap_or_else(|| "<invalid-query>".to_owned());
        let query_key = wire::normalize_domain(&query_label);
        info!("dns_query {}:{}", client_fingerprint, query_label);

        if query_label != "<invalid-query>" {
            match cache.get(&query_key).await {
                Ok(Some(cached)) => {
                    let mut response = cached.response;
                    if let Some(query_id) = wire::query_id(&query) {
                        wire::set_query_id(&mut response, query_id);
                    }
                    info!(
                        "dns_cache_hit {}:{} names={}",
                        client_fingerprint,
                        query_key,
                        format_names(&cached.names)
                    );

                    if resolved_tx
                        .send(ResolvedResponse {
                            request_id,
                            response,
                        })
                        .await
                        .is_err()
                    {
                        debug!(
                            "response channel closed before sending request {} for fingerprint={}",
                            request_id, client_fingerprint
                        );
                    }
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    log_hwaw_error(
                        "persistent cache read failed",
                        &format!("domain={} fingerprint={}", query_key, client_fingerprint),
                        &error,
                    );
                }
            }
        }

        let response = match resolver.resolve(&query).await {
            Ok(response) => response,
            Err(error) => {
                log_hwaw_error(
                    "upstream resolution failed",
                    &format!(
                        "request_id={} fingerprint={} qname={}",
                        request_id, client_fingerprint, query_label
                    ),
                    &error,
                );
                wire::build_servfail_response(&query)
            }
        };

        let response = if response.is_empty() {
            wire::build_servfail_response(&query)
        } else {
            response
        };

        if query_label != "<invalid-query>" {
            match cache.upsert_response(&query_key, &response).await {
                Ok(meta) => {
                    info!(
                        "dns_cache_store {}:{} ttl={} names={}",
                        client_fingerprint,
                        query_key,
                        meta.ttl,
                        format_names(&meta.names)
                    );
                }
                Err(error) => {
                    log_hwaw_error(
                        "persistent cache write failed",
                        &format!("domain={} fingerprint={}", query_key, client_fingerprint),
                        &error,
                    );
                }
            }
        }

        if resolved_tx
            .send(ResolvedResponse {
                request_id,
                response,
            })
            .await
            .is_err()
        {
            debug!(
                "response channel closed before sending request {} for fingerprint={}",
                request_id, client_fingerprint
            );
        }
    });
}

fn log_hwaw_error(how: &str, what: &str, error: &Error) {
    error!("HWaW | how={how} | what={what} | why={error:#}");
}

fn format_names(names: &[String]) -> String {
    if names.is_empty() {
        return "[]".to_owned();
    }
    format!("[{}]", names.join(","))
}

fn is_disconnect_error(error: &Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io_error| {
                matches!(
                    io_error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                )
            })
            .unwrap_or(false)
    })
}
