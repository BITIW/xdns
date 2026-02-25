use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use xdns::client::{self, ClientConfig};
use xdns::protocol::noise;

#[derive(Debug, Parser)]
#[command(name = "xdns-client", about = "XDNS local stub resolver client")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:53")]
    listen_udp: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:53")]
    listen_tcp: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:8443")]
    server: SocketAddr,

    #[arg(long, default_value = "xdns-client.keys")]
    key_file: PathBuf,

    #[arg(long, default_value = "xdns-server.fingerprint")]
    server_fingerprint_file: PathBuf,

    #[arg(long, default_value_t = 5000)]
    request_timeout_ms: u64,

    #[arg(long, default_value_t = 15000)]
    keepalive_ms: u64,

    #[arg(long, default_value_t = 4096)]
    cache_max_entries: usize,

    #[arg(long, default_value_t = 300)]
    cache_max_ttl: u32,

    #[arg(long, default_value_t = 30)]
    cache_negative_ttl: u32,

    #[arg(long, default_value_t = 96)]
    max_padding: usize,

    #[arg(long, default_value_t = 8)]
    batch_size: usize,

    #[arg(long, default_value_t = false)]
    generate_keypair: bool,

    #[arg(long, default_value_t = false)]
    force: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    if args.generate_keypair {
        let keypair = noise::generate_and_write_keypair(&args.key_file, args.force)?;
        println!("saved={}", args.key_file.display());
        println!(
            "public_fingerprint={}",
            noise::key_fingerprint(&keypair.public)
        );
        return Ok(());
    }

    let (client_keypair, created) = noise::load_or_generate_keypair(&args.key_file)?;
    if created {
        warn!(
            "created new client keypair at {} (public_fingerprint={})",
            args.key_file.display(),
            noise::key_fingerprint(&client_keypair.public)
        );
    } else {
        info!(
            "loaded client keypair from {} (public_fingerprint={})",
            args.key_file.display(),
            noise::key_fingerprint(&client_keypair.public)
        );
    }

    let config = ClientConfig {
        listen_udp: args.listen_udp,
        listen_tcp: args.listen_tcp,
        server_addr: args.server,
        client_private_key: client_keypair.private,
        server_fingerprint_file: args.server_fingerprint_file,
        request_timeout: Duration::from_millis(args.request_timeout_ms),
        keepalive_interval: Duration::from_millis(args.keepalive_ms),
        cache_max_entries: args.cache_max_entries,
        cache_max_ttl: args.cache_max_ttl,
        cache_negative_ttl: args.cache_negative_ttl,
        max_padding: args.max_padding,
        batch_size: args.batch_size.max(1),
    };

    client::run(config).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();
}
