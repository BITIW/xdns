use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use xdns::protocol::noise;
use xdns::server::{self, ServerConfig};

#[derive(Debug, Parser)]
#[command(name = "xdns-server", about = "XDNS secure DNS relay server")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

    #[arg(long, default_value = "1.1.1.1:53")]
    upstream: SocketAddr,

    #[arg(long, default_value = "xdns-server.keys")]
    key_file: PathBuf,

    #[arg(long, default_value = "xdns-cache.sqlite")]
    cache_db: PathBuf,

    #[arg(long, default_value_t = 600)]
    cache_max_ttl: u32,

    #[arg(long, default_value_t = 60)]
    cache_negative_ttl: u32,

    #[arg(long, default_value_t = 3500)]
    resolve_timeout_ms: u64,

    #[arg(long, default_value_t = 15000)]
    keepalive_ms: u64,

    #[arg(long, default_value_t = 64)]
    max_padding: usize,

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

    let (server_keypair, created) = noise::load_or_generate_keypair(&args.key_file)?;
    if created {
        warn!(
            "created new server keypair at {} (public_fingerprint={})",
            args.key_file.display(),
            noise::key_fingerprint(&server_keypair.public)
        );
    } else {
        info!(
            "loaded server keypair from {} (public_fingerprint={})",
            args.key_file.display(),
            noise::key_fingerprint(&server_keypair.public)
        );
    }

    let config = ServerConfig {
        bind_addr: args.bind,
        upstream_addr: args.upstream,
        server_private_key: server_keypair.private,
        cache_db_path: args.cache_db,
        cache_max_ttl: args.cache_max_ttl,
        cache_negative_ttl: args.cache_negative_ttl,
        resolve_timeout: Duration::from_millis(args.resolve_timeout_ms),
        keepalive_interval: Duration::from_millis(args.keepalive_ms),
        max_padding: args.max_padding,
    };

    server::run(config).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();
}
