use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, params};

use crate::dns::wire;

#[derive(Debug, Clone)]
pub struct CachedDnsEntry {
    pub response: Vec<u8>,
    pub names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CacheStoreMeta {
    pub ttl: u32,
    pub names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PersistentDnsCache {
    db_path: PathBuf,
    max_ttl: u32,
    negative_ttl: u32,
}

impl PersistentDnsCache {
    pub async fn open(db_path: PathBuf, max_ttl: u32, negative_ttl: u32) -> Result<Self> {
        let cache = Self {
            db_path,
            max_ttl,
            negative_ttl,
        };
        cache.init().await?;
        Ok(cache)
    }

    pub async fn get(&self, domain: &str) -> Result<Option<CachedDnsEntry>> {
        let db_path = self.db_path.clone();
        let domain = wire::normalize_domain(domain);
        let now = unix_now();

        tokio::task::spawn_blocking(move || -> Result<Option<CachedDnsEntry>> {
            let connection = open_connection(&db_path)?;
            let mut stmt = connection
                .prepare("SELECT names_json, response, expires_at FROM dns_cache WHERE domain = ?1")
                .context("failed to prepare cache lookup statement")?;
            let mut rows = stmt
                .query(params![domain.clone()])
                .context("failed to execute cache lookup query")?;

            let Some(row) = rows.next().context("failed to read cache lookup row")? else {
                return Ok(None);
            };

            let names_json: String = row.get(0).context("failed to read names_json")?;
            let response: Vec<u8> = row.get(1).context("failed to read cached response")?;
            let expires_at: i64 = row.get(2).context("failed to read expires_at")?;

            if expires_at <= now {
                connection
                    .execute("DELETE FROM dns_cache WHERE domain = ?1", params![domain])
                    .context("failed to delete expired cache row")?;
                return Ok(None);
            }

            let names: Vec<String> =
                serde_json::from_str(&names_json).context("failed to decode cached names JSON")?;

            Ok(Some(CachedDnsEntry { response, names }))
        })
        .await
        .map_err(|error| anyhow!("cache get task failed: {error}"))?
    }

    pub async fn upsert_response(&self, domain: &str, response: &[u8]) -> Result<CacheStoreMeta> {
        let domain = wire::normalize_domain(domain);
        let ttl = compute_ttl(response, self.max_ttl, self.negative_ttl);
        let names = wire::response_names(response);
        let names_json = serde_json::to_string(&names).context("failed to encode names JSON")?;
        let response = response.to_vec();
        let db_path = self.db_path.clone();
        let now = unix_now();
        let expires_at = now + ttl as i64;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let connection = open_connection(&db_path)?;
            connection
                .execute(
                    "INSERT INTO dns_cache (domain, names_json, response, expires_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(domain) DO UPDATE SET
                        names_json = excluded.names_json,
                        response = excluded.response,
                        expires_at = excluded.expires_at,
                        updated_at = excluded.updated_at",
                    params![domain, names_json, response, expires_at, now],
                )
                .context("failed to upsert cache row")?;

            connection
                .execute("DELETE FROM dns_cache WHERE expires_at <= ?1", params![now])
                .context("failed to cleanup expired cache rows")?;
            Ok(())
        })
        .await
        .map_err(|error| anyhow!("cache upsert task failed: {error}"))??;

        Ok(CacheStoreMeta { ttl, names })
    }

    async fn init(&self) -> Result<()> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let connection = open_connection(&db_path)?;
            connection
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS dns_cache (
                        domain TEXT PRIMARY KEY,
                        names_json TEXT NOT NULL,
                        response BLOB NOT NULL,
                        expires_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_dns_cache_expires ON dns_cache(expires_at);",
                )
                .context("failed to initialize dns_cache schema")?;

            connection
                .execute(
                    "DELETE FROM dns_cache WHERE expires_at <= ?1",
                    params![unix_now()],
                )
                .context("failed to cleanup expired cache rows at startup")?;
            Ok(())
        })
        .await
        .map_err(|error| anyhow!("cache init task failed: {error}"))?
    }
}

fn open_connection(path: &PathBuf) -> Result<Connection> {
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open SQLite cache DB {}", path.display()))?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;",
        )
        .context("failed to configure SQLite pragmas")?;
    Ok(connection)
}

fn compute_ttl(response: &[u8], max_ttl: u32, negative_ttl: u32) -> u32 {
    if wire::is_negative_response(response) {
        return negative_ttl.min(max_ttl).max(1);
    }

    wire::min_ttl(response)
        .unwrap_or(max_ttl)
        .min(max_ttl)
        .max(1)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
