# XDNS

XDNS is a local DNS stub resolver that forwards DNS queries to a remote server over an encrypted transport.

## Features in this MVP

- Two binaries:
  - `client`: local DNS listener (`UDP + TCP`) and transport client.
  - `server`: secure relay and upstream DNS resolver.
- Persistent encrypted channel (`Noise XX` over TCP).
- Public-key exchange during handshake (no manual key exchange args).
- Client-side server fingerprint pinning (TOFU) for reconnect safety.
- Request multiplexing over one secure connection.
- Session-bound sequence counters + replay window checks.
- Optional per-frame random padding.
- Optional batch transfer from client to server.
- TTL-based local cache with negative caching.
- Upstream DNS resolution via UDP with TCP fallback on truncation.
- Server logs by client fingerprint (without client IP in logs).
- Persistent server-side DNS cache in SQLite (`domain -> names[] + DNS wire response`).

## Build

```bash
cargo build
```

## Key generation

Generate and save server keypair to file:

```bash
cargo run --bin server -- --generate-keypair --key-file xdns-server.keys
```

Generate and save client keypair to file:

```bash
cargo run --bin client -- --generate-keypair --key-file xdns-client.keys
```

Result:

```text
saved=<path>
public_fingerprint=<sha256 hex>
```

Key files are stored in text format:

```bash
# XDNS static Noise keypair
private=<BASE64_32B>
public=<BASE64_32B>
```

By default, if `--key-file` does not exist, it is generated automatically.

## Run server

```bash
cargo run --bin server -- \
  --bind 0.0.0.0:8443 \
  --upstream 1.1.1.1:53 \
  --key-file xdns-server.keys \
  --cache-db xdns-cache.sqlite
```

## Run client

```bash
cargo run --bin client -- \
  --server 127.0.0.1:8443 \
  --key-file xdns-client.keys \
  --server-fingerprint-file xdns-server.fingerprint
```

Note: binding to port `53` usually requires elevated privileges. For local development, use `127.0.0.1:5353`.

## TOFU fingerprint behavior

- On first successful connection, client stores server fingerprint in `--server-fingerprint-file`.
- On next connections, fingerprint must match the pinned value.
- If fingerprint changes, connection is rejected until fingerprint file is updated manually.

## Client flags

- `--listen-udp` (default: `127.0.0.1:53`)
- `--listen-tcp` (default: `127.0.0.1:53`)
- `--server` (default: `127.0.0.1:8443`)
- `--key-file` (default: `xdns-client.keys`)
- `--server-fingerprint-file` (default: `xdns-server.fingerprint`)
- `--request-timeout-ms` (default: `5000`)
- `--keepalive-ms` (default: `15000`)
- `--cache-max-entries` (default: `4096`)
- `--cache-max-ttl` (default: `300`)
- `--cache-negative-ttl` (default: `30`)
- `--max-padding` (default: `96`)
- `--batch-size` (default: `8`)
- `--generate-keypair`
- `--force` (overwrite key file when used with `--generate-keypair`)

## Server flags

- `--bind` (default: `0.0.0.0:8443`)
- `--upstream` (default: `1.1.1.1:53`)
- `--key-file` (default: `xdns-server.keys`)
- `--cache-db` (default: `xdns-cache.sqlite`)
- `--cache-max-ttl` (default: `600`)
- `--cache-negative-ttl` (default: `60`)
- `--resolve-timeout-ms` (default: `3500`)
- `--keepalive-ms` (default: `15000`)
- `--max-padding` (default: `64`)
- `--generate-keypair`
- `--force` (overwrite key file when used with `--generate-keypair`)

## Server logging

- Connect/disconnect events are logged with `session` and client `fingerprint`.
- DNS requests are logged as `fingerprint:qname`.
- Cache events are logged as `dns_cache_hit` and `dns_cache_store`.
- Error events include HWaW layout:

```text
HWaW | how=<how it failed> | what=<what failed> | why=<error chain>
```
