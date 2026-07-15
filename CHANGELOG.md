# Changelog

## [1.0.4] - 2026-07-14

### Fixed
- H2 over TLS ALPN negotiation — added h2 to the ALPN list so H2 probes work over TLS
- TE.CL POC generation — corrected from CL.TE-identical payload to proper TE-first format
- `docker-compose` compatibility — migrated from deprecated hyphenated form to `docker compose` with fallback
- Version hardcoded in ASCII banner — now uses `env!("CARGO_PKG_VERSION")` dynamically
- `--json` / `--output` flag interaction — `--output` is no longer silently ignored when `--json` is specified
- CryptoProvider install failure warning — no longer silently discarded
- Fuzz variant checkpoint save — checkpoint is now saved before the fuzz early return
- Exploit attempt tracking — `attempt` field now contains the actual attempt number instead of 0
- `--port` TLS detection — replaced `is_none_or` for broader Rust toolchain compatibility
- Removed dead code (`get_formatter` function in output module)
- `.cargo/config.toml` Windows target — changed from GNU to MSVC to match CI configuration
- Bypass technique count — corrected doc references from 12 to 10 techniques
- `SECURITY.md` contact email — updated to point to GitHub Security Advisories
- Banner SVG version badge — updated from v1.0.0 to v1.0.4

## [1.0.3] - 2026-07-14

### Fixed
- Internal refactoring and stability improvements

## [1.0.2] - 2026-07-14

### Fixed
- Various bug fixes and performance improvements

## [1.0.1] - 2026-07-14

### Fixed
- Minor corrections and polish

## [1.0.0] - 2026-07-14

### Added
- 24+ smuggling variant probes: CL.TE, TE.CL, TE.TE, CL.0/0.CL, H2.CL, H2.TE, H2.0, TE.0, WebSocket, Chunk Extension, Expect:100, Timing, Client-side desync, Connection State, Pause-Based, Header Removal, Contamination, H2 Dual-Path, H2 Fake Pseudo, Parser Discrepancy
- TE obfuscation bypass engine (10 techniques)
- Concurrent scanning with semaphore-bounded parallelism
- Authenticated scanning (cookies + custom headers)
- Pipeline mode (stdin targets, JSONL output)
- Checkpoint/resume for interrupted scans
- Auto-update via GitHub releases with BLAKE3 verification
- HTML, JSON, YAML, Table output formats
- Exploitation engine with connection poisoning daemon
- SPA (Single-Packet Attack), RQP (Response Queue Poisoning), Double-Desync chain
- CL.0 gadget auto-selection with per-host cache
- Cache chain poisoning support
- WAF detection (10 signatures: Cloudflare, Akamai, AWS, Netlify, Generic)
- CVE matrix (21 CVEs from 2005–2026)
- Fuzzer mode for custom probe generation
- Test lab with Docker Compose for offline testing
- Cross-platform support (Linux musl, macOS, Windows, Termux)
