# Changelog

## [1.0.0] - 2026-07-14

### Added
- 13 smuggling variant probes: CL.TE, TE.CL, TE.TE, CL.0/0.CL, H2.CL, H2.TE, H2.0, TE.0, WebSocket, Chunk Extension, Expect:100, Timing, Client-side desync
- TE obfuscation bypass engine (12 techniques)
- Concurrent scanning with semaphore-bounded parallelism
- Authenticated scanning (cookies + custom headers)
- Pipeline mode (stdin targets, JSONL output)
- Checkpoint/resume for interrupted scans
- Auto-update via GitHub releases with BLAKE3 verification
- HTML, JSON, YAML, Table output formats
- Exploitation engine with connection poisoning daemon
- Cache chain poisoning support
- Fuzzer mode for custom probe generation
- Test lab with Docker Compose for offline testing
- Cross-platform support (Linux musl, macOS, Windows, Termux)
- CL.TE detection probe
- TE.CL detection probe
- TE.TE detection with 12-bypass engine
- Authenticated scanning (cookies + custom headers)
- Pipeline mode (stdin targets, JSONL output)
- Checkpoint resume
- Auto-update via GitHub releases
- HTML, JSON, YAML, Table output formats
- Cross-platform support
- Test lab with Docker Compose

### Planned
- P2: CL.0/0.CL, H2.CL, H2.TE, Envoy/Akamai CVEs
- P3: WebSocket, Chunk Extension, Expect:100, Timing, H2.0
- P4: Exploitation engine, cache poisoning, daemon mode
- P5: Client-side desync, fuzzer mode, CVE templates
