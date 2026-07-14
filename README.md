<p align="center">
  <img src="assets/banner.svg" alt="ghostroute" width="100%">
</p>

<p align="center">
  <a href="https://www.rust-lang.org">
    <img src="https://img.shields.io/badge/rust-1.85%2B-blue?logo=rust&style=flat-square" alt="Rust">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  </a>
  <a href="https://github.com/PwnedBytes0x1/ghostroute/releases">
    <img src="https://img.shields.io/github/v/release/PwnedBytes0x1/ghostroute?style=flat-square&label=release&color=58a6ff" alt="Release">
  </a>
  <a href="https://github.com/PwnedBytes0x1/ghostroute">
    <img src="https://img.shields.io/github/stars/PwnedBytes0x1/ghostroute?style=flat-square&label=stars&color=bc8cff" alt="Stars">
  </a>
  <a href="https://github.com/PwnedBytes0x1/ghostroute/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/PwnedBytes0x1/ghostroute/ci.yml?style=flat-square&label=build&color=3fb950" alt="CI">
  </a>
  <a href="https://github.com/PwnedBytes0x1/ghostroute">
    <img src="https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square" alt="Platform">
  </a>
  <a href="https://github.com/PwnedBytes0x1/ghostroute">
    <img src="https://img.shields.io/github/last-commit/PwnedBytes0x1/ghostroute?style=flat-square&color=blueviolet" alt="last commit">
  </a>
</p>

<p align="center">
  <b>ghostroute</b> is a comprehensive HTTP request smuggling detection and exploitation toolkit for Linux.
  <br>
  Built in Rust — 24+ smuggling variants, concurrent scanning, bypass engine, SPA, parser discrepancy, and more.
</p>

---

## ⚠️ Disclaimer

> **ghostroute is provided for authorized security testing and educational purposes only.**  
> Unauthorized use of this tool against systems you do not own or have explicit permission to test
> may violate applicable laws. The authors assume no liability and are not responsible for any
> misuse or damage caused by this tool. You are solely responsible for complying with all
> applicable laws and regulations.

---

## 📋 Table of Contents

- [Features](#-features)
- [What Does It Cover?](#-what-does-it-cover)
- [How Is It Different?](#-how-is-it-different)
- [Installation](#-installation)
- [Usage](#-usage)
- [Smuggling Variants Reference](#-smuggling-variants-reference)
- [Output Examples](#-output-examples)
- [Architecture](#-architecture)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Features

| Icon | Feature | Description |
|:----:|---------|-------------|
| 🧩 | **24+ Smuggling Variants** | CL.TE, TE.CL, TE.TE, CL.0, 0.CL, H2.CL, H2.TE, H2.0, TE.0, WebSocket, Chunk Extension, Expect:100, Timing, Client-Side, Connection State, Pause-Based, Header Removal, Contamination, H2 Dual-Path, H2 Fake Pseudo, Parser Discrepancy, and more |
| ⚡ | **Concurrent Scanning** | Semaphore-bounded parallelism with configurable concurrency |
| 🔄 | **Bypass Engine** | 10 systematic HideTechniques: SPACE, TAB, WRAP, LPAD, HOP, SKIPHOP, DUPE, UNDER, NWRAP, RWRAP |
| 🔍 | **Parser Discrepancy Engine** | 4-way canary comparison classifying outcome as Match / Discrepancy / HighDiscrepancy / WafBlock with Split-vs-Nuke backend typing |
| 🎯 | **Single-Packet Attack (SPA)** | Attack + victim in one TCP write — CL.TE, TE.CL, CL.0, 0.CL variants |
| ⛓️ | **Double-Desync Chain** | CL.0→CL.TE, CL.0→TE.CL, CL.0→TE.TE, 0.CL→CL.TE chains through two intermediaries |
| ☠️ | **RQP Exploit** | Response queue poisoning — poison connection → close → capture victim response mismatch |
| 🕵️ | **WAF Detection** | 10 WAF signatures: 403/406/493 status, body-blocked, Cloudflare/Akamai/Fastly server detection |
| 📋 | **CVE Matrix** | 21 CVE templates (2005–2026) with scores, affected products, payload templates, variant mappings |
| 🔐 | **Authenticated Scanning** | Cookie and custom header injection for authenticated targets |
| 🔗 | **Pipeline Compatible** | JSONL output, stdin pipe for targets, `--silent` mode for automation |
| 💾 | **Checkpoint / Resume** | Auto-save checkpoints to disk, resume interrupted scans |
| 🔄 | **Auto-Update** | Periodic GitHub release checks with BLAKE3 signature verification |
| 📊 | **Multiple Output Formats** | HTML (standalone report), JSON, YAML, Table with outcome/WAF/CVE detail rows |
| 💣 | **Exploitation Engine** | Connection poisoning daemon with retry logic and configurable intervals |
| 🧪 | **POC Generation** | 11 POC techniques: G/FOO/headerConcat/bodyConcat/collab variants |
| 🎲 | **Fuzzer Mode** | Custom payload generation and injection for manual testing |
| 🧪 | **Test Lab** | Docker Compose environment for offline testing |
| 🐧 | **Platform** | Linux (static musl) — build from source on other platforms |

---

## 🎯 What Does It Cover?

| Attack Vector | Stage | Description |
|--------------|-------|-------------|
| **CL.TE** | ✅ Detection | Frontend uses CL, backend uses TE — request splitting via differential probe |
| **TE.CL** | ✅ Detection | Frontend uses TE, backend uses CL — smuggled prefix poisons backend socket |
| **TE.TE** | ✅ Detection | Both parse TE but differ — 10-technique bypass engine finds the gap |
| **CL.0** | ✅ Detection | Frontend consumes CL, backend ignores it — body leaks into next request |
| **0.CL** | ✅ Detection | Backend reads CL, frontend ignores it — 8-gadget detection |
| **H2.CL / H2.TE** | ✅ Detection | HTTP/2 to HTTP/1.1 downgrade desync |
| **H2.0** | ✅ Detection | Cleartext HTTP/2 prior-knowledge attacks |
| **TE.0** | ✅ Detection | Null-byte Transfer-Encoding injection |
| **WebSocket** | ✅ Detection | WebSocket upgrade smuggling |
| **Chunk Extension** | ✅ Detection | Chunked encoding extension abuse (CVE-2025-55315) |
| **Expect:100** | ✅ Detection | 100-Continue protocol desync — 4-category Kettle 2025 matrix |
| **Timing** | ✅ Detection | Response delay differential for blind smuggling confirmation |
| **Client Desync** | ✅ Detection | Browser-server parser mismatch (CL.0 variant) |
| **Connection State** | ✅ Detection | Status/reflect/DNS canary comparison across connections |
| **Pause-Based** | ✅ Detection | 61s delay + 3 poison canaries |
| **Header Removal** | ✅ Detection | Keep-Alive injection + 5x repeat + connection eviction |
| **Contamination** | ✅ Detection | HEAD pollution + 3x stability check |
| **H2 Dual-Path** | ✅ Detection | Dual `:path` pseudo-header injection |
| **H2 Fake Pseudo** | ✅ Detection | Fake pseudo-header reflection |
| **Parser Discrepancy** | ✅ Detection | 4-way canary permutation → SplitOrNuke classification |
| **Connection Poisoning** | ✅ Exploitation | Persistent socket poisoning daemon for request hijacking |
| **Cache Poisoning** | ✅ Exploitation | Multi-hop cache chain poisoning via smuggled prefixes |
| **SPA** | ✅ Exploitation | Single-packet attack — attack + victim in one TCP write |
| **RQP** | ✅ Exploitation | Response queue poisoning across connections |
| **Double-Desync** | ✅ Exploitation | CL.0→CL.TE chain through two intermediaries |
| **CL.0 Gadgets** | ✅ Exploitation | 5-gadget auto-selection with per-host cache |

---

## 🆚 How Is It Different?

| Aspect | ghostroute | smuggler.py | turbointruder | clairvoyance |
|--------|-----------|-------------|---------------|--------------|
| **Variants** | **24+** | 6–7 | N/A (fuzzer) | 5 |
| **Parser Discrepancy** | ✅ 4-way canary + Split/Nuke | ❌ | ❌ | ❌ |
| **SPA** | ✅ Single-packet | ❌ | ❌ | ❌ |
| **RQP / Double-Desync** | ✅ | ❌ | ❌ | ❌ |
| **WAF Detection** | ✅ 10 signatures | ❌ | ❌ | ❌ |
| **CVE Matrix** | ✅ 21 CVEs | ❌ | ❌ | ❌ |
| **HTTP/2** | ✅ H2.CL, H2.TE, H2.0 | ❌ | ❌ | ❌ |
| **Bypass Engine** | ✅ 10 techniques | ❌ | ✅ custom | ❌ |
| **Architecture** | Async Rust (tokio) | Python (sync) | Python | Python + ASGI |
| **Concurrency** | ✅ Semaphore-bounded | ❌ sequential | ✅ thread pool | ❌ sequential |
| **Output Formats** | HTML, JSON, YAML, Table, JSONL | Text | Text | Text |
| **Checkpoint/Resume** | ✅ | ❌ | ❌ | ❌ |
| **Exploitation** | ✅ Daemon + SPA + RQP + chain | ❌ | ❌ | ❌ |
| **Auto-Update** | ✅ BLAKE3 verified | ❌ | ❌ | ❌ |
| **Fuzzer Mode** | ✅ | ❌ | ✅ | ❌ |
| **Binary Size** | ~15 MB (static musl) | Requires Python + deps | Requires Python + Java | Requires Python |
| **Cross-Platform** | ✅ Static musl, macOS, Windows | ✅ | ✅ | ❌ |

---

## 📦 Installation

```bash
git clone https://github.com/PwnedBytes0x1/ghostroute
cd ghostroute
cargo build --release
sudo cp target/release/ghostroute /usr/local/bin/
ghostroute --version
```

---

## 🛠 Usage

### Basic Scan

```bash
# Scan a single target with all variants
ghostroute scan https://example.com

# Scan with custom concurrency and timeout
ghostroute scan https://example.com --concurrency 16 --timeout 10

# Scan multiple targets from a file
ghostroute scan targets.txt

# Specific variant
ghostroute scan https://example.com --variant parser-discrepancy
```

### Authentication

```bash
# Cookie-based authentication
ghostroute scan https://example.com --cookie "session=abc123"

# Custom headers
ghostroute scan https://example.com --header "X-API-Key: sk-xxx" --header "Authorization: Bearer <token>"
```

### Pipeline Mode

```bash
# Pipe targets from stdin, output JSONL
cat targets.txt | ghostroute scan - --json > results.jsonl

# Silent mode (no banner, no progress output)
ghostroute scan targets.txt --silent --json
```

### Specific Variants

```bash
# Classic smuggling variants
ghostroute scan https://example.com --variant clte
ghostroute scan https://example.com --variant tete
ghostroute scan https://example.com --variant h2cl

# Advanced scans
ghostroute scan https://example.com --variant parser-discrepancy
ghostroute scan https://example.com --variant connection-state
ghostroute scan https://example.com --variant pause-desync
ghostroute scan https://example.com --variant header-removal
ghostroute scan https://example.com --variant contamination
ghostroute scan https://example.com --variant h2-dual-path
ghostroute scan https://example.com --variant h2-fake-pseudo
ghostroute scan https://example.com --variant zero-cl

# Fuzzer mode — send custom payloads
ghostroute scan https://example.com --variant fuzz
```

### Exploitation

```bash
# Connection poisoning daemon
ghostroute exploit https://example.com --variant clte --count 50 --delay 10

# Single-packet attack
ghostroute exploit https://example.com --variant clte --prefix-request payload.txt --spa

# Response queue poisoning
ghostroute exploit https://example.com --variant clte --prefix-request payload.txt --rqp

# Double-desync chain
ghostroute exploit https://example.com --variant cl0-clte --prefix-request payload.txt

# Cache chain poisoning
ghostroute exploit https://example.com --variant clte --chain "https://cache.example.com::https://origin.example.com"
```

### Reports

```bash
# HTML report (default)
ghostroute scan https://example.com --output-format html -o report.html

# JSON output (includes outcome, WAF, CVE, POC fields)
ghostroute scan https://example.com --json --output results.json

# YAML output
ghostroute scan https://example.com --output-format yaml -o report.yaml
```

### Test Lab

```bash
# Start lab containers
ghostroute lab up

# Run scan against lab
ghostroute scan http://localhost:8080 --no-tls

# Stop lab
ghostroute lab down
```

---

## ⚙️ Installation Walkthrough

| Step | Description |
|:----:|-------------|
| **1** | 🦀 **Rust check** — verifies `rustc` 1.85+; installs via `rustup` if missing |
| **2** | 📥 **Clone** — `git clone https://github.com/PwnedBytes0x1/ghostroute` |
| **3** | 🔨 **Build** — `cargo build --release` compiles a static musl binary (~15 MB) |
| **4** | 📁 **Install** — `cp target/release/ghostroute /usr/local/bin/` |
| **5** | ✅ **Verify** — `ghostroute --version` confirms the installation |

---

## 📊 Smuggling Variants Reference

| Variant | Phase | Detection Method | Exploitation Vector |
|---------|-------|-----------------|---------------------|
| CL.TE | ✅ P1 | Differential probe (2-connection) | Connection poison |
| TE.CL | ✅ P1 | Differential probe | Connection poison |
| TE.TE | ✅ P1 | 10-technique bypass engine | Connection poison |
| CL.0 | ✅ P2 | Timing + body differential | Cache poison |
| 0.CL | ✅ P2 | 8-gadget detection + timeout + Expect | Cache poison |
| H2.CL | ✅ P2 | H2 frame injection | H2 downgrade poison |
| H2.TE | ✅ P2 | H2 frame injection | H2 downgrade poison |
| TE.0 | ✅ P3 | Null-byte TE injection | Connection poison |
| WebSocket | ✅ P3 | WS upgrade hijack | Connection hijack |
| Chunk Ext | ✅ P3 | Chunk extension abuse (CVE-2025-55315) | Cache poison |
| Expect:100 | ✅ P3 | 100-Continue desync — 4-category matrix | Cache chain |
| Timing | ✅ P3 | Response delay differential | Blind confirmation |
| H2.0 | ✅ P3 | Prior knowledge injection | Cleartext poison |
| Client Desync | ✅ P4 | Browser vs server parser diff | Session hijack |
| Connection State | ✅ P4 | Status/reflect/DNS canary comparison | Cross-connection |
| Pause-Based | ✅ P4 | 61s delay + 3 poison canaries | Timing-based |
| Header Removal | ✅ P4 | Keep-Alive + 5x repeat + eviction | Header-based |
| Contamination | ✅ P4 | HEAD pollution + 3x stability check | Stability check |
| H2 Dual-Path | ✅ P4 | Dual `:path` injection | H2 smuggling |
| H2 Fake Pseudo | ✅ P4 | Fake pseudo-header reflection | H2 reflection |
| Parser Discrepancy | ✅ P4 | 4-way canary → SplitOrNuke | Classification |

---

## 📈 Output Examples

### Table (terminal)

```text
  target : example.com
  vulnerable to : CL.TE, TE.TE (header-folding), TIMING
  server : nginx/1.26.0, haproxy/3.0
    -> CL.TE confirmed: baseline 200 (312b) vs response 404 (0b)
    -> outcome: DISCREPANCY
    -> cves: variant=clte/nuke
```

### HTML Report

Generated as a standalone, self-contained HTML page with color-coded vulnerability table, outcome/WAF/CVE detail rows, server breakdown, and summary metrics. Open in any browser — no external dependencies.

### JSON (pipeline)

```json
{"host":"example.com","port":443,"variant":"clte","vulnerable":true,
 "server":"nginx/1.26.0","bypass":null,"outcome":"DISCREPANCY",
 "waf_detected":null,"cve_matches":["variant=clte/nuke"],"poc_generated":false}
```

---

## 🏗 Architecture

```
src/
├── main.rs                    # Entry point, CLI dispatch
├── cli.rs                     # Clap command definitions
├── auth.rs                    # Auth store (cookies, headers)
├── bypass.rs                  # 10-technique TE obfuscation engine
├── checkpoint.rs              # Scan checkpoint/resume
├── cve.rs                     # 21 CVE templates with scores & payloads
├── update.rs                  # Auto-update with BLAKE3 verification
│
├── net/                       # Network layer
│   ├── mod.rs                 #   NetConfig, connect dispatch
│   ├── tls.rs                 #   TLS connector with ALPN
│   ├── h1.rs                  #   HTTP/1.1 send/recv + parsing
│   ├── h2.rs                  #   HTTP/2 frame handling
│   └── websocket.rs           #   WebSocket upgrade
│
├── scan/                      # Variant probes (24+)
│   ├── mod.rs                 #   Variant dispatch + ScanConfig
│   ├── clte.rs                #   CL.TE differential probe
│   ├── tecl.rs                #   TE.CL differential probe
│   ├── tete.rs                #   TE.TE + bypass engine
│   ├── cl0.rs                 #   CL.0 timing probe
│   ├── te0.rs                 #   TE.0 null-byte probe
│   ├── zero_cl.rs             #   0.CL desync (8-gadget detection)
│   ├── h2cl.rs                #   H2.CL frame injection
│   ├── h2te.rs                #   H2.TE frame injection
│   ├── h20.rs                 #   H2.0 prior knowledge
│   ├── websocket.rs           #   WebSocket smuggling
│   ├── chunk_ext.rs           #   Chunk extension abuse
│   ├── expect100.rs           #   Expect:100 desync (Kettle 2025)
│   ├── timing.rs              #   Timing differential
│   ├── client_desync.rs       #   Client-side desync
│   ├── connection_state.rs    #   Connection state attack
│   ├── pause_desync.rs        #   Pause-based desync (61s)
│   ├── header_removal.rs      #   Header removal detection
│   ├── contamination.rs       #   Contamination test
│   ├── h2_dual_path.rs        #   H2 dual :path injection
│   ├── h2_fake_pseudo.rs      #   H2 fake pseudo-header
│   ├── parser_discrepancy.rs  #   4-way canary → Split/Nuke
│   ├── poc.rs                 #   11 POC technique generators
│   └── fuzzer.rs              #   Custom payload fuzzer
│
├── exploit/                   # Exploitation engine
│   ├── mod.rs                 #   Dispatch + common types
│   ├── daemon.rs              #   Persistent poison daemon
│   ├── cache.rs               #   Cache chain poisoning
│   ├── spa.rs                 #   Single-packet attack
│   ├── rqp.rs                 #   Response queue poisoning
│   ├── double_desync.rs       #   CL.0→CL.TE chain
│   └── gadgets.rs             #   5-gadget CL.0 auto-selection
│
├── detect/                    # Detection enhancements
│   ├── mod.rs
│   ├── parser_discrepancy.rs  #   Permutation outcome engine
│   └── waf.rs                 #   10 WAF signature patterns
│
└── output/                    # Output formatters
    ├── mod.rs                 #   ScanResult + ScanReport
    ├── html.rs                #   Standalone HTML report
    ├── json.rs                #   JSON + YAML formatters
    └── table.rs               #   Terminal table output
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Async Rust (tokio)** | True non-blocking I/O for concurrent scanner operations |
| **Raw TLS + H1/H2** | Full control over ALPN, frame injection, and protocol mismatch — no library abstractions that normalize smuggling |
| **Semaphore concurrency** | Bounded parallelism prevents resource exhaustion while maximizing throughput |
| **Two-connection CL.TE probe** | Avoids pipelining pitfalls on `Connection: close` servers |
| **Differential detection** | Compares baseline vs attack response to eliminate false positives from transient errors |
| **10 bypass techniques** | TE.TE requires finding the parsing discrepancy — one engine covers common obfuscation patterns |
| **4-way canary comparison** | Parser Discrepancy Engine uses hidden×canary permutation matrix to classify outcome |
| **SPA single-write** | Attack + victim in one TCP write avoids connection-state issues between separate writes |

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| `cargo build` fails with OpenSSL error | Install OpenSSL dev headers (`libssl-dev` on Debian, `openssl-devel` on Fedora) or build with `--no-default-features` |
| Connection timeout on scan | Increase timeout: `ghostroute scan https://example.com --timeout 30` |
| False positives on CL.0 / 0.CL | Run `--variant contamination` to verify connection state stability |
| WAF blocking all probes | Check `--variant parser-discrepancy` output for WAF_BLOCK outcome; try `--variant h2-dual-path` |
| No HTTP/2 variants detected | Ensure target supports HTTP/2 (check `--variant h20`); proxy stripping may convert to H1 |
| `ghostroute: command not found` after install | Verify binary is in PATH: `ls /usr/local/bin/ghostroute`; re-run `sudo cp` |
| HTML report not rendering | Open in a modern browser; the report is self-contained with no external dependencies |

---

## 🔧 Development

### Prerequisites

- Rust 1.85+ (see `rust-toolchain.toml`)
- OpenSSL development headers (Linux) — optional, for native TLS

### Setup

```bash
# Clone and build
git clone https://github.com/PwnedBytes0x1/ghostroute
cd ghostroute

# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Lint
cargo clippy

# Format
cargo fmt
```

### Running Against Local Lab

```bash
# Start lab
ghostroute lab up

# Run a quick scan
ghostroute scan http://localhost:8080 --no-tls --concurrency 1

# Scan all variants
ghostroute scan http://localhost:8080 --no-tls --json

# Tear down
ghostroute lab down
```

### Adding a New Variant

1. Create `src/scan/<name>.rs` with a `pub async fn probe(...)` function returning `Result<ScanResult, String>`
2. Register it in `src/scan/mod.rs` (add `pub mod` + match arm in `run_scan`)
3. Add it to the variant list in `cli.rs`
4. Document it in `README.md`

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

**Quick checklist:**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run `cargo clippy` and `cargo test` to verify
5. Submit a pull request against `main`

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## 📄 License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for the full text.

---

## 🙏 Acknowledgements

- 🧠 [PortSwigger Research](https://portswigger.net/research) — foundational HTTP desync research by James Kettle
- 📄 [HTTP Request Smuggling in 2025](https://portswigger.net/research/http-request-smuggling-in-2025) — the paper that drove the v2 upgrade
- 🦀 [Tokio](https://tokio.rs) — async runtime powering concurrent scans
- 🛡️ [Rustls](https://github.com/rustls/rustls) — TLS implementation
- 📱 [Termux](https://termux.com/) — Android terminal emulator (build from source with `cargo build`)

---

<p align="center">
  <sub>Built with ♥ by <a href="https://github.com/PwnedBytes0x1">PwnedBytes0x1</a></sub>
  <br>
  <sub>ghostroute v1.0.3</sub>
  <br>
  <a href="https://github.com/PwnedBytes0x1/ghostroute">
    <img src="https://img.shields.io/github/stars/PwnedBytes0x1/ghostroute?style=social" alt="stars">
  </a>
</p>
