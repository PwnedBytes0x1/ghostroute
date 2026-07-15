use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(name = "ghostroute", version = env!("CARGO_PKG_VERSION"))]
#[command(about = "HTTP request smuggling detection & exploitation tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Scan(ScanArgs),
    Exploit(ExploitArgs),
    Update(UpdateArgs),
    Lab(LabArgs),
}

#[derive(Args, Clone)]
pub struct ScanArgs {
    pub target: Option<String>,

    #[arg(long, help = "Cookie(s) for authenticated scanning (e.g. 'session=abc123')")]
    pub cookie: Option<String>,

    #[arg(short = 'H', long = "header", help = "Custom header(s) for authenticated scanning")]
    pub header: Vec<String>,

    #[arg(long, help = "Output JSONL to stdout (pipeline mode)")]
    pub json: bool,

    #[arg(long, help = "Suppress banner/progress, output results only")]
    pub silent: bool,

    #[arg(short = 'f', long = "file", help = "File with targets (one domain/subdomain per line)")]
    pub file: Option<String>,

    #[arg(short = 'o', long = "output", help = "Output file path for report")]
    pub output: Option<String>,

    #[arg(long, help = "Resume from a checkpoint file")]
    pub resume: Option<String>,

    #[arg(long = "checkpoint-interval", default_value = "25", help = "Probes between checkpoint saves")]
    pub checkpoint_interval: u32,

    #[arg(long, help = "Check for updates before scanning")]
    pub auto_update: bool,

    #[arg(long, default_value = "all", help = "Test specific variant: clte, tecl, tete, cl0, te0, 0cl/zero-cl, pause/pause-desync, header-removal, connection-state, h2cl, h2te, h20, h2-dual-path, h2-fake-pseudo, chunk-ext, websocket, expect100, timing, client-desync, contamination, parser-discrepancy, fuzz, all")]
    pub variant: String,

    #[arg(long, default_value = "10", help = "Connection timeout in seconds")]
    pub timeout: u64,

    #[arg(long, default_value = "4", help = "Concurrent connections")]
    pub concurrency: usize,

    #[arg(long, help = "Proxy URL (e.g. http://127.0.0.1:8080)")]
    pub proxy: Option<String>,

    #[arg(long, help = "Target port (default: 443 for https, 80 for http)")]
    pub port: Option<u16>,

    #[arg(long, help = "Disable TLS")]
    pub no_tls: bool,
}

#[derive(Args, Clone)]
pub struct ExploitArgs {
    pub target: String,

    #[arg(long, help = "Smuggling variant to exploit")]
    pub variant: String,

    #[arg(long, help = "Cookie(s) for authenticated exploitation")]
    pub cookie: Option<String>,

    #[arg(short = 'H', long = "header", help = "Custom header(s) for exploitation")]
    pub header: Vec<String>,

    #[arg(long = "prefix-request", help = "File with prefix request body (smuggled payload)")]
    pub prefix_request: Option<String>,

    #[arg(long = "suffix-request", help = "File with suffix request template")]
    pub suffix_request: Option<String>,

    #[arg(short = 'i', long = "interactive", help = "Interactive mode")]
    pub interactive: bool,

    #[arg(long, help = "Cache poisoning chain: <cache_url>::<origin_url>")]
    pub chain: Option<String>,

    #[arg(long, default_value = "1", help = "Number of poisoned connections")]
    pub count: u32,

    #[arg(long, default_value = "100", help = "Delay between attempts (ms)")]
    pub delay: u64,

    #[arg(long, help = "Proxy URL")]
    pub proxy: Option<String>,

    #[arg(long, default_value = "10", help = "Connection timeout")]
    pub timeout: u64,

    #[arg(long, help = "Target port (default: 443)")]
    pub port: Option<u16>,

    #[arg(long, help = "Output JSON")]
    pub json: bool,

    #[arg(long, help = "Silent mode")]
    pub silent: bool,
}

#[derive(Args, Clone)]
pub struct UpdateArgs {
    #[arg(long, help = "Force update even if up to date")]
    pub force: bool,
}

#[derive(Args, Clone)]
pub struct LabArgs {
    #[command(subcommand)]
    pub action: Option<LabAction>,
}

#[derive(Subcommand, Clone)]
pub enum LabAction {
    Up,
    Down,
    Test,
    Restart,
}
