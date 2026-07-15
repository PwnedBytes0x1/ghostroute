pub mod chunk_ext;
pub mod cl0;
pub mod client_desync;
pub mod clte;
pub mod connection_state;
pub mod contamination;
pub mod expect100;
pub mod fuzzer;
pub mod h20;
pub mod h2_dual_path;
pub mod h2_fake_pseudo;
pub mod h2cl;
pub mod h2te;
pub mod header_removal;
pub mod parser_discrepancy;
pub mod pause_desync;
pub mod te0;
pub mod tecl;
pub mod tete;
pub mod timing;
pub mod websocket;
pub mod zero_cl;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::sleep;

use crate::auth::AuthStore;
use crate::checkpoint::Checkpoint;
use crate::net::NetConfig;
use crate::output::ScanResult;

pub struct ScanConfig {
    pub target: String,
    pub port: u16,
    pub tls: bool,
    pub timeout: u64,
    pub concurrency: usize,
    pub variant: String,
    pub auth: Option<AuthStore>,
    #[allow(dead_code)]
    pub proxy: Option<String>,
    pub checkpoint: Option<Checkpoint>,
    pub checkpoint_interval: u32,
    pub silent: bool,
}

impl ScanConfig {
    pub fn net_config(&self) -> NetConfig {
        NetConfig::new(&self.target, self.port, self.tls, self.timeout)
    }
}

pub async fn run_scan(config: ScanConfig) -> Result<Vec<ScanResult>, String> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut results: Vec<ScanResult> = Vec::new();
    let net_cfg = config.net_config();
    let mut probe_count: u64 = 0;
    let mut checkpoint = config.checkpoint;

    let variants: Vec<&str> = match config.variant.as_str() {
        "clte" => vec!["clte"],
        "tecl" => vec!["tecl"],
        "tete" => vec!["tete"],
        "cl0" => vec!["cl0"],
        "te0" => vec!["te0"],
        "h2cl" => vec!["h2cl"],
        "h2te" => vec!["h2te"],
        "h20" => vec!["h20"],
        "websocket" => vec!["websocket"],
        "chunk-ext" => vec!["chunk-ext"],
        "expect100" => vec!["expect100"],
        "timing" => vec!["timing"],
        "client-desync" => vec!["client-desync"],
        "connection-state" => vec!["connection-state"],
        "contamination" => vec!["contamination"],
        "h2-dual-path" => vec!["h2-dual-path"],
        "h2-fake-pseudo" => vec!["h2-fake-pseudo"],
        "header-removal" => vec!["header-removal"],
        "parser-discrepancy" => vec!["parser-discrepancy"],
        "pause-desync" | "pause" => vec!["pause-desync"],
        "zero-cl" | "0cl" => vec!["zero-cl"],
        "fuzz" => vec!["fuzz"],
        _ => vec!["clte", "tecl", "tete", "cl0", "te0", "h2cl", "h2te", "h20",
                 "websocket", "chunk-ext", "expect100", "timing", "client-desync",
                 "connection-state", "contamination", "h2-dual-path", "h2-fake-pseudo",
                 "header-removal", "pause-desync", "zero-cl",
                 "parser-discrepancy", "fuzz"],
    };

    let target_key = config.target.clone();

    for variant in &variants {
        if let Some(ref cp) = checkpoint {
            if cp.is_completed(&target_key, variant) {
                if !config.silent {
                    eprintln!("  [INF] Skipping {}/{} (already completed per checkpoint)",
                        config.target, variant);
                }
                continue;
            }
        }

        if !config.silent {
            eprintln!("  [INF] Testing {} on {}:{}", variant.to_uppercase(), config.target, config.port);
        }

        let permit = semaphore.clone().acquire_owned().await.map_err(|e| e.to_string())?;

        let result = match *variant {
            "clte" => clte::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "tecl" => tecl::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "tete" => tete::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "cl0" => cl0::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "te0" => te0::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "h2cl" => h2cl::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "h2te" => h2te::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "h20" => h20::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "chunk-ext" => chunk_ext::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "websocket" => websocket::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "expect100" => expect100::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "timing" => timing::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "client-desync" => client_desync::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "connection-state" => connection_state::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "contamination" => contamination::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "h2-dual-path" => h2_dual_path::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "h2-fake-pseudo" => h2_fake_pseudo::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "header-removal" => header_removal::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "parser-discrepancy" => parser_discrepancy::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "pause-desync" => pause_desync::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "zero-cl" => zero_cl::probe(&net_cfg, config.auth.as_ref(), &config.silent).await,
            "fuzz" => {
                match fuzzer::run_fuzz(&net_cfg, config.auth.as_ref(), &config.silent).await {
                    Ok(fuzz_results) => {
                        let count = fuzz_results.len();
                        results.extend(fuzz_results);
                        probe_count += count as u64;
                    }
                    Err(e) => {
                        results.push(ScanResult {
                            host: config.target.clone(),
                            port: config.port,
                            variant: "fuzz".to_string(),
                            vulnerable: false,
                            server: None,
                            bypass: None,
                            status_code: 0,
                            details: Some(e),
                            ..Default::default()
                        });
                    }
                }
                continue;
            }
            _ => Ok(ScanResult {
                host: config.target.clone(),
                port: config.port,
                variant: variant.to_string(),
                vulnerable: false,
                server: None,
                bypass: None,
                status_code: 0,
                details: Some("Unknown variant".into()),
                ..Default::default()
            }),
        };

        drop(permit);

        match result {
            Ok(r) => {
                probe_count += 1;
                results.push(r);
            }
            Err(e) => {
                results.push(ScanResult {
                    host: config.target.clone(),
                    port: config.port,
                    variant: variant.to_string(),
                    vulnerable: false,
                    server: None,
                    bypass: None,
                    status_code: 0,
                    details: Some(e),
                    ..Default::default()
                });
            }
        }

        if let Some(ref mut cp) = checkpoint {
            cp.mark_completed(&target_key);
            cp.increment_probes();
            if probe_count.is_multiple_of(config.checkpoint_interval as u64) {
                let _ = cp.save(None);
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    if let Some(ref mut cp) = checkpoint {
        if let Err(e) = cp.save(None) {
            if !config.silent {
                eprintln!("  [WARN] Failed to save checkpoint: {}", e);
            }
        }
    }

    Ok(results)
}
