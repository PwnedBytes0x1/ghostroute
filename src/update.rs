use std::path::PathBuf;

const GH_API: &str = "https://api.github.com/repos/PwnedBytes0x1/ghostroute/releases/latest";

#[derive(serde::Deserialize)]
pub struct GithubRelease {
    pub tag_name: String,
    pub assets: Vec<GithubAsset>,
    #[allow(dead_code)]
    pub html_url: String,
}

#[derive(serde::Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    #[allow(dead_code)]
    pub size: u64,
}

pub enum UpdateStatus {
    UpToDate,
    Available {
        version: String,
        download_url: String,
        checksum: Option<String>,
    },
}

pub fn target_triple() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    match (os, arch) {
        ("linux", "aarch64") => "aarch64-unknown-linux-musl".to_string(),
        ("linux", "x86_64") => "x86_64-unknown-linux-musl".to_string(),
        ("macos", "aarch64") => "aarch64-apple-darwin".to_string(),
        ("macos", "x86_64") => "x86_64-apple-darwin".to_string(),
        ("windows", "x86_64") => "x86_64-pc-windows-msvc".to_string(),
        ("windows", "aarch64") => "aarch64-pc-windows-msvc".to_string(),
        ("android", "aarch64") => "aarch64-linux-android".to_string(),
        _ => format!("{}-unknown-{}-{}", arch, os, "gnu"),
    }
}

fn current_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub async fn check() -> Result<UpdateStatus, String> {
    let client = reqwest::Client::builder()
        .user_agent("ghostroute-update-checker")
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(GH_API)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to check for updates: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }

    let release: GithubRelease = resp.json().await.map_err(|e| e.to_string())?;
    let latest_ver = release.tag_name.trim_start_matches('v');

    let current = semver::Version::parse(&current_version()).map_err(|e| e.to_string())?;
    let latest = semver::Version::parse(latest_ver).map_err(|e| e.to_string())?;

    if latest <= current {
        return Ok(UpdateStatus::UpToDate);
    }

    let triple = target_triple();
    let exe_ext = if cfg!(windows) { ".exe" } else { "" };
    let asset_name = format!("ghostroute-{}{}", triple, exe_ext);

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name || a.name.ends_with(&asset_name))
        .ok_or_else(|| {
            format!(
                "No asset found for triple {} (expected {})",
                triple, asset_name
            )
        })?;

    let checksum_asset = release.assets.iter().find(|a| a.name == "checksums.blake3");
    let checksum = if let Some(ca) = checksum_asset {
        fetch_checksum(&client, &ca.browser_download_url, &asset_name)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    Ok(UpdateStatus::Available {
        version: latest_ver.to_string(),
        download_url: asset.browser_download_url.clone(),
        checksum,
    })
}

async fn fetch_checksum(
    client: &reqwest::Client,
    url: &str,
    asset_name: &str,
) -> Result<Option<String>, String> {
    let text = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1].trim() == asset_name {
            return Ok(Some(parts[0].to_string()));
        }
    }
    Ok(None)
}

pub async fn download_and_install(status: &UpdateStatus) -> Result<(), String> {
    match status {
        UpdateStatus::Available {
            version,
            download_url,
            checksum,
        } => {
            let client = reqwest::Client::builder()
                .user_agent("ghostroute-installer")
                .build()
                .map_err(|e| e.to_string())?;

            let resp = client
                .get(download_url)
                .send()
                .await
                .map_err(|e| format!("Download failed: {}", e))?;

            let bytes = resp.bytes().await.map_err(|e| e.to_string())?;

            if let Some(expected_hash) = checksum {
                let actual_hash = blake3::hash(&bytes).to_hex().to_string();
                if !actual_hash.eq_ignore_ascii_case(expected_hash) {
                    return Err(format!(
                        "Checksum mismatch! Expected {} got {}",
                        expected_hash, actual_hash
                    ));
                }
            }

            let binary_path = self_binary_path()?;
            let temp_path = binary_path.with_extension("new");

            std::fs::write(&temp_path, &bytes).map_err(|e| e.to_string())?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o755);
                std::fs::set_permissions(&temp_path, perms).map_err(|e| e.to_string())?;
            }

            std::fs::rename(&temp_path, &binary_path).map_err(|e| {
                let _ = std::fs::remove_file(&temp_path);
                format!("Failed to replace binary: {}", e)
            })?;

            crate::print_info(&format!("Updated to version {} successfully!", version));
            Ok(())
        }
        _ => Err("No update available".to_string()),
    }
}

fn self_binary_path() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("Cannot determine binary path: {}", e))
}
