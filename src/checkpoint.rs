use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Checkpoint {
    pub targets: Vec<String>,
    pub completed: Vec<String>,
    pub current_target: Option<String>,
    pub timestamp: String,
    pub variant: String,
    pub total_probes: u64,
}

impl Checkpoint {
    pub fn new(targets: Vec<String>, variant: String) -> Self {
        Checkpoint {
            targets,
            completed: Vec::new(),
            current_target: None,
            timestamp: Utc::now().to_rfc3339(),
            variant,
            total_probes: 0,
        }
    }

    pub fn mark_completed(&mut self, target: &str) {
        let key = format!("{}::{}", target, self.variant);
        self.completed.push(key);
        self.timestamp = Utc::now().to_rfc3339();
    }

    pub fn is_completed(&self, target: &str, variant: &str) -> bool {
        let key = format!("{}::{}", target, variant);
        self.completed.contains(&key)
    }

    pub fn remaining_targets(&self) -> Vec<String> {
        let completed_set: HashSet<String> = self.completed.iter().cloned().collect();
        self.targets
            .iter()
            .filter(|t| {
                let key = format!("{}::{}", t, self.variant);
                !completed_set.contains(&key)
            })
            .cloned()
            .collect()
    }

    pub fn increment_probes(&mut self) {
        self.total_probes += 1;
    }

    pub fn save(&self, path: Option<&str>) -> Result<(), String> {
        let path = path
            .map(PathBuf::from)
            .unwrap_or_else(default_checkpoint_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&data).map_err(|e| e.to_string())
    }
}

fn default_checkpoint_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".ghostroute")
        .join("checkpoints")
        .join(format!("checkpoint_{}.json", Utc::now().format("%Y%m%d_%H%M%S")))
}
