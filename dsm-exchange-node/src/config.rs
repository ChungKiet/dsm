// SPDX-License-Identifier: MIT OR Apache-2.0
//! Configuration loaded from `config.toml` (or path given by `--config`).

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub node: NodeConfig,
    pub storage: StorageConfig,
    pub identity: IdentityConfig,
    pub http: HttpConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    /// Human-readable label for this exchange node (used as SDK node_id).
    pub id: String,
    /// Network: "main" or "test"
    pub network: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    /// List of DSM storage node base URLs.
    /// Must supply ≥ 3 for K=3 replication.
    pub endpoints: Vec<String>,
    /// Path to the dsm_env_config.toml used by StorageNodeSDK for MPC genesis.
    /// If omitted, the SDK falls back to its built-in beta node list.
    pub env_config_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IdentityConfig {
    /// Base directory for all SDK-persisted data (SQLite DBs, state files).
    /// Must be set before any other SDK call.
    pub data_dir: String,
    /// Path to persist the 32-byte DBRW binding key (hex-encoded on disk).
    pub dbrw_key_path: String,
    /// Path to persist genesis identity (device_id + genesis_hash, JSON).
    pub identity_state_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpConfig {
    /// Address to bind, e.g. "0.0.0.0:9090"
    pub listen: String,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config file {path}: {e}"))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("config parse error in {path}: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.node.id.is_empty() {
            anyhow::bail!("node.id must not be empty");
        }
        if self.storage.endpoints.len() < 3 {
            anyhow::bail!(
                "storage.endpoints must have at least 3 entries for K=3 replication (got {})",
                self.storage.endpoints.len()
            );
        }
        if self.identity.data_dir.is_empty() {
            anyhow::bail!("identity.data_dir must not be empty");
        }
        if self.identity.dbrw_key_path.is_empty() {
            anyhow::bail!("identity.dbrw_key_path must not be empty");
        }
        if self.identity.identity_state_path.is_empty() {
            anyhow::bail!("identity.identity_state_path must not be empty");
        }
        Ok(())
    }
}
