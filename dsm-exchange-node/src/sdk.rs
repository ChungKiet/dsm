// SPDX-License-Identifier: MIT OR Apache-2.0
//! SDK bootstrap: DBRW key management, genesis creation, and SDK init.

use std::path::Path;

use anyhow::{anyhow, Context};
use prost::Message;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::info;

use dsm_sdk::handlers::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::sdk::app_state::AppState;
use dsm_sdk::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};
use dsm_sdk::security::cdbrw_access_gate::{
    next_iter, store_trust, AccessLevel, ResonantStatus, TrustSnapshot,
};
use dsm_sdk::storage::{store_genesis_record_with_verification, GenesisRecord};
use dsm_sdk::generated as pb;

use crate::config::Config;

/// Persisted exchange identity (written after first genesis).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdentityState {
    /// 32-byte device ID, hex-encoded.
    pub device_id_hex: String,
    /// 32-byte genesis hash, hex-encoded.
    pub genesis_hash_hex: String,
    /// Kyber public key hex (derived deterministically — stable across restarts).
    #[serde(default)]
    pub kyber_public_key_hex: String,
}

// ── Public bootstrap entry point ─────────────────────────────────────────────

/// Full bootstrap sequence. Call once at startup before serving requests.
pub async fn bootstrap(cfg: &Config) -> anyhow::Result<IdentityState> {
    // Set storage base dir FIRST — SDK panics if any other call happens before this
    let data_dir = std::path::PathBuf::from(&cfg.identity.data_dir);
    dsm_sdk::storage_utils::set_storage_base_dir(data_dir)
        .map_err(|e| anyhow!("set_storage_base_dir failed: {e:?}"))?;
    info!("SDK storage dir: {}", cfg.identity.data_dir);

    // Optionally point StorageNodeSDK at a custom env_config.toml
    if let Some(ref env_path) = cfg.storage.env_config_path {
        dsm_sdk::network::set_env_config_path(env_path.clone());
        info!("StorageNodeSDK env config: {env_path}");
    }

    // Load or generate DBRW binding key
    let dbrw_key = load_or_create_dbrw_key(&cfg.identity.dbrw_key_path)?;
    dsm_sdk::set_cdbrw_binding_key_for_testing(dbrw_key.clone());
    info!("DBRW binding key installed ({} bytes)", dbrw_key.len());

    // Initialise SDK routers (bilateral + unilateral + app router stubs)
    let sdk_cfg = SdkConfig {
        node_id: cfg.node.id.clone(),
        storage_endpoints: cfg.storage.endpoints.clone(),
        enable_offline: false,
    };
    dsm_sdk::init::init_dsm_sdk(&sdk_cfg)
        .map_err(|e| anyhow!("init_dsm_sdk failed: {e}"))?;
    info!("dsm_sdk initialized (node_id={})", cfg.node.id);

    // Load or create genesis identity
    let identity = load_or_create_identity(cfg, &dbrw_key).await?;
    info!(
        "Exchange identity ready: device_id={}…",
        &identity.device_id_hex[..12]
    );

    // Register this device on ALL configured storage endpoints so that
    // fetch_quorum_device_identity (used by wallet.send recipient lookup) can
    // reach a quorum of 3. The SDK's register_device() stops after the first
    // success, so we call each endpoint explicitly here.
    register_on_all_endpoints(cfg, &identity).await;

    Ok(identity)
}

/// Register this device on every configured storage endpoint.
/// Non-fatal — logs warnings on failure but does not abort startup.
async fn register_on_all_endpoints(cfg: &Config, identity: &IdentityState) {
    use prost::Message as _;

    let device_id_bytes = match hex::decode(&identity.device_id_hex) {
        Ok(b) => b,
        Err(_) => return,
    };
    let genesis_bytes = match hex::decode(&identity.genesis_hash_hex) {
        Ok(b) => b,
        Err(_) => return,
    };
    let public_key = dsm_sdk::sdk::app_state::AppState::get_public_key()
        .unwrap_or_default();

    let device_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&device_id_bytes);
    let genesis_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&genesis_bytes);

    let req = dsm_sdk::generated::RegisterDeviceRequest {
        device_id: device_id_bytes,
        pubkey: public_key,
        genesis_hash: genesis_bytes,
    };
    let mut body = Vec::new();
    if req.encode(&mut body).is_err() { return; }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    for endpoint in &cfg.storage.endpoints {
        let ep = endpoint.trim_end_matches('/');

        // Register (or re-issue token if already registered).
        let token_opt = try_register_or_reissue(&client, ep, &body).await;

        if let Some(token_b32) = token_opt {
            // Store the token so b0x submit/ack work on this endpoint.
            if let Err(e) = dsm_sdk::storage::client_db::store_auth_token(
                ep, &device_b32, &genesis_b32, &token_b32,
            ) {
                info!("store_auth_token failed for {ep}: {e}");
            } else {
                info!("Device registered + token stored for {ep}");
            }
        }
    }
}

async fn try_register_or_reissue(
    client: &reqwest::Client,
    endpoint: &str,
    body: &[u8],
) -> Option<String> {
    use prost::Message as _;

    let url_reg = format!("{endpoint}/api/v2/device/register");
    match client
        .post(&url_reg)
        .header("Content-Type", "application/protobuf")
        .body(body.to_vec())
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            let bytes = r.bytes().await.ok()?;
            let resp = dsm_sdk::generated::RegisterDeviceResponse::decode(bytes.as_ref()).ok()?;
            Some(dsm_sdk::util::text_id::encode_base32_crockford(&resp.token))
        }
        Ok(r) if r.status().as_u16() == 409 => {
            // Already registered — re-issue token.
            let url_tok = format!("{endpoint}/api/v2/device/token");
            match client
                .post(&url_tok)
                .header("Content-Type", "application/protobuf")
                .body(body.to_vec())
                .send()
                .await
            {
                Ok(r2) if r2.status().is_success() => {
                    let bytes = r2.bytes().await.ok()?;
                    let resp = dsm_sdk::generated::RegisterDeviceResponse::decode(bytes.as_ref()).ok()?;
                    Some(dsm_sdk::util::text_id::encode_base32_crockford(&resp.token))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

// ── DBRW key helpers ─────────────────────────────────────────────────────────

fn load_or_create_dbrw_key(path: &str) -> anyhow::Result<Vec<u8>> {
    if Path::new(path).exists() {
        let hex_str = std::fs::read_to_string(path)
            .with_context(|| format!("reading DBRW key from {path}"))?;
        let key = hex::decode(hex_str.trim())
            .with_context(|| format!("decoding DBRW key hex from {path}"))?;
        if key.len() != 32 {
            anyhow::bail!("DBRW key at {path} must be 32 bytes");
        }
        info!("DBRW binding key loaded from {path}");
        Ok(key)
    } else {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let hex_str = hex::encode(&key);
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dirs for {path}"))?;
        }
        std::fs::write(path, &hex_str)
            .with_context(|| format!("writing DBRW key to {path}"))?;
        info!("New DBRW binding key generated and saved to {path}");
        Ok(key)
    }
}

// ── Identity helpers ─────────────────────────────────────────────────────────

async fn load_or_create_identity(
    cfg: &Config,
    dbrw_key: &[u8],
) -> anyhow::Result<IdentityState> {
    let path = &cfg.identity.identity_state_path;
    if Path::new(path).exists() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading identity state from {path}"))?;
        let state: IdentityState = serde_json::from_str(&text)
            .with_context(|| format!("parsing identity state from {path}"))?;

        let device_id = hex::decode(&state.device_id_hex)?;
        let genesis_hash = hex::decode(&state.genesis_hash_hex)?;
        let entropy = derive_entropy(&device_id, &genesis_hash, dbrw_key);
        dsm_sdk::initialize_sdk_context(device_id.clone(), genesis_hash.clone(), entropy)
            .map_err(|e| anyhow!("initialize_sdk_context failed: {e:?}"))?;

        // Re-populate AppState from persisted identity on restart.
        // Must derive with K_DBRW (same as genesis path) not raw dbrw_key.
        let k_dbrw_load = {
            let mut hw = [0u8; 32];
            let mut env = [0u8; 32];
            blake3::Hasher::new_derive_key("DSM/exchange-node/hw-entropy")
                .update(dbrw_key).update(cfg.node.id.as_bytes())
                .finalize_xof().fill(&mut hw);
            blake3::Hasher::new_derive_key("DSM/exchange-node/env-fingerprint")
                .update(dbrw_key).update(cfg.node.network.as_bytes())
                .finalize_xof().fill(&mut env);
            dsm_sdk::dsm::crypto::cdbrw_binding::derive_cdbrw_binding_key(
                &genesis_hash, &genesis_hash, &hw, &env,
            ).map(|k| k.to_vec())
            .unwrap_or_else(|_| dbrw_key.to_vec())
        };
        // Install K_DBRW as the binding key so signing_authority uses the same key.
        // Without this, b0x_sdk signs registration requests with raw dbrw_key while
        // AppState reports K_DBRW-derived key → storage node rejects token re-issue.
        if let Ok(k_arr) = k_dbrw_load.as_slice().try_into().map(|b: [u8; 32]| b) {
            dsm_sdk::set_cdbrw_binding_key_for_testing(k_arr.to_vec());
        }

        let public_key = derive_signing_public_key(&genesis_hash, &device_id, &k_dbrw_load)
            .unwrap_or_else(|e| {
                tracing::warn!("signing key derivation failed: {e}; using AppState key");
                AppState::get_public_key().unwrap_or_default()
            });
        let smt_root = dsm_sdk::dsm::merkle::sparse_merkle_tree::empty_root(
            dsm_sdk::dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
        )
        .to_vec();
        AppState::set_identity_info(device_id.clone(), public_key, genesis_hash.clone(), smt_root);
        AppState::set_has_identity(true);

        // Ensure genesis record is in SQLite (idempotent — safe to call on every restart).
        ensure_genesis_record_in_db(&state, &genesis_hash, &device_id, dbrw_key, cfg);

        // Upgrade bootstrap router to full AppRouterImpl
        install_full_router(cfg)?;

        // Backfill kyber_public_key_hex if missing from persisted state (older nodes).
        let state = if state.kyber_public_key_hex.is_empty() {
            IdentityState {
                kyber_public_key_hex: derive_kyber_public_key(&genesis_hash, &device_id, dbrw_key)
                    .map(|k| hex::encode(&k))
                    .unwrap_or_default(),
                ..state
            }
        } else {
            state
        };

        info!("Identity state loaded from {path}");
        return Ok(state);
    }

    let state = create_genesis(cfg, dbrw_key).await?;
    persist_identity(&state, path)?;
    Ok(state)
}

async fn create_genesis(cfg: &Config, dbrw_key: &[u8]) -> anyhow::Result<IdentityState> {
    info!("No identity found — creating genesis via MPC (this may take ~10 s)");

    // Build 32-byte client entropy deterministically from DBRW key + node id
    let mut entropy = [0u8; 32];
    let mut hasher = blake3::Hasher::new_derive_key("DSM/exchange-node/genesis-entropy");
    hasher.update(dbrw_key);
    hasher.update(cfg.node.id.as_bytes());
    entropy.copy_from_slice(hasher.finalize().as_bytes());

    // The updated SDK requires platform silicon inputs (hw_entropy + env_fingerprint)
    // before genesis. On a server there is no hardware security module, so we derive
    // deterministic values from the DBRW key. These serve the same role: binding the
    // genesis to this specific server instance's key material.
    let mut hw = [0u8; 32];
    let mut env = [0u8; 32];
    blake3::Hasher::new_derive_key("DSM/exchange-node/hw-entropy")
        .update(dbrw_key).update(cfg.node.id.as_bytes())
        .finalize_xof().fill(&mut hw);
    blake3::Hasher::new_derive_key("DSM/exchange-node/env-fingerprint")
        .update(dbrw_key).update(cfg.node.network.as_bytes())
        .finalize_xof().fill(&mut env);
    dsm_sdk::sdk::app_state::AppState::set_platform_entropy_inputs(hw.to_vec(), env.to_vec())
        .map_err(|e| anyhow!("set_platform_entropy_inputs: {e}"))?;

    // Build StorageNodeConfig directly from our configured endpoints
    // (bypasses from_env_config which requires a dsm_env_config.toml file)
    let mut node_cfg = StorageNodeConfig::new(cfg.storage.endpoints.clone());
    // The beta nodes expose /api/v2/genesis/entropy so MPC genesis works directly;
    // no dedicated MPC relay URL needed.
    node_cfg.mpc_genesis_url = None;

    let sdk = StorageNodeSDK::new(node_cfg)
        .await
        .map_err(|e| anyhow!("StorageNodeSDK::new failed: {e:?}"))?;

    let res = sdk
        .create_genesis_with_mpc(Some(entropy.to_vec()))
        .await
        .map_err(|e| anyhow!("create_genesis_with_mpc failed: {e:?}"))?;

    if !res.complete {
        anyhow::bail!("genesis did not complete (state={})", res.state);
    }

    let genesis_hash_bytes = res
        .genesis_hash
        .ok_or_else(|| anyhow!("genesis_hash missing from MPC response"))?;

    if genesis_hash_bytes.len() != 32 {
        anyhow::bail!("genesis returned non-32-byte hash");
    }

    // For the root device, device_id == genesis_hash
    let device_id_bytes = genesis_hash_bytes.clone();

    let kyber_pk_hex = derive_kyber_public_key(&genesis_hash_bytes, &device_id_bytes, dbrw_key)
        .map(|k| hex::encode(&k))
        .unwrap_or_default();

    let state = IdentityState {
        device_id_hex: hex::encode(&device_id_bytes),
        genesis_hash_hex: hex::encode(&genesis_hash_bytes),
        kyber_public_key_hex: kyber_pk_hex,
    };

    let derived_entropy = derive_entropy(&device_id_bytes, &genesis_hash_bytes, dbrw_key);
    dsm_sdk::initialize_sdk_context(
        device_id_bytes.clone(),
        genesis_hash_bytes.clone(),
        derived_entropy,
    )
    .map_err(|e| anyhow!("initialize_sdk_context after genesis: {e:?}"))?;

    // After create_genesis_with_mpc the SDK installs K_DBRW (not the raw dbrw_key).
    // K_DBRW = derive_cdbrw_binding_key(genesis_hash, genesis_hash, hw, env).
    // The signing key must be derived from K_DBRW, not dbrw_key directly.
    let k_dbrw = {
        let mut hw = [0u8; 32];
        let mut env = [0u8; 32];
        blake3::Hasher::new_derive_key("DSM/exchange-node/hw-entropy")
            .update(dbrw_key).update(cfg.node.id.as_bytes())
            .finalize_xof().fill(&mut hw);
        blake3::Hasher::new_derive_key("DSM/exchange-node/env-fingerprint")
            .update(dbrw_key).update(cfg.node.network.as_bytes())
            .finalize_xof().fill(&mut env);
        dsm_sdk::dsm::crypto::cdbrw_binding::derive_cdbrw_binding_key(
            &genesis_hash_bytes, &genesis_hash_bytes, &hw, &env,
        ).map(|k| k.to_vec())
        .unwrap_or_else(|_| dbrw_key.to_vec())
    };
    let public_key = derive_signing_public_key(&genesis_hash_bytes, &device_id_bytes, &k_dbrw)
        .unwrap_or_else(|e| {
            tracing::warn!("signing key derivation failed post-genesis: {e}; using AppState key");
            AppState::get_public_key().unwrap_or_default()
        });

    // Publish genesis to storage nodes so contacts.addManual can verify it
    let empty_root = dsm_sdk::dsm::merkle::sparse_merkle_tree::empty_root(
        dsm_sdk::dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
    );
    // Use dsm_sdk::generated types (SDK's own prost-generated code) — different
    // from dsm_sdk::types::proto which re-exports the dsm crate's proto types.
    let genesis_created = dsm_sdk::generated::GenesisCreated {
        device_id: device_id_bytes.clone(),
        genesis_hash: Some(dsm_sdk::generated::Hash32 {
            v: genesis_hash_bytes.clone(),
        }),
        public_key: public_key.clone(),
        smt_root: Some(dsm_sdk::generated::Hash32 {
            v: empty_root.to_vec(),
        }),
        device_entropy: entropy.to_vec(),
        session_id: res.session_id,
        threshold: 3,
        storage_nodes: cfg.storage.endpoints.clone(),
        network_id: cfg.node.network.clone(),
        locale: "en".to_string(),
    };
    // Re-use the StorageNodeSDK instance for publishing
    let mut publish_cfg = StorageNodeConfig::new(cfg.storage.endpoints.clone());
    publish_cfg.mpc_genesis_url = None;
    if let Ok(publish_sdk) = StorageNodeSDK::new(publish_cfg).await {
        match publish_sdk.publish_genesis_to_nodes(genesis_created).await {
            Ok(r) => info!(
                "Genesis published to {}/{} nodes",
                r.published_to_nodes,
                cfg.storage.endpoints.len()
            ),
            Err(e) => tracing::warn!("Genesis publish failed (non-fatal): {e:?}"),
        }
    }
    let smt_root = dsm_sdk::dsm::merkle::sparse_merkle_tree::empty_root(
        dsm_sdk::dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
    )
    .to_vec();
    AppState::set_identity_info(
        device_id_bytes.clone(),
        public_key,
        genesis_hash_bytes.clone(),
        smt_root,
    );
    AppState::set_has_identity(true);

    // Store genesis record in SQLite so wallet.sendSmart can resolve local_genesis_hash().
    ensure_genesis_record_in_db(&state, &genesis_hash_bytes, &device_id_bytes, dbrw_key, cfg);

    // Upgrade MinimalBootstrapRouter → full AppRouterImpl
    install_full_router(cfg)?;

    info!("Genesis complete: device_id={}…", &state.device_id_hex[..12]);
    Ok(state)
}

/// Replace MinimalBootstrapRouter with the full AppRouterImpl.
/// Must be called AFTER AppState has device_id + genesis_hash set.
fn install_full_router(cfg: &Config) -> anyhow::Result<()> {
    let sdk_cfg = SdkConfig {
        node_id: cfg.node.id.clone(),
        storage_endpoints: cfg.storage.endpoints.clone(),
        enable_offline: false,
    };
    let router = AppRouterImpl::new(sdk_cfg)
        .map_err(|e| anyhow!("AppRouterImpl::new failed: {e:?}"))?;
    dsm_sdk::bridge::install_app_router(std::sync::Arc::new(router))
        .map_err(|e| anyhow!("install_app_router failed: {e:?}"))?;
    info!("Full AppRouterImpl installed");

    // Bootstrap C-DBRW trust for server process (no mobile hardware orbit).
    // On a server the binding key IS the "device" — publish FullAccess directly.
    store_trust(TrustSnapshot {
        access_level: AccessLevel::FullAccess,
        resonant_status: ResonantStatus::Pass,
        h_hat: 1.0,
        rho_hat: 0.0,
        l_hat: 1.0,
        h0_eff: 1.0,
        trust_score: 1.0,
        recommended_n: 1,
        w1_distance: 0.0,
        w1_threshold: 1.0,
        iter: next_iter(),
    });
    info!("C-DBRW trust bootstrapped (server mode, FullAccess)");
    Ok(())
}

/// Ensure the genesis_records SQLite row exists for wallet.sendSmart.
/// Uses INSERT OR REPLACE so safe to call on every boot.
fn ensure_genesis_record_in_db(
    state: &IdentityState,
    genesis_hash: &[u8],
    device_id: &[u8],
    dbrw_key: &[u8],
    cfg: &Config,
) {
    let genesis_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(genesis_hash);
    let device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(device_id);
    let empty_smt_root = dsm_sdk::dsm::merkle::sparse_merkle_tree::empty_root(
        dsm_sdk::dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
    );
    let mut entropy_hasher = blake3::Hasher::new_derive_key("DSM/sdk-hash");
    entropy_hasher.update(device_id);
    entropy_hasher.update(genesis_hash);
    entropy_hasher.update(dbrw_key);
    let entropy_hash = hex::encode(entropy_hasher.finalize().as_bytes());

    let record = GenesisRecord {
        genesis_id: genesis_id_b32,
        device_id: device_id_b32,
        mpc_proof: state.genesis_hash_hex.clone(),
        dbrw_binding: hex::encode(dbrw_key),
        merkle_root: hex::encode(&empty_smt_root[..]),
        participant_count: 3,
        progress_marker: "genesis".to_string(),
        publication_hash: String::new(),
        storage_nodes: cfg.storage.endpoints.clone(),
        entropy_hash,
        protocol_version: "1".to_string(),
        hash_chain_proof: None,
        smt_proof: None,
        verification_step: None,
    };
    match store_genesis_record_with_verification(&record) {
        Ok(_) => info!(
            "Genesis record ensured in SQLite ({}…)",
            &state.genesis_hash_hex[..12]
        ),
        Err(e) => tracing::warn!("ensure_genesis_record_in_db failed (non-fatal): {e:?}"),
    }
}

fn persist_identity(state: &IdentityState, path: &str) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dirs for {path}"))?;
    }
    let text = serde_json::to_string_pretty(state)?;
    std::fs::write(path, text).with_context(|| format!("writing identity state to {path}"))?;
    info!("Identity state persisted to {path}");
    Ok(())
}

// ── Utility ──────────────────────────────────────────────────────────────────

/// Derive SPHINCS+ signing public key from genesis_hash || device_id || dbrw_key.
/// Mirrors the derivation in dsm_sdk::init (Android init path).
fn derive_signing_public_key(
    genesis_hash: &[u8],
    device_id: &[u8],
    dbrw_key: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use dsm_sdk::crypto::signatures::SignatureKeyPair;
    let mut key_entropy = Vec::with_capacity(96);
    key_entropy.extend_from_slice(genesis_hash);
    key_entropy.extend_from_slice(device_id);
    key_entropy.extend_from_slice(dbrw_key);
    let keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)
        .map_err(|e| anyhow!("generate_from_entropy: {e:?}"))?;
    Ok(keypair.public_key().to_vec())
}

/// Derive a stable Kyber public key from genesis_hash || device_id || dbrw_key.
/// Deterministic so the keypair is stable across restarts.
pub fn derive_kyber_public_key(
    genesis_hash: &[u8],
    device_id: &[u8],
    dbrw_key: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use dsm_sdk::dsm::crypto::kyber::generate_kyber_keypair_from_entropy;
    let mut entropy = Vec::with_capacity(96);
    entropy.extend_from_slice(genesis_hash);
    entropy.extend_from_slice(device_id);
    entropy.extend_from_slice(dbrw_key);
    let (pk, _sk) = generate_kyber_keypair_from_entropy(&entropy, "DSM/exchange-node/kyber-key")
        .map_err(|e| anyhow!("generate_kyber_keypair_from_entropy: {e:?}"))?;
    Ok(pk)
}

fn derive_entropy(device_id: &[u8], genesis_hash: &[u8], dbrw_key: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key("DSM/sdk-hash");
    h.update(device_id);
    h.update(genesis_hash);
    h.update(dbrw_key);
    h.finalize().as_bytes().to_vec()
}

/// Strip the 0x03 Envelope-v3 framing prefix from an SDK response.
pub fn strip_envelope_prefix(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    match data.first() {
        Some(0x03) => Ok(data[1..].to_vec()),
        _ => Ok(data.to_vec()),
    }
}

/// Encode a proto message into an `ArgPack(codec=PROTO)` and return the wire bytes.
pub fn make_arg_pack<T: Message>(msg: &T) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    msg.encode(&mut body)
        .map_err(|e| anyhow!("proto encode: {e}"))?;

    let arg_pack = pb::ArgPack {
        schema_hash: None,
        codec: pb::Codec::Proto as i32,
        body,
    };
    let mut out = Vec::new();
    arg_pack
        .encode(&mut out)
        .map_err(|e| anyhow!("encode ArgPack: {e}"))?;
    Ok(out)
}

// ── Proto type re-exports for route handlers ──────────────────────────────────
pub use pb::{ContactManualAddRequest, InboxRequest, OnlineTransferSmartRequest};
