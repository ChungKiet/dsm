// SPDX-License-Identifier: MIT OR Apache-2.0
//! SDK bootstrap: mnemonic-rooted (Genesis v2/v3) wallet identity, genesis creation, and SDK init.
//!
//! ## Migration note (2026-09)
//!
//! This module used to bootstrap identity from a random on-disk "C-DBRW" hardware-binding
//! key (`load_or_create_dbrw_key`, `set_cdbrw_binding_key_for_testing`, `cdbrw_binding`).
//! `dsm_sdk` has since dropped that model entirely in favour of the canonical **mnemonic-
//! rooted Genesis v2/v3** identity: a device's whole identity (device_id, genesis hash, AK
//! signing keypair, Kyber keypair) is a deterministic function of a BIP-39 wallet seed, the
//! network id, and a fixed authority-policy hash — re-derivable at any time from the seed
//! alone, with no separate binding-key file and no C-DBRW trust gate.
//!
//! The real onboarding path this mirrors is `handle_create_genesis_v2_query`
//! (`dsm_sdk::handlers::system_routes`, `system.createGenesisV2`) together with the
//! production restart path in `dsm_sdk::init::install_full_app_router_self_config` — see
//! [`load_or_create_identity`] and [`install_full_router`] below for the exchange-node
//! equivalents (adapted because both of those are `pub(crate)` inside `dsm_sdk` and this
//! crate only gets the public surface).

use std::path::Path;

use anyhow::{anyhow, Context};
use prost::Message;
use serde::{Deserialize, Serialize};
use tracing::info;

use dsm_sdk::handlers::AppRouterImpl;
use dsm_sdk::init::SdkConfig;
use dsm_sdk::sdk::app_state::AppState;
use dsm_sdk::sdk::core_sdk::CoreSDK;
use dsm_sdk::sdk::kyber_identity::build_local_kyber_identity_binding;
use dsm_sdk::sdk::recovery_sdk::RecoverySDK;
use dsm_sdk::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};
use dsm_sdk::storage::{store_genesis_record_with_verification, GenesisRecord};
use dsm_sdk::generated as pb;

use crate::config::Config;

/// Persisted (well — re-derivable) exchange identity, reported via `GET /identity`.
///
/// This is NOT the source of truth across restarts: the source of truth is the wallet seed
/// (sealed at rest by `dsm_sdk`, or re-derivable from the local mnemonic backup file — see
/// [`ensure_wallet_seed_cached`]) plus `dsm_sdk`'s own `AppState` persistence
/// (`dsm_app_state.pb`). Genesis v3 is a deterministic function of the wallet seed, so this
/// struct is simply rebuilt fresh on every boot; it never needs its own on-disk file.
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

    // Initialise SDK routers (bilateral + unilateral + app router stubs)
    let sdk_cfg = SdkConfig {
        node_id: cfg.node.id.clone(),
        storage_endpoints: cfg.storage.endpoints.clone(),
        enable_offline: false,
    };
    dsm_sdk::init::init_dsm_sdk(&sdk_cfg)
        .map_err(|e| anyhow!("init_dsm_sdk failed: {e}"))?;
    info!("dsm_sdk initialized (node_id={})", cfg.node.id);

    // Load or create the mnemonic-rooted genesis identity.
    let identity = load_or_create_identity(cfg).await?;
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
    let public_key = dsm_sdk::sdk::app_state::AppState::get_public_key().unwrap_or_default();

    // MANDATORY on the current registration wire format: the ML-KEM-768 public key
    // recipients encapsulate against for online per-step-EK sends, plus the device-AK
    // signature binding it to (device_id, genesis_hash). Built the same way production
    // does it (`b0x_sdk`, `storage_node_sdk`) — never hand-rolled here.
    let (kyber_public_key, kyber_binding_sig) = match build_local_kyber_identity_binding() {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(
                "kyber identity binding unavailable; skipping device registration: {e}"
            );
            return;
        }
    };

    let device_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&device_id_bytes);
    let genesis_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&genesis_bytes);

    let req = dsm_sdk::generated::RegisterDeviceRequest {
        device_id: device_id_bytes,
        pubkey: public_key,
        genesis_hash: genesis_bytes,
        kyber_public_key,
        kyber_binding_sig,
    };
    let mut body = Vec::new();
    if req.encode(&mut body).is_err() {
        return;
    }

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
                    let resp =
                        dsm_sdk::generated::RegisterDeviceResponse::decode(bytes.as_ref()).ok()?;
                    Some(dsm_sdk::util::text_id::encode_base32_crockford(&resp.token))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

// ── Wallet-seed helpers ──────────────────────────────────────────────────────

/// Ensure the BIP-39 wallet seed is cached in-process (unlocking, or creating, this
/// exchange node's identity), and return it.
///
/// A server has no human present at boot to type a mnemonic, so unlike the mobile wallet
/// this has to bootstrap unattended. Order of preference:
///
///  1. **Fast path**: [`RecoverySDK::load_and_cache_wallet_seed`] restores the seed from the
///     sealed-at-rest blob `dsm_sdk` already keeps in its SQLite DB (sealed via
///     `dsm_sdk::sdk::seed_vault` — a software XChaCha20-Poly1305 box on a non-Android host,
///     the same mechanism a phone restart uses without re-prompting for the mnemonic).
///  2. **Local mnemonic backup**: if that sealed blob is missing (e.g. `data_dir`'s SQLite
///     file was wiped/rotated independently of the mnemonic backup), read the plaintext
///     mnemonic this function persisted on first boot and re-derive+re-cache from it (which
///     also reseals the blob for next time).
///  3. **Genuinely first boot**: generate a fresh mnemonic, cache+seal it, and ALSO persist
///     the plaintext mnemonic to `cfg.identity.mnemonic_path`. This is a deliberate departure
///     from the phone model (which never persists the mnemonic, only the sealed seed) — a
///     server has no separate secure paper-backup step, and losing both the sealed blob and
///     the mnemonic would strand real customer funds. The mnemonic file is therefore this
///     process's disaster-recovery backup; treat its directory with the same care as the old
///     `dbrw.key` it replaces (owner-only permissions, not world-readable, not committed).
fn ensure_wallet_seed_cached(cfg: &Config) -> anyhow::Result<Vec<u8>> {
    if matches!(RecoverySDK::load_and_cache_wallet_seed(), Ok(true)) {
        info!("Wallet seed restored from sealed at-rest cache");
        return RecoverySDK::get_cached_wallet_seed()
            .ok_or_else(|| anyhow!("wallet seed cache unexpectedly empty after sealed load"));
    }

    let path = &cfg.identity.mnemonic_path;
    if Path::new(path).exists() {
        let mnemonic = std::fs::read_to_string(path)
            .with_context(|| format!("reading mnemonic backup from {path}"))?;
        RecoverySDK::derive_and_cache_key(mnemonic.trim())
            .map_err(|e| anyhow!("derive_and_cache_key from persisted mnemonic failed: {e:?}"))?;
        info!("Wallet seed re-derived from persisted mnemonic backup at {path}");
    } else {
        info!("No existing identity — generating a new mnemonic-rooted wallet identity");
        let mnemonic = RecoverySDK::generate_mnemonic()
            .map_err(|e| anyhow!("generate_mnemonic failed: {e:?}"))?;
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dirs for {path}"))?;
        }
        std::fs::write(path, &mnemonic).with_context(|| format!("writing mnemonic to {path}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perm = meta.permissions();
                perm.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perm);
            }
        }
        RecoverySDK::derive_and_cache_key(&mnemonic)
            .map_err(|e| anyhow!("derive_and_cache_key for new mnemonic failed: {e:?}"))?;
        info!("New mnemonic generated and persisted to {path}");
    }

    RecoverySDK::get_cached_wallet_seed()
        .ok_or_else(|| anyhow!("wallet seed cache unexpectedly empty after derive_and_cache_key"))
}

// ── Identity helpers ─────────────────────────────────────────────────────────

/// Bring up (or re-derive) this exchange node's identity and install it everywhere `dsm_sdk`
/// expects it to live: `AppState`, the SDK context, the durable device-head cache, and the
/// full `AppRouterImpl`.
///
/// Genesis v3 is a pure function of `(wallet_seed, network_id, wallet_index, device_slot,
/// genesis_version, authority_policy_hash)`, so re-running it on every boot with the SAME
/// wallet seed reproduces the identical `(device_id, genesis_hash, AK keypair)` every time —
/// there is no "first boot vs restart" branch to get wrong here, and every downstream install
/// step below (`install_v2_genesis`, `store_genesis_record_with_verification`,
/// `AppState::set_identity_info`) is documented idempotent / safe to repeat.
async fn load_or_create_identity(cfg: &Config) -> anyhow::Result<IdentityState> {
    let wallet_seed = ensure_wallet_seed_cached(cfg)?;

    let aph = dsm_sdk::dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let outcome = dsm_sdk::dsm::core::identity::genesis::create_genesis_v3_self_attested(
        &wallet_seed,
        cfg.node.network.as_bytes(),
        0, // wallet_index
        0, // device_slot (primary device)
        3, // genesis_version
        &aph,
    )
    .map_err(|e| anyhow!("genesis v3 derivation failed: {e:?}"))?;

    let devid = outcome
        .state
        .device_id
        .ok_or_else(|| anyhow!("v3 genesis missing device_id"))?;
    let g = outcome.state.hash;
    let ak_pk = outcome.state.signing_key.public_key.clone();
    let smt_root = outcome.state.merkle_root.unwrap_or(g);

    // Install the genesis as the canonical device-head root. `install_v2_genesis` /
    // `write_genesis_device_head` PRESERVE an already-advanced head if one exists in the
    // durable `bcr_device_heads` cache (they only fill in the genesis digest/legacy-root
    // when missing) — so on a restart this call is a safe no-op re-assertion, never a
    // rollback of real balances/history. On a genuinely first boot it seeds a fresh
    // zero-value head.
    let device_info = dsm_sdk::dsm::types::state_types::DeviceInfo::new(devid, ak_pk.clone());
    let core = CoreSDK::new_with_device(device_info)
        .map_err(|e| anyhow!("CoreSDK::new_with_device failed: {e:?}"))?;
    core.install_v2_genesis(&outcome.state)
        .map_err(|e| anyhow!("install_v2_genesis failed: {e:?}"))?;

    // Persist the public GenesisRecord (INSERT OR REPLACE — safe every boot) and ensure a
    // wallet_state row exists so wallet.sendSmart can resolve local_genesis_hash().
    let device_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&devid);
    let genesis_id_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&g);
    let nonce_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&outcome.genesis_nonce);
    let record = GenesisRecord {
        genesis_id: genesis_id_b32.clone(),
        device_id: device_id_b32.clone(),
        mpc_proof: String::new(),
        // Legacy C-DBRW binding-record column; Genesis v2/v3 has no silicon binding.
        device_birth_binding: String::new(),
        merkle_root: dsm_sdk::util::text_id::encode_base32_crockford(&smt_root),
        participant_count: 0,
        progress_marker: "genesis".to_string(),
        publication_hash: genesis_id_b32,
        storage_nodes: cfg.storage.endpoints.clone(),
        entropy_hash: nonce_b32.clone(),
        protocol_version: "genesis-v3".to_string(),
        hash_chain_proof: None,
        smt_proof: None,
        verification_step: None,
        genesis_nonce: nonce_b32,
        genesis_profile: "MnemonicV3".to_string(),
        network_id: cfg.node.network.clone(),
    };
    store_genesis_record_with_verification(&record)
        .map_err(|e| anyhow!("store_genesis_record_with_verification failed: {e}"))?;
    dsm_sdk::storage::client_db::ensure_wallet_state_for_device(&device_id_b32)
        .map_err(|e| anyhow!("ensure_wallet_state_for_device failed: {e}"))?;

    // Install identity into AppState — persisted to dsm_app_state.pb, so a restart's
    // `AppState::get_has_identity()`/`get_device_id()`/etc. read it back automatically.
    AppState::set_identity_info(devid.to_vec(), ak_pk.clone(), g.to_vec(), smt_root.to_vec());
    AppState::set_has_identity(true);

    // SDK-context entropy, rooted in the wallet seed. Mirrors dsm_sdk's own
    // `derive_production_entropy` (domain "DSM/sdk-hash" over device_id||genesis||seed),
    // which is `pub(crate)` and not reachable from this crate.
    let entropy = derive_entropy(&devid, &g, &wallet_seed);
    dsm_sdk::initialize_sdk_context(devid.to_vec(), g.to_vec(), entropy)
        .map_err(|e| anyhow!("initialize_sdk_context failed: {e:?}"))?;

    // Upgrade MinimalBootstrapRouter → full AppRouterImpl.
    install_full_router(cfg).await?;

    // Best-effort registry publish so a peer's contacts.addManual can verify this genesis.
    // Non-fatal: local genesis is already durable regardless of network reachability.
    publish_genesis_to_registry(cfg, &devid, &g, &ak_pk, &smt_root, &outcome.genesis_nonce).await;

    let kyber_public_key_hex = match build_local_kyber_identity_binding() {
        Ok((pk, _sig)) => hex::encode(pk),
        Err(e) => {
            tracing::warn!("kyber identity binding unavailable at genesis time: {e}");
            String::new()
        }
    };

    info!("Genesis ready: device_id={}…", &device_id_b32[..12.min(device_id_b32.len())]);
    Ok(IdentityState {
        device_id_hex: hex::encode(devid),
        genesis_hash_hex: hex::encode(g),
        kyber_public_key_hex,
    })
}

/// Replace MinimalBootstrapRouter with the full [`AppRouterImpl`].
/// Must be called AFTER AppState has device_id + genesis_hash set.
async fn install_full_router(cfg: &Config) -> anyhow::Result<()> {
    let sdk_cfg = SdkConfig {
        node_id: cfg.node.id.clone(),
        storage_endpoints: cfg.storage.endpoints.clone(),
        enable_offline: false,
    };
    let router = std::sync::Arc::new(
        AppRouterImpl::new(sdk_cfg).map_err(|e| anyhow!("AppRouterImpl::new failed: {e:?}"))?,
    );
    let router_for_setup = router.clone();
    dsm_sdk::bridge::install_app_router(router)
        .map_err(|e| anyhow!("install_app_router failed: {e:?}"))?;
    info!("Full AppRouterImpl installed");

    // Mirrors `dsm_sdk::init`'s warm-swap rehydrate (`spawn_token_registry_rehydrate`):
    // without this a token policy created in a previous process (or before this restart)
    // cannot be resolved in-memory, and a device could not send/receive an asset it holds.
    // We await it synchronously here (rather than spawning) because dsm-exchange-node wants
    // full readiness BEFORE serving HTTP traffic — unlike the mobile app, nothing here needs
    // wallet-creation UI to stay unblocked while it runs.
    router_for_setup.install_policy_resolver();
    router_for_setup.rehydrate_token_registry().await;
    router_for_setup.republish_owned_policies().await;
    info!("Policy resolver installed; token registry rehydrated");
    Ok(())
}

/// Publish this device's genesis to the storage fleet's registry so a peer's
/// `contacts.addManual` can verify it. Best-effort / non-fatal: a device's local genesis is
/// durable independent of whether the network happens to be reachable right now.
async fn publish_genesis_to_registry(
    cfg: &Config,
    device_id: &[u8; 32],
    genesis_hash: &[u8; 32],
    public_key: &[u8],
    smt_root: &[u8; 32],
    genesis_nonce: &[u8; 32],
) {
    let genesis_created = pb::GenesisCreated {
        device_id: device_id.to_vec(),
        genesis_hash: Some(pb::Hash32 {
            v: genesis_hash.to_vec(),
        }),
        public_key: public_key.to_vec(),
        smt_root: Some(pb::Hash32 {
            v: smt_root.to_vec(),
        }),
        device_entropy: genesis_nonce.to_vec(),
        session_id: String::new(),
        threshold: 0,
        storage_nodes: cfg.storage.endpoints.clone(),
        network_id: cfg.node.network.clone(),
        locale: "en".to_string(),
    };
    let mut publish_cfg = StorageNodeConfig::new(cfg.storage.endpoints.clone());
    publish_cfg.mpc_genesis_url = None;
    match StorageNodeSDK::new(publish_cfg).await {
        Ok(sdk) => match sdk.publish_genesis_to_nodes(genesis_created).await {
            Ok(r) => info!(
                "Genesis published to {}/{} nodes",
                r.published_to_nodes,
                cfg.storage.endpoints.len()
            ),
            Err(e) => tracing::warn!("Genesis publish failed (non-fatal): {e:?}"),
        },
        Err(e) => tracing::warn!("StorageNodeSDK::new failed for genesis publish (non-fatal): {e:?}"),
    }
}

// ── Utility ──────────────────────────────────────────────────────────────────

/// Domain-separated BLAKE3 over `device_id || genesis_hash || wallet_seed` — mirrors
/// `dsm_sdk`'s internal `derive_production_entropy` (`pub(crate)`, domain "DSM/sdk-hash").
fn derive_entropy(device_id: &[u8], genesis_hash: &[u8], wallet_seed: &[u8]) -> Vec<u8> {
    let mut h = dsm_sdk::dsm::crypto::blake3::dsm_domain_hasher(
        dsm_sdk::dsm::common::domain_tags::TAG_DSM_SDK_HASH,
    );
    h.update(device_id);
    h.update(genesis_hash);
    h.update(wallet_seed);
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
