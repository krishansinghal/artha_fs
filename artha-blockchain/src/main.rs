mod consensus;
mod network;
mod types;
mod security;

use std::sync::Arc;
use tokio;
use log::info;
use ed25519_dalek::SigningKey as Keypair;

use crate::network::{NetworkManager, NetworkConfig, RateLimit};
use crate::consensus::{ConsensusEngine, ValidatorSet, ConsensusNetworkManager};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();
    info!("Starting Artha Blockchain node...");


    // Generate or load validator key
    let validator_keypair = Keypair::generate(&mut rand::thread_rng());
    let validator_pubkey = validator_keypair.verifying_key();

    // Initialize network configuration
    let network_config = NetworkConfig {
        max_peers: 100,
        min_peers: 10,
        peer_discovery_interval: tokio::time::Duration::from_secs(300),
        peer_cleanup_interval: tokio::time::Duration::from_secs(60),
        message_timeout: tokio::time::Duration::from_secs(30),
        rate_limit: RateLimit {
            messages_per_second: 100,
            bytes_per_second: 1024 * 1024, // 1 MB/s
            burst_size: 1000,
        },
        max_message_size: 1024 * 1024, // 1 MB
        network_id: "artha-mainnet".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // Initialize network manager
    let network_manager = Arc::new(NetworkManager::new(network_config));

    // Initialize consensus network manager
    let consensus_network = Arc::new(ConsensusNetworkManager::new());

    // Initialize validator set with initial validator
    let mut validator_set = ValidatorSet::new(vec![validator_pubkey]);
    validator_set.proposer = Some(validator_set.validators[0].clone());

    // Initialize consensus engine with consensus network manager
    let consensus_engine = ConsensusEngine::new(
        validator_pubkey,
        validator_set,
        consensus_network,
        None, // Use default config
    );

    // Start network manager
    network_manager.start().await?;

    // Start consensus engine
    consensus_engine.start().await?;

    // Keep the main thread alive
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
