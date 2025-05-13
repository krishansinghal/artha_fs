use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub blockchain: BlockchainConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub bootstrap_nodes: Vec<String>,
    pub max_peers: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub threshold: f64,
    pub min_votes: usize,
    pub block_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockchainConfig {
    pub difficulty: u64,
    pub max_transactions_per_block: usize,
    pub genesis_block_reward: f64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                listen_addr: "/ip4/0.0.0.0/tcp/8080".to_string(),
                bootstrap_nodes: vec![],
                max_peers: 50,
            },
            consensus: ConsensusConfig {
                threshold: 0.7,
                min_votes: 3,
                block_time: 10,
            },
            blockchain: BlockchainConfig {
                difficulty: 4,
                max_transactions_per_block: 1000,
                genesis_block_reward: 100.0,
            },
        }
    }
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = std::fs::read_to_string(path)?;
        let config: NodeConfig = serde_json::from_str(&config_str)?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let config_str = serde_json::to_string_pretty(self)?;
        std::fs::write(path, config_str)?;
        Ok(())
    }
} 