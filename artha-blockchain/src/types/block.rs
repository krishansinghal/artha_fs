use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use crate::types::transaction::Transaction;
use ed25519_dalek::VerifyingKey as PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub merkle_root: String,
    pub state_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_hash: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub height: u64,
    pub proposer: PublicKey,
    pub transaction_root: Vec<u8>,
    pub state_root: Vec<u8>,
    pub evidence_root: Vec<u8>,
    pub validator_hash: Vec<u8>,
    pub consensus_hash: Vec<u8>,
    pub app_hash: Vec<u8>,
}

impl Block {
    pub fn new(
        previous_hash: String,
        height: u64,
        proposer: PublicKey,
        transactions: Vec<Transaction>,
        state_root: String,
    ) -> Self {
        let header = BlockHeader {
            version: 1,
            previous_hash: previous_hash.into_bytes(),
            timestamp: Utc::now(),
            height,
            proposer,
            transaction_root: Vec::new(),
            state_root: state_root.clone().into_bytes(),
            evidence_root: Vec::new(),
            validator_hash: Vec::new(),
            consensus_hash: Vec::new(),
            app_hash: state_root.clone().into_bytes(),
        };

        let merkle_root = Self::calculate_merkle_root(&transactions);

        Self {
            header,
            transactions,
            merkle_root,
            state_root,
        }
    }

    pub fn calculate_merkle_root(transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            return String::new();
        }

        let mut hashes: Vec<String> = transactions
            .iter()
            .map(|tx| {
                let mut hasher = Sha256::new();
                hasher.update(tx.id.as_bytes());
                hex::encode(hasher.finalize())
            })
            .collect();

        while hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                if chunk.len() == 2 {
                    hasher.update(chunk[0].as_bytes());
                    hasher.update(chunk[1].as_bytes());
                } else {
                    hasher.update(chunk[0].as_bytes());
                    hasher.update(chunk[0].as_bytes());
                }
                new_hashes.push(hex::encode(hasher.finalize()));
            }
            hashes = new_hashes;
        }

        hashes[0].clone()
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        let header_bytes = serde_json::to_vec(&self.header).unwrap();
        hasher.update(&header_bytes);
        hex::encode(hasher.finalize())
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate block structure
        if self.transactions.is_empty() {
            return Err("Block must contain at least one transaction".to_string());
        }

        // Validate merkle root
        let calculated_root = Self::calculate_merkle_root(&self.transactions);
        if calculated_root != self.merkle_root {
            return Err("Invalid merkle root".to_string());
        }

        // Validate timestamp
        let now = Utc::now();
        if self.header.timestamp > now {
            return Err("Block timestamp is in the future".to_string());
        }

        Ok(())
    }
}

impl BlockHeader {
    pub fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.previous_hash);
        hasher.update(self.timestamp.timestamp().to_le_bytes());
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.proposer.to_bytes());
        hasher.update(&self.transaction_root);
        hasher.update(&self.state_root);
        hasher.update(&self.evidence_root);
        hasher.update(&self.validator_hash);
        hasher.update(&self.consensus_hash);
        hasher.update(&self.app_hash);
        hasher.finalize().to_vec()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub block_height: u64,
    pub state_changes: HashMap<String, StateChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub key: String,
    pub value: String,
}

impl StateTransition {
    pub fn new(block_height: u64) -> Self {
        Self {
            block_height,
            state_changes: HashMap::new(),
        }
    }

    pub fn add_change(&mut self, key: String, value: String) {
        self.state_changes.insert(key.clone(), StateChange {
            key,
            value,
        });
    }

    pub fn calculate_state_root(&self) -> String {
        let mut hasher = Sha256::new();
        let mut keys: Vec<_> = self.state_changes.keys().collect();
        keys.sort();

        for key in keys {
            if let Some(change) = self.state_changes.get(key) {
                hasher.update(key.as_bytes());
                hasher.update(change.value.as_bytes());
            }
        }

        hex::encode(hasher.finalize())
    }
} 