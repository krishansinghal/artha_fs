use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::types::transaction::TransactionError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorKey {
    pub address: String,
    pub key_pair: KeyPair,
    pub voting_power: u64,
    pub is_active: bool,
    pub last_rotation: DateTime<Utc>,
    pub next_rotation: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingCondition {
    pub validator_address: String,
    pub evidence_type: SlashingEvidenceType,
    pub timestamp: DateTime<Utc>,
    pub block_height: u64,
    pub evidence_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingEvidenceType {
    DoubleSigning,
    InvalidBlock,
    InvalidVote,
    UnauthorizedProposal,
}

pub struct SecurityManager {
    validator_keys: Arc<RwLock<HashMap<String, ValidatorKey>>>,
    slashing_conditions: Arc<RwLock<Vec<SlashingCondition>>>,
    key_rotation_period: chrono::Duration,
}

impl SecurityManager {
    pub fn new(key_rotation_period_days: i64) -> Self {
        Self {
            validator_keys: Arc::new(RwLock::new(HashMap::new())),
            slashing_conditions: Arc::new(RwLock::new(Vec::new())),
            key_rotation_period: chrono::Duration::days(key_rotation_period_days),
        }
    }

    pub async fn generate_key_pair(&self) -> Result<KeyPair, String> {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        
        Ok(KeyPair {
            public_key: verifying_key.to_bytes().to_vec(),
            private_key: signing_key.to_bytes().to_vec(),
            created_at: Utc::now(),
            last_used: Utc::now(),
        })
    }

    pub async fn add_validator_key(&self, address: String, voting_power: u64) -> Result<(), String> {
        let key_pair = self.generate_key_pair().await?;
        let now = Utc::now();
        
        let validator_key = ValidatorKey {
            address: address.clone(),
            key_pair,
            voting_power,
            is_active: true,
            last_rotation: now,
            next_rotation: now + self.key_rotation_period,
        };

        let mut keys = self.validator_keys.write().await;
        keys.insert(address, validator_key);
        Ok(())
    }

    pub async fn rotate_validator_key(&self, address: &str) -> Result<(), String> {
        let mut keys = self.validator_keys.write().await;
        if let Some(validator) = keys.get_mut(address) {
            let new_key_pair = self.generate_key_pair().await?;
            let now = Utc::now();
            
            validator.key_pair = new_key_pair;
            validator.last_rotation = now;
            validator.next_rotation = now + self.key_rotation_period;
            Ok(())
        } else {
            Err("Validator not found".to_string())
        }
    }

    pub async fn sign_message(&self, address: &str, message: &[u8]) -> Result<Signature, TransactionError> {
        let keys = self.validator_keys.read().await;
        if let Some(validator) = keys.get(address) {
            let private_key: [u8; 32] = validator.key_pair.private_key.as_slice()
                .try_into()
                .map_err(|_| TransactionError::InvalidSignature("Invalid private key length".to_string()))?;
    
            // FIX: No need for map_err here, as `from_bytes` does not return Result
            let signing_key = SigningKey::from_bytes(&private_key);
    
            Ok(signing_key.sign(message))
        } else {
            Err(TransactionError::SecurityError("Validator not found".to_string()))
        }
    }
    

    pub async fn verify_signature(&self, address: &str, message: &[u8], signature: &Signature) -> Result<bool, TransactionError> {
        let keys = self.validator_keys.read().await;
        if let Some(validator) = keys.get(address) {
            let public_key: [u8; 32] = validator.key_pair.public_key.as_slice()
                .try_into()
                .map_err(|_| TransactionError::InvalidSignature("Invalid public key length".to_string()))?;
            
            let verifying_key = VerifyingKey::from_bytes(&public_key)
                .map_err(|e| TransactionError::InvalidSignature(e.to_string()))?;
            
            Ok(verifying_key.verify(message, signature).is_ok())
        } else {
            Err(TransactionError::SecurityError("Validator not found".to_string()))
        }
    }

    pub async fn add_slashing_condition(&self, condition: SlashingCondition) -> Result<(), String> {
        let mut conditions = self.slashing_conditions.write().await;
        conditions.push(condition);
        Ok(())
    }

    pub async fn get_slashing_conditions(&self, address: &str) -> Vec<SlashingCondition> {
        let conditions = self.slashing_conditions.read().await;
        conditions.iter()
            .filter(|c| c.validator_address == address)
            .cloned()
            .collect()
    }

    pub async fn check_key_rotation(&self) -> Vec<String> {
        let mut keys = self.validator_keys.write().await;
        let now = Utc::now();
        let mut needs_rotation = Vec::new();

        for (address, validator) in keys.iter_mut() {
            if validator.next_rotation <= now {
                needs_rotation.push(address.clone());
                validator.is_active = false;
            }
        }

        needs_rotation
    }

    pub async fn is_validator_active(&self, address: &str) -> Result<bool, String> {
        let keys = self.validator_keys.read().await;
        Ok(keys.get(address)
            .map(|k| k.is_active)
            .unwrap_or(false))
    }
}

// Cryptographic utility functions
pub fn hash_message(message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}

pub fn verify_merkle_proof(root: &[u8], leaf: &[u8], proof: &[Vec<u8>]) -> bool {
    let mut current = hash_message(leaf);
    
    for sibling in proof {
        if current < *sibling {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            hasher.update(sibling);
            current = hasher.finalize().to_vec();
        } else {
            let mut hasher = Sha256::new();
            hasher.update(sibling);
            hasher.update(&current);
            current = hasher.finalize().to_vec();
        }
    }
    
    current == root
} 