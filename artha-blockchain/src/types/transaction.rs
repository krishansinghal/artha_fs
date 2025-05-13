use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use ed25519_dalek::Signature;
use ed25519_dalek::SignatureError;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use crate::security::{SecurityManager};
use std::sync::Arc;
use std::convert::TryFrom;

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionError {
    InvalidSignature(String),
    InvalidNonce(String),
    ValidationError(String),
    SecurityError(String),
    SerializationError(String),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            TransactionError::InvalidNonce(msg) => write!(f, "Invalid nonce: {}", msg),
            TransactionError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            TransactionError::SecurityError(msg) => write!(f, "Security error: {}", msg),
            TransactionError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl Error for TransactionError {}

impl From<SignatureError> for TransactionError {
    fn from(err: SignatureError) -> Self {
        TransactionError::InvalidSignature(err.to_string())
    }
}

impl From<TransactionError> for String {
    fn from(err: TransactionError) -> Self {
        err.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub timestamp: DateTime<Utc>,
    pub nonce: u64,
    pub signature: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub chain_id: u64,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub gas_used: u64,
    pub block_number: u64,
    pub block_hash: String,
    pub logs: Vec<TransactionLog>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
    Reverted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTransactionRequest {
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub data: Option<Vec<u8>>,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub chain_id: u64,
}

impl Transaction {
    pub fn new(
        sender: String,
        recipient: String,
        amount: u64,
        nonce: u64,
        gas_limit: u64,
        gas_price: u64,
        chain_id: u64,
    ) -> Self {
        Self {
            id: String::new(),
            sender,
            recipient,
            amount,
            timestamp: Utc::now(),
            nonce,
            signature: None,
            data: None,
            gas_limit,
            gas_price,
            chain_id,
            version: 1,
        }
    }

    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        let tx_data = serde_json::to_vec(&self).unwrap();
        hasher.update(&tx_data);
        hex::encode(hasher.finalize())
    }

    pub async fn sign(&mut self, security_manager: &SecurityManager) -> Result<(), TransactionError> {
        let message = self.to_bytes()
            .map_err(|e| TransactionError::SerializationError(e.to_string()))?;
        
        let signature = security_manager.sign_message(&self.sender, &message)
            .await
            .map_err(|e| TransactionError::SecurityError(e.to_string()))?;
        
        self.signature = Some(signature.to_bytes().to_vec());
        Ok(())
    }

    pub async fn verify(&self, security_manager: &SecurityManager) -> Result<bool, TransactionError> {
        let signature = match &self.signature {
            Some(sig) => {
                if sig.len() != 64 {
                    return Err(TransactionError::InvalidSignature("Invalid signature length".to_string()));
                }

                let sig_array: [u8; 64] = sig
                    .clone()
                    .try_into()
                    .map_err(|_| TransactionError::InvalidSignature("Failed to convert signature to fixed array".to_string()))?;

                Signature::try_from(&sig_array[..])
                    .map_err(|e| TransactionError::InvalidSignature(e.to_string()))?
            }
            None => return Ok(false),
        };
    
        let message = self.to_bytes()
            .map_err(|e| TransactionError::SerializationError(e.to_string()))?;
    
        security_manager
            .verify_signature(&self.sender, &message, &signature)
            .await
            .map_err(|e| TransactionError::SecurityError(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        // Create a deterministic representation of the transaction
        let mut data = Vec::new();
        data.extend_from_slice(self.sender.as_bytes());
        data.extend_from_slice(self.recipient.as_bytes());
        data.extend_from_slice(&self.amount.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.chain_id.to_le_bytes());
        data.extend_from_slice(&self.version.to_le_bytes());
        if let Some(ref tx_data) = self.data {
            data.extend_from_slice(tx_data);
        }
        Ok(data)
    }

    pub async fn validate(&self, security_manager: &SecurityManager) -> Result<(), TransactionError> {
        // Basic validation
        if self.amount == 0 {
            return Err(TransactionError::ValidationError("Transaction amount cannot be zero".to_string()));
        }

        if self.gas_limit == 0 {
            return Err(TransactionError::ValidationError("Gas limit cannot be zero".to_string()));
        }

        if self.gas_price == 0 {
            return Err(TransactionError::ValidationError("Gas price cannot be zero".to_string()));
        }

        // Check if transaction is expired (e.g., older than 24 hours)
        let now = Utc::now();
        if (now - self.timestamp).num_hours() > 24 {
            return Err(TransactionError::ValidationError("Transaction is expired".to_string()));
        }

        // Verify signature
        if !self.verify(security_manager).await? {
            return Err(TransactionError::InvalidSignature("Invalid transaction signature".to_string()));
        }

        Ok(())
    }

    pub fn check_replay_attack(&self, last_nonce: u64) -> Result<(), TransactionError> {
        if self.nonce <= last_nonce {
            return Err(TransactionError::InvalidNonce("Transaction nonce is too low (possible replay attack)".to_string()));
        }
        Ok(())
    }
}

pub struct TransactionPool {
    transactions: HashMap<String, Transaction>,
    nonce_tracker: HashMap<String, u64>, // address -> last nonce
    security_manager: Arc<SecurityManager>,
}

impl TransactionPool {
    pub fn new(security_manager: Arc<SecurityManager>) -> Self {
        Self {
            transactions: HashMap::new(),
            nonce_tracker: HashMap::new(),
            security_manager,
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), TransactionError> {
        // Check for replay attacks
        let last_nonce = self.nonce_tracker.get(&transaction.sender)
            .copied()
            .unwrap_or(0);
        transaction.check_replay_attack(last_nonce)?;

        // Update nonce tracker
        self.nonce_tracker.insert(transaction.sender.clone(), transaction.nonce);

        // Add transaction to pool
        self.transactions.insert(transaction.id.clone(), transaction);
        Ok(())
    }

    pub fn get_transaction(&self, id: &str) -> Option<&Transaction> {
        self.transactions.get(id)
    }

    pub fn get_all_transactions(&self) -> Vec<&Transaction> {
        self.transactions.values().collect()
    }

    pub fn remove_transaction(&mut self, id: &str) {
        if let Some(tx) = self.transactions.remove(id) {
            // Update nonce tracker if this was the latest transaction
            if let Some(last_nonce) = self.nonce_tracker.get(&tx.sender) {
                if *last_nonce == tx.nonce {
                    // Find the next highest nonce for this sender
                    let next_nonce = self.transactions.values()
                        .filter(|t| t.sender == tx.sender)
                        .map(|t| t.nonce)
                        .max()
                        .unwrap_or(0);
                    self.nonce_tracker.insert(tx.sender, next_nonce);
                }
            }
        }
    }

    pub fn get_sender_nonce(&self, address: &str) -> u64 {
        self.nonce_tracker.get(address).copied().unwrap_or(0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionMetrics {
    pub transaction_id: String,
    pub block_time: f64,
    pub finality_time: f64,
    pub transaction_time: f64,
    pub block_number: u64,
    pub confirmation_count: u32,
    pub gas_used: u64,
    pub effective_gas_price: u64,
}

// Implement Default for TransactionMetrics
impl Default for TransactionMetrics {
    fn default() -> Self {
        Self {
            transaction_id: String::new(),
            block_time: 0.0,
            finality_time: 0.0,
            transaction_time: 0.0,
            block_number: 0,
            confirmation_count: 0,
            gas_used: 0,
            effective_gas_price: 0,
        }
    }
}

// Implement PartialEq for TransactionMetrics
impl PartialEq for TransactionMetrics {
    fn eq(&self, other: &Self) -> bool {
        self.transaction_id == other.transaction_id
            && self.block_time == other.block_time
            && self.finality_time == other.finality_time
            && self.transaction_time == other.transaction_time
            && self.block_number == other.block_number
            && self.confirmation_count == other.confirmation_count
            && self.gas_used == other.gas_used
            && self.effective_gas_price == other.effective_gas_price
    }
}

// Implement Eq for TransactionMetrics
impl Eq for TransactionMetrics {}

// Add Default implementation for CreateTransactionRequest
impl Default for CreateTransactionRequest {
    fn default() -> Self {
        Self {
            sender: String::new(),
            recipient: String::new(),
            amount: 0,
            data: None,
            gas_limit: 0,
            gas_price: 0,
            chain_id: 0,
        }
    }
} 