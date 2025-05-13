use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::security::SecurityManager;
use crate::types::transaction::Transaction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
    pub code_hash: Option<Vec<u8>>,
    pub storage_root: Vec<u8>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub is_contract: bool,
    pub is_frozen: bool,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Permission {
    Transfer,
    DeployContract,
    CallContract,
    Vote,
    Propose,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from_state: Vec<u8>,
    pub to_state: Vec<u8>,
    pub transaction_hash: Vec<u8>,
    pub block_number: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub validator: String,
    pub signature: Vec<u8>,
}

pub struct StateSecurityManager {
    accounts: Arc<RwLock<HashMap<String, AccountState>>>,
    state_transitions: Arc<RwLock<Vec<StateTransition>>>,
    security_manager: Arc<SecurityManager>,
    state_root: Arc<RwLock<Vec<u8>>>,
    max_state_size: usize,
    max_transitions_per_block: u32,
}

impl StateSecurityManager {
    pub fn new(security_manager: Arc<SecurityManager>) -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            state_transitions: Arc::new(RwLock::new(Vec::new())),
            security_manager,
            state_root: Arc::new(RwLock::new(vec![])),
            max_state_size: 1_000_000, // 1 million accounts
            max_transitions_per_block: 10_000,
        }
    }

    pub async fn apply_transaction(&self, transaction: &Transaction) -> Result<StateTransition, String> {
        // Check state size limit
        let accounts = self.accounts.read().await;
        if accounts.len() >= self.max_state_size {
            return Err("State size limit exceeded".to_string());
        }

        // Verify transaction
        transaction.validate(&self.security_manager)?;

        // Get current state
        let mut accounts = self.accounts.write().await;
        let from_state = self.calculate_state_root(&accounts).await?;

        // Apply transaction
        self.apply_transaction_to_state(&mut accounts, transaction).await?;

        // Calculate new state root
        let to_state = self.calculate_state_root(&accounts).await?;

        // Create state transition
        let transition = StateTransition {
            from_state,
            to_state,
            transaction_hash: transaction.calculate_hash().as_bytes().to_vec(),
            block_number: 0, // Will be set by block processor
            timestamp: chrono::Utc::now(),
            validator: "".to_string(), // Will be set by validator
            signature: vec![], // Will be set by validator
        };

        // Store transition
        let mut transitions = self.state_transitions.write().await;
        if transitions.len() >= self.max_transitions_per_block as usize {
            return Err("Too many state transitions in block".to_string());
        }
        transitions.push(transition.clone());

        // Update state root
        *self.state_root.write().await = to_state.clone();

        Ok(transition)
    }

    async fn apply_transaction_to_state(
        &self,
        accounts: &mut HashMap<String, AccountState>,
        transaction: &Transaction,
    ) -> Result<(), String> {
        // Get or create sender account
        let sender_account = accounts.entry(transaction.sender.clone())
            .or_insert_with(|| AccountState {
                balance: 0,
                nonce: 0,
                code_hash: None,
                storage_root: vec![],
                last_updated: chrono::Utc::now(),
                is_contract: false,
                is_frozen: false,
                permissions: vec![Permission::Transfer],
            });

        // Check account permissions
        if !self.has_permission(sender_account, &Permission::Transfer) {
            return Err("Account does not have transfer permission".to_string());
        }

        // Check if account is frozen
        if sender_account.is_frozen {
            return Err("Account is frozen".to_string());
        }

        // Check balance
        let total_cost = transaction.amount + transaction.gas_limit * transaction.gas_price;
        if sender_account.balance < total_cost {
            return Err("Insufficient balance".to_string());
        }

        // Check nonce
        if transaction.nonce != sender_account.nonce + 1 {
            return Err("Invalid nonce".to_string());
        }

        // Get or create recipient account
        let recipient_account = accounts.entry(transaction.recipient.clone())
            .or_insert_with(|| AccountState {
                balance: 0,
                nonce: 0,
                code_hash: None,
                storage_root: vec![],
                last_updated: chrono::Utc::now(),
                is_contract: false,
                is_frozen: false,
                permissions: vec![Permission::Transfer],
            });

        // Apply transaction
        sender_account.balance -= total_cost;
        sender_account.nonce += 1;
        sender_account.last_updated = chrono::Utc::now();

        recipient_account.balance += transaction.amount;
        recipient_account.last_updated = chrono::Utc::now();

        Ok(())
    }

    pub async fn calculate_state_root(&self, accounts: &HashMap<String, AccountState>) -> Result<Vec<u8>, String> {
        let mut hasher = Sha256::new();
        
        // Sort accounts by address for deterministic hashing
        let mut sorted_accounts: Vec<_> = accounts.iter().collect();
        sorted_accounts.sort_by_key(|(addr, _)| addr.clone());

        for (address, account) in sorted_accounts {
            hasher.update(address.as_bytes());
            hasher.update(&account.balance.to_le_bytes());
            hasher.update(&account.nonce.to_le_bytes());
            if let Some(ref code_hash) = account.code_hash {
                hasher.update(code_hash);
            }
            hasher.update(&account.storage_root);
        }

        Ok(hasher.finalize().to_vec())
    }

    pub async fn verify_state_transition(&self, transition: &StateTransition) -> Result<bool, String> {
        // Verify transition signature
        let message = serde_json::to_vec(&transition)
            .map_err(|_| "Failed to serialize transition")?;
        let signature = ed25519_dalek::Signature::from_bytes(&transition.signature)
            .map_err(|_| "Invalid signature format")?;

        self.security_manager.verify_signature(
            &transition.validator,
            &message,
            &signature
        ).await
    }

    pub async fn get_account_state(&self, address: &str) -> Option<AccountState> {
        self.accounts.read().await.get(address).cloned()
    }

    pub async fn freeze_account(&self, address: &str) -> Result<(), String> {
        let mut accounts = self.accounts.write().await;
        if let Some(account) = accounts.get_mut(address) {
            account.is_frozen = true;
            account.last_updated = chrono::Utc::now();
            Ok(())
        } else {
            Err("Account not found".to_string())
        }
    }

    pub async fn unfreeze_account(&self, address: &str) -> Result<(), String> {
        let mut accounts = self.accounts.write().await;
        if let Some(account) = accounts.get_mut(address) {
            account.is_frozen = false;
            account.last_updated = chrono::Utc::now();
            Ok(())
        } else {
            Err("Account not found".to_string())
        }
    }

    pub async fn add_permission(&self, address: &str, permission: Permission) -> Result<(), String> {
        let mut accounts = self.accounts.write().await;
        if let Some(account) = accounts.get_mut(address) {
            if !account.permissions.contains(&permission) {
                account.permissions.push(permission);
                account.last_updated = chrono::Utc::now();
            }
            Ok(())
        } else {
            Err("Account not found".to_string())
        }
    }

    pub async fn remove_permission(&self, address: &str, permission: Permission) -> Result<(), String> {
        let mut accounts = self.accounts.write().await;
        if let Some(account) = accounts.get_mut(address) {
            account.permissions.retain(|p| p != &permission);
            account.last_updated = chrono::Utc::now();
            Ok(())
        } else {
            Err("Account not found".to_string())
        }
    }

    fn has_permission(&self, account: &AccountState, permission: &Permission) -> bool {
        account.permissions.contains(permission) || account.permissions.contains(&Permission::Admin)
    }

    pub async fn get_state_root(&self) -> Vec<u8> {
        self.state_root.read().await.clone()
    }

    pub async fn verify_state_proof(&self, address: &str, proof: &[Vec<u8>]) -> Result<bool, String> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(address) {
            let account_bytes = serde_json::to_vec(account)
                .map_err(|_| "Failed to serialize account")?;
            let root = self.state_root.read().await;
            crate::security::verify_merkle_proof(&root, &account_bytes, proof)
        } else {
            Ok(false)
        }
    }
} 