use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::convert::TryFrom;
use tokio::sync::{Mutex, RwLock};
use chrono::{Utc};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, VerifyingKey as PublicKey, Verifier};
use sha2::{Sha256, Digest};
use hex;

use crate::types::block::{Block, BlockHeader};
use crate::security::{SecurityManager, SlashingCondition, SlashingEvidenceType};
use crate::types::transaction::{Transaction, TransactionError};
use crate::consensus::{ConsensusError, Commit, Vote, Proposal, Evidence, ConsensusEngine, EvidenceType};
use std::convert::TryInto;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoundStep {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

impl Default for RoundStep {
    fn default() -> Self {
        RoundStep::Propose
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    pub step: RoundStep,
    pub height: u64,
    pub round: u32,
    pub last_committed_height: u64,
    pub last_committed_hash: Option<Vec<u8>>,
    pub proposer: Option<PublicKey>,
}

impl Default for ConsensusState {
    fn default() -> Self {
        ConsensusState {
            step: RoundStep::Propose,
            height: 0,
            round: 0,
            last_committed_height: 0,
            last_committed_hash: None,
            proposer: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub height: u64,
    pub round: u32,
    pub sender: PublicKey,
    pub signature: Vec<u8>,
    pub block_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    NewRound { metadata: MessageMetadata },
    Proposal { metadata: MessageMetadata, block: Block, proposer: PublicKey },
    Vote { metadata: MessageMetadata, block_hash: Vec<u8>, voter: PublicKey },
    Commit { metadata: MessageMetadata, votes: Vec<Vote> },
    Evidence { metadata: MessageMetadata, block_hash: Vec<u8>, voter: PublicKey },
}

impl ConsensusMessage {
    pub fn get_metadata(&self) -> &MessageMetadata {
        match self {
            ConsensusMessage::NewRound { metadata } => metadata,
            ConsensusMessage::Proposal { metadata, .. } => metadata,
            ConsensusMessage::Vote { metadata, .. } => metadata,
            ConsensusMessage::Commit { metadata, .. } => metadata,
            ConsensusMessage::Evidence { metadata, .. } => metadata,
        }
    }

    pub fn get_height(&self) -> u64 {
        self.get_metadata().height
    }

    pub fn get_round(&self) -> u32 {
        self.get_metadata().round
    }

    pub fn get_sender(&self) -> &PublicKey {
        &self.get_metadata().sender
    }

    pub fn get_signature(&self) -> &[u8] {
        &self.get_metadata().signature
    }

    pub async fn handle(&self, engine: &ConsensusEngine) -> Result<(), ConsensusError> {
        match self {
            ConsensusMessage::Proposal { metadata, block, proposer } => {
                engine.handle_proposal(Proposal {
                    proposer: *proposer,
                    height: metadata.height,
                    round: metadata.round,
                    block: block.clone(),
                    timestamp: Utc::now(),
                    signature: metadata.signature.clone(),
                }).await?;
            }
            ConsensusMessage::Vote { metadata, block_hash, voter } => {
                engine.handle_vote(Vote {
                    validator: *voter,
                    height: metadata.height,
                    round: metadata.round,
                    block_hash: block_hash.to_vec(),
                    timestamp: Utc::now(),
                    signature: metadata.signature.clone(),
                }).await?;
            }
            ConsensusMessage::Evidence { metadata, block_hash, voter } => {
                engine.handle_evidence(Evidence {
                    evidence_type: EvidenceType::InvalidVote,
                    validator: *voter,
                    height: metadata.height,
                    round: metadata.round,
                    timestamp: Utc::now(),
                    signature: metadata.signature.clone(),
                }).await?;
            }
            ConsensusMessage::NewRound { metadata } => {
                engine.handle_new_round(metadata.height, metadata.round).await?;
            }
            ConsensusMessage::Commit { metadata, votes } => {
                engine.handle_commit(Commit {
                    height: metadata.height,
                    round: metadata.round,
                    block_hash: metadata.block_hash.clone().unwrap_or_default(),
                    votes: votes.clone(),
                    timestamp: Utc::now(),
                    signature: metadata.signature.clone(),
                }).await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Proposal,
    Vote,
    Evidence,
    NewRound,
    Commit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: String,
    pub voting_power: u64,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundState {
    pub height: u64,
    pub round: u32,
    pub step: ConsensusState,
    pub proposal: Option<Proposal>,
    pub votes: HashMap<String, HashSet<String>>, // block_hash -> set of voter addresses
    pub last_commit: Option<Commit>,
}

pub struct TendermintConsensus {
    validators: Arc<RwLock<Vec<Validator>>>,
    state: Arc<Mutex<ConsensusState>>,
    current_round: Arc<Mutex<u64>>,
    current_height: Arc<Mutex<u64>>,
    locked_block: Arc<Mutex<Option<Block>>>,
    valid_round: Arc<Mutex<Option<u64>>>,
    votes: Arc<RwLock<HashMap<String, HashMap<String, HashSet<String>>>>>, // height -> round -> set of voter addresses
    threshold: u64,
    security_manager: Arc<SecurityManager>,
    evidence_pool: Arc<RwLock<Vec<SlashingCondition>>>,
    round_state: Arc<RwLock<RoundState>>,
    validator_key: PublicKey,
}

impl TendermintConsensus {
    pub fn new(validators: Vec<Validator>, threshold: u64, security_manager: Arc<SecurityManager>, validator_key: PublicKey) -> Self {
        Self {
            validators: Arc::new(RwLock::new(validators)),
            state: Arc::new(Mutex::new(ConsensusState::default())),
            current_round: Arc::new(Mutex::new(0)),
            current_height: Arc::new(Mutex::new(0)),
            locked_block: Arc::new(Mutex::new(None)),
            valid_round: Arc::new(Mutex::new(None)),
            votes: Arc::new(RwLock::new(HashMap::new())),
            threshold,
            security_manager,
            evidence_pool: Arc::new(RwLock::new(Vec::new())),
            round_state: Arc::new(RwLock::new(RoundState {
                height: 0,
                round: 0,
                step: ConsensusState::default(),
                proposal: None,
                votes: HashMap::new(),
                last_commit: None,
            })),
            validator_key,
        }
    }

    async fn verify_message(&self, message: &ConsensusMessage) -> Result<bool, TransactionError> {
        // Verify message signature
        let message_bytes = serde_json::to_vec(message)
            .map_err(|e| TransactionError::SerializationError(e.to_string()))?;
        
        let metadata = message.get_metadata();
        let sig_bytes: &[u8; 64] = metadata.signature.as_slice().try_into()
            .map_err(|_| TransactionError::InvalidSignature("Invalid signature length".to_string()))?;
    
        let signature = Signature::try_from(sig_bytes)
            .map_err(|e| TransactionError::InvalidSignature(e.to_string()))?;

        // Get validator address from public key
        let validators = self.validators.read().await;
        let validator = validators.iter()
            .find(|v| v.public_key == hex::encode(metadata.sender.to_bytes()))
            .ok_or_else(|| TransactionError::SecurityError("Unknown validator".to_string()))?;

        self.security_manager.verify_signature(&validator.address, &message_bytes, &signature)
            .await
            .map_err(|e| TransactionError::SecurityError(e.to_string()))
    }

    async fn check_double_signing(&self, message: &ConsensusMessage) -> Result<(), String> {
        let metadata = message.get_metadata();
        let votes = self.votes.read().await;
        if let Some(round_votes) = votes.get(&metadata.height.to_string()) {
            if let Some(block_votes) = round_votes.get(&metadata.round.to_string()) {
                if block_votes.contains(&hex::encode(metadata.sender.to_bytes())) {
                    // Double signing detected
                    let evidence = SlashingCondition {
                        validator_address: hex::encode(metadata.sender.to_bytes()),
                        evidence_type: SlashingEvidenceType::DoubleSigning,
                        timestamp: Utc::now(),
                        block_height: metadata.height,
                        evidence_data: serde_json::to_vec(message).unwrap(),
                    };
                    
                    self.security_manager.add_slashing_condition(evidence).await?;
                    return Err("Double signing detected".to_string());
                }
            }
        }
        Ok(())
    }

    pub async fn handle_message(&self, message: ConsensusMessage) -> Result<(), String> {
        // Verify message signature
        if !self.verify_message(&message).await? {
            return Err("Invalid message signature".to_string());
        }

        // Check for double signing
        self.check_double_signing(&message).await?;

        // Verify validator is active
        let validators = self.validators.read().await;
        let sender = message.get_sender();
        let validator = validators.iter()
            .find(|v| v.public_key == hex::encode(sender.to_bytes()))
            .ok_or("Unknown validator")?;

        // Check if validator is active
        if !self.security_manager.is_validator_active(&validator.address).await? {
            return Err("Validator is not active".to_string());
        }

        match message {
            ConsensusMessage::Proposal { metadata, block, proposer } => {
                self.handle_propose(block, metadata.round as u64, hex::encode(proposer.to_bytes())).await?;
            },
            ConsensusMessage::Vote { metadata, block_hash, voter } => {
                self.handle_prevote(
                    hex::encode(&block_hash),
                    metadata.round as u64,
                    hex::encode(voter.to_bytes())
                ).await?;
            },
            ConsensusMessage::Evidence { metadata, block_hash, voter } => {
                self.handle_precommit(
                    hex::encode(&block_hash),
                    metadata.round as u64,
                    hex::encode(voter.to_bytes())
                ).await?;
            },
            ConsensusMessage::NewRound { metadata } => {
                self.handle_new_round(metadata.height, metadata.round)
                    .await
                    .map_err(|e| e.to_string())?;
            },
            ConsensusMessage::Commit { metadata, votes } => {
                let commit = Commit {
                    height: metadata.height,
                    round: metadata.round,
                    block_hash: metadata.block_hash.unwrap_or_default(),
                    votes,
                    timestamp: Utc::now(),
                    signature: metadata.signature.clone(),
                };
                self.handle_commit(commit)
                    .await
                    .map_err(|e| e.to_string())?;
            },
        }

        Ok(())
    }

    pub async fn start_round(&self) {
        let mut round = self.current_round.lock().await;
        *round += 1;
        
        let mut state = self.state.lock().await;
        *state = ConsensusState::default();
    }

    pub async fn handle_propose(&self, block: Block, round: u64, proposer: String) -> Result<(), String> {
        let current_round = *self.current_round.lock().await;
        if round != current_round {
            return Err("Invalid round".to_string());
        }

        // Validate proposer
        let validators = self.validators.read().await;
        if !validators.iter().any(|v| v.address == proposer) {
            return Err("Invalid proposer".to_string());
        }

        // Validate block
        block.validate()?;

        // Store the proposed block
        let mut locked_block = self.locked_block.lock().await;
        *locked_block = Some(block);

        // Move to prevote state
        let mut state = self.state.lock().await;
        *state = ConsensusState {
            step: RoundStep::Prevote,
            height: state.height,
            round: state.round,
            last_committed_height: state.last_committed_height,
            last_committed_hash: state.last_committed_hash.clone(),
            proposer: Some(PublicKey::from_bytes(&hex::decode(proposer)
                .map_err(|_| "Invalid proposer public key format")?
                .try_into()
                .map_err(|_| "Invalid public key length")?)
                .map_err(|e| format!("Invalid public key: {}", e))?),
        };

        Ok(())
    }

    pub async fn handle_prevote(&self, block_hash: String, round: u64, voter: String) -> Result<(), String> {
        let current_round = *self.current_round.lock().await;
        if round != current_round {
            return Err("Invalid round".to_string());
        }

        // Validate voter
        let validators = self.validators.read().await;
        if !validators.iter().any(|v| v.address == voter) {
            return Err("Invalid voter".to_string());
        }

        // Record vote
        let mut votes = self.votes.write().await;
        let block_votes = votes.entry(block_hash).or_insert_with(HashMap::new);
        block_votes.insert(voter, HashSet::new());

        // Check if we have enough votes
        if block_votes.len() as u64 >= self.threshold {
            // Move to precommit state
            let mut state = self.state.lock().await;
            *state = ConsensusState {
                step: RoundStep::Precommit,
                height: state.height,
                round: state.round,
                last_committed_height: state.last_committed_height,
                last_committed_hash: state.last_committed_hash.clone(),
                proposer: state.proposer,
            };
        }

        Ok(())
    }

    pub async fn handle_precommit(&self, block_hash: String, round: u64, voter: String) -> Result<(), String> {
        let current_round = *self.current_round.lock().await;
        if round != current_round {
            return Err("Invalid round".to_string());
        }

        // Validate voter
        let validators = self.validators.read().await;
        if !validators.iter().any(|v| v.address == voter) {
            return Err("Invalid voter".to_string());
        }

        // Record vote
        let mut votes = self.votes.write().await;
        let block_votes = votes.entry(block_hash).or_insert_with(HashMap::new);
        block_votes.insert(voter, HashSet::new());

        // Check if we have enough votes
        if block_votes.len() as u64 >= self.threshold {
            // Move to commit state
            let mut state = self.state.lock().await;
            *state = ConsensusState {
                step: RoundStep::Commit,
                height: state.height,
                round: state.round,
                last_committed_height: state.height,
                last_committed_hash: state.last_committed_hash.clone(),
                proposer: state.proposer,
            };

            // Increment height
            let mut height = self.current_height.lock().await;
            *height += 1;

            // Reset for next round
            *self.valid_round.lock().await = None;
            *self.locked_block.lock().await = None;
            votes.clear();
        }

        Ok(())
    }

    pub async fn get_current_state(&self) -> ConsensusState {
        let state = self.state.lock().await;
        (*state).clone()
    }

    pub async fn get_current_round(&self) -> u64 {
        *self.current_round.lock().await
    }

    pub async fn get_current_height(&self) -> u64 {
        *self.current_height.lock().await
    }

    pub async fn get_validators(&self) -> Vec<Validator> {
        self.validators.read().await.clone()
    }

    pub async fn add_evidence(&self, evidence: SlashingCondition) -> Result<(), String> {
        let mut evidence_pool = self.evidence_pool.write().await;
        evidence_pool.push(evidence);
        Ok(())
    }

    pub async fn get_evidence(&self, validator_address: &str) -> Vec<SlashingCondition> {
        let evidence_pool = self.evidence_pool.read().await;
        evidence_pool.iter()
            .filter(|e| e.validator_address == validator_address)
            .cloned()
            .collect()
    }

    pub async fn process_evidence(&self) -> Result<(), String> {
        let evidence_pool = self.evidence_pool.read().await;
        let mut validators = self.validators.write().await;

        for evidence in evidence_pool.iter() {
            if let Some(validator) = validators.iter_mut()
                .find(|v| v.address == evidence.validator_address) {
                // Apply slashing conditions based on evidence type
                match evidence.evidence_type {
                    SlashingEvidenceType::DoubleSigning => {
                        validator.voting_power = 0; // Remove voting power
                    },
                    SlashingEvidenceType::InvalidBlock => {
                        validator.voting_power = validator.voting_power / 2; // Reduce voting power
                    },
                    SlashingEvidenceType::InvalidVote => {
                        validator.voting_power = validator.voting_power * 3 / 4; // Reduce voting power
                    },
                    SlashingEvidenceType::UnauthorizedProposal => {
                        validator.voting_power = 0; // Remove voting power
                    },
                }
            }
        }

        Ok(())
    }

    pub async fn handle_commit(&self, commit: Commit) -> Result<(), ConsensusError> {
        // Verify commit
        if !self.verify_commit(&commit).await? {
            return Err(ConsensusError::InvalidCommit("Invalid commit".to_string()));
        }

        let mut state = self.state.lock().await;
        let mut round_state = self.round_state.write().await;
        
        // Check if we're in the right height
        if commit.height != round_state.height {
            return Err(ConsensusError::InvalidCommit("Wrong height".to_string()));
        }

        // Store commit
        round_state.last_commit = Some(commit.clone());

        // Finalize block if we have a proposal
        if let Some(proposal) = &round_state.proposal {
            self.finalize_block(proposal).await?;
        }

        Ok(())
    }

    async fn verify_commit(&self, commit: &Commit) -> Result<bool, ConsensusError> {
        // Verify commit signatures
        let block_hash_hex = hex::encode(&commit.block_hash);
        let message = format!("{}:{}", commit.height, block_hash_hex);
        let mut total_voting_power = 0;

        for vote in &commit.votes {
            // Convert signature bytes to fixed-size array
            let sig_bytes: [u8; 64] = vote.signature.as_slice()
                .try_into()
                .map_err(|_| ConsensusError::InvalidSignature("Invalid signature length".to_string()))?;
            
            let signature = Signature::try_from(&sig_bytes)
                .map_err(|e| ConsensusError::InvalidSignature(format!("Invalid signature format: {}", e)))?;
            
            if !vote.validator.verify(message.as_bytes(), &signature).is_ok() {
                return Ok(false);
            }

            // Sum voting power
            let validators = self.validators.read().await;
            if let Some(validator) = validators.iter()
                .find(|v| v.public_key == hex::encode(vote.validator.to_bytes())) 
            {
                total_voting_power += validator.voting_power;
            }
        }

        // Check if we have enough voting power
        let validators = self.validators.read().await;
        let total_validator_power: u64 = validators.iter().map(|v| v.voting_power).sum();
        if total_voting_power <= total_validator_power / 3 {
            return Ok(false);
        }

        Ok(true)
    }

    async fn finalize_block(&self, proposal: &Proposal) -> Result<(), ConsensusError> {
        let mut state = self.state.lock().await;
        let round_state = self.round_state.read().await;

        // Update state
        *state = ConsensusState {
            step: RoundStep::Commit,
            height: state.height,
            round: state.round,
            last_committed_height: state.height,
            last_committed_hash: state.last_committed_hash.clone(),
            proposer: state.proposer,
        };

        // Apply block transactions
        for tx in &proposal.block.transactions {
            self.apply_transaction(&mut *state, tx).await?;
        }

        // Save block and state
        self.save_block(&proposal.block).await?;
        self.save_state().await?;

        // Start new height
        self.enter_new_height().await?;

        Ok(())
    }

    pub async fn save_state(&self) -> Result<(), ConsensusError> {
        // TODO: Implement state persistence
        // For now, just return Ok
        Ok(())
    }

    pub async fn enter_new_height(&self) -> Result<(), ConsensusError> {
        let mut current_height = self.current_height.lock().await;
        let mut state = self.state.lock().await;
        
        // Increment height
        *current_height += 1;
        
        // Reset state to Propose for new height
        *state = ConsensusState::default();
        
        Ok(())
    }

    pub async fn save_block(&self, _block: &Block) -> Result<(), ConsensusError> {
        // TODO: Implement block persistence
        // For now, just return Ok
        Ok(())
    }

    pub async fn apply_transaction(&self, _state: &mut ConsensusState, tx: &Transaction) -> Result<bool, ConsensusError> {
        // TODO: Implement actual transaction validation and state updates
        // For now, just verify basic transaction properties
        if tx.amount == 0 {
            return Err(ConsensusError::InvalidTransaction("Zero amount transaction".to_string()));
        }

        if tx.gas_price == 0 {
            return Err(ConsensusError::InvalidTransaction("Zero gas price transaction".to_string()));
        }

        if tx.gas_limit == 0 {
            return Err(ConsensusError::InvalidTransaction("Zero gas limit transaction".to_string()));
        }
        // Verify signature using security_manager
        let message = format!("{}:{}:{}:{}", tx.id, tx.sender, tx.recipient, tx.amount);
        
        // Convert signature bytes to fixed-size array
        let flattened: Vec<u8> = tx.signature.as_slice().iter().flatten().cloned().collect();
        let sig_bytes: [u8; 64] = match flattened.try_into() {
            Ok(arr) => arr,
            Err(_) => return Err(ConsensusError::InvalidSignature("Invalid length for array conversion".to_string())),
        };
        // Create signature using try_into
        let signature = Signature::try_from(&sig_bytes)
            .map_err(|e| ConsensusError::InvalidSignature(format!("Invalid signature format: {}", e)))?;

        if !self.security_manager.verify_signature(&tx.sender, message.as_bytes(), &signature)
            .await
            .map_err(|e| ConsensusError::SecurityError(e.to_string()))? 
        {
            return Err(ConsensusError::InvalidSignature("Invalid transaction signature".to_string()));
        }

        Ok(true)
    }

    pub async fn handle_new_round(&self, height: u64, round: u32) -> Result<(), ConsensusError> {
        let mut round_state = self.round_state.write().await;
        round_state.height = height;
        round_state.round = round;
        round_state.step = ConsensusState::default();
        round_state.proposal = None;
        round_state.votes.clear();
        round_state.last_commit = None;
        Ok(())
    }

    async fn create_block(&self, transactions: Vec<Transaction>) -> Result<Block, ConsensusError> {
        let state = self.state.lock().await;
        let round_state = self.round_state.read().await;

        // Calculate merkle root for transactions
        let merkle_root = Block::calculate_merkle_root(&transactions);
        
        // Calculate state root (for now, just use a placeholder)
        let state_root = "placeholder_state_root".to_string();

        // Create block header
        let header = BlockHeader {
            version: 1,
            previous_hash: state.last_committed_hash.clone().unwrap_or_default(),
            timestamp: Utc::now(),
            height: round_state.height,
            proposer: self.validator_key.clone(),
            transaction_root: self.calculate_transaction_root(&transactions).await?,
            state_root: state_root.clone().into_bytes(),
            evidence_root: Vec::new(),
            validator_hash: Vec::new(),
            consensus_hash: Vec::new(),
            app_hash: Vec::new(),
        };

        // Create block
        Ok(Block {
            header,
            transactions,
            merkle_root,
            state_root,
        })
    }

    async fn calculate_transaction_root(&self, transactions: &[Transaction]) -> Result<Vec<u8>, ConsensusError> {
        let mut hasher = Sha256::new();
        for tx in transactions {
            // Hash transaction ID and amount
            hasher.update(&tx.id);
            hasher.update(tx.sender.clone().into_bytes());
            hasher.update(tx.recipient.clone().into_bytes());
            hasher.update(&tx.amount.to_le_bytes());
            // Remove the fee field since it doesn't exist
            hasher.update(&tx.timestamp.timestamp().to_le_bytes());
            // Handle optional signature
            if let Some(signature) = &tx.signature {
                hasher.update(signature);
            }
        }
        Ok(hasher.finalize().to_vec())
    }

    async fn create_vote(&self, block_hash: Vec<u8>) -> Result<Vote, ConsensusError> {
        let round_state = self.round_state.read().await;
        let validators = self.validators.read().await;
        
        // Find the validator's address using the public key
        let validator_address = validators.iter()
            .find(|v| v.public_key == hex::encode(self.validator_key.to_bytes()))
            .ok_or_else(|| ConsensusError::SecurityError("Validator not found".to_string()))?
            .address.clone();

        let mut vote = Vote {
            validator: self.validator_key.clone(),
            height: round_state.height,
            round: round_state.round,
            block_hash,
            timestamp: Utc::now(),
            signature: Vec::new(),
        };

        // Sign the vote using security_manager with the validator's address
        let message = format!("{}:{}:{}", round_state.height, round_state.round, hex::encode(&vote.block_hash));
        let signature = self.security_manager.sign_message(&validator_address, message.as_bytes())
            .await
            .map_err(|e| ConsensusError::SecurityError(e.to_string()))?;
        vote.signature = signature.to_bytes().to_vec();

        Ok(vote)
    }

    async fn create_commit(&self, block_hash: Vec<u8>) -> Result<Commit, ConsensusError> {
        let round_state = self.round_state.read().await;
        let validators = self.validators.read().await;
        
        // Find the validator's address using the public key
        let validator_address = validators.iter()
            .find(|v| v.public_key == hex::encode(self.validator_key.to_bytes()))
            .ok_or_else(|| ConsensusError::SecurityError("Validator not found".to_string()))?
            .address.clone();

        let mut commit = Commit {
            height: round_state.height,
            round: round_state.round,
            block_hash: block_hash.clone(),
            votes: Vec::new(),
            timestamp: Utc::now(),
            signature: Vec::new(),
        };

        // Sign the commit using security_manager with the validator's address
        let message = format!("{}:{}:{}", round_state.height, round_state.round, hex::encode(&block_hash));
        let signature = self.security_manager.sign_message(&validator_address, message.as_bytes())
            .await
            .map_err(|e| ConsensusError::SecurityError(e.to_string()))?;
        commit.signature = signature.to_bytes().to_vec();

        Ok(commit)
    }
} 