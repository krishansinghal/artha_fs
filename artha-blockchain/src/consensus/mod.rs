pub mod svbft;
pub mod tendermint;

use std::collections::{HashMap, BinaryHeap};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use chrono::{DateTime, Utc, Duration};
use ed25519_dalek::{VerifyingKey as PublicKey, Verifier, Signature};
use thiserror::Error;
use log::{error};
use hex;
use sha2::{Sha256, Digest};
use std::cmp::Ordering;

// Add new imports for merkle tree
use std::collections::BTreeMap;

use crate::types::block::{Block, BlockHeader};
use crate::types::transaction::Transaction as TypesTransaction;
use crate::consensus::tendermint::{ConsensusMessage, MessageMetadata};
use tokio::time::{self, Duration as TokioDuration};

// Add missing type definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorUpdate {
    Add { pub_key: PublicKey, voting_power: u64 },
    Remove { pub_key: PublicKey },
    UpdateVotingPower { pub_key: PublicKey, voting_power: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedState {
    pub height: u64,
    pub block_hash: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePool {
    #[serde(serialize_with = "serialize_evidence_map", deserialize_with = "deserialize_evidence_map")]
    pub evidence: HashMap<String, Vec<Evidence>>,
    pub pending_evidence: Vec<Evidence>,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub max_evidence_age: Duration,
}

fn serialize_evidence_map<S>(
    evidence: &HashMap<String, Vec<Evidence>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    evidence.serialize(serializer)
}

fn deserialize_evidence_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<Evidence>>, D::Error>
where
    D: Deserializer<'de>,
{
    HashMap::<String, Vec<Evidence>>::deserialize(deserializer)
}

fn serialize_duration<S>(
    duration: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    duration.num_seconds().serialize(serializer)
}

fn deserialize_duration<'de, D>(
    deserializer: D,
) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let seconds = i64::deserialize(deserializer)?;
    Ok(Duration::seconds(seconds))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: String,
    pub pub_key: PublicKey,
    pub voting_power: u64,
    pub proposer_priority: i64,
    pub jailed_until: Option<DateTime<Utc>>,
    pub accumulated_slashes: u32,
    pub last_height: u64,
    pub last_round: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub total_voting_power: u64,
    pub proposer: Option<Validator>,
    pub last_height: u64,
    pub last_round: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    DuplicateVote,
    InvalidVote,
    InvalidProposal,
    InvalidCommit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub validator: PublicKey,
    pub height: u64,
    pub round: u32,
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>, // Store signature as bytes for serialization
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingCondition {
    pub evidence_type: EvidenceType,
    pub slash_amount: u64,
    pub jail_duration: Duration,
    pub min_evidence_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundState {
    pub height: u64,
    pub round: u32,
    pub step: RoundStep,
    pub start_time: DateTime<Utc>,
    pub commit_time: DateTime<Utc>,
    pub validators: ValidatorSet,
    pub votes: HashMap<String, Vote>,
    pub proposal: Option<Proposal>,
    pub last_commit: Option<Commit>,
    pub timeout_propose: Duration,
    pub timeout_prevote: Duration,
    pub timeout_precommit: Duration,
    pub timeout_commit: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RoundStep {
    NewHeight,
    NewRound,
    Propose,
    Prevote,
    Precommit,
    Commit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub validator: PublicKey,
    pub height: u64,
    pub round: u32,
    pub block_hash: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>, // Store signature as bytes for serialization
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposer: PublicKey,
    pub height: u64,
    pub round: u32,
    pub block: Block,
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>, // Store signature as bytes for serialization
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub height: u64,
    pub round: u32,
    pub block_hash: Vec<u8>,
    pub votes: Vec<Vote>,
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>, // Store signature as bytes for serialization
}

#[derive(Debug, Clone)]
pub struct ConsensusNetworkManager {
    peers: Arc<RwLock<HashMap<String, Peer>>>,
    peer_scores: Arc<RwLock<HashMap<String, f64>>>,
    message_queue: Arc<RwLock<Vec<ConsensusMessage>>>,
    mempool: Arc<RwLock<Mempool>>,
    bandwidth_limits: Arc<RwLock<HashMap<String, BandwidthLimit>>>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimit>>>,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub address: String,
    pub last_seen: DateTime<Utc>,
    pub connection_quality: f64,
    pub bandwidth_usage: usize,
    pub score: f64,
}

pub struct ConsensusEngine {
    state: Arc<RwLock<ConsensusState>>,
    validator_set: Arc<RwLock<ValidatorSet>>,
    evidence_pool: Arc<RwLock<EvidencePool>>,
    round_state: Arc<RwLock<RoundState>>,
    slashing_conditions: Vec<SlashingCondition>,
    network: Arc<ConsensusNetworkManager>,
    validator_key: PublicKey,
    config: ConsensusConfig,
}

#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    pub max_evidence_age: Duration,
    pub min_evidence_count: u32,
    pub max_block_size: usize,
    pub max_transactions_per_block: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            max_evidence_age: Duration::hours(24),
            min_evidence_count: 2,
            max_block_size: 1_000_000, // 1MB
            max_transactions_per_block: 1000,
        }
    }
}

#[derive(Debug, Clone)]
struct ConsensusState {
    height: u64,
    round: u32,
    step: RoundStep,
    last_committed_height: u64,
    last_committed_round: u32,
    last_committed_hash: Vec<u8>,
    validators: ValidatorSet,
    evidence: Vec<Evidence>,
    state_tree: MerkleTree,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Vec<u8>,
    pub sender: PublicKey,
    pub receiver: PublicKey,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>,
}

impl ConsensusNetworkManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_scores: Arc::new(RwLock::new(HashMap::new())),
            message_queue: Arc::new(RwLock::new(Vec::new())),
            mempool: Arc::new(RwLock::new(Mempool::new(10000))), // 10k transaction limit
            bandwidth_limits: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn broadcast_message(&self, message: ConsensusMessage) -> Result<(), ConsensusError> {
        // Implement message broadcasting with retry logic
        let retries = 0;
        let max_retries = 3;

        while retries < max_retries {
            // Add message to queue instead of trying to broadcast directly
            let mut message_queue = self.message_queue.write().await;
            message_queue.push(message.clone());
            return Ok(());
        }

        Ok(())
    }

    async fn send_message_to_peer(&self, peer_id: &str, message: ConsensusMessage) -> Result<(), ConsensusError> {
        // Get message size
        let message_size = self.calculate_message_size(&message)?;
        
        // Update bandwidth usage
        let mut bandwidth_limits = self.bandwidth_limits.write().await;
        let peer_bandwidth = bandwidth_limits.entry(peer_id.to_string())
            .or_insert_with(|| BandwidthLimit {
                bytes_sent: 0,
                bytes_received: 0,
                last_reset: Utc::now(),
                limit: 1_000_000, // 1MB per second
            });
        
        if peer_bandwidth.bytes_sent + message_size > peer_bandwidth.limit {
            return Err(ConsensusError::NetworkError("Bandwidth limit exceeded".into()));
        }
        
        peer_bandwidth.bytes_sent += message_size;
        
        // TODO: Implement actual message sending
        // This should:
        // 1. Serialize message
        // 2. Send over network
        // 3. Handle response
        // For now, just simulate success
        Ok(())
    }

    async fn check_rate_limit(&self, peer_id: &str) -> Result<bool, ConsensusError> {
        let mut rate_limits = self.rate_limits.write().await;
        let peer_rate = rate_limits.entry(peer_id.to_string())
            .or_insert_with(|| RateLimit {
                messages_sent: 0,
                last_reset: Utc::now(),
                limit: 100, // 100 messages per second
            });
        
        // Reset counter if needed
        if Utc::now() - peer_rate.last_reset > Duration::seconds(1) {
            peer_rate.messages_sent = 0;
            peer_rate.last_reset = Utc::now();
        }
        
        if peer_rate.messages_sent >= peer_rate.limit {
            return Ok(false);
        }
        
        peer_rate.messages_sent += 1;
        Ok(true)
    }

    async fn check_bandwidth_limit(&self, peer_id: &str) -> Result<bool, ConsensusError> {
        let mut bandwidth_limits = self.bandwidth_limits.write().await;
        let peer_bandwidth = bandwidth_limits.entry(peer_id.to_string())
            .or_insert_with(|| BandwidthLimit {
                bytes_sent: 0,
                bytes_received: 0,
                last_reset: Utc::now(),
                limit: 1_000_000, // 1MB per second
            });
        
        // Reset counter if needed
        if Utc::now() - peer_bandwidth.last_reset > Duration::seconds(1) {
            peer_bandwidth.bytes_sent = 0;
            peer_bandwidth.bytes_received = 0;
            peer_bandwidth.last_reset = Utc::now();
        }
        
        Ok(true)
    }

    async fn update_peer_metrics(&self, peer_id: &str, success: bool) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.last_seen = Utc::now();
            if success {
                peer.connection_quality = (peer.connection_quality * 0.9) + 0.1;
            } else {
                peer.connection_quality = peer.connection_quality * 0.9;
            }
        }
    }

    async fn monitor_peer_quality(&self) {
        let mut peers = self.peers.write().await;
        let now = Utc::now();
        
        for peer in peers.values_mut() {
            // Update connection quality based on:
            // - Message latency
            // - Message loss rate
            // - Bandwidth usage
            // - Response time
            
            // Check if peer is inactive
            if now - peer.last_seen > Duration::seconds(30) {
                peer.connection_quality *= 0.5;
            }
            
            // Update bandwidth usage
            if let Some(bandwidth) = self.bandwidth_limits.read().await.get(&peer.id) {
                peer.bandwidth_usage = bandwidth.bytes_sent + bandwidth.bytes_received;
            }
            
            // Update peer score
            let score = self.calculate_peer_score(peer).await;
            peer.score = score;
        }
    }

    async fn calculate_peer_score(&self, peer: &Peer) -> f64 {
        let mut score = peer.connection_quality;
        
        // Adjust score based on bandwidth usage
        let bandwidth_usage = peer.bandwidth_usage as f64 / 1_000_000.0; // Convert to MB
        if bandwidth_usage > 0.8 { // More than 80% of limit
            score *= 0.8;
        }
        
        // Adjust score based on last seen time
        let time_since_last_seen = (Utc::now() - peer.last_seen).num_seconds() as f64;
        if time_since_last_seen > 10.0 {
            score *= 0.9;
        }
        
        score
    }

    fn calculate_message_size(&self, message: &ConsensusMessage) -> Result<usize, ConsensusError> {
        // Calculate approximate message size in bytes
        let size = match message {
            ConsensusMessage::NewRound { metadata } => {
                8 + // height
                4 + // round
                32 + // sender
                64 // signature
            },
            ConsensusMessage::Proposal { metadata, block, proposer } => {
                8 + // height
                4 + // round
                8 + // timestamp
                32 + // proposer public key
                block.transactions.iter()
                    .map(|tx| self.calculate_transaction_size(&TypesTransaction::from(tx.clone())))
                    .sum::<Result<usize, ConsensusError>>()? +
                64 // signature
            },
            ConsensusMessage::Vote { metadata, block_hash, voter } => {
                8 + // height
                4 + // round
                32 + // block hash
                8 + // timestamp
                32 + // validator public key
                64 // signature
            },
            ConsensusMessage::Commit { metadata, votes } => {
                8 + // height
                4 + // round
                32 + // block hash
                8 + // timestamp
                votes.iter()
                    .map(|v| self.calculate_vote_size(v))
                    .sum::<Result<usize, ConsensusError>>()? +
                64 // signature
            },
            ConsensusMessage::Evidence { metadata, block_hash, voter } => {
                1 + // evidence type
                32 + // validator public key
                8 + // height
                4 + // round
                8 + // timestamp
                64 // signature
            },
        };
        
        Ok(size)
    }

    fn calculate_transaction_size(&self, tx: &TypesTransaction) -> Result<usize, ConsensusError> {
        Ok(
            tx.id.len() +
            tx.sender.len() + // String length
            tx.recipient.len() + // String length
            std::mem::size_of::<u64>() * 2 + // amount and fee
            std::mem::size_of::<i64>() + // timestamp
            tx.signature.as_ref().map_or(0, |sig| sig.len()) // Handle Option<Vec<u8>>
        )
    }

    fn calculate_vote_size(&self, _vote: &Vote) -> Result<usize, ConsensusError> {
        Ok(
            8 + // height
            4 + // round
            32 + // block hash
            8 + // timestamp
            32 + // validator public key
            64 // signature
        )
    }

    pub async fn get_mempool(&self) -> Result<Vec<Transaction>, ConsensusError> {
        let mempool = self.mempool.read().await;
        Ok(mempool.get_transactions())
    }

    pub async fn add_transaction(&self, transaction: Transaction) -> Result<(), ConsensusError> {
        let mut mempool = self.mempool.write().await;
        
        // Calculate transaction priority based on fee
        let priority = transaction.fee;
        
        mempool.add_transaction(transaction, priority);
        Ok(())
    }

    pub async fn get_peers(&self) -> Result<Vec<Peer>, ConsensusError> {
        let peers = self.peers.read().await;
        Ok(peers.values().cloned().collect())
    }

    pub async fn get_peer_latency(&self, peer: &Peer) -> Result<Duration, ConsensusError> {
        // Calculate latency based on last seen time
        let now = Utc::now();
        let latency = now - peer.last_seen;
        Ok(latency)
    }

    pub async fn get_peer_success_rate(&self, peer: &Peer) -> Result<f64, ConsensusError> {
        let peer_scores = self.peer_scores.read().await;
        Ok(*peer_scores.get(&peer.id).unwrap_or(&0.0))
    }

    pub async fn update_peer_quality(&self, peer: Peer, latency: Duration, success_rate: f64) -> Result<(), ConsensusError> {
        let mut peers = self.peers.write().await;
        let mut peer_scores = self.peer_scores.write().await;

        // Update peer's connection quality based on latency and success rate
        let latency_factor = if latency.num_seconds() < 1 {
            1.0
        } else {
            1.0 / (latency.num_seconds() as f64)
        };

        let quality_score = (success_rate * 0.7 + latency_factor * 0.3).min(1.0).max(0.0);
        
        if let Some(existing_peer) = peers.get_mut(&peer.id) {
            existing_peer.connection_quality = quality_score;
            existing_peer.last_seen = Utc::now();
        }

        peer_scores.insert(peer.id.clone(), quality_score);
        Ok(())
    }
}

// Add new types for network management
#[derive(Debug, Clone)]
struct BandwidthLimit {
    bytes_sent: usize,
    bytes_received: usize,
    last_reset: DateTime<Utc>,
    limit: usize,
}

#[derive(Debug, Clone)]
struct RateLimit {
    messages_sent: usize,
    last_reset: DateTime<Utc>,
    limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Mempool {
    #[serde(serialize_with = "serialize_transaction_heap", deserialize_with = "deserialize_transaction_heap")]
    transactions: BinaryHeap<TransactionWithPriority>,
    max_size: usize,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            transactions: BinaryHeap::new(),
            max_size,
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction, priority: u64) {
        if self.transactions.len() >= self.max_size {
            // Remove lowest priority transaction if mempool is full
            self.transactions.pop();
        }
        self.transactions.push(TransactionWithPriority { transaction, priority });
    }

    pub fn get_transactions(&self) -> Vec<Transaction> {
        self.transactions.iter()
            .map(|tx| tx.transaction.clone())
            .collect()
    }
}

// Add serialization functions for BinaryHeap<TransactionWithPriority>
fn serialize_transaction_heap<S>(
    heap: &BinaryHeap<TransactionWithPriority>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert heap to Vec for serialization
    let vec: Vec<_> = heap.iter().collect();
    vec.serialize(serializer)
}

fn deserialize_transaction_heap<'de, D>(
    deserializer: D,
) -> Result<BinaryHeap<TransactionWithPriority>, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize as Vec first, then convert to BinaryHeap
    let vec: Vec<TransactionWithPriority> = Vec::deserialize(deserializer)?;
    Ok(BinaryHeap::from(vec))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWithPriority {
    pub transaction: Transaction,
    pub priority: u64,
}

impl Ord for TransactionWithPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for TransactionWithPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TransactionWithPriority {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for TransactionWithPriority {}

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Invalid validator: {0}")]
    InvalidValidator(String),
    #[error("Invalid voting power: {0}")]
    InvalidVotingPower(String),
    #[error("Invalid evidence: {0}")]
    InvalidEvidence(String),
    #[error("Round timeout: {0}")]
    RoundTimeout(String),
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("State error: {0}")]
    StateError(String),
    #[error("Invalid vote: {0}")]
    InvalidVote(String),
    #[error("Invalid proposal: {0}")]
    InvalidProposal(String),
    #[error("Invalid commit: {0}")]
    InvalidCommit(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Mempool error: {0}")]
    MempoolError(String),
    #[error("Security error: {0}")]
    SecurityError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateNode {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub version: u64,
    pub hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: BTreeMap<Vec<u8>, StateNode>,
    root: Vec<u8>,
    version: u64,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            root: vec![0; 32], // Empty tree root
            version: 0,
        }
    }

    pub fn update(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<Vec<u8>, ConsensusError> {
        self.version += 1;
        
        // Create new node
        let mut hasher = Sha256::new();
        hasher.update(&key);
        hasher.update(&value);
        hasher.update(&self.version.to_le_bytes());
        let node_hash = hasher.finalize().to_vec();
        
        let node = StateNode {
            key: key.clone(),
            value,
            version: self.version,
            hash: node_hash,
        };
        
        // Insert or update node
        self.nodes.insert(key, node);
        
        // Recalculate root
        self.recalculate_root()?;
        
        Ok(self.root.clone())
    }

    pub fn get(&self, key: &[u8]) -> Option<&StateNode> {
        self.nodes.get(key)
    }

    pub fn get_root(&self) -> Vec<u8> {
        self.root.clone()
    }

    pub fn get_version(&self) -> u64 {
        self.version
    }

    pub fn create_proof(&self, key: &[u8]) -> Result<MerkleProof, ConsensusError> {
        let node = self.nodes.get(key)
            .ok_or_else(|| ConsensusError::StateError("Key not found".into()))?;
        
        let mut proof = MerkleProof {
            key: key.to_vec(),
            value: node.value.clone(),
            version: node.version,
            siblings: Vec::new(),
            root: self.root.clone(),
        };
        
        // Get all nodes sorted by key
        let sorted_nodes: Vec<_> = self.nodes.values().collect();
        
        // Find the index of our node
        let node_index = sorted_nodes.iter()
            .position(|n| n.key == key)
            .ok_or_else(|| ConsensusError::StateError("Node not found in sorted list".into()))?;
        
        // Calculate the path to root
        let mut current_index = node_index;
        let mut level_size = sorted_nodes.len();
        
        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            if sibling_index < level_size {
                proof.siblings.push(sorted_nodes[sibling_index].hash.clone());
            }
            
            current_index /= 2;
            level_size = (level_size + 1) / 2;
        }
        
        Ok(proof)
    }

    pub fn verify_proof(&self, proof: &MerkleProof) -> Result<bool, ConsensusError> {
        let mut current_hash = proof.key.clone();
        let mut siblings = proof.siblings.iter().peekable();

        while let Some(sibling) = siblings.next() {
            let mut hasher = Sha256::new();
            
            // Compare the key with the sibling to determine the order
            if proof.key < *sibling {  // Dereference the sibling
                hasher.update(&current_hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current_hash);
            }
            
            current_hash = hasher.finalize().to_vec();
        }

        Ok(current_hash == proof.root)
    }

    fn recalculate_root(&mut self) -> Result<(), ConsensusError> {
        if self.nodes.is_empty() {
            self.root = vec![0; 32];
            return Ok(());
        }
        
        // Get all nodes sorted by key
        let sorted_nodes: Vec<_> = self.nodes.values().collect();
        
        // Build the tree level by level
        let mut current_level = sorted_nodes.iter()
            .map(|n| n.hash.clone())
            .collect::<Vec<_>>();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            
            for chunk in current_level.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                } else {
                    // Duplicate last node if odd number of nodes
                    hasher.update(&chunk[0]);
                }
                next_level.push(hasher.finalize().to_vec());
            }
            
            current_level = next_level;
        }
        
        self.root = current_level[0].clone();
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub version: u64,
    pub siblings: Vec<Vec<u8>>,
    pub root: Vec<u8>,
}

impl RoundState {
    pub fn new() -> Self {
        Self {
            height: 0,
            round: 0,
            step: RoundStep::NewHeight,
            start_time: Utc::now(),
            commit_time: Utc::now(),
            validators: ValidatorSet {
                validators: Vec::new(),
                total_voting_power: 0,
                proposer: None,
                last_height: 0,
                last_round: 0,
            },
            votes: HashMap::new(),
            proposal: None,
            last_commit: None,
            timeout_propose: Duration::milliseconds(3000),
            timeout_prevote: Duration::milliseconds(1000),
            timeout_precommit: Duration::milliseconds(1000),
            timeout_commit: Duration::milliseconds(1000),
        }
    }
}

impl EvidencePool {
    pub fn new() -> Self {
        Self {
            evidence: HashMap::new(),
            pending_evidence: Vec::new(),
            max_evidence_age: Duration::hours(24),
        }
    }
}

impl ValidatorSet {
    pub fn new(validators: Vec<PublicKey>) -> Self {
        let validators: Vec<Validator> = validators.into_iter()
            .map(|pub_key| Validator {
                address: hex::encode(pub_key.to_bytes()),
                pub_key,
                voting_power: 1,
                proposer_priority: 0,
                jailed_until: None,
                accumulated_slashes: 0,
                last_height: 0,
                last_round: 0,
            })
            .collect();

        let total_voting_power = validators.iter()
            .map(|v| v.voting_power)
            .sum();

        Self {
            validators,
            total_voting_power,
            proposer: None,
            last_height: 0,
            last_round: 0,
        }
    }
}

impl ConsensusEngine {
    pub fn new(
        validator_key: PublicKey,
        validator_set: ValidatorSet,
        network_manager: Arc<ConsensusNetworkManager>,
        config: Option<ConsensusConfig>,
    ) -> Self {
        let state = ConsensusState {
            height: 0,
            round: 0,
            step: RoundStep::NewHeight,
            last_committed_height: 0,
            last_committed_round: 0,
            last_committed_hash: vec![0; 32], // Initialize with empty hash
            validators: validator_set.clone(),
            evidence: Vec::new(),
            state_tree: MerkleTree::new(),
        };

        let slashing_conditions = vec![
            SlashingCondition {
                evidence_type: EvidenceType::DuplicateVote,
                slash_amount: 1000,
                jail_duration: Duration::hours(24),
                min_evidence_count: 2,
            },
            SlashingCondition {
                evidence_type: EvidenceType::InvalidVote,
                slash_amount: 5000,
                jail_duration: Duration::hours(72),
                min_evidence_count: 1,
            },
        ];

        Self {
            state: Arc::new(RwLock::new(state)),
            validator_set: Arc::new(RwLock::new(validator_set)),
            evidence_pool: Arc::new(RwLock::new(EvidencePool::new())),
            round_state: Arc::new(RwLock::new(RoundState::new())),
            slashing_conditions,
            network: network_manager,
            validator_key,
            config: config.unwrap_or_default(),
        }
    }

    pub async fn start(&self) -> Result<(), ConsensusError> {
        // Start the consensus engine
        self.enter_new_height().await?;
        self.start_round().await?;
        Ok(())
    }

    async fn enter_new_height(&self) -> Result<(), ConsensusError> {
        let mut state = self.state.write().await;
        let mut round_state = self.round_state.write().await;
        
        state.height += 1;
        state.round = 0;
        state.step = RoundStep::NewHeight;
        
        round_state.height = state.height;
        round_state.start_time = Utc::now();
        
        Ok(())
    }

    async fn start_round(&self) -> Result<(), ConsensusError> {
        let mut round_state = self.round_state.write().await;
        round_state.round += 1;
        round_state.step = RoundStep::NewRound;
        round_state.start_time = Utc::now();

        // Select proposer for this round
        self.select_proposer().await?;

        // Broadcast new round message
        self.broadcast_new_round(round_state.height, round_state.round).await?;

        Ok(())
    }

    async fn update_validator_set(&self, updates: Vec<ValidatorUpdate>) -> Result<(), ConsensusError> {
        let mut validator_set = self.validator_set.write().await;
        
        // Store these values before the mutable borrow
        let last_height = validator_set.last_height;
        let last_round = validator_set.last_round;
        
        for update in updates {
            match update {
                ValidatorUpdate::Add { pub_key, voting_power } => {
                    // Check if validator already exists
                    if validator_set.validators.iter().any(|v| v.pub_key == pub_key) {
                        continue;
                    }

                    // Add new validator
                    validator_set.validators.push(Validator {
                        address: hex::encode(pub_key.to_bytes()),
                        pub_key,
                        voting_power,
                        proposer_priority: 0,
                        jailed_until: None,
                        accumulated_slashes: 0,
                        last_height,
                        last_round,
                    });
                }
                ValidatorUpdate::Remove { pub_key } => {
                    // Remove validator
                    validator_set.validators.retain(|v| v.pub_key != pub_key);
                }
                ValidatorUpdate::UpdateVotingPower { pub_key, voting_power } => {
                    // Update voting power
                    if let Some(validator) = validator_set.validators.iter_mut()
                        .find(|v| v.pub_key == pub_key) 
                    {
                        validator.voting_power = voting_power;
                    }
                }
            }
        }

        // Update total voting power
        validator_set.total_voting_power = validator_set.validators.iter()
            .map(|v| v.voting_power)
            .sum();

        // Update proposer priority
        self.update_proposer_priority(&mut validator_set).await?;

        Ok(())
    }

    async fn update_proposer_priority(&self, validator_set: &mut ValidatorSet) -> Result<(), ConsensusError> {
        let total_voting_power = validator_set.total_voting_power;
        if total_voting_power == 0 {
            return Err(ConsensusError::InvalidState("No validators in set".into()));
        }

        // Update proposer priorities based on voting power and performance
        for validator in &mut validator_set.validators {
            // Calculate base priority from voting power
            let base_priority = (validator.voting_power as f64 / total_voting_power as f64) * 1000.0;
            
            // Adjust priority based on performance metrics
            let performance_factor = self.calculate_validator_performance(validator).await?;
            let adjusted_priority = (base_priority * performance_factor) as i64;
            
            // Update validator's proposer priority
            validator.proposer_priority = adjusted_priority;
        }

        // Select proposer based on priority and clone the full validator
        validator_set.proposer = validator_set.validators.iter()
            .max_by_key(|v| v.proposer_priority)
            .cloned();

        Ok(())
    }

    async fn calculate_validator_performance(&self, validator: &Validator) -> Result<f64, ConsensusError> {
        let mut performance_score = 1.0;

        // Check if validator is jailed
        if let Some(jail_time) = validator.jailed_until {
            if jail_time > Utc::now() {
                return Ok(0.0); // Jailed validators get zero priority
            }
            // Reduce priority for recently jailed validators
            performance_score *= 0.5;
        }

        // Check accumulated slashes
        if validator.accumulated_slashes > 0 {
            performance_score *= 1.0 / (1.0 + (validator.accumulated_slashes as f64 * 0.2));
        }

        // Check voting power (validators with higher voting power get slightly higher priority)
        performance_score *= 1.0 + (validator.voting_power as f64 / 100.0);

        Ok(performance_score)
    }

    async fn process_evidence(&self) -> Result<(), ConsensusError> {
        let mut evidence_pool = self.evidence_pool.write().await;
        let mut validator_set = self.validator_set.write().await;

        // Collect pending evidence first to avoid multiple mutable borrows
        let pending_evidence: Vec<Evidence> = evidence_pool.pending_evidence.drain(..).collect();

        // Process collected evidence
        for evidence in pending_evidence {
            // Verify evidence
            if self.verify_evidence(&evidence).await? {
                // Apply slashing conditions
                self.apply_slashing_conditions(&evidence, &mut validator_set).await?;
                
                // Add to processed evidence using validator's public key as identifier
                let validator_id = hex::encode(evidence.validator.to_bytes());
                evidence_pool.evidence
                    .entry(validator_id)
                    .or_default()
                    .push(evidence);
            }
        }

        Ok(())
    }

    async fn verify_evidence(&self, evidence: &Evidence) -> Result<bool, ConsensusError> {
        // Verify evidence timestamp
        let evidence_age = Utc::now() - evidence.timestamp;
        if evidence_age > self.config.max_evidence_age {
            return Ok(false);
        }

        // Verify validator exists and wasn't jailed at the time
        let validator_set = self.validator_set.read().await;
        let validator_id = hex::encode(evidence.validator.to_bytes());
        
        let validator = validator_set.validators.iter()
            .find(|v| v.address == validator_id)
            .ok_or_else(|| ConsensusError::InvalidState("Validator not found".into()))?;

        if let Some(jail_time) = validator.jailed_until {
            if jail_time > evidence.timestamp {
                return Ok(false); // Validator was jailed at the time
            }
        }

        // Verify evidence signature
        let message = format!("{:?}:{}", evidence.evidence_type, evidence.height);
        let signature_bytes: [u8; 64] = evidence.signature.as_slice()
            .try_into()
            .map_err(|_| ConsensusError::InvalidSignature("Invalid signature length".into()))?;
        let signature = Signature::try_from(&signature_bytes[..])
            .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))?;
        
        if !evidence.validator.verify(message.as_bytes(), &signature).is_ok() {
            return Ok(false);
        }

        // Check for duplicate evidence
        let evidence_pool = self.evidence_pool.read().await;
        if let Some(existing_evidence) = evidence_pool.evidence.get(&validator_id) {
            if existing_evidence.iter().any(|e| 
                e.evidence_type == evidence.evidence_type && 
                e.height == evidence.height
            ) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn apply_slashing_conditions(
        &self,
        evidence: &Evidence,
        validator_set: &mut ValidatorSet,
    ) -> Result<(), ConsensusError> {
        let validator_id = hex::encode(evidence.validator.to_bytes());
        if let Some(validator) = validator_set.validators.iter_mut()
            .find(|v| v.address == validator_id) 
        {
            // Find applicable slashing condition
            if let Some(condition) = self.slashing_conditions.iter()
                .find(|c| c.evidence_type == evidence.evidence_type) 
            {
                // Apply slashing
                validator.accumulated_slashes += 1;
                validator.voting_power = validator.voting_power.saturating_sub(condition.slash_amount);
                validator.jailed_until = Some(Utc::now() + condition.jail_duration);

                // Update total voting power
                validator_set.total_voting_power = validator_set.validators.iter()
                    .map(|v| v.voting_power)
                    .sum();
            }
        }

        Ok(())
    }

    async fn select_proposer(&self) -> Result<(), ConsensusError> {
        let mut round_state = self.round_state.write().await;
        let validator_set = self.validator_set.read().await;

        // Implement proposer selection logic
        // This should be based on voting power and proposer priority
        if let Some(proposer) = validator_set.validators.iter()
            .max_by_key(|v| (v.proposer_priority, v.voting_power))
        {
            round_state.validators.proposer = Some(proposer.clone());
        }

        Ok(())
    }

    pub async fn handle_message(&self, message: ConsensusMessage) -> Result<(), ConsensusError> {
        match message {
            ConsensusMessage::NewRound { metadata } => {
                self.handle_new_round(metadata.height, metadata.round).await?;
            }
            ConsensusMessage::Proposal { metadata, block, proposer } => {
                let proposal = Proposal {
                    proposer,
                    height: metadata.height,
                    round: metadata.round,
                    block,
                    timestamp: Utc::now(),
                    signature: metadata.signature,
                };
                self.handle_proposal(proposal).await?;
            }
            ConsensusMessage::Vote { metadata, block_hash, voter } => {
                let vote = Vote {
                    validator: voter,
                    height: metadata.height,
                    round: metadata.round,
                    block_hash,
                    timestamp: Utc::now(),
                    signature: metadata.signature,
                };
                self.handle_vote(vote).await?;
            }
            ConsensusMessage::Commit { metadata, votes } => {
                let commit = Commit {
                    height: metadata.height,
                    round: metadata.round,
                    block_hash: metadata.block_hash.unwrap_or_default(),
                    votes,
                    timestamp: Utc::now(),
                    signature: metadata.signature,
                };
                self.handle_commit(commit).await?;
            }
            ConsensusMessage::Evidence { metadata, block_hash, voter } => {
                let evidence = Evidence {
                    evidence_type: EvidenceType::InvalidVote,
                    validator: voter,
                    height: metadata.height,
                    round: metadata.round,
                    timestamp: Utc::now(),
                    signature: metadata.signature,
                };
                self.handle_evidence(evidence).await?;
            }
        }
        Ok(())
    }

    async fn handle_proposal(&self, proposal: Proposal) -> Result<(), ConsensusError> {
        // Verify proposal
        if !self.verify_proposal(&proposal).await? {
            return Err(ConsensusError::InvalidProposal("Invalid proposal".into()));
        }

        let mut round_state = self.round_state.write().await;
        
        // Check if we're in the right round
        if proposal.height != round_state.height || proposal.round != round_state.round {
            return Err(ConsensusError::InvalidProposal("Wrong height or round".into()));
        }

        // Check if we're the proposer
        if round_state.validators.proposer.as_ref().map(|v| v.pub_key) != Some(self.validator_key) {
            return Err(ConsensusError::InvalidState("Not the proposer".into()));
        }

        // Store proposal
        round_state.proposal = Some(proposal.clone());

        // Broadcast vote if we're a validator
        if self.is_validator() {
            let vote = self.create_vote(proposal.block.hash().clone().into()).await?;
            let message = ConsensusMessage::Vote {
                metadata: MessageMetadata {
                    height: vote.height,
                    round: vote.round,
                    sender: self.validator_key,
                    signature: vote.signature,
                    block_hash: Some(vote.block_hash.clone()),
                },
                block_hash: vote.block_hash,
                voter: vote.validator,
            };
            self.broadcast_message(message).await?;
        }

        Ok(())
    }

    async fn handle_vote(&self, vote: Vote) -> Result<(), ConsensusError> {
        // Verify vote
        if !self.verify_vote(&vote).await? {
            return Err(ConsensusError::InvalidVote("Invalid vote".into()));
        }

        let mut round_state = self.round_state.write().await;
        
        // Check if we're in the right round
        if vote.height != round_state.height || vote.round != round_state.round {
            return Err(ConsensusError::InvalidVote("Wrong height or round".into()));
        }

        // Add vote to round state using validator's public key as the key
        let validator_key = hex::encode(vote.validator.to_bytes());
        round_state.votes.insert(validator_key, vote.clone());

        // Check if we have enough votes to commit
        if self.has_sufficient_votes(round_state.votes.values().cloned().collect::<Vec<_>>().as_slice()).await? {
            // Create and broadcast commit
            let block_hash = hex::decode(round_state.proposal.as_ref().unwrap().block.hash())
                .map_err(|e| ConsensusError::InvalidState(format!("Invalid block hash: {}", e)))?;
            let commit = self.create_commit(block_hash).await?;
            let message = ConsensusMessage::Commit {
                metadata: MessageMetadata {
                    height: commit.height,
                    round: commit.round,
                    sender: self.validator_key,
                    signature: commit.signature,
                    block_hash: Some(commit.block_hash),
                },
                votes: commit.votes,
            };
            self.broadcast_message(message).await?;
        }

        Ok(())
    }

    async fn handle_evidence(&self, evidence: Evidence) -> Result<(), ConsensusError> {
        // Add evidence to pending pool
        let mut evidence_pool = self.evidence_pool.write().await;
        evidence_pool.pending_evidence.push(evidence);

        // Process evidence if we have enough
        let min_count = self.config.min_evidence_count as usize;
        if evidence_pool.pending_evidence.len() >= min_count {
            self.process_evidence().await?;
        }

        Ok(())
    }

    async fn handle_new_round(&self, height: u64, round: u32) -> Result<(), ConsensusError> {
        let state = self.state.write().await;
        let mut round_state = self.round_state.write().await;
        
        if height != state.height {
            return Err(ConsensusError::InvalidState("Wrong height".into()));
        }
        
        round_state.round = round;
        round_state.step = RoundStep::NewRound;
        round_state.start_time = Utc::now();
        
        // Clear previous round data
        round_state.proposal = None;
        round_state.votes.clear();
        
        Ok(())
    }

    async fn handle_commit(&self, commit: Commit) -> Result<(), ConsensusError> {
        // Verify commit
        if !self.verify_commit(&commit).await? {
            return Err(ConsensusError::InvalidCommit("Invalid commit".into()));
        }

        let state = self.state.write().await;
        let mut round_state = self.round_state.write().await;
        
        // Check if we're in the right height
        if commit.height != state.height {
            return Err(ConsensusError::InvalidCommit("Wrong height".into()));
        }

        // Store commit
        round_state.last_commit = Some(commit.clone());

        // Finalize block if we have a proposal
        if let Some(proposal) = &round_state.proposal {
            self.finalize_block(proposal).await?;
        }

        Ok(())
    }

    async fn verify_proposal(&self, proposal: &Proposal) -> Result<bool, ConsensusError> {
        // Verify proposal signature
        let block_hash = proposal.block.hash();
        let message = format!("{}:{}:{}", proposal.height, proposal.round, hex::encode(&block_hash));
        let signature_bytes: [u8; 64] = proposal.signature.as_slice()
            .try_into()
            .map_err(|_| ConsensusError::InvalidSignature("Invalid signature length".into()))?;
        let signature = Signature::try_from(&signature_bytes[..])
            .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))?;
        
        if !proposal.proposer.verify(message.as_bytes(), &signature).is_ok() {
            return Ok(false);
        }

        // Verify block
        if !self.verify_block(&proposal.block).await? {
            return Ok(false);
        }

        Ok(true)
    }

    async fn verify_vote(&self, vote: &Vote) -> Result<bool, ConsensusError> {
        // Verify vote signature
        let message = format!("{}:{}:{}", vote.height, vote.round, hex::encode(&vote.block_hash));
        let signature_bytes: [u8; 64] = vote.signature.as_slice()
            .try_into()
            .map_err(|_| ConsensusError::InvalidSignature("Invalid signature length".into()))?;
        let signature = Signature::try_from(&signature_bytes[..])
            .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))?;
        
        if !vote.validator.verify(message.as_bytes(), &signature).is_ok() {
            return Ok(false);
        }

        // Verify validator exists and has voting power
        let validator_set = self.validator_set.read().await;
        let validator = validator_set.validators.iter()
            .find(|v| v.pub_key == vote.validator)
            .ok_or_else(|| ConsensusError::InvalidVote("Validator not found".into()))?;

        if validator.voting_power == 0 {
            return Ok(false);
        }

        Ok(true)
    }

    async fn verify_commit(&self, commit: &Commit) -> Result<bool, ConsensusError> {
        // Verify commit signatures
        let message = format!("{}:{}", commit.height, hex::encode(&commit.block_hash));
        let mut total_voting_power = 0;

        for vote in &commit.votes {
            let signature_bytes: [u8; 64] = vote.signature.as_slice()
                .try_into()
                .map_err(|_| ConsensusError::InvalidSignature("Invalid signature length".into()))?;
            let signature = Signature::try_from(&signature_bytes[..])
                .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))?;
            
            if !vote.validator.verify(message.as_bytes(), &signature).is_ok() {
                return Ok(false);
            }

            // Sum voting power
            let validator_set = self.validator_set.read().await;
            if let Some(validator) = validator_set.validators.iter()
                .find(|v| v.pub_key == vote.validator) 
            {
                total_voting_power += validator.voting_power;
            }
        }

        // Check if we have enough voting power
        let validator_set = self.validator_set.read().await;
        if total_voting_power <= validator_set.total_voting_power / 3 {
            return Ok(false);
        }

        Ok(true)
    }

    async fn verify_block(&self, block: &Block) -> Result<bool, ConsensusError> {
        // Verify block header
        if block.header.height != self.state.read().await.height {
            return Ok(false);
        }

        // Verify block hash
        if block.header.calculate_hash() != block.hash().as_bytes() {
            return Ok(false);
        }

        // Verify transactions
        for tx in &block.transactions {
            // Convert transaction::Transaction to consensus::Transaction
            let consensus_tx = Transaction::from(tx.clone());
            if !self.verify_transaction(&consensus_tx).await? {
                return Ok(false);
            }
        }

        // Verify state transitions
        if !self.verify_state_transitions(block).await? {
            return Ok(false);
        }

        Ok(true)
    }

    async fn verify_transaction(&self, tx: &Transaction) -> Result<bool, ConsensusError> {
        // Verify transaction signature
        let message = format!("{}:{}:{}:{}", 
            hex::encode(tx.sender.to_bytes()),
            hex::encode(tx.receiver.to_bytes()),
            tx.amount,
            tx.fee
        );
        let signature_bytes: [u8; 64] = tx.signature.as_slice()
            .try_into()
            .map_err(|_| ConsensusError::InvalidSignature("Invalid signature length".into()))?;
        let signature = Signature::try_from(&signature_bytes[..])
            .map_err(|e| ConsensusError::InvalidSignature(e.to_string()))?;
        
        if !tx.sender.verify(message.as_bytes(), &signature).is_ok() {
            return Ok(false);
        }

        // Verify transaction data
        if !self.verify_transaction_data(tx).await? {
            return Ok(false);
        }

        Ok(true)
    }

    async fn verify_transaction_data(&self, _tx: &Transaction) -> Result<bool, ConsensusError> {
        // Implement transaction-specific verification logic
        // This could include checking account balances, permissions, etc.
        Ok(true)
    }

    async fn verify_state_transitions(&self, block: &Block) -> Result<bool, ConsensusError> {
        // Get current state
        let state = self.state.read().await;
        
        // Apply transactions to a copy of the state
        let mut new_state = state.clone();
        for tx in &block.transactions {
            // Convert transaction::Transaction to consensus::Transaction
            let consensus_tx = Transaction::from(tx.clone());
            if !self.verify_transaction(&consensus_tx).await? {
                return Ok(false);
            }
            if !self.apply_transaction(&mut new_state, &consensus_tx).await? {
                return Ok(false);
            }
        }

        // Verify state root matches
        if new_state.state_tree.get_root() != block.header.state_root {
            return Ok(false);
        }

        Ok(true)
    }

    async fn apply_transaction(&self, _state: &mut ConsensusState, _tx: &Transaction) -> Result<bool, ConsensusError> {
        // TODO: Implement transaction application logic
        Ok(true)
    }

    async fn has_sufficient_votes(&self, votes: &[Vote]) -> Result<bool, ConsensusError> {
        let validator_set = self.validator_set.read().await;
        let mut total_voting_power = 0;

        for vote in votes {
            if let Some(validator) = validator_set.validators.iter()
                .find(|v| v.pub_key == vote.validator) 
            {
                total_voting_power += validator.voting_power;
            }
        }

        // Check if we have more than 2/3 of total voting power
        Ok(total_voting_power > (validator_set.total_voting_power * 2) / 3)
    }

    async fn create_vote(&self, block_hash: Vec<u8>) -> Result<Vote, ConsensusError> {
        let round_state = self.round_state.read().await;
        
        // Create vote message
        let message = format!("{}:{}:{}", round_state.height, round_state.round, hex::encode(&block_hash));
        
        // Sign message
        let signature = self.sign_message(message.as_bytes()).await?;

        Ok(Vote {
            validator: self.validator_key,
            height: round_state.height,
            round: round_state.round,
            block_hash,
            timestamp: Utc::now(),
            signature,
        })
    }

    async fn create_commit(&self, block_hash: Vec<u8>) -> Result<Commit, ConsensusError> {
        let round_state = self.round_state.read().await;
        
        // Convert HashMap votes to Vec<Vote>
        let votes: Vec<Vote> = round_state.votes.values().cloned().collect();
        
        // Create signature message with cloned block_hash
        let signature = self.sign_message(
            format!("{}:{}:{}", round_state.height, round_state.round, hex::encode(&block_hash.clone()))
            .as_bytes()
        ).await?;
        
        Ok(Commit {
            height: round_state.height,
            round: round_state.round,
            block_hash,
            votes,
            timestamp: Utc::now(),
            signature,
        })
    }

    async fn finalize_block(&self, proposal: &Proposal) -> Result<(), ConsensusError> {
        let mut state = self.state.write().await;
        let round_state = self.round_state.read().await;

        // Update state
        state.height += 1;
        state.last_committed_height = round_state.height;
        state.last_committed_round = round_state.round;

        // Apply block transactions
        for tx in &proposal.block.transactions {
            // Convert transaction::Transaction to consensus::Transaction
            let consensus_tx = Transaction::from(tx.clone());
            self.apply_transaction(&mut state, &consensus_tx).await?;
        }

        // Save block
        self.save_block(&proposal.block).await?;

        // Save state
        self.save_state().await?;

        // Start new height
        self.enter_new_height().await?;

        Ok(())
    }

    async fn save_block(&self, _block: &Block) -> Result<(), ConsensusError> {
        // TODO: Implement block persistence
        Ok(())
    }

    async fn save_state(&self) -> Result<(), ConsensusError> {
        // TODO: Implement state persistence
        Ok(())
    }

    fn is_validator(&self) -> bool {
        // Check if we're a validator in the current validator set
        let validator_set = self.validator_set.blocking_read();
        validator_set.validators.iter()
            .any(|v| v.pub_key == self.validator_key)
    }

    async fn broadcast_message(&self, message: ConsensusMessage) -> Result<(), ConsensusError> {
        // Implement message broadcasting with retry logic
        let mut retries = 0;
        let max_retries = 3;

        while retries < max_retries {
            match self.network.broadcast_message(message.clone()).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    retries += 1;
                    if retries == max_retries {
                        return Err(ConsensusError::NetworkError(e.to_string()));
                    }
                    time::sleep(TokioDuration::from_millis(100 * retries as u64)).await;
                }
            }
        }

        Ok(())
    }

    pub async fn create_proposal(&self) -> Result<Proposal, ConsensusError> {
        let round_state = self.round_state.read().await;
        
        // Check if we're the proposer
        if round_state.validators.proposer.as_ref().map(|v| v.pub_key) != Some(self.validator_key) {
            return Err(ConsensusError::InvalidState("Not the proposer".into()));
        }

        // Get transactions from mempool
        let transactions = self.get_transactions_from_mempool().await?;

        // Create block
        let block = self.create_block(transactions).await?;

        // Create proposal message
        let message = format!("{}:{}:{}", round_state.height, round_state.round, block.hash().clone());
        
        // Sign message
        let signature = self.sign_message(message.as_bytes()).await?;

        Ok(Proposal {
            proposer: self.validator_key,
            height: round_state.height,
            round: round_state.round,
            block,
            timestamp: Utc::now(),
            signature,
        })
    }

    async fn create_block(&self, transactions: Vec<Transaction>) -> Result<Block, ConsensusError> {
        let state = self.state.read().await;
        let round_state = self.round_state.read().await;

        // Calculate transaction root
        let merkle_root = self.calculate_transaction_root(&transactions).await?;

        // Convert transactions to the correct type
        let block_transactions: Vec<TypesTransaction> = transactions.into_iter()
            .map(|tx| TypesTransaction::from(tx))
            .collect();

        // Create block header
        let header = BlockHeader {
            version: 1,
            previous_hash: state.last_committed_hash.clone(),
            timestamp: Utc::now(),
            height: state.height,
            proposer: self.validator_key,
            transaction_root: merkle_root.clone(),
            state_root: state.state_tree.get_root(),
            app_hash: vec![0; 32], // Default app hash
            consensus_hash: vec![0; 32], // Default consensus hash
            evidence_root: vec![0; 32], // Default evidence root
            validator_hash: vec![0; 32], // Default validator hash
        };

        Ok(Block {
            header,
            transactions: block_transactions,
            merkle_root: hex::encode(merkle_root),
            state_root: hex::encode(state.state_tree.get_root()),
        })
    }

    async fn get_transactions_from_mempool(&self) -> Result<Vec<Transaction>, ConsensusError> {
        // Get transactions from network's mempool
        let mempool_txs = self.network.get_mempool().await
            .map_err(|e| ConsensusError::MempoolError(e.to_string()))?;

        // Map to our transaction type
        let transactions = mempool_txs.into_iter()
            .map(|tx| Transaction::from(tx))
            .collect();

        Ok(transactions)
    }

    async fn calculate_transaction_root(&self, transactions: &[Transaction]) -> Result<Vec<u8>, ConsensusError> {
        if transactions.is_empty() {
            return Ok(vec![0; 32]); // Empty merkle root
        }

        // Calculate transaction hashes
        let mut hashes: Vec<Vec<u8>> = transactions.iter()
            .map(|tx| {
                let mut hasher = Sha256::new();
                hasher.update(&tx.id);
                hasher.finalize().to_vec()
            })
            .collect();

        // Build merkle tree
        while hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate last hash if odd number
                }
                new_hashes.push(hasher.finalize().to_vec());
            }
            hashes = new_hashes;
        }

        Ok(hashes[0].clone())
    }

    async fn sign_message(&self, _message: &[u8]) -> Result<Vec<u8>, ConsensusError> {
        // TODO: Implement proper key management
        // For now, return a dummy signature
        Ok(vec![0; 64])
    }

    pub async fn recover_state(&self) -> Result<(), ConsensusError> {
        // Load last committed state
        if let Some(state) = self.load_last_committed_state().await? {
            let mut current_state = self.state.write().await;
            *current_state = state;
        }

        // Update validator set
        self.update_validator_set(Vec::new()).await?;

        // Process any pending evidence
        self.process_evidence().await?;

        Ok(())
    }

    async fn load_last_committed_state(&self) -> Result<Option<ConsensusState>, ConsensusError> {
        // TODO: Implement state loading from persistent storage
        Ok(None)
    }

    pub async fn monitor_peer_quality(&self) -> Result<(), ConsensusError> {
        let peers = self.network.get_peers().await
            .map_err(|e| ConsensusError::NetworkError(e.to_string()))?;

        for peer in peers {
            // Calculate peer quality metrics
            let latency = self.network.get_peer_latency(&peer).await
                .map_err(|e| ConsensusError::NetworkError(e.to_string()))?;
            
            let success_rate = self.network.get_peer_success_rate(&peer).await
                .map_err(|e| ConsensusError::NetworkError(e.to_string()))?;

            // Update peer quality in network manager
            self.network.update_peer_quality(peer, latency, success_rate).await
                .map_err(|e| ConsensusError::NetworkError(e.to_string()))?;
        }

        Ok(())
    }

    pub async fn get_validator_set(&self) -> Result<ValidatorSet, ConsensusError> {
        Ok(self.validator_set.read().await.clone())
    }

    pub async fn get_evidence_pool(&self) -> Result<EvidencePool, ConsensusError> {
        Ok(self.evidence_pool.read().await.clone())
    }

    pub async fn get_round_state(&self) -> Result<RoundState, ConsensusError> {
        Ok(self.round_state.read().await.clone())
    }

    pub async fn get_current_state(&self) -> Result<ConsensusState, ConsensusError> {
        let state = self.state.read().await;
        Ok((*state).clone())
    }

    pub async fn broadcast_new_round(&self, height: u64, round: u32) -> Result<(), ConsensusError> {
        let metadata = MessageMetadata {
            height,
            round,
            sender: self.validator_key,
            signature: Vec::new(), // This should be properly signed in a real implementation
            block_hash: None,
        };
        let message = ConsensusMessage::NewRound { metadata };
        self.broadcast_message(message).await
    }
}

// Add conversion between transaction types
impl From<Transaction> for TypesTransaction {
    fn from(tx: Transaction) -> Self {
        Self {
            id: hex::encode(&tx.id), // Convert Vec<u8> to hex string
            sender: hex::encode(tx.sender.to_bytes()), // Convert PublicKey to hex string
            recipient: hex::encode(tx.receiver.to_bytes()), // Convert PublicKey to hex string
            amount: tx.amount,
            timestamp: tx.timestamp,
            signature: Some(tx.signature),
            data: Some(vec![]), // Wrap empty vec in Some
            nonce: 0, // Default nonce
            gas_price: 0, // Default gas price
            gas_limit: 0, // Default gas limit
            chain_id: 1, // Default chain ID as u64
            version: 1, // Default version
        }
    }
}

impl From<TypesTransaction> for Transaction {
    fn from(tx: TypesTransaction) -> Self {
        // Convert hex strings to appropriate types
        let id = hex::decode(&tx.id).unwrap_or_default();
        
        // Convert hex strings to fixed-size arrays for PublicKey
        let sender_bytes = hex::decode(&tx.sender)
            .unwrap_or_default()
            .try_into()
            .unwrap_or_else(|_| [0; 32]);
        let sender = PublicKey::from_bytes(&sender_bytes)
            .unwrap_or_else(|_| PublicKey::from_bytes(&[0; 32]).unwrap());

        let receiver_bytes = hex::decode(&tx.recipient)
            .unwrap_or_default()
            .try_into()
            .unwrap_or_else(|_| [0; 32]);
        let receiver = PublicKey::from_bytes(&receiver_bytes)
            .unwrap_or_else(|_| PublicKey::from_bytes(&[0; 32]).unwrap());

        Self {
            id,
            sender,
            receiver,
            amount: tx.amount,
            fee: tx.gas_price * tx.gas_limit, // Use gas price and limit to calculate fee
            timestamp: tx.timestamp,
            signature: tx.signature.unwrap_or_default(),
        }
    }
}

// Add TransactionStatus enum if not already defined
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
}