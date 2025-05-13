use async_trait::async_trait;
use std::collections::HashMap;
use crate::types::block::Block;

#[derive(Debug, Clone)]
pub struct Vote {
    pub block_hash: String,
    pub validator: String,
}

#[derive(Debug)]
pub struct ConsensusState {
    pub votes: HashMap<String, Vec<Vote>>,
    pub finalized_blocks: Vec<String>,
}

pub struct SVBFTConsensus {
    state: ConsensusState,
    validators: Vec<String>,
    threshold: usize,
}

impl SVBFTConsensus {
    pub fn new(validators: Vec<String>, threshold: usize) -> Self {
        Self {
            state: ConsensusState {
                votes: HashMap::new(),
                finalized_blocks: Vec::new(),
            },
            validators,
            threshold,
        }
    }

    pub fn add_vote(&mut self, vote: Vote) -> bool {
        let block_votes = self.state.votes
            .entry(vote.block_hash.clone())
            .or_insert_with(Vec::new);

        block_votes.push(vote.clone());

        let vote_count = block_votes.len();
        if vote_count >= self.threshold {
            if !self.state.finalized_blocks.contains(&vote.block_hash) {
                self.state.finalized_blocks.push(vote.block_hash);
                return true;
            }
        }
        false
    }

    pub fn is_finalized(&self, block_hash: &str) -> bool {
        self.state.finalized_blocks.iter().any(|h| h == block_hash)
    }

    pub fn get_vote_count(&self, block_hash: &str) -> usize {
        self.state.votes
            .get(block_hash)
            .map_or(0, |votes| votes.len())
    }

    pub fn get_finalized_blocks_count(&self) -> usize {
        self.state.finalized_blocks.len()
    }

    pub fn get_pending_votes_count(&self) -> usize {
        self.state.votes.len()
    }

    pub async fn propose_block(&mut self, _block: Block) -> Result<(), String> {
        // Implementation for block proposal
        Ok(())
    }
}

#[async_trait]
pub trait ConsensusProtocol {
    async fn propose_block(&mut self, block: Block) -> Result<(), String>;
    async fn vote(&mut self, block_hash: String, voter_id: String, social_value_score: f64) -> Result<(), String>;
    async fn finalize_block(&mut self, block_hash: String) -> Result<(), String>;
}

#[async_trait]
impl ConsensusProtocol for SVBFTConsensus {
    async fn propose_block(&mut self, _block: Block) -> Result<(), String> {
        // In a real implementation, this would broadcast the block to the network
        Ok(())
    }

    async fn vote(&mut self, block_hash: String, voter_id: String, _social_value_score: f64) -> Result<(), String> {
        let vote = Vote {
            block_hash,
            validator: voter_id,
        };
        
        if self.add_vote(vote) {
            Ok(())
        } else {
            Err("Not enough votes to finalize block".to_string())
        }
    }

    async fn finalize_block(&mut self, block_hash: String) -> Result<(), String> {
        if self.is_finalized(&block_hash) {
            Ok(())
        } else {
            Err("Block not finalized".to_string())
        }
    }
} 