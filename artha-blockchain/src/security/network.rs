use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use crate::security::SecurityManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub public_key: Vec<u8>,
    pub last_seen: DateTime<Utc>,
    pub connection_count: u32,
    pub failed_attempts: u32,
    pub ban_until: Option<DateTime<Utc>>,
    pub reputation_score: i32,
    pub is_whitelisted: bool,
    pub is_blacklisted: bool,
    pub bandwidth_usage: u64,
    pub last_message_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub peer_count: u32,
    pub active_connections: u32,
    pub banned_peers: u32,
    pub total_bandwidth_usage: u64,
    pub message_rate: f64,
    pub sync_status: SyncStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    Synced,
    Syncing(u64), // Current block height
    NotSynced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_connections: u32,
    pub max_messages_per_second: u32,
    pub max_bandwidth_per_second: u64,
    pub ban_duration_minutes: u32,
    pub reputation_threshold: i32,
}

pub struct NetworkSecurityManager {
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    metrics: Arc<RwLock<NetworkMetrics>>,
    rate_limits: RateLimit,
    security_manager: Arc<SecurityManager>,
    message_history: Arc<RwLock<HashMap<String, Vec<(DateTime<Utc>, Vec<u8>)>>>>, // peer -> (timestamp, message_hash)
}

impl NetworkSecurityManager {
    pub fn new(security_manager: Arc<SecurityManager>) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(NetworkMetrics {
                peer_count: 0,
                active_connections: 0,
                banned_peers: 0,
                total_bandwidth_usage: 0,
                message_rate: 0.0,
                sync_status: SyncStatus::NotSynced,
            })),
            rate_limits: RateLimit {
                max_connections: 100,
                max_messages_per_second: 1000,
                max_bandwidth_per_second: 10_000_000, // 10 MB/s
                ban_duration_minutes: 60,
                reputation_threshold: -50,
            },
            security_manager,
            message_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_peer(&self, address: String, public_key: Vec<u8>) -> Result<(), String> {
        let mut peers = self.peers.write().await;
        if peers.contains_key(&address) {
            return Err("Peer already exists".to_string());
        }

        let peer_info = PeerInfo {
            address: address.clone(),
            public_key,
            last_seen: Utc::now(),
            connection_count: 0,
            failed_attempts: 0,
            ban_until: None,
            reputation_score: 0,
            is_whitelisted: false,
            is_blacklisted: false,
            bandwidth_usage: 0,
            last_message_hash: None,
        };

        peers.insert(address, peer_info);
        self.update_metrics().await;
        Ok(())
    }

    pub async fn update_peer_status(&self, address: &str, success: bool) -> Result<(), String> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(address) {
            peer.last_seen = Utc::now();
            if success {
                peer.connection_count += 1;
                peer.failed_attempts = 0;
                peer.reputation_score = (peer.reputation_score + 1).min(100);
            } else {
                peer.failed_attempts += 1;
                peer.reputation_score = (peer.reputation_score - 5).max(-100);
                
                if peer.failed_attempts >= 3 || peer.reputation_score <= self.rate_limits.reputation_threshold {
                    self.ban_peer(address).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn ban_peer(&self, address: &str) -> Result<(), String> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(address) {
            peer.ban_until = Some(Utc::now() + Duration::minutes(self.rate_limits.ban_duration_minutes as i64));
            peer.is_blacklisted = true;
            self.update_metrics().await;
        }
        Ok(())
    }

    pub async fn check_rate_limit(&self, address: &str, message_size: u64) -> Result<bool, String> {
        let mut peers = self.peers.write().await;
        let mut message_history = self.message_history.write().await;
        
        if let Some(peer) = peers.get_mut(address) {
            // Check if peer is banned
            if let Some(ban_until) = peer.ban_until {
                if Utc::now() < ban_until {
                    return Ok(false);
                }
                peer.ban_until = None;
                peer.is_blacklisted = false;
            }

            // Check bandwidth usage
            peer.bandwidth_usage += message_size;
            if peer.bandwidth_usage > self.rate_limits.max_bandwidth_per_second {
                self.ban_peer(address).await?;
                return Ok(false);
            }

            // Check message rate
            let now = Utc::now();
            let peer_messages = message_history.entry(address.to_string())
                .or_insert_with(Vec::new);
            
            // Remove old messages
            peer_messages.retain(|(time, _)| (now - *time).num_seconds() < 1);
            
            if peer_messages.len() >= self.rate_limits.max_messages_per_second as usize {
                self.ban_peer(address).await?;
                return Ok(false);
            }

            // Add new message
            peer_messages.push((now, vec![])); // In real implementation, store message hash
        }

        Ok(true)
    }

    pub async fn verify_peer_message(&self, address: &str, message: &[u8], signature: &[u8]) -> Result<bool, String> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(address) {
            // Verify message signature
            let signature = ed25519_dalek::Signature::from_bytes(signature)
                .map_err(|_| "Invalid signature format")?;
            
            self.security_manager.verify_signature(
                &hex::encode(&peer.public_key),
                message,
                &signature
            ).await
        } else {
            Err("Unknown peer".to_string())
        }
    }

    async fn update_metrics(&self) {
        let peers = self.peers.read().await;
        let mut metrics = self.metrics.write().await;
        
        metrics.peer_count = peers.len() as u32;
        metrics.active_connections = peers.values()
            .filter(|p| p.ban_until.is_none())
            .count() as u32;
        metrics.banned_peers = peers.values()
            .filter(|p| p.ban_until.is_some())
            .count() as u32;
        metrics.total_bandwidth_usage = peers.values()
            .map(|p| p.bandwidth_usage)
            .sum();
    }

    pub async fn get_metrics(&self) -> NetworkMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn cleanup_old_peers(&self, max_age_hours: i64) {
        let mut peers = self.peers.write().await;
        let now = Utc::now();
        
        peers.retain(|_, peer| {
            (now - peer.last_seen).num_hours() < max_age_hours || peer.is_whitelisted
        });
        
        self.update_metrics().await;
    }

    pub async fn whitelist_peer(&self, address: &str) -> Result<(), String> {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(address) {
            peer.is_whitelisted = true;
            peer.is_blacklisted = false;
            peer.ban_until = None;
            peer.reputation_score = 100;
        }
        Ok(())
    }
} 