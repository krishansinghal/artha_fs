use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use ed25519_dalek::PublicKey;
use log::{info, error, warn};
use rand::Rng;
use sha2::{Sha256, Digest};

use crate::network::{NetworkError, PeerInfo, NetworkMessage};

const K_BUCKET_SIZE: usize = 20;
const ALPHA: usize = 3; // Number of parallel requests
const MAX_PEERS: usize = 1000;
const PEER_EXCHANGE_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const PEER_CLEANUP_INTERVAL: Duration = Duration::from_secs(60); // 1 minute

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("DHT error: {0}")]
    DHTError(String),
    #[error("Peer error: {0}")]
    PeerError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeId([u8; 32]);

impl NodeId {
    pub fn new(pub_key: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pub_key.to_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        NodeId(id)
    }

    pub fn distance(&self, other: &NodeId) -> u32 {
        let mut distance = 0;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            let xor = a ^ b;
            if xor == 0 {
                distance += 8;
            } else {
                distance += xor.leading_zeros();
                break;
            }
        }
        distance
    }
}

#[derive(Debug, Clone)]
pub struct KBucket {
    nodes: Vec<(NodeId, PeerInfo)>,
    last_updated: Instant,
}

impl KBucket {
    pub fn new() -> Self {
        Self {
            nodes: Vec::with_capacity(K_BUCKET_SIZE),
            last_updated: Instant::now(),
        }
    }

    pub fn update(&mut self, node_id: NodeId, peer: PeerInfo) {
        // Check if node already exists
        if let Some(pos) = self.nodes.iter().position(|(id, _)| id.0 == node_id.0) {
            // Move to end (most recently seen)
            let node = self.nodes.remove(pos);
            self.nodes.push(node);
        } else if self.nodes.len() < K_BUCKET_SIZE {
            // Add new node if bucket not full
            self.nodes.push((node_id, peer));
        } else {
            // Replace oldest node if bucket is full
            self.nodes.remove(0);
            self.nodes.push((node_id, peer));
        }
        self.last_updated = Instant::now();
    }

    pub fn get_closest(&self, target: &NodeId, count: usize) -> Vec<PeerInfo> {
        let mut nodes = self.nodes.clone();
        nodes.sort_by(|a, b| {
            a.0.distance(target).cmp(&b.0.distance(target))
        });
        nodes.into_iter()
            .take(count)
            .map(|(_, peer)| peer)
            .collect()
    }
}

pub struct DHT {
    node_id: NodeId,
    k_buckets: Vec<KBucket>,
    bootstrap_nodes: Vec<SocketAddr>,
    known_peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    last_peer_exchange: Arc<RwLock<Instant>>,
}

impl DHT {
    pub fn new(pub_key: PublicKey, bootstrap_nodes: Vec<SocketAddr>) -> Self {
        Self {
            node_id: NodeId::new(&pub_key),
            k_buckets: vec![KBucket::new(); 256], // One bucket per bit
            bootstrap_nodes,
            known_peers: Arc::new(RwLock::new(HashMap::new())),
            last_peer_exchange: Arc::new(RwLock::new(Instant::now())),
        }
    }

    pub async fn start(&self) -> Result<(), DiscoveryError> {
        // Start bootstrap process
        self.bootstrap().await?;
        
        // Start periodic tasks
        self.start_periodic_tasks().await;
        
        Ok(())
    }

    async fn bootstrap(&self) -> Result<(), DiscoveryError> {
        // Try to connect to bootstrap nodes
        for addr in &self.bootstrap_nodes {
            if let Ok(peer) = self.ping_node(*addr).await {
                self.add_peer(peer).await;
            }
        }

        // If no bootstrap nodes available, try to discover peers
        if self.known_peers.read().await.is_empty() {
            self.discover_peers().await?;
        }

        Ok(())
    }

    async fn start_periodic_tasks(&self) {
        let known_peers = self.known_peers.clone();
        let last_peer_exchange = self.last_peer_exchange.clone();
        
        // Start peer exchange task
        tokio::spawn(async move {
            loop {
                if last_peer_exchange.read().await.elapsed() >= PEER_EXCHANGE_INTERVAL {
                    // Exchange peer lists with random peers
                    let peers = known_peers.read().await;
                    let mut rng = rand::thread_rng();
                    let peer_count = peers.len();
                    
                    if peer_count > 0 {
                        let sample_size = std::cmp::min(ALPHA, peer_count);
                        let random_peers: Vec<_> = peers.values()
                            .choose_multiple(&mut rng, sample_size)
                            .collect();
                        
                        for peer in random_peers {
                            // Request peer list from peer
                            // This would typically send a PEX_REQUEST message
                        }
                    }
                    
                    *last_peer_exchange.write().await = Instant::now();
                }
                
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        // Start cleanup task
        let known_peers = self.known_peers.clone();
        tokio::spawn(async move {
            loop {
                let mut peers = known_peers.write().await;
                peers.retain(|_, peer| {
                    peer.last_seen.elapsed() < PEER_CLEANUP_INTERVAL
                });
                
                tokio::time::sleep(PEER_CLEANUP_INTERVAL).await;
            }
        });
    }

    pub async fn discover_peers(&self) -> Result<Vec<PeerInfo>, DiscoveryError> {
        let mut discovered_peers = Vec::new();
        let mut queried_peers = HashSet::new();
        let mut to_query = Vec::new();
        
        // Start with known peers
        {
            let peers = self.known_peers.read().await;
            to_query.extend(peers.values().cloned());
        }

        while !to_query.is_empty() && discovered_peers.len() < MAX_PEERS {
            // Take next batch of peers to query
            let batch: Vec<_> = to_query.drain(..std::cmp::min(ALPHA, to_query.len())).collect();
            
            // Query peers in parallel
            let mut handles = Vec::new();
            for peer in batch {
                if !queried_peers.contains(&peer.id) {
                    queried_peers.insert(peer.id.clone());
                    handles.push(self.query_peer(peer));
                }
            }
            
            // Wait for all queries to complete
            for result in futures::future::join_all(handles).await {
                match result {
                    Ok(new_peers) => {
                        for peer in new_peers {
                            if !queried_peers.contains(&peer.id) {
                                discovered_peers.push(peer.clone());
                                to_query.push(peer);
                            }
                        }
                    }
                    Err(e) => warn!("Failed to query peer: {}", e),
                }
            }
        }

        Ok(discovered_peers)
    }

    async fn query_peer(&self, peer: PeerInfo) -> Result<Vec<PeerInfo>, DiscoveryError> {
        // Send FIND_NODE request to peer
        // This would typically send a DHT message and wait for response
        // For now, return empty vector
        Ok(Vec::new())
    }

    async fn ping_node(&self, addr: SocketAddr) -> Result<PeerInfo, DiscoveryError> {
        // Implement ping logic
        // This would typically:
        // 1. Connect to the node
        // 2. Send PING message
        // 3. Wait for PONG response
        // 4. Return peer info
        Err(DiscoveryError::NetworkError("Not implemented".into()))
    }

    pub async fn add_peer(&self, peer: PeerInfo) {
        let node_id = NodeId::new(&peer.pub_key);
        let distance = self.node_id.distance(&node_id);
        
        // Update k-bucket
        if let Some(bucket) = self.k_buckets.get_mut(distance as usize) {
            bucket.update(node_id, peer.clone());
        }
        
        // Update known peers
        self.known_peers.write().await.insert(peer.id.clone(), peer);
    }

    pub async fn get_closest_peers(&self, target: &PublicKey, count: usize) -> Vec<PeerInfo> {
        let target_id = NodeId::new(target);
        let mut closest_peers = Vec::new();
        
        // Get closest peers from each k-bucket
        for bucket in &self.k_buckets {
            closest_peers.extend(bucket.get_closest(&target_id, count));
        }
        
        // Sort by distance and take closest
        closest_peers.sort_by(|a, b| {
            let dist_a = NodeId::new(&a.pub_key).distance(&target_id);
            let dist_b = NodeId::new(&b.pub_key).distance(&target_id);
            dist_a.cmp(&dist_b)
        });
        
        closest_peers.into_iter().take(count).collect()
    }
}

pub struct PeerDiscovery {
    dht: Arc<RwLock<DHT>>,
    known_peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    bootstrap_nodes: Vec<SocketAddr>,
    discovery_interval: Duration,
}

impl PeerDiscovery {
    pub fn new(
        pub_key: PublicKey,
        bootstrap_nodes: Vec<SocketAddr>,
        discovery_interval: Duration,
    ) -> Self {
        let dht = Arc::new(RwLock::new(DHT::new(pub_key, bootstrap_nodes.clone())));
        
        Self {
            dht,
            known_peers: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_nodes,
            discovery_interval,
        }
    }

    pub async fn start(&self) -> Result<(), DiscoveryError> {
        // Start DHT
        self.dht.write().await.start().await?;
        
        // Start periodic discovery
        self.start_periodic_discovery().await;
        
        Ok(())
    }

    async fn start_periodic_discovery(&self) {
        let dht = self.dht.clone();
        let known_peers = self.known_peers.clone();
        
        tokio::spawn(async move {
            loop {
                // Discover new peers
                if let Ok(new_peers) = dht.read().await.discover_peers().await {
                    let mut peers = known_peers.write().await;
                    for peer in new_peers {
                        peers.insert(peer.id.clone(), peer);
                    }
                }
                
                tokio::time::sleep(dht.read().await.discovery_interval).await;
            }
        });
    }

    pub async fn discover_peers(&self) -> Result<Vec<PeerInfo>, DiscoveryError> {
        self.dht.read().await.discover_peers().await
    }

    pub async fn add_peer(&self, peer: PeerInfo) {
        self.dht.write().await.add_peer(peer).await;
    }

    pub async fn get_closest_peers(&self, target: &PublicKey, count: usize) -> Vec<PeerInfo> {
        self.dht.read().await.get_closest_peers(target, count).await
    }
} 