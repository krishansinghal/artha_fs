use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, TcpListener};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, timeout};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use ed25519_dalek::PublicKey;
use futures::StreamExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use bincode::{serialize, deserialize};
use log::{info, error, warn};

use crate::network::{NetworkMessage, NetworkError, PeerInfo, RateLimit};

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_millis(100);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    #[error("Handshake error: {0}")]
    HandshakeError(String),
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
}

pub struct Connection {
    stream: TcpStream,
    peer_info: PeerInfo,
    rate_limit: RateLimit,
    message_queue: mpsc::Sender<NetworkMessage>,
    last_message_time: Arc<RwLock<Instant>>,
    message_count: Arc<RwLock<u32>>,
    byte_count: Arc<RwLock<u64>>,
}

impl Connection {
    pub async fn new(
        stream: TcpStream,
        peer_info: PeerInfo,
        rate_limit: RateLimit,
        message_queue: mpsc::Sender<NetworkMessage>,
    ) -> Result<Self, ConnectionError> {
        let connection = Self {
            stream,
            peer_info,
            rate_limit,
            message_queue,
            last_message_time: Arc::new(RwLock::new(Instant::now())),
            message_count: Arc::new(RwLock::new(0)),
            byte_count: Arc::new(RwLock::new(0)),
        };

        // Perform handshake
        connection.perform_handshake().await?;

        Ok(connection)
    }

    async fn perform_handshake(&self) -> Result<(), ConnectionError> {
        // Send handshake message
        let handshake = HandshakeMessage {
            version: env!("CARGO_PKG_VERSION").to_string(),
            network_id: "artha-mainnet".to_string(),
            pub_key: self.peer_info.pub_key,
            timestamp: Utc::now(),
        };

        self.send_message(NetworkMessage::Handshake(handshake)).await?;

        // Wait for handshake response with timeout
        match timeout(HANDSHAKE_TIMEOUT, self.receive_message()).await {
            Ok(Ok(NetworkMessage::Handshake(response))) => {
                // Verify handshake response
                if response.network_id != "artha-mainnet" {
                    return Err(ConnectionError::HandshakeError("Invalid network ID".into()));
                }
                if response.version != env!("CARGO_PKG_VERSION") {
                    warn!("Peer version mismatch: {} vs {}", response.version, env!("CARGO_PKG_VERSION"));
                }
                Ok(())
            }
            Ok(Ok(_)) => Err(ConnectionError::HandshakeError("Invalid handshake response".into())),
            Ok(Err(e)) => Err(ConnectionError::HandshakeError(e.to_string())),
            Err(_) => Err(ConnectionError::TimeoutError("Handshake timeout".into())),
        }
    }

    pub async fn start(&self) -> Result<(), ConnectionError> {
        let mut framed = Framed::new(self.stream.clone(), LengthDelimitedCodec::new());
        
        loop {
            // Check rate limits
            if !self.check_rate_limits().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            // Receive message
            match framed.next().await {
                Some(Ok(bytes)) => {
                    // Update rate limit counters
                    self.update_rate_limits(bytes.len() as u64).await;

                    // Deserialize and process message
                    match deserialize(&bytes) {
                        Ok(message) => {
                            if let Err(e) = self.message_queue.send(message).await {
                                error!("Failed to send message to queue: {}", e);
                            }
                        }
                        Err(e) => error!("Failed to deserialize message: {}", e),
                    }
                }
                Some(Err(e)) => {
                    error!("Connection error: {}", e);
                    break;
                }
                None => break,
            }
        }

        Ok(())
    }

    pub async fn send_message(&self, message: NetworkMessage) -> Result<(), ConnectionError> {
        // Check rate limits
        if !self.check_rate_limits().await {
            return Err(ConnectionError::RateLimitExceeded("Rate limit exceeded".into()));
        }

        // Serialize message
        let bytes = serialize(&message)?;
        
        // Update rate limit counters
        self.update_rate_limits(bytes.len() as u64).await;

        // Send with retries
        let mut retries = 0;
        while retries < MAX_RETRIES {
            match self.stream.write_all(&bytes).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    retries += 1;
                    if retries == MAX_RETRIES {
                        return Err(ConnectionError::IoError(e));
                    }
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }

        Ok(())
    }

    async fn receive_message(&self) -> Result<NetworkMessage, ConnectionError> {
        let mut framed = Framed::new(self.stream.clone(), LengthDelimitedCodec::new());
        
        match framed.next().await {
            Some(Ok(bytes)) => {
                // Update rate limit counters
                self.update_rate_limits(bytes.len() as u64).await;

                // Deserialize message
                Ok(deserialize(&bytes)?)
            }
            Some(Err(e)) => Err(ConnectionError::IoError(e)),
            None => Err(ConnectionError::IoError(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Connection closed",
            ))),
        }
    }

    async fn check_rate_limits(&self) -> bool {
        let now = Instant::now();
        let mut last_message_time = self.last_message_time.write().await;
        let mut message_count = self.message_count.write().await;
        let mut byte_count = self.byte_count.write().await;

        // Reset counters if interval has passed
        if now.duration_since(*last_message_time) >= Duration::from_secs(1) {
            *message_count = 0;
            *byte_count = 0;
            *last_message_time = now;
        }

        // Check message rate
        if *message_count >= self.rate_limit.messages_per_second {
            return false;
        }

        // Check byte rate
        if *byte_count >= self.rate_limit.bytes_per_second {
            return false;
        }

        true
    }

    async fn update_rate_limits(&self, bytes: u64) {
        let mut message_count = self.message_count.write().await;
        let mut byte_count = self.byte_count.write().await;
        
        *message_count += 1;
        *byte_count += bytes;
    }
}

pub struct ConnectionManager {
    listener: TcpListener,
    connections: Arc<RwLock<HashMap<String, Connection>>>,
    rate_limit: RateLimit,
    message_queue: mpsc::Sender<NetworkMessage>,
}

impl ConnectionManager {
    pub async fn new(
        addr: SocketAddr,
        rate_limit: RateLimit,
        message_queue: mpsc::Sender<NetworkMessage>,
    ) -> Result<Self, ConnectionError> {
        let listener = TcpListener::bind(addr).await?;
        
        Ok(Self {
            listener,
            connections: Arc::new(RwLock::new(HashMap::new())),
            rate_limit,
            message_queue,
        })
    }

    pub async fn start(&self) -> Result<(), ConnectionError> {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    let peer_info = PeerInfo {
                        id: addr.to_string(),
                        address: addr,
                        pub_key: PublicKey::default(), // Will be updated during handshake
                        version: String::new(),
                        network_id: String::new(),
                        last_seen: Utc::now(),
                        connection_quality: 1.0,
                        bandwidth_usage: 0,
                        message_count: 0,
                        error_count: 0,
                    };

                    let connection = Connection::new(
                        stream,
                        peer_info,
                        self.rate_limit.clone(),
                        self.message_queue.clone(),
                    ).await?;

                    let peer_id = connection.peer_info.id.clone();
                    self.connections.write().await.insert(peer_id, connection);

                    // Start connection handling
                    tokio::spawn(async move {
                        if let Err(e) = connection.start().await {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => error!("Failed to accept connection: {}", e),
            }
        }
    }

    pub async fn connect_to_peer(&self, addr: SocketAddr) -> Result<(), ConnectionError> {
        let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await??;
        
        let peer_info = PeerInfo {
            id: addr.to_string(),
            address: addr,
            pub_key: PublicKey::default(), // Will be updated during handshake
            version: String::new(),
            network_id: String::new(),
            last_seen: Utc::now(),
            connection_quality: 1.0,
            bandwidth_usage: 0,
            message_count: 0,
            error_count: 0,
        };

        let connection = Connection::new(
            stream,
            peer_info,
            self.rate_limit.clone(),
            self.message_queue.clone(),
        ).await?;

        let peer_id = connection.peer_info.id.clone();
        self.connections.write().await.insert(peer_id, connection);

        Ok(())
    }

    pub async fn broadcast_message(&self, message: NetworkMessage) -> Result<(), ConnectionError> {
        let connections = self.connections.read().await;
        for connection in connections.values() {
            if let Err(e) = connection.send_message(message.clone()).await {
                error!("Failed to send message to peer {}: {}", connection.peer_info.id, e);
            }
        }
        Ok(())
    }
} 