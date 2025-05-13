use libp2p::{
    identity,
    swarm::{Swarm, SwarmEvent, NetworkBehaviour},
    PeerId,
    futures::StreamExt,
    core::upgrade,
    noise,
    tcp,
    yamux,
    Transport,
};
use libp2p::floodsub::{Floodsub, FloodsubEvent, Topic};
use libp2p::mdns::{tokio::Behaviour as Mdns, Event as MdnsEvent, Config as MdnsConfig};
use tokio::sync::mpsc;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::types::{Block, Transaction, TransactionPool};
use crate::consensus::tendermint::{ConsensusMessage, ConsensusState};

#[derive(Debug)]
pub enum NetworkEvent {
    Floodsub(FloodsubEvent),
    Mdns(MdnsEvent),
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NetworkEvent")]
pub struct BlockchainBehaviour {
    pub floodsub: Floodsub,
    pub mdns: Mdns,
}

impl From<FloodsubEvent> for NetworkEvent {
    fn from(event: FloodsubEvent) -> Self {
        NetworkEvent::Floodsub(event)
    }
}

impl From<MdnsEvent> for NetworkEvent {
    fn from(event: MdnsEvent) -> Self {
        NetworkEvent::Mdns(event)
    }
}

pub struct P2PNetwork {
    swarm: Swarm<BlockchainBehaviour>,
    event_sender: mpsc::Sender<NetworkEvent>,
    event_receiver: mpsc::Receiver<NetworkEvent>,
}

impl P2PNetwork {
    pub async fn new(
        _consensus_state: Arc<Mutex<ConsensusState>>,
        _transaction_pool: Arc<Mutex<TransactionPool>>,
    ) -> Result<Self, Box<dyn Error>> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        println!("Local peer id: {:?}", local_peer_id);

        let transport = {
            let tcp = tcp::tokio::Transport::default();
            let noise = noise::Config::new(&local_key)?;
            let yamux = yamux::Config::default();
            tcp.upgrade(upgrade::Version::V1)
                .authenticate(noise)
                .multiplex(yamux)
                .boxed()
        };

        let mut floodsub = Floodsub::new(local_peer_id);
        floodsub.subscribe(Topic::new("blocks"));
        floodsub.subscribe(Topic::new("transactions"));
        floodsub.subscribe(Topic::new("consensus"));

        let mdns = Mdns::new(MdnsConfig::default(), local_peer_id)?;

        let behaviour = BlockchainBehaviour {
            floodsub,
            mdns,
        };

        let swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );

        let (event_sender, event_receiver) = mpsc::channel(100);

        Ok(Self {
            swarm,
            event_sender,
            event_receiver,
        })
    }

    pub async fn start(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        self.swarm.listen_on(addr.parse()?)?;
        Ok(())
    }

    pub async fn broadcast_block(&mut self, block: &Block) -> Result<(), Box<dyn Error>> {
        let message = serde_json::to_vec(block)?;
        self.swarm.behaviour_mut().floodsub.publish(Topic::new("blocks"), message);
        Ok(())
    }

    pub async fn broadcast_transaction(&mut self, transaction: &Transaction) -> Result<(), Box<dyn Error>> {
        let message = serde_json::to_vec(transaction)?;
        self.swarm.behaviour_mut().floodsub.publish(Topic::new("transactions"), message);
        Ok(())
    }

    pub async fn broadcast_consensus_message(&mut self, message: &ConsensusMessage) -> Result<(), Box<dyn Error>> {
        let message = serde_json::to_vec(message)?;
        self.swarm.behaviour_mut().floodsub.publish(Topic::new("consensus"), message);
        Ok(())
    }

    pub async fn run(&mut self) {
        while let Some(event) = self.swarm.next().await {
            match event {
                SwarmEvent::Behaviour(event) => {
                    if let Err(e) = self.event_sender.send(event).await {
                        eprintln!("Error sending network event: {}", e);
                    }
                }
                _ => {}
            }
        }
    }
} 