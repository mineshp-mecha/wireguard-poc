use std::time::SystemTime;

use anyhow::{bail, Result};
use bytes::Bytes;
use local_ip_address::list_afinet_netifas;
use serde_json::{json, Value};
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver, Sender},
        oneshot,
    },
};

use crate::{
    messaging::{Messaging, MessagingMessage},
    wireguard::{PeerConfiguration, WgConfig, Wireguard},
};

pub struct AgentOptions {}

pub enum AgentMessage {
    Hello {
        name: String,
        reply_to: oneshot::Sender<Result<bool>>,
    },
}
#[derive(Debug)]
pub struct Agent {
    name: String,
    wg_config: WgConfig,
    msg_client: Messaging,
}

impl Agent {
    pub fn new(name: String, wg_config: WgConfig, messaging_tx: Sender<MessagingMessage>) -> Self {
        Self {
            name,
            wg_config,
            msg_client: Messaging::new(messaging_tx),
        }
    }
    pub async fn run(
        &mut self,
        mut agent_rx: mpsc::Receiver<AgentMessage>,
        mut messaging_rx: Receiver<MessagingMessage>,
        mut wg_client: Wireguard,
    ) -> Result<()> {
        // Step 1: Connect to nats
        let _ = match self.msg_client.connect().await {
            Ok(_) => (),
            Err(e) => {
                println!("Error connecting to nats: {}", e);
            }
        };

        // Step 2: Discover endpoints
        let endpoints = match discover_endpoints(self.wg_config.port) {
            Ok(res) => res,
            Err(e) => {
                println!("Error discovering endpoints: {}", e);
                vec![]
            }
        };
        println!("Endpoints: {:?}", endpoints);
        // Sync messages
        let _ = match self
            .msg_client
            .pull("wireguard".to_string(), "wireguard.hello".to_string())
            .await
        {
            Ok(_) => (),
            Err(e) => {
                println!("Error pulling messages: {}", e);
            }
        };

        loop {
            select! {
                msg = agent_rx.recv() => {
                    if msg.is_none() {
                        continue;
                    }
                    match msg.unwrap() {
                        AgentMessage::Hello { name, reply_to } => {
                            println!("Peer Request: name: {name}");
                            let peer_info = PeerConfiguration {
                                name: self.name.clone(),
                                public_key: self.wg_config.public_key.clone(),
                                allowed_ips: vec![self.wg_config.ip_address.clone()],
                                endpoint: endpoints.clone().into_iter().nth(0).unwrap(),
                            };
                            let _ = self.send_agent_hello(peer_info).await;
                           let _ = reply_to.send(Ok(true));
                        }
                    };
                }
                nats_msg = messaging_rx.recv() => {
                    if nats_msg.is_none() {
                        continue;
                    }
                    match nats_msg.unwrap() {
                        MessagingMessage::NatsMessage { subject, message, reply_to } => {
                            // Process message
                            let payload :PeerConfiguration = match process_message(message){
                                Ok(p) => p,
                                Err(e) => {
                                    println!("Error processing message: {}", e);
                                    continue;
                                }
                            };
                            if payload.name == self.name {
                                println!("Ignoring peer request as matched agent name.");
                                continue;
                            }
                            match wg_client.process_peer_request(subject, payload){
                                Ok(_) => (),
                                Err(e) => {
                                    println!("Error processing message: {}", e);
                                }
                            };
                            let _ = reply_to.send(Ok(true));
                        }
                    };
                }
            }
        }
    }
    async fn send_agent_hello(&self, payload: PeerConfiguration) -> Result<()> {
        let data = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(e) => {
                println!("Error converting payload to string - {}", e);
                bail!(e);
            }
        };
        let _ = self
            .msg_client
            .publish("wireguard.hello".to_string(), data)
            .await;
        Ok(())
    }
}

fn process_message(message: Bytes) -> Result<PeerConfiguration> {
    let slice = message.as_ref();

    // Parse the byte slice as JSON
    let payload_value: Value = match serde_json::from_slice(slice) {
        Ok(s) => s,
        Err(e) => {
            println!("Error converting payload to string - {}", e);
            bail!(e);
        }
    };
    let payload: PeerConfiguration = match serde_json::from_value(payload_value) {
        Ok(s) => s,
        Err(e) => {
            bail!(e)
        }
    };
    Ok(payload)
}

pub fn discover_endpoints(port: u32) -> Result<Vec<String>> {
    let network_interfaces = match list_afinet_netifas() {
        Ok(n) => n,
        Err(e) => {
            println!("Error discovering endpoints: {}", e);
            bail!(e)
        }
    };
    let mut endpoints = vec![];
    #[cfg(target_os = "macos")]
    for (name, ip) in network_interfaces.iter() {
        if name.to_lowercase().starts_with("en") {
            println!("{}:\t{:?}", name, ip);
            endpoints.push(ip.to_string());
        }
    }
    #[cfg(target_os = "linux")]
    for (name, ip) in network_interfaces.iter() {
        println!("{}:\t{:?}", name, ip);
        if name.to_lowercase().starts_with("wlan") || name.to_lowercase().starts_with("eth") {
            endpoints.push(ip.to_string());
        }
    }
    // add port to each ip address
    let endpoints: Vec<String> = endpoints
        .iter()
        .map(|ip| format!("{}:{}", ip, port))
        .collect();
    Ok(endpoints)
}
