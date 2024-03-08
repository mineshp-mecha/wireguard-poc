use anyhow::{bail, Result};
use bytes::Bytes;
use defguard_wireguard_rs::{
    host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, WireguardApiUserspace,
    WireguardInterfaceApi,
};
use hex::encode;
use local_ip_address::list_afinet_netifas;
use serde::{Deserialize, Serialize};
use serde_json::{from_reader, to_writer};
use std::{
    fs::File,
    io::{stdin, stdout, Read, Write},
    net::SocketAddr,
    str::FromStr,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerConfiguration {
    pub name: String, // peer name
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct WgConfig {
    pub secret_key: String,
    pub public_key: String,
    pub ip_address: String,
    pub port: u32,
    pub interface_name: String,
}

#[derive(Clone)]
pub struct Wireguard {
    pub api: WireguardApiUserspace,
    pub ifname: String,
}
impl Wireguard {
    pub fn new(ifname: String) -> Self {
        let api = WireguardApiUserspace::new(ifname.clone()).unwrap();
        Self { api, ifname }
    }

    /// Responsible for setting up wireguard interface
    #[cfg(target_os = "macos")]
    pub fn setup_wireguard(&mut self, wg_config: &WgConfig) -> Result<bool> {
        let ifname = self.ifname.clone();

        // Remove existing
        match self.api.remove_interface() {
            Ok(_) => println!("Interface {ifname} removed."),
            Err(e) => {
                println!("Error removing interface: {}", e);
            }
        };

        // create interface
        match self.api.create_interface() {
            Ok(_) => (),
            Err(e) => {
                println!("Error creating interface: {}", e);
                return Err(e.into());
            }
        };

        // interface configuration
        let interface_config = InterfaceConfiguration {
            name: ifname.clone(),
            prvkey: wg_config.secret_key.clone(),
            address: wg_config.ip_address.clone(),
            port: wg_config.port,
            peers: vec![],
        };

        #[cfg(not(windows))]
        match self.api.configure_interface(&interface_config) {
            Ok(_) => (),
            Err(e) => {
                println!("Error configuring interface: {}", e);
                return Err(e.into());
            }
        };
        println!("Interface {ifname} configured.");
        // pause();

        Ok(true)
    }
    pub fn add_peer(
        &mut self,
        peer_configuration: PeerConfiguration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ifname = self.ifname.clone();

        // Peer configuration
        let secret = EphemeralSecret::random();
        let key = PublicKey::from(&secret);
        // Peer secret key
        let peer_key: Key = key.as_ref().try_into().unwrap();
        let mut peer = Peer::new(peer_key.clone());

        println!("peer configuration: {:?}", peer_configuration);
        // Your WireGuard server endpoint which peer connects too
        if peer_configuration.name == "node1" {
            peer.endpoint = Some("192.168.206.92:51820".parse().unwrap());
        } else {
            peer.endpoint = Some("192.168.206.92:51821".parse().unwrap());
        }
        // let endpoint: SocketAddr = peer_configuration.endpoint.parse().unwrap();
        // // Peer endpoint and interval
        // peer.endpoint = Some(endpoint);
        peer.persistent_keepalive_interval = Some(25);

        // Peer allowed ips
        for allowed_ip in peer_configuration.allowed_ips {
            let addr = IpAddrMask::from_str(&allowed_ip)?;
            peer.allowed_ips.push(addr);
        }

        match self.api.configure_peer(&peer) {
            Ok(_) => println!("Peer {:?} configured.", peer_configuration.name),
            Err(e) => {
                println!("Error configuring peer: {}", e);
                return Err(e.into());
            }
        }
        Ok(())
    }
    pub fn process_peer_request(
        &mut self,
        subject: String,
        message: PeerConfiguration,
    ) -> Result<()> {
        match self.add_peer(message) {
            Ok(_) => (),
            Err(e) => {
                println!("Error adding peer: {}", e);
                bail!(e.to_string())
            }
        }
        Ok(())
    }
}
pub fn generate_new_key_pair(file_name: String, config: WgConfig) -> Result<WgConfig> {
    let wg_secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let wg_public_key = PublicKey::from(&wg_secret_key);

    let secret_key_bytes = wg_secret_key.to_bytes();
    let public_key_bytes = wg_public_key.to_bytes();
    //store to file
    let wg_key_pair = WgConfig {
        interface_name: config.interface_name,
        secret_key: encode(secret_key_bytes),
        public_key: encode(public_key_bytes),
        ip_address: config.ip_address,
        port: config.port,
    };
    let mut file = match File::create(file_name) {
        Ok(f) => f,
        Err(e) => {
            println!("Error creating file: {}", e);
            bail!(e)
        }
    };
    match to_writer(&mut file, &wg_key_pair) {
        Ok(_) => (),
        Err(e) => {
            println!("Error writing to file: {}", e);
            bail!(e)
        }
    };
    Ok(wg_key_pair)
}

pub fn read_config(filename: &str) -> Result<WgConfig> {
    let mut file = match File::open(filename) {
        Ok(f) => f,
        Err(e) => {
            println!("Error opening file: {}", e);
            bail!(e)
        }
    };
    let config: WgConfig = match from_reader(&mut file) {
        Ok(c) => c,
        Err(e) => {
            println!("Error reading file: {}", e);
            bail!(e)
        }
    };
    Ok(config)
}
