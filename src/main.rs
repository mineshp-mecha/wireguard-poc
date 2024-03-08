use std::{env, time::Duration};

use anyhow::{bail, Result};
use tokio::{sync::mpsc, time::sleep};
use wireguard::{read_config, WgConfig, Wireguard};

use crate::{
    agent::{Agent, AgentMessage},
    wireguard::generate_new_key_pair,
};
pub mod agent;
pub mod messaging;
pub mod wireguard;
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Read agent_name and wireguard details from arguments
    let args: Vec<String> = env::args().collect();
    let (agent_name, ifname, address, port) = read_agent_and_wg_info(&args);

    // Step 1: key pair exist? if not create
    let wg_config = match read_key_pair_or_create_new(&agent_name, &ifname, &address, port) {
        Ok(key_pair) => key_pair,
        Err(e) => {
            println!("Error reading key pair: {}", e);
            bail!(e);
        }
    };

    // Step 2: Create agent
    let (agent_tx, agent_rx) = mpsc::channel(32);
    let (messaging_tx, messaging_rx) = mpsc::channel(32);
    let mut agent = Agent::new(agent_name.clone(), wg_config.clone(), messaging_tx.clone());

    //  Step 3: Setup wireguard
    let mut wireguard = Wireguard::new(ifname.clone());
    match wireguard.setup_wireguard(&wg_config) {
        Ok(_) => (),
        Err(e) => {
            println!("Error setting up wireguard: {}", e);
            bail!(e);
        }
    };

    // Step 4: Run agent and Nats connect
    let agent_t = tokio::spawn(async move {
        match agent.run(agent_rx, messaging_rx, wireguard.clone()).await {
            Ok(_) => (),
            Err(e) => {
                println!("Error running agent: {}", e);
                bail!(e);
            }
        };
        Ok(())
    });

    // Step: 5 Send hello message
    let (tx, rx) = tokio::sync::oneshot::channel();
    let start_t = tokio::task::spawn(async move {
        sleep(Duration::from_secs(10)).await;
        println!("triggering greeting message ");
        match agent_tx
            .send(AgentMessage::Hello {
                name: agent_name,
                reply_to: tx,
            })
            .await
        {
            Ok(_) => (),
            Err(e) => {
                println!("Error sending message: {}", e);
            }
        };
    });
    agent_t.await;
    start_t.await.unwrap();

    Ok(())
}

/// check if key pair file exist if not then create new and store
fn read_key_pair_or_create_new(
    agent_name: &str,
    ifname: &str,
    address: &str,
    port: u32,
) -> Result<WgConfig> {
    let file_name = agent_name.to_owned() + "_" + "wg_config.txt";
    if file_exists(&file_name) {
        match read_config(&file_name) {
            Ok(config) => return Ok(config),
            Err(e) => {
                println!("Error reading config: {}", e);
                bail!(e);
            }
        }
    } else {
        let config = WgConfig {
            ip_address: address.to_string(),
            port,
            interface_name: ifname.to_string(),
            ..Default::default()
        };
        match generate_new_key_pair(file_name, config) {
            Ok(config) => return Ok(config),
            Err(e) => {
                println!("Error generating key pair: {}", e);
                bail!(e);
            }
        }
    }
}

fn file_exists(file_name: &str) -> bool {
    std::path::Path::new(file_name).exists()
}

fn read_agent_and_wg_info(args: &[String]) -> (String, String, String, u32) {
    let agent_name = if args.len() > 2 && (args[1] == "-n") {
        args[2].clone()
    } else {
        String::from("agent")
    };

    let ifname = args[3].clone();
    let address = args[4].clone();
    let port: u32 = args[5].parse::<u32>().unwrap();

    (agent_name, ifname, address, port)
}
