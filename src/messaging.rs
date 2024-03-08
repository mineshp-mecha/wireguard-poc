use anyhow::{bail, Result};
use async_nats::jetstream::stream::DiscardPolicy;
use bytes::Bytes;
use futures::StreamExt;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use tokio::{
    select,
    sync::{
        mpsc::{self, Sender},
        oneshot,
    },
};
pub enum MessagingMessage {
    NatsMessage {
        subject: String,
        message: Bytes,
        reply_to: oneshot::Sender<Result<bool>>,
    },
}
pub struct MessagingOptions {}
#[derive(Debug)]
pub struct Messaging {
    nats_client: Option<async_nats::Client>,
    messaging_tx: Sender<MessagingMessage>,
}

impl Messaging {
    pub fn new(messaging_tx: Sender<MessagingMessage>) -> Self {
        Self {
            nats_client: None,
            messaging_tx,
        }
    }

    pub async fn connect(&mut self) -> Result<bool> {
        let path = std::path::PathBuf::from("services_user.creds");
        self.nats_client = match async_nats::ConnectOptions::new()
            .credentials_file(path)
            .await
            .unwrap()
            .connect("nats.sandbox.mecha.build:4222")
            .await
        {
            Ok(c) => {
                println!("Connected to nats");
                Some(c)
            }
            Err(e) => {
                return Err(anyhow::anyhow!("error while connecting:{}", e));
            }
        };
        Ok(true)
    }
    pub async fn pull(&self, stream_name: String, subjects: String) -> Result<bool> {
        let client = self.nats_client.as_ref().unwrap();
        let jetstream = async_nats::jetstream::new(client.clone());

        // jetstream.delete_stream(stream_name.clone()).await;
        // create or get stream
        let stream = match jetstream
            .get_or_create_stream(async_nats::jetstream::stream::Config {
                name: stream_name.to_string(),
                max_messages: 10_000_000,
                discard: DiscardPolicy::New,
                deny_purge: false,
                max_message_size: 4096, //in bytes
                subjects: vec!["wireguard.>".to_string()],
                ..Default::default()
            })
            .await
        {
            Ok(s) => s,
            Err(err) => bail!(err),
        };
        stream.purge().await?;
        // Create consumer
        let consumer_name: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let consumer = match stream
            .create_consumer(async_nats::jetstream::consumer::pull::Config {
                name: Some(consumer_name),
                filter_subject: subjects,
                ..Default::default()
            })
            .await
        {
            Ok(s) => s,
            Err(e) => bail!(e),
        };
        let mut messages = match consumer.messages().await {
            Ok(s) => s,
            Err(e) => {
                println!("Error getting messages: {}", e);
                bail!(e);
            }
        };
        let messaging_tx = self.messaging_tx.clone();
        tokio::spawn(async move {
            while let Some(msg) = messages.next().await {
                match msg {
                    Ok(m) => {
                        let (tx, _rx) = oneshot::channel();
                        let _ = messaging_tx
                            .clone()
                            .send(MessagingMessage::NatsMessage {
                                subject: m.subject.to_string(),
                                message: m.payload.clone(),
                                reply_to: tx,
                            })
                            .await;
                        let _ = m.ack().await;
                    }
                    Err(e) => {
                        println!("Error getting message: {}", e);
                    }
                }
            }
        });
        Ok(true)
    }
    pub async fn publish(&self, subject: String, message: String) -> Result<bool> {
        let client = self.nats_client.as_ref().unwrap();
        let _ = client.publish(subject, message.into()).await;
        Ok(true)
    }
}
