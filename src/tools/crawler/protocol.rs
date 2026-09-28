use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::timeout;

use futures_util::SinkExt;
use pea2pea::{
    protocols::{Handshake, Reading, Writing},
    Config, Connection, ConnectionSide, Node as Pea2PeaNode, Pea2Pea,
};
use tokio_util::codec::Framed;
use tracing::*;
use ziggurat_zcash::{
    protocol::{
        message::Message,
        payload::{block::Headers, Addr, Version},
    },
    tools::synthetic_node::MessageCodec,
};

use super::network::KnownNetwork;
use crate::network::ConnectionState;

pub const NUM_CONN_ATTEMPTS_PERIODIC: usize = 500;
pub const MAX_CONCURRENT_CONNECTIONS: u16 = 1200;
pub const MAIN_LOOP_INTERVAL_SECS: u64 = 20;
pub const RECONNECT_INTERVAL_SECS: u64 = 5 * 60;
pub const MAX_WAIT_FOR_ADDR_SECS: u64 = 3 * 60;
/// TCP connect timeout. Without this, connects to dead/firewalled peers hang on
/// SYN retries for the OS default (~120s), leaking one FD each until exhaustion.
pub const CONNECT_TIMEOUT_SECS: u64 = 5;

/// Represents the crawler together with network metrics it has collected.
#[derive(Clone)]
pub struct Crawler {
    node: Pea2PeaNode,
    pub known_network: Arc<KnownNetwork>,
    pub start_time: Instant,
    pub socks5_proxy: Option<SocketAddr>,
}

impl Pea2Pea for Crawler {
    fn node(&self) -> &Pea2PeaNode {
        &self.node
    }
}

impl Crawler {
    /// Creates a new instance of the `Crawler` without starting it.
    pub async fn new() -> Self {
        let config = Config {
            name: Some("crawler".into()),
            listener_ip: None,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            ..Default::default()
        };

        Self {
            node: Pea2PeaNode::new(config),
            known_network: Default::default(),
            start_time: Instant::now(),
            socks5_proxy: None,
        }
    }

    /// Attempts to connect the crawler to the given address.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        trace!(parent: self.node().span(), "attempting to connect to {}", addr);

        let timestamp = Instant::now();

        if let Some(node) = self.known_network.nodes.write().get_mut(&addr) {
            node.last_attempt = Some(timestamp);
            node.version_received = false;
            node.verack_received = false;
        }
        let connect = async {
            if let Some(proxy) = self.socks5_proxy {
                let stream = tokio_socks::tcp::Socks5Stream::connect(proxy, addr)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                self.node
                    .connect_using_stream(addr, stream.into_inner())
                    .await
            } else {
                self.node.connect(addr).await
            }
        };
        let result = match timeout(
            Duration::from_secs(if self.socks5_proxy.is_some() {
                30
            } else {
                CONNECT_TIMEOUT_SECS
            }),
            connect,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP connect timed out",
            )),
        };

        if let Some(ref mut known_node) = self.known_network.nodes.write().get_mut(&addr) {
            match result {
                Ok(_) => {
                    known_node.connection_failures = 0;
                    known_node.last_connected = Some(timestamp);
                    known_node.state = ConnectionState::Connected;
                }
                Err(_) => {
                    trace!(parent: self.node().span(), "failed to connect to {}", addr);
                    known_node.connection_failures =
                        known_node.connection_failures.saturating_add(1);
                }
            }
        }

        result
    }

    /// Checks to see if crawler should connect to the given address.
    pub fn should_connect(&self, addr: SocketAddr) -> bool {
        if self.known_network.nodes().get(&addr).is_some() {
            // Ensure that crawler is not exceeding the MAX_CONCURRENT_CONNECTIONS.
            if self.node().num_connected() + self.node().num_connecting()
                >= MAX_CONCURRENT_CONNECTIONS.into()
            {
                return false;
            }

            // Ensure that there are no active connections with the given addr.
            if self.node().is_connected(addr) || self.node().is_connecting(addr) {
                return false;
            }

            true
        } else {
            panic!("Logic bug! The crawler should only attempt to connect to known addresses.");
        }
    }
}

#[async_trait::async_trait]
impl Handshake for Crawler {
    // Set handshake timeout to 300ms
    const TIMEOUT_MS: u64 = 300;

    async fn perform_handshake(&self, mut conn: Connection) -> io::Result<Connection> {
        let conn_addr = conn.addr();
        let own_listening_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let mut framed_stream = Framed::new(self.borrow_stream(&mut conn), MessageCodec::default());

        let own_version = Message::Version(Version::new(conn_addr, own_listening_addr));
        framed_stream.send(own_version).await?;

        // Here should be waiting for remote version message but as some nodes don't send it
        // quickly enough we will wait for it in the process_message function.
        // @see process_message function for more details.

        Ok(conn)
    }
}

#[async_trait::async_trait]
impl Reading for Crawler {
    type Message = Message;
    type Codec = MessageCodec;

    fn codec(&self, _addr: SocketAddr, _side: ConnectionSide) -> Self::Codec {
        Default::default()
    }

    async fn process_message(&self, source: SocketAddr, message: Self::Message) -> io::Result<()> {
        match message {
            Message::Addr(addr) => {
                let len = addr.addrs.len();
                info!(parent: self.node().span(), "got {} address(es) from {}", len, source);

                let mut listening_addrs = Vec::with_capacity(len);
                for addr in &addr.addrs {
                    listening_addrs.push(addr.addr);
                }

                self.known_network.add_addrs(source, &listening_addrs);

                // Disconnect after getting more than 1 addresses or if the received address is
                // not the same as the source address.
                // In theory, zero length addr response has no sense but it's not
                // forbidden by the standard so we should handle it. (that's why there is len == 1
                // condition preventing address comparision to source when len would be 0).
                if len > 1 || (len == 1 && addr.addrs[0].addr != source) {
                    self.node().disconnect(source).await;
                    self.known_network
                        .set_node_state(source, ConnectionState::Disconnected);
                }
            }
            Message::Ping(nonce) => {
                let _ = self.unicast(source, Message::Pong(nonce))?.await;
            }
            Message::GetAddr => {
                let _ = self.unicast(source, Message::Addr(Addr::empty()))?.await;
            }
            Message::GetHeaders(_) => {
                let _ = self
                    .unicast(source, Message::Headers(Headers::empty()))?
                    .await;
            }
            Message::GetData(inv) => {
                let _ = self.unicast(source, Message::NotFound(inv.clone()))?.await;
            }
            Message::Verack => {
                if let Some(node) = self.known_network.nodes.write().get_mut(&source) {
                    node.verack_received = true;
                    node.record_verification();
                }
            }
            Message::Version(ver) => {
                // Update source node with information from version.
                if let Some(known_node) = self.known_network.nodes.write().get_mut(&source) {
                    known_node.protocol_version = Some(ver.version);
                    known_node.user_agent = Some(ver.user_agent);
                    known_node.services = Some(ver.services);
                    known_node.start_height = Some(ver.start_height);
                    known_node.version_received = true;
                    known_node.record_verification();
                }

                let _ = self.unicast(source, Message::Verack)?.await;

                // Send GetAddr as soon as we get version message from the peer.
                // In fact, this part should be done during the handshake but it would increase
                // handshake time and there are some nodes that do not send version message
                // quickly (we know that zebra can delay sending version message for over 30 seconds).
                // Sending GetAddr before receiving the version results in dropping this message by
                // the remote peer, so we're stuck waiting for a reply that will never come that's why we
                // need to wait for the remote version message response.
                // Extra background: Sending GetAddr message was moved to this place,
                // and it's not sent anymore directly from the main module.
                let _ = self.unicast(source, Message::GetAddr)?.await;
            }
            _ => {}
        }

        Ok(())
    }
}

impl Writing for Crawler {
    type Message = Message;
    type Codec = MessageCodec;

    fn codec(&self, _addr: SocketAddr, _side: ConnectionSide) -> Self::Codec {
        Default::default()
    }
}

#[cfg(test)]
mod repair_tests {
    use super::*;
    use crate::metrics::NetworkMetrics;
    use crate::network::KnownNode;
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct SlowHandshake(Pea2PeaNode);
    impl Pea2Pea for SlowHandshake {
        fn node(&self) -> &Pea2PeaNode {
            &self.0
        }
    }
    #[async_trait::async_trait]
    impl Handshake for SlowHandshake {
        const TIMEOUT_MS: u64 = 60_000;
        async fn perform_handshake(&self, conn: Connection) -> io::Result<Connection> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(conn)
        }
    }

    #[tokio::test]
    async fn cancelled_connect_releases_capacity_and_allows_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let node = SlowHandshake(Pea2PeaNode::new(Config {
            listener_ip: None,
            ..Default::default()
        }));
        node.enable_handshake().await;
        for _ in 0..3 {
            let (result, accepted) = tokio::join!(
                timeout(Duration::from_millis(30), node.node().connect(addr)),
                listener.accept()
            );
            assert!(result.is_err());
            assert_eq!(node.node().num_connecting(), 0);
            drop(accepted.unwrap());
        }
        node.node().shut_down().await;
    }

    #[tokio::test]
    async fn prepared_stream_uses_destination_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        let node = Pea2PeaNode::new(Config {
            listener_ip: None,
            ..Default::default()
        });
        let destination = "192.0.2.1:8233".parse().unwrap();
        node.connect_using_stream(destination, stream)
            .await
            .unwrap();
        assert!(node.is_connected(destination));
        assert_eq!(node.num_connecting(), 0);
        node.shut_down().await;
    }

    #[tokio::test]
    async fn empty_graph_summary_advances_and_only_recent_protocol_handshakes_count() {
        let crawler = Crawler::new().await;
        let good: SocketAddr = "192.0.2.1:8233".parse().unwrap();
        let old: SocketAddr = "192.0.2.2:8233".parse().unwrap();
        let tcp_only: SocketAddr = "192.0.2.3:8233".parse().unwrap();
        let mut verified = KnownNode {
            version_received: true,
            verack_received: true,
            ..Default::default()
        };
        verified.record_verification();
        let old_node = KnownNode {
            last_verified: Some(Instant::now() - Duration::from_secs(3601)),
            ..Default::default()
        };
        let tcp_node = KnownNode {
            last_connected: Some(Instant::now()),
            ..Default::default()
        };
        crawler.known_network.nodes.write().extend([
            (good, verified),
            (old, old_node),
            (tcp_only, tcp_node),
        ]);
        let mut metrics = NetworkMetrics::default();
        let first = metrics.request_summary(&crawler);
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second = metrics.request_summary(&crawler);
        assert!(second.generated_at_ms > first.generated_at_ms);
        assert!(second.summary.crawler_runtime > first.summary.crawler_runtime);
        assert_eq!(second.summary.num_good_nodes, 1);
        assert_eq!(second.node_info[0].addr, good.to_string());
        assert!(second.node_info[0].last_verified_at_ms.is_some());
        assert_eq!(second.all_node_reachable.iter().filter(|v| **v).count(), 1);
    }

    #[test]
    fn verification_requires_both_version_and_verack() {
        let mut node = KnownNode {
            version_received: true,
            ..Default::default()
        };
        node.record_verification();
        assert!(!node.recently_verified());
        node.verack_received = true;
        node.record_verification();
        assert!(node.recently_verified());
    }
}
