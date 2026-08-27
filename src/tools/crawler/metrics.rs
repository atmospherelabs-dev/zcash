use std::{collections::HashMap, net::SocketAddr};

use regex::Regex;
use serde::Serialize;
use spectre::{edge::Edge, graph::Graph};
use ziggurat_core_crawler::summary::{NetworkSummary, NetworkType};

use crate::{
    network::{KnownNode, LAST_SEEN_CUTOFF},
    Crawler,
};

const MIN_BLOCK_HEIGHT: i32 = 2_000_000;
pub const ZCASH_P2P_DEFAULT_MAINNET_PORT: u16 = 8233;
pub const ZCASH_P2P_DEFAULT_TESTNET_PORT: u16 = 18233;

/// Per-node info exposed in the extended summary for the cruncher.
#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub addr: String,
    pub user_agent: Option<String>,
    pub protocol_version: Option<u32>,
    pub start_height: Option<i32>,
    pub services: Option<u64>,
    pub handshake_time_ms: Option<u64>,
}

/// Extended summary that includes per-node metadata alongside the standard NetworkSummary.
#[derive(Clone, Serialize)]
pub struct ExtendedSummary {
    #[serde(flatten)]
    pub summary: NetworkSummary,
    pub node_info: Vec<NodeInfo>,
}

#[derive(Default)]
pub struct NetworkMetrics {
    graph: Graph<SocketAddr>,
}

impl NetworkMetrics {
    /// Updates the network graph with new connections.
    pub fn update_graph(&mut self, crawler: &Crawler) {
        for conn in crawler.known_network.connections() {
            let edge = Edge::new(conn.a, conn.b);
            if conn.last_seen.elapsed().as_secs() > LAST_SEEN_CUTOFF {
                self.graph.remove(&edge);
            } else {
                self.graph.insert(edge);
            }
        }
    }

    /// Requests a summary of the network metrics (extended with per-node info).
    pub fn request_summary(&mut self, crawler: &Crawler) -> ExtendedSummary {
        let summary = new_network_summary(crawler, &self.graph);
        let nodes = crawler.known_network.nodes();

        let node_info: Vec<NodeInfo> = summary.node_addrs.iter().map(|addr| {
            let known = nodes.get(addr);
            NodeInfo {
                addr: addr.to_string(),
                user_agent: known.and_then(|n| n.user_agent.as_ref().map(|v| v.0.clone())),
                protocol_version: known.and_then(|n| n.protocol_version.map(|v| v.0)),
                start_height: known.and_then(|n| n.start_height),
                services: known.and_then(|n| n.services),
                handshake_time_ms: known.and_then(|n| n.handshake_time.map(|d| d.as_millis() as u64)),
            }
        }).collect();

        ExtendedSummary { summary, node_info }
    }
}

// Recognize network types with fixes for current mainnet:
// - MagicBean major version 6+ is zcashd (NOT Flux — Flux uses different identifiers now)
// - Zakura nodes are explicitly recognized
// - Zebra regex updated for multi-digit versions (e.g. Zebra:6.3.0)
fn recognize_network_types(
    nodes: &HashMap<SocketAddr, KnownNode>,
    good_nodes: &Vec<SocketAddr>,
) -> Vec<NetworkType> {
    let num_good_nodes = good_nodes.len();
    let mut node_network_types = Vec::with_capacity(num_good_nodes);

    let zcash_regex = Regex::new(r"^/MagicBean:(\d+)\.(\d+)\.(\d+)/$").unwrap();
    let zebra_regex = Regex::new(r"^/Zebra:(\d+)\.(\d+)\.(\d+)").unwrap();
    let zakura_regex = Regex::new(r"^/Zakura:(\d+)\.(\d+)\.(\d+)").unwrap();

    for node in good_nodes {
        let mut agent_matches = false;

        let port_matches = node.port() == ZCASH_P2P_DEFAULT_MAINNET_PORT
            || node.port() == ZCASH_P2P_DEFAULT_TESTNET_PORT;

        let agent = if let Some(agent) = &nodes[node].user_agent {
            agent.0.clone()
        } else {
            "".to_string()
        };

        // Zakura (Zcash implementation by Shielded Labs)
        if zakura_regex.is_match(&agent) {
            agent_matches = true;
        }

        // Zebra (Zcash Foundation Rust implementation)
        if zebra_regex.is_match(&agent) {
            agent_matches = true;
        }

        // zcashd / MagicBean — all versions are valid Zcash nodes
        // (Flux no longer uses this identifier pattern on mainnet)
        if zcash_regex.is_match(&agent) {
            agent_matches = true;
        }

        // Check block height — mandatory for any Zcash node
        let height = nodes[node].start_height.unwrap_or(0);
        if height < MIN_BLOCK_HEIGHT {
            node_network_types.push(NetworkType::Unknown);
            continue;
        }

        if port_matches || agent_matches {
            node_network_types.push(NetworkType::Zcash);
        } else {
            node_network_types.push(NetworkType::Unknown);
        }
    }

    node_network_types
}

/// Constructs a new NetworkSummary from given nodes.
pub fn new_network_summary(crawler: &Crawler, graph: &Graph<SocketAddr>) -> NetworkSummary {
    let nodes = crawler.known_network.nodes();
    let connections = crawler.known_network.connections();

    let num_known_nodes = nodes.len();
    let num_known_connections = connections.len();

    let good_nodes = nodes
        .clone()
        .into_iter()
        .filter_map(|(addr, node)| node.last_connected.map(|_| addr))
        .collect::<Vec<_>>();

    let num_good_nodes = good_nodes.len();

    let mut protocol_versions = HashMap::with_capacity(num_known_nodes);
    let mut user_agents = HashMap::with_capacity(num_known_nodes);

    for (_, node) in nodes.iter() {
        if node.protocol_version.is_some() {
            protocol_versions
                .entry(node.protocol_version.unwrap().0)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            user_agents
                .entry(node.user_agent.clone().unwrap().0)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
    }

    let node_network_types = recognize_network_types(&nodes, &good_nodes);

    let num_versions = protocol_versions.values().sum();
    let nodes_indices = graph.get_filtered_adjacency_indices(&good_nodes);

    NetworkSummary {
        num_known_nodes,
        num_good_nodes,
        num_known_connections,
        num_versions,
        protocol_versions,
        user_agents,
        crawler_runtime: crawler.start_time.elapsed(),
        node_addrs: good_nodes,
        node_network_types,
        nodes_indices,
    }
}
