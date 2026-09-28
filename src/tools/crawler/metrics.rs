use std::{collections::HashMap, net::SocketAddr};

use regex::Regex;
use serde::Serialize;
use spectre::{edge::Edge, graph::Graph};
use ziggurat_core_crawler::summary::{NetworkSummary, NetworkType};

use crate::{
    network::{unix_ms, KnownNode, LAST_SEEN_CUTOFF},
    Crawler,
};

const MIN_BLOCK_HEIGHT: i32 = 2_000_000;
pub const ZCASH_P2P_DEFAULT_MAINNET_PORT: u16 = 8233;
pub const ZCASH_P2P_DEFAULT_TESTNET_PORT: u16 = 18233;

/// Per-node info exposed in the extended summary for the cruncher.
#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub addr: String,
    pub last_verified_at_ms: Option<u64>,
    pub user_agent: Option<String>,
    pub protocol_version: Option<u32>,
    pub start_height: Option<i32>,
    pub services: Option<u64>,
    pub handshake_time_ms: Option<u64>,
}

/// Extended summary that includes per-node metadata alongside the standard NetworkSummary.
///
/// The standard `summary` (node_addrs / nodes_indices) is filtered to *good*
/// (reachable, handshake-completed) nodes only. The `all_*` fields below expose
/// the FULL known-network graph — every address the crawler has heard about via
/// gossip, including nodes it could not reach — so downstream consumers can render
/// the reachable core plus the wider known-address space ("off"/unreachable nodes).
#[derive(Clone, Serialize)]
pub struct ExtendedSummary {
    #[serde(flatten)]
    pub summary: NetworkSummary,
    pub generated_at_ms: u64,
    pub node_info: Vec<NodeInfo>,
    /// All known node addresses (reachable + unreachable), stable order matching `all_nodes_indices`.
    pub all_node_addrs: Vec<String>,
    /// Adjacency list over `all_node_addrs` (indices refer to positions in that vec).
    pub all_nodes_indices: Vec<Vec<usize>>,
    /// Parallel to `all_node_addrs`: true if the node completed a handshake (reachable).
    pub all_node_reachable: Vec<bool>,
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
        let nodes = crawler.known_network.nodes();
        let summary = new_network_summary(crawler, &self.graph, &nodes);

        let node_info: Vec<NodeInfo> = summary
            .node_addrs
            .iter()
            .map(|addr| {
                let known = nodes.get(addr);
                NodeInfo {
                    addr: addr.to_string(),
                    last_verified_at_ms: known.and_then(|n| n.last_verified_at_ms),
                    user_agent: known.and_then(|n| n.user_agent.as_ref().map(|v| v.0.clone())),
                    protocol_version: known.and_then(|n| n.protocol_version.map(|v| v.0)),
                    start_height: known.and_then(|n| n.start_height),
                    services: known.and_then(|n| n.services),
                    handshake_time_ms: known
                        .and_then(|n| n.handshake_time.map(|d| d.as_millis() as u64)),
                }
            })
            .collect();

        // Full known-network graph: every address heard about, connected as observed
        // in the gossip graph. `get_filtered_adjacency_indices` returns adjacency whose
        // indices reference positions in the passed slice, so we build the addr vec once
        // and reuse its ordering for addrs, indices, and reachability.
        let all_addrs: Vec<SocketAddr> = nodes.keys().cloned().collect();
        let all_nodes_indices = self.graph.get_filtered_adjacency_indices(&all_addrs);
        let all_node_reachable: Vec<bool> = all_addrs
            .iter()
            .map(|a| nodes.get(a).is_some_and(|n| n.recently_verified()))
            .collect();
        let all_node_addrs: Vec<String> = all_addrs.iter().map(|a| a.to_string()).collect();

        ExtendedSummary {
            summary,
            generated_at_ms: unix_ms(),
            node_info,
            all_node_addrs,
            all_nodes_indices,
            all_node_reachable,
        }
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

    let zcash_regex = Regex::new(r"^/MagicBean:(\d+)\.(\d+)\.(\d+)[^/]*/$").unwrap();
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
///
/// Accepts a pre-cloned `nodes` snapshot so callers that also need the map
/// (e.g. `request_summary`) avoid cloning it a second time.
pub fn new_network_summary(
    crawler: &Crawler,
    graph: &Graph<SocketAddr>,
    nodes: &HashMap<SocketAddr, KnownNode>,
) -> NetworkSummary {
    let connections = crawler.known_network.connections();

    let num_known_nodes = nodes.len();
    let num_known_connections = connections.len();

    let good_nodes = nodes
        .iter()
        .filter_map(|(addr, node)| node.recently_verified().then_some(*addr))
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

    let node_network_types = recognize_network_types(nodes, &good_nodes);

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
