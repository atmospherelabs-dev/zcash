# pea2pea 0.46.0 local patch

Unmodified crates.io 0.46.0 source except `src/node.rs`:
- Drop guard releases pending-connection accounting when a caller cancels connect.
- `connect_using_stream` accepts native SOCKS streams while retaining peer identity.

The upstream CC0 license is retained. Regression coverage lives in the crawler's
protocol tests. This avoids upgrading the protocol library during incident repair.
