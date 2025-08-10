# Discovery Implementation

## Overview

The `discovery.c/h` files implement the bootstrap discovery functionality for the Betanet overlay mesh, providing mechanisms for nodes to find entry points into the network.

## File Information

- **Files**: `src/overlay/discovery.c`, `src/overlay/discovery.h`
- **Purpose**: Implement bootstrap peer discovery mechanisms
- **Specification Reference**: Section 6.3 (Bootstrap Discovery)

## Discovery Methods

As specified in §6.3, clients must iterate through the following methods in order until ≥ 5 peers respond:

| Order | Method | Central infra? | Implementation |
| ----- | ------ | -------------- | -------------- |
| a | **Rotating Rendezvous DHT**: 64 ephemeral IDs derived from BeaconSet | No | Primary method |
| b | **mDNS** service `_betanet._udp` | No | Local network discovery |
| c | **Bluetooth LE** UUID `0xB7A7` | No | Nearby device discovery |
| d | **Onion v3 list** (signed, mirrored via IPFS) | Minimal | Fallback method |
| e | **DNS fallback list** | Yes (fallback) | Last resort |

## API

The discovery module should expose functions for:

1. Initializing the discovery subsystem
2. Finding bootstrap peers through various methods
3. Managing discovered peers
4. Implementing proof-of-work for responding to discovery requests

Expected function prototypes include:

```c
// Initialize the discovery subsystem
int bn_discovery_init(bn_discovery_ctx *ctx);

// Find bootstrap peers (tries methods in order)
int bn_discovery_find_bootstrap_peers(bn_discovery_ctx *ctx, 
                                     bn_peer_info **peers,
                                     size_t *num_peers);

// Find peers using rotating rendezvous DHT
int bn_discovery_rendezvous_dht(bn_discovery_ctx *ctx,
                               bn_peer_info **peers,
                               size_t *num_peers);

// Find peers using mDNS
int bn_discovery_mdns(bn_discovery_ctx *ctx,
                     bn_peer_info **peers,
                     size_t *num_peers);

// Find peers using Bluetooth LE
int bn_discovery_ble(bn_discovery_ctx *ctx,
                    bn_peer_info **peers,
                    size_t *num_peers);

// Find peers using Onion v3 list
int bn_discovery_onion_list(bn_discovery_ctx *ctx,
                           bn_peer_info **peers,
                           size_t *num_peers);

// Find peers using DNS fallback list
int bn_discovery_dns_fallback(bn_discovery_ctx *ctx,
                             bn_peer_info **peers,
                             size_t *num_peers);

// Calculate current BeaconSet value
int bn_discovery_beacon_set(uint64_t epoch_day, uint8_t beacon_set[32]);

// Generate rendezvous IDs for current epoch
int bn_discovery_rendezvous_ids(const uint8_t beacon_set[32],
                               bn_peer_id *ids,
                               size_t num_ids);

// Respond to discovery requests (with PoW verification)
int bn_discovery_respond(bn_discovery_ctx *ctx,
                        const uint8_t *request,
                        size_t request_len,
                        uint8_t *response,
                        size_t *response_len);

// Verify proof-of-work for discovery responses
bool bn_discovery_verify_pow(const uint8_t *data,
                            size_t data_len,
                            uint32_t difficulty_bits);

// Clean up the discovery subsystem
void bn_discovery_cleanup(bn_discovery_ctx *ctx);
```

## Usage in Betanet

The discovery functionality is used for:

1. Bootstrap: Finding initial peers to connect to the network (§6.3)
2. Responding to discovery requests from other nodes
3. Implementing anti-abuse mechanisms for discovery
4. Supporting multiple discovery methods for robustness

## Implementation Requirements

- **Rotating Rendezvous DHT**:
  - Must calculate 64 ephemeral IDs using `SHA256("bn-seed" ‖ BeaconSet(epochDay) ‖ i)`
  - `epochDay = floor(unixTime/86400)` in UTC
  - Must not use deterministic seeds from 1.0 (REMOVED)

- **BeaconSet Calculation**:
  - Must combine drand, NIST Randomness Beacon, and Ethereum L1 finalized hash
  - May use fallback `BeaconSet(epoch) = SHA256("bn-fallback" ‖ K0c ‖ uint64_be(epoch))` when components unavailable

- **Anti-Abuse Mechanisms**:
  - Responders must require proof-of-work (initial ≥ 22 bits, adaptive per §6.5)
  - Must rate-limit per source prefix
  - Verification must be constant-time

- **Method Iteration**:
  - Must try methods in order (a→e) until ≥ 5 peers respond
  - Must implement all methods for maximum compatibility