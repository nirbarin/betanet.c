# Bitswap Implementation

## Overview

The `bitswap.c/h` files implement the Bitswap block exchange protocol for the Betanet overlay mesh, providing content-addressable storage and retrieval.

## File Information

- **Files**: `src/overlay/bitswap.c`, `src/overlay/bitswap.h`
- **Purpose**: Implement the Bitswap content exchange protocol
- **Specification Reference**: Section 6.4 (Block Exchange)

## Protocol Specification

As defined in §6.4:

- Content identifiers (CIDs) are calculated as `multihash(SHA-256(content))`
- The protocol uses Bitswap-v2 on the protocol path `/betanet/bitswap/2.2.0`
- Requesters should open ≥ 2 parallel streams on distinct SCION paths
- Requesters may open a third stream under good conditions

## API

The Bitswap module should expose functions for:

1. Initializing the Bitswap subsystem
2. Storing and retrieving content blocks
3. Managing want-lists and have-lists
4. Handling block exchange with peers

Expected function prototypes include:

```c
// Initialize the Bitswap subsystem
int bn_bitswap_init(bn_bitswap_ctx *ctx, bn_libp2p_ctx *libp2p_ctx);

// Calculate CID for content
int bn_bitswap_calculate_cid(const uint8_t *data, 
                            size_t data_len, 
                            bn_cid *cid);

// Store a block locally
int bn_bitswap_put(bn_bitswap_ctx *ctx, 
                  const uint8_t *data, 
                  size_t data_len, 
                  bn_cid *cid);

// Get a block by CID (local or remote)
int bn_bitswap_get(bn_bitswap_ctx *ctx, 
                  const bn_cid *cid, 
                  uint8_t **data, 
                  size_t *data_len);

// Add a CID to the want-list
int bn_bitswap_want(bn_bitswap_ctx *ctx, 
                   const bn_cid *cid, 
                   int priority);

// Cancel a want request
int bn_bitswap_cancel(bn_bitswap_ctx *ctx, const bn_cid *cid);

// Handle an incoming Bitswap message
int bn_bitswap_handle_message(bn_bitswap_ctx *ctx, 
                             const bn_peer_id *peer_id,
                             const uint8_t *message, 
                             size_t message_len);

// Create a Bitswap message containing wanted blocks
int bn_bitswap_create_message(bn_bitswap_ctx *ctx, 
                             const bn_peer_id *peer_id,
                             uint8_t *message, 
                             size_t *message_len);

// Send a Bitswap message to a peer
int bn_bitswap_send_message(bn_bitswap_ctx *ctx, 
                           const bn_peer_id *peer_id,
                           const uint8_t *message, 
                           size_t message_len);

// Clean up the Bitswap subsystem
void bn_bitswap_cleanup(bn_bitswap_ctx *ctx);
```

## Usage in Betanet

The Bitswap protocol is used for:

1. Content-addressable block exchange in the overlay mesh (§6.4)
2. Distributing content across the network
3. Retrieving content from multiple sources in parallel
4. Implementing a distributed content store

## Implementation Requirements

- **Content Identifiers**:
  - Must calculate CIDs as `multihash(SHA-256(content))`
  - Must properly validate content against CIDs

- **Protocol Version**:
  - Must implement Bitswap-v2 on `/betanet/bitswap/2.2.0`
  - Must follow the Bitswap-v2 message format and semantics

- **Multipath Streaming**:
  - Requesters should open ≥ 2 parallel streams on distinct SCION paths
  - May open a third under good conditions
  - Must handle multiple concurrent streams efficiently

- **Peer Selection**:
  - Should select peers based on availability and performance metrics
  - Should manage peer reputation based on successful exchanges

- **Storage Management**:
  - Should implement caching and garbage collection policies
  - Should prioritize storage based on popularity and local interest