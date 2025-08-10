# Mixnode Selection Implementation

## Overview

The `selection.c/h` files implement the mixnode selection functionality for the Betanet privacy layer, providing algorithms to securely choose mix nodes for anonymous routing.

## File Information

- **Files**: `src/privacy/selection.c`, `src/privacy/selection.h`
- **Purpose**: Implement mixnode selection algorithms
- **Specification Reference**: Section 7.2 (Mixnode Selection)

## Selection Mechanism

As specified in §7.2, mixnode selection uses:

1. Epoch-based BeaconSet for randomness
2. Per-stream entropy for diversity
3. VRF-based selection for unpredictability
4. Diversity requirements to prevent correlation

The algorithm follows these steps:
1. Calculate `epoch = floor(unixTime/3600)`
2. Compute `BeaconSet(epoch)` from multiple entropy sources
3. For each stream, generate 16-byte `streamNonce`
4. Calculate `seed = SHA256(BeaconSet(epoch) ‖ srcPeerID ‖ dstPeerID ‖ streamNonce)`
5. Select hops using VRF over the `seed` from the advertised mixnode set

## API

The selection module should expose functions for:

1. Calculating BeaconSet values
2. Selecting mix nodes for circuits
3. Enforcing diversity requirements
4. Managing the mixnode set

Expected function prototypes include:

```c
// Calculate BeaconSet for an epoch
int bn_mixnet_beacon_set(uint64_t epoch, uint8_t beacon_set[32]);

// Calculate fallback BeaconSet when primary sources unavailable
int bn_mixnet_beacon_set_fallback(uint64_t epoch, 
                                 const uint8_t k0c[32],
                                 uint8_t beacon_set[32]);

// Select mix hops for a circuit
int bn_mixnet_select_hops(const bn_mixnet_ctx *ctx,
                         const uint8_t beacon_set[32],
                         const bn_peer_id *src_peer_id,
                         const bn_peer_id *dst_peer_id,
                         const uint8_t stream_nonce[16],
                         bn_mix_hop *hops,
                         size_t num_hops);

// Verify that selected hops meet diversity requirements
bool bn_mixnet_verify_hop_diversity(const bn_mixnet_ctx *ctx,
                                   const bn_mix_hop *hops,
                                   size_t num_hops);

// Add a mix node to the available set
int bn_mixnet_add_node(bn_mixnet_ctx *ctx,
                      const bn_mix_node_info *node_info);

// Remove a mix node from the available set
int bn_mixnet_remove_node(bn_mixnet_ctx *ctx,
                         const bn_peer_id *node_id);

// Get information about available mix nodes
int bn_mixnet_get_nodes(bn_mixnet_ctx *ctx,
                       bn_mix_node_info **nodes,
                       size_t *num_nodes);
```

## Usage in Betanet

The mixnode selection functionality is used for:

1. Securely choosing mix nodes for anonymous circuits (§7.2)
2. Ensuring unpredictability of node selection
3. Providing diversity in hop selection
4. Preventing adversarial control of circuits

## Implementation Requirements

- **BeaconSet Calculation**:
  - Primary: `XOR32(drand(epoch), nistRBv2(epoch), ethL1_finalized_hash(epoch))`
  - Fallback: `SHA256("bn-fallback" ‖ K0c ‖ uint64_be(epoch))`
  - Must log when fallback is used

- **Hop Selection**:
  - Must use VRF over seed from advertised mixnode set
  - Seed must be `SHA256(BeaconSet(epoch) ‖ srcPeerID ‖ dstPeerID ‖ streamNonce)`
  - Must generate 16-byte `streamNonce` for each stream

- **Diversity Requirements**:
  - Within `(src,dst,epoch)`, must avoid reusing exact hop set until ≥ 8 distinct sets are tried
  - Must include at least one hop outside both source and destination AS groups

- **Epoch Handling**:
  - Must calculate `epoch = floor(unixTime/3600)`
  - Must handle epoch transitions smoothly