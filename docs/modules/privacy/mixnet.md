# Mixnet Implementation

## Overview

The `mixnet.c/h` files implement the core mixnet functionality for the Betanet privacy layer, providing anonymous routing through a network of mix nodes.

## File Information

- **Files**: `src/privacy/mixnet.c`, `src/privacy/mixnet.h`
- **Purpose**: Implement core mixnet functionality
- **Specification Reference**: Section 7 (Privacy Layer)

## Privacy Modes

As specified in §7.1, the mixnet supports three modes:

| Mode | Requirement |
| ---- | ----------- |
| **strict** | Every stream through ≥ 3 Nym hops |
| **balanced** (default) | ≥ 2 hops until peer-trust ≥ 0.8 |
| **performance** | No mixnet unless destination label `.mixreq` |

## API

The mixnet module should expose functions for:

1. Initializing the mixnet subsystem
2. Setting the privacy mode
3. Creating and routing through mix circuits
4. Handling packet formats and encryption

Expected function prototypes include:

```c
// Initialize the mixnet subsystem
int bn_mixnet_init(bn_mixnet_ctx *ctx);

// Set the privacy mode
int bn_mixnet_set_mode(bn_mixnet_ctx *ctx, bn_mixnet_mode mode);

// Get the current privacy mode
bn_mixnet_mode bn_mixnet_get_mode(bn_mixnet_ctx *ctx);

// Create a mix circuit to a destination
int bn_mixnet_create_circuit(bn_mixnet_ctx *ctx,
                            const bn_peer_id *destination,
                            const uint8_t *stream_nonce,
                            bn_mixnet_circuit *circuit);

// Send data through a mix circuit
int bn_mixnet_send(bn_mixnet_circuit *circuit,
                  const uint8_t *data,
                  size_t data_len);

// Receive data from a mix circuit
int bn_mixnet_recv(bn_mixnet_circuit *circuit,
                  uint8_t *buffer,
                  size_t buffer_size,
                  size_t *data_len);

// Close a mix circuit
int bn_mixnet_close_circuit(bn_mixnet_circuit *circuit);

// Process an incoming mix packet
int bn_mixnet_process_packet(bn_mixnet_ctx *ctx,
                            const uint8_t *packet,
                            size_t packet_len);

// Create a mix packet for forwarding
int bn_mixnet_create_packet(bn_mixnet_ctx *ctx,
                           const bn_mix_hop *hops,
                           size_t num_hops,
                           const uint8_t *payload,
                           size_t payload_len,
                           uint8_t *packet,
                           size_t *packet_len);

// Clean up the mixnet subsystem
void bn_mixnet_cleanup(bn_mixnet_ctx *ctx);
```

## Usage in Betanet

The mixnet functionality is used for:

1. Providing anonymous communication (§7)
2. Hiding sender-receiver relationships
3. Protecting against traffic analysis
4. Supporting different privacy/performance trade-offs

## Implementation Requirements

- **Privacy Modes**:
  - Must implement all three modes as specified in §7.1
  - Must use the balanced mode as default

- **Hop Selection**:
  - Must follow the selection criteria in §7.2
  - Must use ≥ 3 hops in strict mode
  - Must use ≥ 2 hops in balanced mode until peer-trust ≥ 0.8
  - Must use mixnet in performance mode only for `.mixreq` destinations

- **Packet Format**:
  - Must use layered encryption (onion routing)
  - Must prevent correlation between incoming and outgoing packets
  - Must implement cover traffic as needed

- **Performance**:
  - Should minimize latency while maintaining privacy
  - Should handle failures gracefully