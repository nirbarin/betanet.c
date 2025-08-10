# Peer Identity Implementation

## Overview

The `peer.c/h` files implement the peer identity functionality for the Betanet overlay mesh, defining how nodes identify and authenticate each other in the network.

## File Information

- **Files**: `src/overlay/peer.c`, `src/overlay/peer.h`
- **Purpose**: Implement peer identity management
- **Specification Reference**: Section 6.1 (Peer Identity)

## Peer Identity Format

As defined in the specification (§6.1), the peer identity is:

```
PeerID = multihash(0x12 0x20 || SHA-256(pubkey))
```

Where:
- `0x12` is the multihash code for SHA-256
- `0x20` is the length (32 bytes)
- The content is the SHA-256 hash of the peer's public key

## API

The peer module should expose functions for:

1. Creating peer identities
2. Validating peer identities
3. Converting between different representations
4. Managing peer information

Expected function prototypes include:

```c
// Create a peer ID from a public key
int bn_peer_id_from_pubkey(const uint8_t *pubkey, size_t pubkey_len, 
                          bn_peer_id *peer_id);

// Validate that a peer ID matches a public key
bool bn_peer_id_validate(const bn_peer_id *peer_id, 
                        const uint8_t *pubkey, size_t pubkey_len);

// Convert a peer ID to a string representation
int bn_peer_id_to_string(const bn_peer_id *peer_id, 
                        char *buffer, size_t buffer_size);

// Parse a peer ID from a string representation
int bn_peer_id_from_string(const char *str, bn_peer_id *peer_id);

// Compare two peer IDs for equality
bool bn_peer_id_equals(const bn_peer_id *a, const bn_peer_id *b);

// Create a new peer info structure
int bn_peer_info_create(bn_peer_info *info, 
                       const bn_peer_id *id,
                       const uint8_t *pubkey, size_t pubkey_len);

// Add a transport address to a peer info
int bn_peer_info_add_address(bn_peer_info *info,
                            const char *multiaddr);

// Free resources associated with peer info
void bn_peer_info_destroy(bn_peer_info *info);
```

## Usage in Betanet

Peer identity is used for:

1. Uniquely identifying nodes in the overlay mesh (§6.1)
2. Authenticating peers during connection establishment
3. Addressing content and messages to specific peers
4. Building the DHT and other distributed data structures

## Implementation Requirements

- **Identity Format**: Must follow the multihash format specified in §6.1
- **Self-Certification**: Must derive peer IDs from public keys to enable self-certification
- **Validation**: Must verify that peer IDs match the corresponding public keys
- **Representation**: Should support both binary and textual representations of peer IDs
- **Storage**: Should efficiently store and manage peer information
- **Thread Safety**: Should be thread-safe for concurrent access