# Hash Implementation (SHA-256)

## Overview

The `hash.c/h` files implement the SHA-256 cryptographic hash function as specified in the Betanet 1.1 specification.

## File Information

- **Files**: `src/crypto/hash.c`, `src/crypto/hash.h`
- **Purpose**: Provide SHA-256 hash functionality (32-byte output)
- **Specification Reference**: Section 2 (Cryptography)

## API

The hash module should expose functions for:

1. One-shot hashing of complete messages
2. Incremental hashing for streaming data
3. Context management for multi-part hashing operations

Expected function prototypes include:

```c
// Initialize a hash context
int bn_hash_init(bn_hash_ctx *ctx);

// Update a hash context with data
int bn_hash_update(bn_hash_ctx *ctx, const uint8_t *data, size_t len);

// Finalize a hash operation and get the result
int bn_hash_final(bn_hash_ctx *ctx, uint8_t output[32]);

// One-shot hash function
int bn_hash(const uint8_t *data, size_t len, uint8_t output[32]);
```

## Usage in Betanet

SHA-256 is used throughout the protocol for:

1. Creating content identifiers (CIDs) in the overlay mesh
2. Generating peer IDs (`PeerID = multihash(0x12 0x20 || SHA-256(pubkey))`)
3. Deriving self-certifying IDs (`betanet://<hex SHA-256(service-pubkey)>`)
4. Computing BeaconSet seeds for mixnode selection
5. Key derivation input for HKDF
6. Computing access tickets and other authentication tokens

## Implementation Requirements

- Constant-time implementation to prevent timing attacks
- Must be hardened against side-channel attacks
- Should be optimized for performance on modern processors