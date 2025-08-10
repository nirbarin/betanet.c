# Hash Implementation (SHA-256)

## Overview

The `hash.c/h` files implement the SHA-256 cryptographic hash function as specified in the Betanet 1.1 specification. The implementation uses libsodium to provide a constant-time, side-channel resistant hash function.

## File Information

- **Files**: `src/crypto/hash.c`, `src/crypto/hash.h`
- **Purpose**: Provide SHA-256 hash functionality (32-byte output)
- **Specification Reference**: Section 2 (Cryptography)

## API

The hash module exposes functions for:

1. One-shot hashing of complete messages
2. Incremental hashing for streaming data
3. Context management for multi-part hashing operations

Function prototypes include:

```c
// Initialize a hash context
int bn_crypto_hash_init(CryptoHashCtx *ctx);

// Update a hash context with data
int bn_crypto_hash_update(CryptoHashCtx *ctx, const uint8_t *data, size_t len);

// Finalize a hash operation and get the result
int bn_crypto_hash_final(CryptoHashCtx *ctx, uint8_t output[CRYPTO_HASH_SIZE_SHA256]);

// One-shot hash function
int bn_crypto_hash(const uint8_t *data, size_t len, uint8_t output[CRYPTO_HASH_SIZE_SHA256]);

// Clean a hash context
int bn_crypto_hash_cleanup(CryptoHashCtx *ctx);
```

## Error Handling

All functions follow the common error pattern:

- Return 0 for success
- Return negative values for errors:
  - -1: Invalid parameters (NULL pointers)
  - -2: Resource errors (memory allocation, uninitialized context)
  - -3: Internal errors (crypto operation failures)

## Usage Examples

### One-shot Hashing

```c
uint8_t message[] = "Hello, world!";
uint8_t hash[CRYPTO_HASH_SIZE_SHA256];

int result = bn_crypto_hash(message, sizeof(message) - 1, hash);
if (result < 0) {
    // Handle error
}
```

### Incremental Hashing

```c
CryptoHashCtx ctx;
uint8_t hash[CRYPTO_HASH_SIZE_SHA256];
uint8_t chunk1[] = "Hello, ";
uint8_t chunk2[] = "world!";

int result = bn_crypto_hash_init(&ctx);
if (result < 0) {
    // Handle error
}

result = bn_crypto_hash_update(&ctx, chunk1, sizeof(chunk1) - 1);
if (result < 0) {
    bn_crypto_hash_cleanup(&ctx);
    // Handle error
}

result = bn_crypto_hash_update(&ctx, chunk2, sizeof(chunk2) - 1);
if (result < 0) {
    bn_crypto_hash_cleanup(&ctx);
    // Handle error
}

result = bn_crypto_hash_final(&ctx, hash);
if (result < 0) {
    // Handle error
}
```

## Usage in Betanet

SHA-256 is used throughout the protocol for:

1. Creating content identifiers (CIDs) in the overlay mesh
2. Generating peer IDs (`PeerID = multihash(0x12 0x20 || SHA-256(pubkey))`)
3. Deriving self-certifying IDs (`betanet://<hex SHA-256(service-pubkey)>`)
4. Computing BeaconSet seeds for mixnode selection
5. Key derivation input for HKDF
6. Computing access tickets and other authentication tokens

## Implementation Details

- Uses libsodium's constant-time SHA-256 implementation
- Prefixed with `bn_crypto_` to avoid naming conflicts with libsodium's functions
- All memory containing sensitive hash state is securely wiped after use
- Follows the project's resource cleanup pattern with goto for error handling
- All input parameters are validated before use
- Properly handles incremental hashing for large data sets