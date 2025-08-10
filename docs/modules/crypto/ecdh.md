# ECDH Implementation (X25519)

## Overview

The `ecdh.c/h` files implement the X25519 Diffie-Hellman key exchange function as specified in the Betanet 1.1 specification.

## File Information

- **Files**: `src/crypto/ecdh.c`, `src/crypto/ecdh.h`
- **Purpose**: Provide X25519 elliptic curve Diffie-Hellman functionality
- **Specification Reference**: Section 2 (Cryptography)

## API

The ECDH module should expose functions for:

1. Key generation
2. Shared secret computation
3. Key validation

Expected function prototypes include:

```c
// Generate a new X25519 key pair
int bn_x25519_keypair_generate(uint8_t private_key[32], uint8_t public_key[32]);

// Compute a shared secret using your private key and peer's public key
int bn_x25519_shared_secret(const uint8_t private_key[32], 
                           const uint8_t peer_public_key[32],
                           uint8_t shared_secret[32]);

// Validate an X25519 public key
bool bn_x25519_public_key_validate(const uint8_t public_key[32]);
```

## Usage in Betanet

X25519 is used throughout the protocol for:

1. Access-Ticket Bootstrap for negotiated carrier (§5.2)
2. Inner Noise XK handshake for HTX (§5.3)
3. Key agreement in the X25519-Kyber768 hybrid scheme (post-quantum requirement)

## Implementation Requirements

- Constant-time implementation to prevent timing attacks
- Must be hardened against side-channel attacks
- Should follow the X25519 specification from RFC 7748
- Must handle key validation properly
- Required until at least 2027-01-01, when hybrid X25519-Kyber768 becomes mandatory

## Hybrid Mode

For the post-quantum hybrid mode (X25519-Kyber768), the ECDH component should interoperate with the `src/crypto/pq/hybrid.c/h` implementation.