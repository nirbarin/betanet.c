# Post-Quantum Cryptography Implementation

## Overview

The post-quantum (PQ) module implements the Kyber768 algorithm and its hybrid combination with X25519 as specified in the Betanet 1.1 specification.

## File Information

- **Files**: 
  - `src/crypto/pq/kyber.c`, `src/crypto/pq/kyber.h` - Kyber768 implementation
  - `src/crypto/pq/hybrid.c`, `src/crypto/pq/hybrid.h` - X25519-Kyber768 hybrid implementation
- **Purpose**: Provide post-quantum secure key exchange
- **Specification Reference**: Section 2 (Cryptography)

## Kyber Implementation

### API

The Kyber module should expose functions for:

1. Key generation
2. Encapsulation (generating a shared secret and encapsulating it)
3. Decapsulation (recovering the shared secret)

Expected function prototypes include:

```c
// Generate a new Kyber768 key pair
int bn_kyber_keypair_generate(uint8_t *public_key, uint8_t *private_key);

// Encapsulate a shared secret
int bn_kyber_encapsulate(const uint8_t *public_key, 
                        uint8_t *ciphertext,
                        uint8_t shared_secret[32]);

// Decapsulate a shared secret
int bn_kyber_decapsulate(const uint8_t *private_key,
                        const uint8_t *ciphertext,
                        uint8_t shared_secret[32]);
```

## Hybrid Implementation

### API

The hybrid module combines X25519 and Kyber768 for robust security:

```c
// Generate a hybrid X25519-Kyber768 key pair
int bn_hybrid_keypair_generate(bn_hybrid_keypair *keypair);

// Client: Perform hybrid key exchange (both X25519 and Kyber)
int bn_hybrid_client_exchange(const uint8_t *server_pubkey, 
                             uint8_t *client_pubkey,
                             uint8_t *encapsulation,
                             uint8_t *shared_secret);

// Server: Process hybrid key exchange
int bn_hybrid_server_exchange(const bn_hybrid_keypair *server_keypair,
                             const uint8_t *client_pubkey,
                             const uint8_t *encapsulation,
                             uint8_t *shared_secret);
```

## Usage in Betanet

The post-quantum hybrid scheme is used for:

1. Inner Noise XK handshake for HTX (§5.3)
2. Required from *2027-01-01*, when initiators **MUST** use hybrid X25519-Kyber768 for the inner handshake

## Implementation Requirements

- The implementation should use a well-audited, constant-time version of Kyber768
- The hybrid combination must combine the shared secrets from both X25519 and Kyber768 in a secure manner
- The hybrid scheme should defend against both classical and quantum attacks
- Must be hardened against side-channel attacks
- Should support the cryptographic algorithm registry for future algorithm agility