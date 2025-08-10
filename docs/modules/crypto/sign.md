# Signature Implementation (Ed25519)

## Overview

The `sign.c/h` files implement the Ed25519 signature scheme as specified in the Betanet 1.1 specification.

## File Information

- **Files**: `src/crypto/sign.c`, `src/crypto/sign.h`
- **Purpose**: Provide Ed25519 signature functionality
- **Specification Reference**: Section 2 (Cryptography)

## API

The signature module should expose functions for:

1. Key generation
2. Signature creation
3. Signature verification
4. Batch verification (optional optimization)

Expected function prototypes include:

```c
// Generate a new Ed25519 key pair
int bn_ed25519_keypair_generate(uint8_t private_key[64], uint8_t public_key[32]);

// Sign a message using an Ed25519 private key
int bn_ed25519_sign(const uint8_t private_key[64], 
                   const uint8_t *message, size_t message_len,
                   uint8_t signature[64]);

// Verify an Ed25519 signature
bool bn_ed25519_verify(const uint8_t public_key[32],
                      const uint8_t *message, size_t message_len,
                      const uint8_t signature[64]);

// Optional: Verify multiple signatures in batch for efficiency
bool bn_ed25519_verify_batch(size_t num_signatures,
                            const uint8_t **public_keys,
                            const uint8_t **messages, const size_t *message_lens,
                            const uint8_t **signatures);
```

## Usage in Betanet

Ed25519 signatures are used throughout the protocol for:

1. Signing AS-hop in SCION path segments (§4.1)
2. Transition Control Stream signatures: `SIG = Ed25519 over (prevAS ‖ nextAS ‖ TS ‖ FLOW ‖ NONCE ‖ "bn-t1")` (§4.2)
3. Quorum certificates for Emergency Advance in the naming ledger (§8.2)
4. Federated Cashu mints using FROST-Ed25519 (§9.1)
5. Voucher authentication (§9.1)
6. Governance voting (§10)

## Implementation Requirements

- Constant-time implementation to prevent timing attacks
- Must be hardened against side-channel attacks
- Should follow RFC 8032 for Ed25519 implementation
- Must properly handle malleability concerns
- Should optimize batch verification for efficiency when multiple signatures need verification

## Special Cases

- For the federated Cashu mints, the implementation must support FROST-Ed25519 threshold signatures with parameters n ≥ 5, t = 3 as specified in §9.1
- Aggregated signatures for vouchers must be properly supported