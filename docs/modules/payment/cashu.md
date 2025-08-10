# Cashu Implementation

## Overview

The `cashu.c/h` files implement the federated Cashu mint functionality for the Betanet payment system, providing privacy-preserving ecash.

## File Information

- **Files**: `src/payment/cashu.c`, `src/payment/cashu.h`
- **Purpose**: Implement federated Cashu mints
- **Specification Reference**: Section 9.1 (Federated Cashu Mints)

## Cashu Mint Structure

As specified in §9.1:

- Each mint is a FROST-Ed25519 **(n ≥ 5, t = 3)** group
- Keyset ID is the `SHA-256(sorted pubkeys)`
- Mints announce on `betanet.mints` with ≥ 22-bit PoW and an HTX contact endpoint

## API

The Cashu module should expose functions for:

1. Initializing and managing Cashu mints
2. Creating and verifying blind signatures
3. Handling mint federation operations
4. Managing keysets and announcements

Expected function prototypes include:

```c
// Initialize a Cashu mint context
int bn_cashu_init(bn_cashu_ctx *ctx);

// Create a new mint keyset
int bn_cashu_create_keyset(bn_cashu_ctx *ctx,
                          const uint8_t **pubkeys,
                          size_t num_pubkeys,
                          uint8_t keyset_id[32]);

// Generate blinding factor for blind signatures
int bn_cashu_generate_blinding(bn_cashu_ctx *ctx,
                              uint8_t blinding[32]);

// Create a blinded message
int bn_cashu_blind_message(bn_cashu_ctx *ctx,
                          const uint8_t *secret,
                          size_t secret_len,
                          const uint8_t *blinding,
                          uint8_t *blinded_message);

// Create a partial blind signature (mint participant)
int bn_cashu_partial_sign(bn_cashu_ctx *ctx,
                         const uint8_t *blinded_message,
                         size_t blinded_message_len,
                         uint8_t participant_index,
                         const uint8_t *participant_key,
                         uint8_t *partial_signature);

// Aggregate partial signatures into a complete signature
int bn_cashu_aggregate_signatures(bn_cashu_ctx *ctx,
                                const uint8_t **partial_signatures,
                                const size_t *participant_indices,
                                size_t num_participants,
                                uint8_t aggregated_sig[64]);

// Unblind a signature
int bn_cashu_unblind_signature(bn_cashu_ctx *ctx,
                              const uint8_t *blinded_signature,
                              const uint8_t *blinding,
                              uint8_t *unblinded_signature);

// Verify a Cashu signature
bool bn_cashu_verify_signature(bn_cashu_ctx *ctx,
                              const uint8_t *keyset_id,
                              const uint8_t *secret,
                              size_t secret_len,
                              const uint8_t *signature);

// Create a mint announcement
int bn_cashu_create_announcement(bn_cashu_ctx *ctx,
                               const uint8_t *keyset_id,
                               const char *endpoint,
                               uint8_t *announcement,
                               size_t *announcement_len);

// Verify a mint announcement
bool bn_cashu_verify_announcement(bn_cashu_ctx *ctx,
                                const uint8_t *announcement,
                                size_t announcement_len);

// Clean up a Cashu context
void bn_cashu_cleanup(bn_cashu_ctx *ctx);
```

## Usage in Betanet

The Cashu functionality is used for:

1. Creating and operating federated mints (§9.1)
2. Issuing and verifying ecash tokens
3. Supporting the voucher system
4. Providing the economic infrastructure for the network

## Implementation Requirements

- **Mint Structure**:
  - Must implement FROST-Ed25519 threshold signatures
  - Must support n ≥ 5 participants with threshold t = 3
  - Must correctly compute keyset ID as `SHA-256(sorted pubkeys)`

- **Blind Signatures**:
  - Must implement blind signature protocol securely
  - Must prevent double-spending
  - Must ensure privacy of transactions

- **Announcements**:
  - Mints must announce on `betanet.mints`
  - Announcements must include ≥ 22-bit PoW
  - Must provide an HTX contact endpoint

- **Security Considerations**:
  - Must ensure secure key management
  - Must validate all inputs
  - Must prevent signature forgery