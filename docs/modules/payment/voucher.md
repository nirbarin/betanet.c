# Voucher Implementation

## Overview

The `voucher.c/h` files implement the voucher format and handling functionality for the Betanet payment system, providing a compact representation of ecash tokens.

## File Information

- **Files**: `src/payment/voucher.c`, `src/payment/voucher.h`
- **Purpose**: Implement voucher format and handling
- **Specification Reference**: Section 9.1 (Federated Cashu Mints)

## Voucher Format

As specified in §9.1, the voucher format is 128 bytes:

```
keysetID32 ‖ secret32 ‖ aggregatedSig64
```

Where:
- `keysetID32` is the 32-byte keyset identifier
- `secret32` is the 32-byte secret value
- `aggregatedSig64` is the 64-byte Ed25519 aggregate signature over `secret32`

## API

The voucher module should expose functions for:

1. Creating and validating vouchers
2. Serializing and deserializing vouchers
3. Managing voucher processing and redemption

Expected function prototypes include:

```c
// Create a new voucher
int bn_voucher_create(bn_voucher *voucher,
                     const uint8_t *keyset_id,
                     const uint8_t *secret,
                     const uint8_t *signature);

// Serialize a voucher to a binary representation
int bn_voucher_serialize(const bn_voucher *voucher,
                        uint8_t *buffer,
                        size_t buffer_size);

// Deserialize a voucher from a binary representation
int bn_voucher_deserialize(const uint8_t *buffer,
                          size_t buffer_size,
                          bn_voucher *voucher);

// Validate a voucher
bool bn_voucher_validate(const bn_voucher *voucher,
                        const bn_cashu_ctx *cashu_ctx);

// Check if a voucher uses a known keyset
bool bn_voucher_has_known_keyset(const bn_voucher *voucher,
                                const bn_cashu_ctx *cashu_ctx);

// Process a voucher for payment
int bn_voucher_process(bn_voucher_ctx *ctx,
                      const bn_voucher *voucher,
                      const char *peer_id);

// Check if a voucher has been spent
bool bn_voucher_is_spent(bn_voucher_ctx *ctx,
                        const bn_voucher *voucher);

// Record a voucher as spent
int bn_voucher_mark_spent(bn_voucher_ctx *ctx,
                         const bn_voucher *voucher);

// Check rate limits for voucher processing
bool bn_voucher_check_rate_limits(bn_voucher_ctx *ctx,
                                 const bn_voucher *voucher,
                                 const char *peer_id);

// Create a legacy 64-byte voucher (for compatibility)
int bn_voucher_create_legacy(bn_voucher_legacy *voucher,
                            const uint8_t *keyset_id,
                            const uint8_t *signature);

// Convert between 128-byte and 64-byte voucher formats
int bn_voucher_convert(const bn_voucher *voucher,
                      bn_voucher_legacy *legacy_voucher);

// Clean up voucher context
void bn_voucher_cleanup(bn_voucher_ctx *ctx);
```

## Usage in Betanet

The voucher functionality is used for:

1. Representing ecash payments in a compact format (§9.1)
2. Enabling transfer of value between peers
3. Paying for services within the network
4. Supporting economic incentives

## Implementation Requirements

- **Voucher Format**:
  - Must implement the 128-byte format as specified
  - May support legacy 64-byte format for backward compatibility
  - Must properly parse and validate all components

- **Validation**:
  - Relays must accept vouchers only for known keysets
  - Unknown keysets may be cached pending validation
  - Must apply per-keyset and per-peer rate limits

- **Security**:
  - Vouchers must not leave encrypted streams
  - Must prevent double-spending through proper tracking
  - Must validate signatures before acceptance

- **Legacy Support**:
  - 64-byte vouchers may be issued only to legacy peers
  - 1.1 receivers must accept both formats for the operator-defined deprecation window