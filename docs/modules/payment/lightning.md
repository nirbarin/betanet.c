# Lightning Implementation

## Overview

The `lightning.c/h` files implement the Lightning Network settlement functionality for the Betanet payment system, providing a connection to the broader Bitcoin ecosystem.

## File Information

- **Files**: `src/payment/lightning.c`, `src/payment/lightning.h`
- **Purpose**: Implement Lightning Network settlement
- **Specification Reference**: Section 9.2 (Settlement)

## Settlement Mechanism

As specified in §9.2:

- Relays may redeem ≥ 10,000 sat via their own Lightning node
- Relays may swap vouchers with peers
- Vouchers must not leave encrypted streams

## API

The Lightning module should expose functions for:

1. Managing Lightning Network connections
2. Creating and processing invoices
3. Settling vouchers via Lightning
4. Handling peer-to-peer swaps

Expected function prototypes include:

```c
// Initialize the Lightning settlement subsystem
int bn_lightning_init(bn_lightning_ctx *ctx, const char *node_config);

// Connect to a Lightning node
int bn_lightning_connect(bn_lightning_ctx *ctx,
                        const char *node_uri);

// Create a Lightning invoice
int bn_lightning_create_invoice(bn_lightning_ctx *ctx,
                               uint64_t amount_sat,
                               const char *description,
                               char *invoice,
                               size_t invoice_size);

// Pay a Lightning invoice
int bn_lightning_pay_invoice(bn_lightning_ctx *ctx,
                            const char *invoice,
                            bn_lightning_payment *payment);

// Redeem vouchers via Lightning
int bn_lightning_redeem_vouchers(bn_lightning_ctx *ctx,
                                const bn_voucher **vouchers,
                                size_t num_vouchers,
                                const char *destination_invoice);

// Swap vouchers with a peer
int bn_lightning_swap_with_peer(bn_lightning_ctx *ctx,
                               const bn_voucher **local_vouchers,
                               size_t num_local_vouchers,
                               const bn_peer_id *peer_id,
                               bn_voucher **received_vouchers,
                               size_t *num_received_vouchers);

// Check if an amount meets the minimum settlement threshold
bool bn_lightning_meets_threshold(uint64_t amount_sat);

// Validate a Lightning invoice
bool bn_lightning_validate_invoice(bn_lightning_ctx *ctx,
                                  const char *invoice,
                                  uint64_t *amount_sat);

// Get the node's public key
int bn_lightning_get_node_id(bn_lightning_ctx *ctx,
                            char *node_id,
                            size_t node_id_size);

// Clean up the Lightning settlement subsystem
void bn_lightning_cleanup(bn_lightning_ctx *ctx);
```

## Usage in Betanet

The Lightning functionality is used for:

1. Settling larger amounts of ecash (§9.2)
2. Connecting the Betanet economy to the broader Bitcoin ecosystem
3. Enabling peer-to-peer swaps between relays
4. Providing liquidity for the voucher system

## Implementation Requirements

- **Settlement Threshold**:
  - Must enforce minimum settlement threshold of 10,000 sat
  - Should batch smaller amounts for efficiency

- **Node Management**:
  - Should support connection to local or remote Lightning nodes
  - Must securely manage node credentials
  - Should handle connection failures gracefully

- **Invoice Handling**:
  - Must validate invoices before payment
  - Must verify successful payments
  - Should handle payment failures appropriately

- **Security Considerations**:
  - Vouchers must not leave encrypted streams
  - Must implement secure swap protocols
  - Should handle timeout and failure cases
  - Must verify peer identity during swaps