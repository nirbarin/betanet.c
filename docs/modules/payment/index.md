# Payment System Module

The Payment System module implements the Layer 6 (L6) functionality of the Betanet specification, providing infrastructure for payments and economic incentives.

## Overview

This module provides the following payment components:

| Component | Purpose | Files |
| --------- | ------- | ----- |
| Cashu | Federated Cashu mint implementation | [cashu.c/h](cashu.md) |
| Voucher | Voucher format and handling | [voucher.c/h](voucher.md) |
| Lightning | Lightning Network settlement | [lightning.c/h](lightning.md) |

## Layer Model Coverage

The payment module covers:

- **L6**: Payments (federated Cashu + Lightning)

## Key Features

1. **Federated Cashu Mints**: Privacy-preserving e-cash system
2. **Voucher Format**: Compact payment representation
3. **Lightning Settlement**: Connection to the Lightning Network

## Files

- [cashu.c/h](cashu.md) - Federated Cashu mint implementation
- [voucher.c/h](voucher.md) - Voucher format implementation
- [lightning.c/h](lightning.md) - Lightning Network settlement

## Compliance Requirements

1. Accepts 128-byte Cashu vouchers for known keysets
2. Supports FROST-Ed25519 (n ≥ 5, t = 3) federated mints
3. Implements proper rate-limiting and validation
4. Supports Lightning settlement for larger amounts