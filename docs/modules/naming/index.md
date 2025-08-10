# Naming & Trust Module

The Naming & Trust module implements the Layer 5 (L5) functionality of the Betanet specification, providing self-certifying identities and a human-readable alias system.

## Overview

This module provides the following naming and trust components:

| Component | Purpose | Files |
| --------- | ------- | ----- |
| ID | Self-certifying identity system | [id.c/h](id.md) |
| Ledger | Human-readable alias ledger | [ledger.c/h](ledger.md) |
| Quorum | Quorum certificates for liveness | [quorum.c/h](quorum.md) |

## Layer Model Coverage

The naming module covers:

- **L5**: Naming & trust (self-certifying IDs + 3-chain alias ledger)

## Key Features

1. **Self-Certifying IDs**: Cryptographically verifiable identities
2. **Human-Readable Aliases**: User-friendly name system
3. **Multi-Chain Consensus**: Finality-bound 2-of-3 chain consensus
4. **Liveness Mechanism**: Emergency advance for continued operation during chain issues

## Files

- [id.c/h](id.md) - Self-certifying identity implementation
- [ledger.c/h](ledger.md) - Alias ledger implementation
- [quorum.c/h](quorum.md) - Quorum certificate implementation

## Compliance Requirements

1. Verifies that peer's presented pubkey hashes to the ID
2. Validates alias records across multiple chains with finality guarantees
3. Implements emergency advance liveness mechanism with proper quorum certificates