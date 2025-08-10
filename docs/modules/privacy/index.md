# Privacy Layer Module

The Privacy Layer module implements the Layer 4 (L4) functionality of the Betanet specification, providing optional anonymity through mixnet routing.

## Overview

This module provides the following privacy components:

| Component | Purpose | Files |
| --------- | ------- | ----- |
| Mixnet | Core mixnet implementation | [mixnet.c/h](mixnet.md) |
| Selection | Mixnode selection algorithms | [selection.c/h](selection.md) |
| Trust | Peer trust computation | [trust.c/h](trust.md) |

## Layer Model Coverage

The privacy module covers:

- **L4**: Optional privacy hop (Nym mixnet)

## Key Features

1. **Mixnet Routing**: Anonymous routing through multiple hops
2. **Mode Selection**: Different privacy/performance trade-offs
3. **Node Selection**: Secure, random selection of mix nodes
4. **Trust Computation**: Evaluation of peer trustworthiness

## Files

- [mixnet.c/h](mixnet.md) - Core mixnet implementation
- [selection.c/h](selection.md) - Mixnode selection algorithms
- [trust.c/h](trust.md) - Peer trust computation

## Compliance Requirements

1. Implements three privacy modes:
   - **strict**: Every stream through ≥ 3 Nym hops
   - **balanced** (default): ≥ 2 hops until peer-trust ≥ 0.8
   - **performance**: No mixnet unless destination label `.mixreq`
2. Selects mixnodes using BeaconSet randomness with per-stream entropy
3. Computes peer trust based on uptime attestations, observed behavior, and staked ecash