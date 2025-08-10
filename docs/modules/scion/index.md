# SCION Module

The SCION module implements the path selection and routing functionality for Betanet, providing the Layer 1 (L1) routing infrastructure.

## Overview

SCION (Scalability, Control, and Isolation On Next-generation networks) is a path-aware network architecture that provides path selection, multipath communication, and strong security guarantees.

This module provides the following components:

| Component | Purpose | Files |
| --------- | ------- | ----- |
| Header Format | SCION packet header definition | [header.h](header.md) |
| Path Management | Path selection and maintenance | [path/](path/index.md) |
| Transition | HTX-tunneled transition across non-SCION links | [transition.c/h](transition.md) |

## Layer Model Coverage

The SCION module covers:

- **L1**: Path selection & routing (SCION + HTX-tunnelled transition)

## Key Features

1. **Path Selection**: Explicit control over path selection
2. **Multi-Path Communication**: Use of multiple paths for resilience and performance
3. **Security**: Validation of path segments with cryptographic signatures
4. **Transition**: Tunneling through non-SCION networks using HTX

## Files

- [header.h](header.md) - SCION packet header format definition
- [path/path.c/h](path/path.md) - Path representation and selection
- [path/maintenance.c/h](path/maintenance.md) - Path maintenance algorithms
- [transition.c/h](transition.md) - HTX-tunneled transition mechanisms

## Compliance Requirements

1. Bridges non-SCION links by **HTX-tunnelled transition**
2. No on-wire transition header on public networks (§4.2)
3. Properly validates path segments and AS-hop signatures
4. Maintains multiple disjoint paths per peer with proper failover