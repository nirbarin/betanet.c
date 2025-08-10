# SCION Path Module

The Path module implements the path representation, selection, and validation functionality for SCION routing as specified in the Betanet 1.1 specification.

## Overview

This module provides the following path management components:

| Component | Purpose | Files |
| --------- | ------- | ----- |
| Path Representation | Data structures for SCION paths | [path.c/h](path.md) |
| Path Maintenance | Algorithms for path discovery and maintenance | [maintenance.c/h](maintenance.md) |

## Key Features

1. **Path Storage**: Efficient representation of SCION paths
2. **Path Selection**: Selection of optimal paths based on various criteria
3. **Path Validation**: Cryptographic validation of path segments
4. **Path Maintenance**: Discovery and maintenance of multiple paths per peer
5. **Path Failover**: Quick switching to alternative paths when failures occur

## Files

- [path.c/h](path.md) - Path representation and selection
- [maintenance.c/h](maintenance.md) - Path maintenance algorithms

## Compliance Requirements

1. Maintain up to 3 disjoint validated paths per peer
2. Switch within 300 ms when an alternative validated path exists
3. Implement proper path probing with exponential backoff