# Overlay Mesh Module

The Overlay Mesh module implements the Layer 3 (L3) functionality of the Betanet specification, providing peer-to-peer networking and content-addressable storage.

## Overview

This module provides the following overlay components:

| Component | Purpose | Files |
| --------- | ------- | ----- |
| Peer Identity | Peer identification and management | [peer.c/h](peer.md) |
| Discovery | Bootstrap peer discovery | [discovery.c/h](discovery.md) |
| libp2p | Network protocol implementation | [libp2p.c/h](libp2p.md) |
| Bitswap | Content exchange protocol | [bitswap.c/h](bitswap.md) |
| Proof of Work | Anti-abuse mechanisms | [pow.c/h](pow.md) |

## Layer Model Coverage

The overlay module covers:

- **L3**: Overlay mesh (libp2p-v2 object relay)

## Key Features

1. **Peer Identity**: Self-certifying peer identities
2. **Bootstrap Discovery**: Rotating rendezvous mechanisms
3. **Transport Protocols**: Multiple transport protocols
4. **Content Exchange**: Bitswap block exchange protocol
5. **Anti-Abuse**: Proof-of-work and rate limiting

## Files

- [peer.c/h](peer.md) - Peer identity implementation
- [discovery.c/h](discovery.md) - Bootstrap discovery mechanisms
- [libp2p.c/h](libp2p.md) - libp2p protocol implementation
- [bitswap.c/h](bitswap.md) - Content exchange protocol
- [pow.c/h](pow.md) - Proof-of-work implementation

## Compliance Requirements

1. Offers `/betanet/htx/1.1.0` and `/betanet/htxquic/1.1.0` transports
2. Bootstraps via rotating rendezvous IDs derived from BeaconSet with PoW
3. Implements Bitswap-v2 for content exchange
4. Enforces anti-abuse mechanisms including proof-of-work and rate limiting