# Networking Module

The Networking module implements the Layer 0-2 functionality of the Betanet specification, providing the foundational transport mechanisms for the network.

## Overview

This module provides the following networking components:

| Component | Purpose | Files |
| --------- | ------- | ----- |
| TCP Transport | Basic TCP connections over port 443 | [tcp.c/h](tcp.md) |
| QUIC Transport | QUIC protocol over UDP port 443 | [quic.c/h](quic.md) |
| HTX Protocol | Cover transport protocol for covert, censorship-resistant communication | [htx/](htx.md) |

## Layer Model Coverage

The networking module covers:

- **L0**: Access media (any IP bearer: fibre, 5G, sat, LoRa, etc.)
- **L2**: Cover transport (HTX over TCP-443 / QUIC-443)

## Key Features

1. **Origin Mirroring**: Mimics TLS fingerprints of legitimate front origins
2. **Access Tickets**: Replay-bound authentication for initial connection
3. **Noise Protocol**: Inner encryption with XK pattern
4. **Anti-Correlation**: Techniques to defeat traffic analysis

## Files

- [tcp.c/h](tcp.md) - TCP transport implementation
- [quic.c/h](quic.md) - QUIC transport implementation
- [htx/htx.c/h](htx.md) - Core HTX protocol implementation
- [htx/frame.c/h](htx/frame.md) - Frame format handling
- [htx/noise.c/h](htx/noise.md) - Noise XK handshake implementation
- [htx/ticket.c/h](htx/ticket.md) - Access ticket implementation
- [htx/origin_mirror.c/h](htx/origin_mirror.md) - Origin mirroring functionality

## Compliance Requirements

1. Implements HTX over TCP-443 **and** QUIC-443 with origin-mirrored TLS + ECH
2. Performs per-connection calibration (§5.1)
3. Uses **negotiated-carrier, replay-bound** access tickets (§5.2) with variable lengths and rate-limits
4. Performs inner Noise *XK* with key separation, nonce lifecycle, and rekeying (§5.3)
5. Emulates HTTP/2/3 with adaptive cadences and origin-mirrored parameters (§5.5)
6. Implements anti-correlation fallback with cover connections on UDP→TCP retries (§5.6)