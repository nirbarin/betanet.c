# HTX (Hidden Transport) Module

## Overview

The HTX module implements the cover transport protocol for Betanet, providing covert, censorship-resistant communication that appears to be regular HTTPS traffic.

## File Information

- **Directory**: `src/net/htx/`
- **Purpose**: Implement the HTX protocol as specified in Section 5 of the specification
- **Specification Reference**: Section 5 (Cover Transport)

## Components

HTX consists of several components:

1. **Core Protocol** (`htx.c/h`) - Main protocol implementation
2. **Frame Format** (`frame.c/h`) - Inner frame format handling
3. **Noise Protocol** (`noise.c/h`) - Noise XK handshake implementation
4. **Access Tickets** (`ticket.c/h`) - Access ticket authentication
5. **Origin Mirroring** (`origin_mirror.c/h`) - TLS fingerprint mirroring

## Key Features

1. **Outer TLS 1.3 Handshake with Origin Mirroring**:
   - Mirrors front origin's fingerprint (JA3/JA4, ALPN, extensions, GREASE, etc.)
   - Per-connection calibration pre-flight
   - Strict tolerance requirements for fingerprint matching

2. **Access-Ticket Bootstrap**:
   - Decoy site publishes ticket parameters
   - Negotiated carrier mechanism (cookie, query, body)
   - Replay protection and rate limiting

3. **Noise XK Inner Handshake**:
   - End-to-end encryption using Noise XK pattern
   - Post-quantum hybrid (X25519-Kyber768) from 2027-01-01
   - Strict key management and rekeying requirements

4. **Inner Frame Format**:
   - Multiplexed streams with flow control
   - Multiple frame types (STREAM, PING, CLOSE, KEY_UPDATE, WINDOW_UPDATE)

5. **HTTP/2 / HTTP/3 Behavior Emulation**:
   - Mirrors origin's H2 SETTINGS
   - Random PING cadence to defeat timing analysis
   - Idle padding to defeat traffic analysis

6. **Anti-Correlation Fallback**:
   - Detects blocking and falls back from QUIC to TCP
   - Uses cover connections to defeat correlation analysis

## Implementation Requirements

1. **Protocol Versions**:
   - Must implement `/betanet/htx/1.1.0` (TCP)
   - Must implement `/betanet/htxquic/1.1.0` (QUIC)
   - May offer `/betanet/htx/1.0.0` for legacy compatibility

2. **Security Requirements**:
   - Must use negotiated-carrier, replay-bound access tickets
   - Must implement origin-mirrored TLS
   - Must use Noise XK with proper key separation and rekeying
   - Must implement anti-correlation measures

3. **Emulation Requirements**:
   - Must emulate HTTP/2 or HTTP/3 with adaptive cadences
   - Must match origin's HTTP behavior within specified tolerances

## Individual Component Documentation

- [HTX Core](htx/htx.md)
- [Frame Format](htx/frame.md)
- [Noise Protocol](htx/noise.md)
- [Access Tickets](htx/ticket.md)
- [Origin Mirroring](htx/origin_mirror.md)