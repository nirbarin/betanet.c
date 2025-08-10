# HTX Core Implementation

## Overview

The `htx.c/h` files implement the core functionality of the HTX (Hidden Transport) protocol for Betanet, coordinating all the components needed for covert, censorship-resistant communication.

## File Information

- **Files**: `src/net/htx/htx.c`, `src/net/htx/htx.h`
- **Purpose**: Implement the core HTX protocol functionality
- **Specification Reference**: Section 5 (Cover Transport)

## API

The HTX core module should expose functions for:

1. Initializing the HTX protocol
2. Establishing HTX sessions
3. Creating and managing streams
4. Coordinating between the various HTX components

Expected function prototypes include:

```c
// Initialize HTX context
int bn_htx_init(bn_htx_ctx *ctx, const bn_htx_config *config);

// Connect to a remote host using HTX
int bn_htx_connect(bn_htx_ctx *ctx, const char *host, uint16_t port);

// Accept an incoming HTX connection (server-side)
int bn_htx_accept(bn_htx_ctx *ctx, bn_htx_connection *conn);

// Open a new HTX stream
int bn_htx_stream_open(bn_htx_ctx *ctx, bn_htx_stream *stream);

// Send data on an HTX stream
int bn_htx_stream_send(bn_htx_stream *stream, const uint8_t *data, size_t len);

// Receive data from an HTX stream
int bn_htx_stream_recv(bn_htx_stream *stream, uint8_t *buffer, size_t len, size_t *received);

// Close an HTX stream
int bn_htx_stream_close(bn_htx_stream *stream);

// Close an HTX connection
int bn_htx_close(bn_htx_ctx *ctx);

// Handle HTX events and maintain the connection
int bn_htx_process_events(bn_htx_ctx *ctx);
```

## Usage in Betanet

The HTX core is used for:

1. Coordinating all aspects of the HTX protocol (§5)
2. Managing the establishment of the inner encrypted tunnel
3. Handling stream multiplexing and flow control
4. Coordinating between TCP and QUIC transports
5. Providing the SCION transition tunneling capability (§4.2)

## Implementation Requirements

- **Protocol Flow**:
  1. Establish outer TLS connection with origin mirroring
  2. Perform access ticket authentication
  3. Establish inner Noise XK tunnel
  4. Create and manage streams for data exchange
  5. Handle rekeying and connection maintenance

- **Transport Support**:
  - Must support both TCP and QUIC transports
  - Must handle fallback from QUIC to TCP with anti-correlation

- **Stream Handling**:
  - Client streams must be odd-numbered
  - Server streams must be even-numbered
  - Must implement flow control with 65,535 byte window
  - Must send WINDOW_UPDATE when ≥ 50% of window is consumed

- **Connection Maintenance**:
  - Must implement HTTP/2 or HTTP/3 emulation
  - Must send PING frames with random cadence
  - Must perform rekeying when thresholds are reached
  - Must manage idle padding for traffic analysis resistance