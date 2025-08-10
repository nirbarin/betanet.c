# QUIC Transport Implementation

## Overview

The `quic.c/h` files implement the QUIC transport functionality for Betanet, providing a modern, multiplexed, encrypted transport over UDP port 443.

## File Information

- **Files**: `src/net/quic.c`, `src/net/quic.h`
- **Purpose**: Provide QUIC transport functionality over UDP port 443
- **Specification Reference**: Sections 3 (Layer Model), 5.1 (Outer TLS 1.3 Handshake), 5.6 (UDP Variant & Anti-Correlation Fallback)

## API

The QUIC module should expose functions for:

1. Establishing QUIC connections
2. Managing connection lifecycle and streams
3. Sending and receiving data
4. Handling connection failures and fallback to TCP
5. Implementing MASQUE CONNECT-UDP

Expected function prototypes include:

```c
// Initialize a QUIC transport context
int bn_quic_init(bn_quic_ctx *ctx, const bn_quic_config *config);

// Connect to a remote host using QUIC
int bn_quic_connect(bn_quic_ctx *ctx, const char *host, uint16_t port);

// Open a new stream
int bn_quic_stream_open(bn_quic_ctx *ctx, bn_quic_stream *stream);

// Send data on a QUIC stream
int bn_quic_stream_send(bn_quic_stream *stream, const uint8_t *data, size_t len);

// Receive data from a QUIC stream
int bn_quic_stream_recv(bn_quic_stream *stream, uint8_t *buffer, size_t len, size_t *received);

// Close a QUIC stream
int bn_quic_stream_close(bn_quic_stream *stream);

// Close a QUIC connection
int bn_quic_close(bn_quic_ctx *ctx);

// Detect QUIC blocking and trigger TCP fallback
bool bn_quic_is_blocked(bn_quic_ctx *ctx);

// Implement MASQUE CONNECT-UDP
int bn_quic_masque_connect_udp(bn_quic_ctx *ctx, const char *target_host, uint16_t target_port);
```

## Usage in Betanet

QUIC transport is used for:

1. Preferred transport for HTX protocol (§5.6)
2. Establishing the `/betanet/htxquic/1.1.0` transport (§6.2)
3. Implementing MASQUE `CONNECT-UDP` for proxy functionality

## Implementation Requirements

- **QUIC v1**: Must implement QUIC version 1 (RFC 9000)
- **UDP Port 443**: Must use UDP port 443 to blend with HTTP/3 traffic
- **Origin Mirroring**: Must implement origin mirroring as described in §5.1
- **HTTP/3 Emulation**: Must emulate HTTP/3 behavior for traffic analysis resistance
- **Fallback**: Must detect blocking and trigger fallback to TCP:
  - On failure, retry TCP with randomized back-off **[200 ms, 1 200 ms]**
  - Use **fresh** ClientHello randomness and fresh QUIC Connection IDs
- **Connection IDs**: Must properly manage Connection IDs to prevent linkability
- **MASQUE**: Must implement MASQUE `CONNECT-UDP` for tunneling