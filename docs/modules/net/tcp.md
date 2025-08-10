# TCP Transport Implementation

## Overview

The `tcp.c/h` files implement the TCP transport functionality for Betanet, providing a reliable connection-oriented transport over port 443.

## File Information

- **Files**: `src/net/tcp.c`, `src/net/tcp.h`
- **Purpose**: Provide TCP transport functionality over port 443
- **Specification Reference**: Sections 3 (Layer Model), 5.1 (Outer TLS 1.3 Handshake), 5.6 (Anti-Correlation Fallback)

## API

The TCP module should expose functions for:

1. Establishing TCP connections with TLS
2. Managing connection lifecycle
3. Sending and receiving data
4. Handling connection failures and retries
5. Implementing anti-correlation measures

Expected function prototypes include:

```c
// Initialize a TCP transport context
int bn_tcp_init(bn_tcp_ctx *ctx, const bn_tcp_config *config);

// Connect to a remote host with TLS
int bn_tcp_connect(bn_tcp_ctx *ctx, const char *host, uint16_t port);

// Send data over a TCP connection
int bn_tcp_send(bn_tcp_ctx *ctx, const uint8_t *data, size_t len);

// Receive data from a TCP connection
int bn_tcp_recv(bn_tcp_ctx *ctx, uint8_t *buffer, size_t len, size_t *received);

// Close a TCP connection
int bn_tcp_close(bn_tcp_ctx *ctx);

// Implement anti-correlation measures (cover connections)
int bn_tcp_cover_connect(const char *unrelated_host, uint16_t port);
```

## Usage in Betanet

TCP transport is used for:

1. Primary transport for HTX protocol (§5)
2. Fallback when QUIC is blocked (§5.6)
3. Establishing the `/betanet/htx/1.1.0` transport (§6.2)

## Implementation Requirements

- **TLS 1.3**: Must use TLS 1.3 for encryption
- **Origin Mirroring**: Must implement origin mirroring as described in §5.1
- **Port 443**: Must use TCP port 443 to blend with HTTPS traffic
- **Anti-Correlation**: On QUIC→TCP fallback, must implement cover connections (§5.6):
  - On failure, retry TCP with randomized back-off **[200 ms, 1 200 ms]**
  - Launch **cover connections** to **≥ 2** unrelated origins within **[0, 1 000 ms]**
  - Delay HTX start by an additional **[100, 700 ms]**
  - Limit cover connections to **2** retries per minute
  - Tear down cover connections within **[3, 15] s** unless they carry user traffic
- **HTTP/2 Emulation**: Must emulate HTTP/2 behavior for traffic analysis resistance