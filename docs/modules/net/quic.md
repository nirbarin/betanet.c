# QUIC Transport Implementation

## Overview

The QUIC transport module implements the QUIC protocol (RFC 9000) for Betanet, providing a modern, multiplexed, encrypted transport over UDP port 443. It supports HTTP/3 emulation for traffic analysis resistance and includes MASQUE CONNECT-UDP for proxy functionality.

## File Information

- **Main Interface**: `src/net/quic.c`, `src/net/quic/quic.h`
- **Implementation Directory**: `src/net/quic/`
- **Purpose**: Provide QUIC transport functionality over UDP port 443
- **Specification Reference**: Sections 3 (Layer Model), 5.1 (Outer TLS 1.3 Handshake), 5.6 (UDP Variant & Anti-Correlation Fallback)

## Implementation Structure

The QUIC implementation follows a modular approach with the following components:

1. **Public API**: Defined in `quic.h` and implemented in `quic.c`
2. **Internal Components**:
   - `internal.h`: Internal structures and function declarations
   - `config.c`: Configuration and utility functions
   - `conn.c`: Connection management and processing
   - `stream.c`: Stream operations
   - `masque.c`: MASQUE protocol support for UDP tunneling

This modular structure allows for better maintainability, testability, and performance profiling.

## API

The QUIC module exposes functions for:

1. Establishing QUIC connections
2. Managing connection lifecycle and streams
3. Sending and receiving data
4. Handling connection failures and fallback to TCP
5. Implementing MASQUE CONNECT-UDP

Key function prototypes include:

```c
// Module initialization/cleanup
int bn_quic_module_init(void);
int bn_quic_module_cleanup(void);

// Context management
int bn_quic_create(bn_quic_ctx_t **ctx, const bn_quic_config_t *config);
int bn_quic_destroy(bn_quic_ctx_t *ctx);

// Connection management
int bn_quic_connect(bn_quic_ctx_t *ctx, const char *host, uint16_t port);
int bn_quic_close(bn_quic_ctx_t *ctx, bool app_error, uint64_t error_code, const char *reason);
int bn_quic_process(bn_quic_ctx_t *ctx, uint32_t timeout_ms);

// Stream operations
int bn_quic_stream_open(bn_quic_ctx_t *ctx, bn_quic_stream_t **stream, bn_quic_stream_direction_t direction);
int bn_quic_stream_send(bn_quic_stream_t *stream, const uint8_t *data, size_t len, size_t *sent, bool fin);
int bn_quic_stream_recv(bn_quic_stream_t *stream, uint8_t *buffer, size_t len, size_t *received, bool *fin);
int bn_quic_stream_close(bn_quic_stream_t *stream);

// Fallback detection
bool bn_quic_is_blocked(bn_quic_ctx_t *ctx);

// MASQUE support
int bn_quic_masque_connect_udp(bn_quic_ctx_t *ctx, const char *target_host, uint16_t target_port);

// Utility functions
const char* bn_quic_error_string(int error);
int bn_quic_config_default(bn_quic_config_t *config);
```

## Usage in Betanet

QUIC transport is used for:

1. Preferred transport for HTX protocol (§5.6)
2. Establishing the `/betanet/htxquic/1.1.0` transport (§6.2)
3. Implementing MASQUE `CONNECT-UDP` for proxy functionality

## Implementation Requirements

- **QUIC v1**: Implements QUIC version 1 (RFC 9000)
- **UDP Port 443**: Uses UDP port 443 to blend with HTTP/3 traffic
- **Origin Mirroring**: Implements origin mirroring as described in §5.1
- **HTTP/3 Emulation**: Emulates HTTP/3 behavior for traffic analysis resistance
- **Fallback**: Detects blocking and triggers fallback to TCP:
  - On failure, retries with TCP using randomized back-off **[200 ms, 1 200 ms]**
  - Uses **fresh** ClientHello randomness and fresh QUIC Connection IDs
- **Connection IDs**: Properly manages Connection IDs to prevent linkability
- **MASQUE**: Implements MASQUE `CONNECT-UDP` for tunneling

## Error Handling

The module uses a consistent error handling approach:
- Return codes: `BN_QUIC_SUCCESS` (0) for success, negative values for errors
- Error propagation: Functions return error codes directly to the caller
- Resource cleanup: Proper cleanup on error paths using goto for complex functions

## Dependencies

- **ngtcp2**: QUIC implementation library (via deps.cmake)
- **OpenSSL**: For cryptographic operations
- Standard C libraries for networking and utilities

## Thread Safety

- The implementation is not thread-safe by default
- Each context should be used by a single thread
- Caller must implement synchronization if sharing contexts between threads