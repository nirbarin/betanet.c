# libp2p Implementation

## Overview

The `libp2p.c/h` files implement the libp2p protocol functionality for the Betanet overlay mesh, providing the core peer-to-peer networking capabilities.

## File Information

- **Files**: `src/overlay/libp2p.c`, `src/overlay/libp2p.h`
- **Purpose**: Implement libp2p protocol for overlay networking
- **Specification Reference**: Section 6.2 (Transports)

## Supported Transports

As specified in §6.2, the libp2p implementation must support:

```
/betanet/htx/1.1.0      (TCP-443)
/betanet/htxquic/1.1.0  (QUIC-443)
/betanet/webrtc/1.0.0   (optional)
```

## API

The libp2p module should expose functions for:

1. Initializing the libp2p subsystem
2. Establishing connections with peers
3. Managing multiple transport protocols
4. Handling protocol negotiation
5. Supporting stream multiplexing

Expected function prototypes include:

```c
// Initialize the libp2p subsystem
int bn_libp2p_init(bn_libp2p_ctx *ctx);

// Connect to a peer using any available transport
int bn_libp2p_connect(bn_libp2p_ctx *ctx,
                     const bn_peer_info *peer,
                     bn_libp2p_conn *conn);

// Connect to a peer using a specific transport
int bn_libp2p_connect_transport(bn_libp2p_ctx *ctx,
                               const bn_peer_info *peer,
                               const char *transport_protocol,
                               bn_libp2p_conn *conn);

// Open a new stream for a protocol
int bn_libp2p_open_stream(bn_libp2p_conn *conn,
                         const char *protocol,
                         bn_libp2p_stream *stream);

// Send data on a stream
int bn_libp2p_stream_write(bn_libp2p_stream *stream,
                          const uint8_t *data,
                          size_t data_len);

// Receive data from a stream
int bn_libp2p_stream_read(bn_libp2p_stream *stream,
                         uint8_t *buffer,
                         size_t buffer_size,
                         size_t *read_len);

// Close a stream
int bn_libp2p_stream_close(bn_libp2p_stream *stream);

// Close a connection
int bn_libp2p_conn_close(bn_libp2p_conn *conn);

// Start listening for incoming connections
int bn_libp2p_listen(bn_libp2p_ctx *ctx,
                    const char *transport_protocol,
                    const char *listen_addr);

// Handle incoming connections and streams
int bn_libp2p_set_stream_handler(bn_libp2p_ctx *ctx,
                                const char *protocol,
                                bn_libp2p_stream_handler handler,
                                void *user_data);

// Clean up the libp2p subsystem
void bn_libp2p_cleanup(bn_libp2p_ctx *ctx);
```

## Usage in Betanet

The libp2p functionality is used for:

1. Establishing peer-to-peer connections in the overlay mesh (§6.2)
2. Supporting multiple transport protocols for robustness
3. Multiplexing multiple protocol streams over a single connection
4. Providing security and authentication for peer connections

## Implementation Requirements

- **Transport Protocols**:
  - Must implement `/betanet/htx/1.1.0` over TCP-443
  - Must implement `/betanet/htxquic/1.1.0` over QUIC-443
  - May implement `/betanet/webrtc/1.0.0` (optional)

- **Protocol Negotiation**:
  - Must follow the libp2p multistream-select protocol
  - Must support protocol versioning

- **Connection Security**:
  - Must authenticate peers based on their public keys
  - Must validate that peer IDs match public keys

- **Stream Multiplexing**:
  - Must support multiple concurrent streams
  - Must implement flow control

- **Path Selection**:
  - Requesters should open ≥ 2 parallel streams on distinct SCION paths
  - May open a third under good conditions