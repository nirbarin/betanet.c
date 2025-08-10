# HTX Frame Format Implementation

## Overview

The `frame.c/h` files implement the inner frame format for the HTX protocol, defining the structure and handling of all data exchanged within an HTX session.

## File Information

- **Files**: `src/net/htx/frame.c`, `src/net/htx/frame.h`
- **Purpose**: Define and handle the HTX inner frame format
- **Specification Reference**: Section 5.4 (Inner Frame Format)

## Frame Structure

As defined in the specification (§5.4), the HTX inner frame format is:

```c
struct Frame {
  uint24  length;     // ciphertext length (excl. tag)
  uint8   type;       // 0=STREAM, 1=PING, 2=CLOSE, 3=KEY_UPDATE, 4=WINDOW_UPDATE
  varint  stream_id;  // present if type==STREAM or type==WINDOW_UPDATE
  uint8[] ciphertext;
}
```

## Frame Types

1. **STREAM (0)**: Carries stream data
2. **PING (1)**: Connection maintenance
3. **CLOSE (2)**: Closes a connection
4. **KEY_UPDATE (3)**: Signals a rekeying event
5. **WINDOW_UPDATE (4)**: Updates flow control window

## API

The frame module should expose functions for:

1. Creating frames of different types
2. Parsing received frames
3. Validating frame structure and content

Expected function prototypes include:

```c
// Create a STREAM frame
int bn_htx_frame_create_stream(uint8_t *buffer, size_t buffer_size, 
                              uint64_t stream_id, const uint8_t *data, 
                              size_t data_len, size_t *frame_len);

// Create a PING frame
int bn_htx_frame_create_ping(uint8_t *buffer, size_t buffer_size, 
                            size_t *frame_len);

// Create a CLOSE frame
int bn_htx_frame_create_close(uint8_t *buffer, size_t buffer_size, 
                             uint16_t error_code, const char *reason, 
                             size_t *frame_len);

// Create a KEY_UPDATE frame
int bn_htx_frame_create_key_update(uint8_t *buffer, size_t buffer_size, 
                                  size_t *frame_len);

// Create a WINDOW_UPDATE frame
int bn_htx_frame_create_window_update(uint8_t *buffer, size_t buffer_size, 
                                     uint64_t stream_id, uint32_t increment, 
                                     size_t *frame_len);

// Parse a received frame
int bn_htx_frame_parse(const uint8_t *buffer, size_t buffer_size, 
                      bn_htx_frame *frame, size_t *consumed);

// Encrypt a frame
int bn_htx_frame_encrypt(const bn_htx_crypto_ctx *crypto_ctx, 
                        bn_htx_frame *frame, 
                        uint8_t *output, size_t output_size, 
                        size_t *output_len);

// Decrypt a frame
int bn_htx_frame_decrypt(const bn_htx_crypto_ctx *crypto_ctx, 
                        const uint8_t *buffer, size_t buffer_size, 
                        bn_htx_frame *frame);
```

## Usage in Betanet

The frame format is used for:

1. All communication within an established HTX session
2. Carrying application data on STREAM frames
3. Maintaining the connection with PING frames
4. Managing flow control with WINDOW_UPDATE frames
5. Handling security with KEY_UPDATE frames
6. Gracefully terminating connections with CLOSE frames

## Implementation Requirements

- **Stream Handling**:
  - Client streams must be odd-numbered
  - Server streams must be even-numbered
  - Stream IDs must be encoded as QUIC variable-length integers (varint)

- **Flow Control**:
  - Initial window size must be 65,535 bytes
  - WINDOW_UPDATE must be sent when ≥ 50% of the window is consumed

- **PING Cadence**:
  - Must be random in [10s, 60s] with ±10% jitter
  - Must not have a fixed periodicity

- **KEY_UPDATE Processing**:
  - Receivers must accept KEY_UPDATE out-of-order relative to data frames
  - Must discard frames that verify only under the previous key after acknowledging KEY_UPDATE
  - Senders must cease using the old key immediately after transmitting KEY_UPDATE