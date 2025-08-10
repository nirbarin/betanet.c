# SCION Transition Implementation

## Overview

The `transition.c/h` files implement the transition mechanism for SCION packets across non-SCION network segments, using HTX tunneling as specified in the Betanet 1.1 specification.

## File Information

- **Files**: `src/scion/transition.c`, `src/scion/transition.h`
- **Purpose**: Provide tunneling of SCION packets across non-SCION networks
- **Specification Reference**: Section 4.2 (Transition Across Non-SCION Links)

## Transition Mechanism

The transition mechanism allows SCION packets to traverse non-SCION segments of the network by encapsulating them inside an HTX control session:

1. Establish an HTX session between gateways using origin-mirrored TLS (§5)
2. Negotiate a **Transition Control Stream** opened by the gateway acting as the server, with **stream_id=2** (first even stream)
3. Send a control stream payload with a CBOR map containing authentication and control information
4. Carry SCION payloads on subsequent HTX streams
5. Handle control stream rekey and maintenance

## Control Stream Payload

The control stream payload is a CBOR map with the following structure:

```
{ prevAS, nextAS, TS, FLOW, NONCE, SIG }
```

Where:
- `TS` = unix-sec timestamp
- `FLOW` = 8-byte random value
- `NONCE` = 8-byte random value
- `SIG` = Ed25519 signature over `(prevAS ‖ nextAS ‖ TS ‖ FLOW ‖ NONCE ‖ "bn-t1")`

## API

The transition module should expose functions for:

1. Establishing transition tunnels between gateways
2. Creating and verifying control stream payloads
3. Encapsulating and extracting SCION packets
4. Managing tunnel lifecycle

Expected function prototypes include:

```c
// Initialize a transition context as a client gateway
int bn_transition_init_client(bn_transition_ctx *ctx, 
                             const char *remote_gateway,
                             uint16_t port);

// Initialize a transition context as a server gateway
int bn_transition_init_server(bn_transition_ctx *ctx, 
                             uint16_t listen_port);

// Create a control stream payload
int bn_transition_create_control_payload(bn_transition_ctx *ctx,
                                        const bn_as_id *prev_as,
                                        const bn_as_id *next_as,
                                        uint8_t *output,
                                        size_t *output_len);

// Verify a control stream payload
int bn_transition_verify_control_payload(bn_transition_ctx *ctx,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        bn_as_id *prev_as,
                                        bn_as_id *next_as);

// Send a SCION packet through the transition tunnel
int bn_transition_send_packet(bn_transition_ctx *ctx,
                             const uint8_t *scion_packet,
                             size_t packet_len);

// Receive a SCION packet from the transition tunnel
int bn_transition_recv_packet(bn_transition_ctx *ctx,
                             uint8_t *buffer,
                             size_t buffer_size,
                             size_t *packet_len);

// Close a transition tunnel
int bn_transition_close(bn_transition_ctx *ctx);
```

## Usage in Betanet

The transition mechanism is used for:

1. Bridging non-SCION segments of the network (§4.2)
2. Providing secure and authenticated tunneling of SCION packets
3. Maintaining the end-to-end SCION path model across heterogeneous networks

## Implementation Requirements

- **Tunnel Protocol**: Must use HTX (§5) for the tunnel
- **Authentication**: Gateways must verify:
  - `TS` within ±300 seconds
  - Reject duplicate `(FLOW,TS)` for 2 hours
  - Apply per-peer token buckets
- **Encapsulation**: SCION payloads must be carried on HTX streams after control stream establishment
- **No Wire Header**: No per-packet transition header may appear on the public wire
- **Control Stream Management**: Gateways must close and re-establish the control stream on rekey (§5.3)
- **Legacy Compatibility**: The legacy on-wire transition header is prohibited on public networks and may only be used on private, administratively controlled links

## Security Considerations

- Signatures must be verified to prevent unauthorized tunneling
- Timestamp verification prevents replay attacks
- Flow and nonce values provide uniqueness
- Token buckets prevent resource exhaustion
- No plaintext SCION headers appear on public networks