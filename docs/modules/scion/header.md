# SCION Header Implementation

## Overview

The `header.h` file defines the SCION packet header format as specified in the Betanet 1.1 specification.

## File Information

- **File**: `src/scion/header.h`
- **Purpose**: Define the SCION packet header structure
- **Specification Reference**: Section 4.1 (SCION Packet Header)

## Header Structure

As defined in the specification (§4.1), the SCION packet header format is:

```
0       1       2       3
+-------+-------+-------+-------+
|Ver=0x2|Reserved|  Type        |
+-------------------------------+
|     Total Header Length       |
+-------------------------------+
|       Payload Length          |
+-------------------------------+
|      Path Segment 0 …         |
+-------------------------------+
```

The header should be defined as a struct with appropriate fields:

```c
// SCION packet header
typedef struct {
    uint8_t  version;        // Must be 0x02
    uint8_t  reserved;       // Reserved for future use
    uint16_t type;           // Packet type (0x01=single path, 0x03=path list)
    uint32_t header_length;  // Total header length in bytes
    uint32_t payload_length; // Payload length in bytes
    // Path segments follow the header
} bn_scion_header_t;
```

## Header Types

1. **Single Path (0x01)**: Packet contains a single path
2. **Path List (0x03)**: Packet contains multiple path options

## API

The header module should expose functions for:

1. Creating SCION headers
2. Parsing received headers
3. Validating header fields

Expected function prototypes include:

```c
// Create a SCION header
int bn_scion_header_create(bn_scion_header_t *header, 
                          uint16_t type,
                          uint32_t header_length,
                          uint32_t payload_length);

// Parse a received SCION header
int bn_scion_header_parse(const uint8_t *buffer, 
                         size_t buffer_size,
                         bn_scion_header_t *header);

// Validate a SCION header
bool bn_scion_header_validate(const bn_scion_header_t *header);

// Serialize a SCION header to a buffer
int bn_scion_header_serialize(const bn_scion_header_t *header,
                             uint8_t *buffer,
                             size_t buffer_size);

// Get the size of a SCION header
size_t bn_scion_header_size(void);
```

## Usage in Betanet

The SCION header is used for:

1. All packet routing in the SCION layer (L1)
2. Defining the format of packets that traverse the network
3. Indicating whether packets use single or multiple paths
4. Delimiting the path information from payload data

## Implementation Requirements

- **Version**: Must be `0x02`
- **Type**: Must be `0x01` (single path) or `0x03` (path list)
- **Path Segments**: Each AS-hop signature in every segment must be verified before forwarding; otherwise packets must be dropped
- **Format**: All multi-byte integers must be encoded as unsigned big-endian
- **Processing**: Implementation must properly parse and validate all header fields before processing a packet