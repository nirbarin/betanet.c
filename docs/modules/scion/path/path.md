# SCION Path Representation

## Overview

The `path.c/h` files implement the path representation and selection functionality for SCION routing, defining the data structures and algorithms needed to represent, validate, and select paths through the network.

## File Information

- **Files**: `src/scion/path/path.c`, `src/scion/path/path.h`
- **Purpose**: Provide data structures and functions for SCION path handling
- **Specification Reference**: Section 4 (Path Layer)

## Path Structure

A SCION path consists of a sequence of AS-hop segments, each with its own signature. The path module must represent:

1. **Path Segments**: Sequences of inter-domain links
2. **AS-Hops**: Individual Autonomous System traversals
3. **Path Properties**: Metrics like latency, bandwidth, and reliability
4. **Path Validation**: Cryptographic verification of path segments

## API

The path module should expose functions for:

1. Creating and manipulating path structures
2. Validating path segments and signatures
3. Selecting paths based on various criteria
4. Serializing and deserializing paths

Expected function prototypes include:

```c
// Create a new path structure
int bn_path_create(bn_path *path);

// Add a segment to a path
int bn_path_add_segment(bn_path *path, const bn_path_segment *segment);

// Validate a path segment's signature
bool bn_path_validate_segment(const bn_path_segment *segment, 
                             const bn_as_cert *as_cert);

// Validate an entire path
bool bn_path_validate(const bn_path *path, const bn_cert_store *cert_store);

// Select the best path from multiple options based on criteria
int bn_path_select_best(const bn_path **paths, size_t num_paths, 
                       bn_path_criteria criteria, bn_path **selected);

// Serialize a path to a buffer
int bn_path_serialize(const bn_path *path, uint8_t *buffer, 
                     size_t buffer_size, size_t *written);

// Deserialize a path from a buffer
int bn_path_deserialize(const uint8_t *buffer, size_t buffer_size, 
                       bn_path *path, size_t *consumed);

// Compare two paths for equality
bool bn_path_equals(const bn_path *path1, const bn_path *path2);

// Check if two paths are disjoint
bool bn_path_is_disjoint(const bn_path *path1, const bn_path *path2);

// Free resources associated with a path
void bn_path_destroy(bn_path *path);
```

## Usage in Betanet

The path representation is used for:

1. Storing and managing SCION paths (§4)
2. Validating path segments before forwarding packets
3. Selecting optimal paths for communication
4. Maintaining multiple disjoint paths per peer
5. Supporting path-aware communication

## Implementation Requirements

- **Path Validation**: Must verify AS-hop signatures in each segment before forwarding; otherwise drop
- **Path Selection**: Must support selection of optimal paths based on metrics
- **Path Diversity**: Must be able to identify and maintain disjoint paths
- **Path Types**: Must support both single path (type 0x01) and path list (type 0x03) formats
- **Segment Structure**: Must properly represent the hierarchical structure of SCION path segments