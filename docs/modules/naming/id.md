# Self-Certifying ID Implementation

## Overview

The `id.c/h` files implement the self-certifying identity functionality for the Betanet naming and trust layer, providing cryptographically verifiable identities.

## File Information

- **Files**: `src/naming/id.c`, `src/naming/id.h`
- **Purpose**: Implement self-certifying identity system
- **Specification Reference**: Section 8.1 (Self-Certifying ID)

## ID Format

As defined in §8.1, the self-certifying ID format is:

```
betanet://<hex SHA-256(service-pubkey)>[/resource]
```

The identity is derived from the SHA-256 hash of the service's public key, allowing anyone to verify that an entity presenting a public key is the rightful owner of the corresponding ID.

## API

The ID module should expose functions for:

1. Creating self-certifying IDs from public keys
2. Parsing and formatting ID strings
3. Verifying that public keys match IDs
4. Managing resource paths

Expected function prototypes include:

```c
// Create a self-certifying ID from a public key
int bn_id_from_pubkey(const uint8_t *pubkey, 
                     size_t pubkey_len, 
                     bn_id *id);

// Format an ID as a string
int bn_id_to_string(const bn_id *id, 
                   const char *resource,
                   char *buffer, 
                   size_t buffer_size);

// Parse an ID string
int bn_id_from_string(const char *id_string, 
                     bn_id *id, 
                     char **resource);

// Verify that a public key matches an ID
bool bn_id_verify(const bn_id *id, 
                 const uint8_t *pubkey, 
                 size_t pubkey_len);

// Compare two IDs for equality
bool bn_id_equals(const bn_id *a, const bn_id *b);

// Extract resource path from an ID string
int bn_id_get_resource(const char *id_string, 
                      char *resource, 
                      size_t resource_size);

// Check if an ID is valid
bool bn_id_is_valid(const bn_id *id);
```

## Usage in Betanet

The self-certifying ID functionality is used for:

1. Creating cryptographically verifiable identities (§8.1)
2. Addressing resources in the network
3. Verifying ownership of identities
4. Providing the foundation for the naming system

## Implementation Requirements

- **ID Generation**:
  - Must derive IDs from SHA-256 hash of service public keys
  - Must properly format IDs as specified in §8.1

- **Verification**:
  - Must verify that presented public keys hash to the claimed ID
  - Must reject connections if verification fails

- **String Formatting**:
  - Must format IDs as `betanet://<hex SHA-256(service-pubkey)>`
  - Must properly handle optional resource paths
  - Must use lowercase hexadecimal representation

- **Resource Paths**:
  - Should support arbitrary resource paths
  - Must properly escape and unescape special characters in paths