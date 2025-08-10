# Cryptographic Algorithm Registry

## Overview

The `registry.c/h` files implement the algorithm agility registry as specified in Section 2 of the Betanet 1.1 specification. This registry enables dynamic selection of cryptographic algorithms and facilitates future algorithm transitions without changing wire formats.

## File Information

- **Files**: `src/crypto/registry.c`, `src/crypto/registry.h`
- **Purpose**: Provide a registry for cryptographic algorithm agility
- **Specification Reference**: Section 2 (Cryptography): "Algorithm agility. Implementations **MUST** expose a registry of cryptographic parameters keyed by OIDs; future substitutions **MUST** be negotiated via governance (L7) without changing wire formats where lengths permit."

## API

The registry module exposes functions for:

1. Registry initialization and management
2. Algorithm registration and lookup
3. OID (Object Identifier) mapping
4. Algorithm selection and instantiation

Function prototypes include:

```c
// Registry context
typedef struct CryptoRegistryCtx CryptoRegistryCtx;
typedef struct CryptoAlgorithm CryptoAlgorithm;

// Algorithm types
typedef enum {
    BN_CRYPTO_ALG_HASH,       // Hash functions
    BN_CRYPTO_ALG_SIGNATURE,  // Signature schemes
    BN_CRYPTO_ALG_KDF,        // Key derivation functions
    BN_CRYPTO_ALG_ECDH,       // Key exchange
    BN_CRYPTO_ALG_AEAD,       // Authenticated encryption
    BN_CRYPTO_ALG_PQ_KE       // Post-quantum key exchange
} CryptoAlgorithmType;

// Initialize the cryptographic registry
int bn_crypto_registry_init(CryptoRegistryCtx **ctx);

// Register a new algorithm with the registry
int bn_crypto_registry_register(
    CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithmType type,
    const void *params,
    const void *implementation);

// Look up an algorithm by OID
int bn_crypto_registry_lookup(
    const CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithm **algorithm);

// Get a default algorithm for a specific type
int bn_crypto_registry_get_default(
    const CryptoRegistryCtx *ctx,
    CryptoAlgorithmType type,
    CryptoAlgorithm **algorithm);

// Set a default algorithm for a specific type
int bn_crypto_registry_set_default(
    CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithmType type);

// Get information about a registered algorithm
int bn_crypto_registry_get_info(
    const CryptoAlgorithm *algorithm,
    CryptoAlgorithmType *type,
    const char **oid,
    const void **params);

// Clean up registry resources
int bn_crypto_registry_cleanup(CryptoRegistryCtx *ctx);
```

## Error Handling

All functions follow the common error pattern:

- Return 0 for success
- Return negative values for errors:
  - -1: Invalid parameters (NULL pointers)
  - -2: Resource errors (memory allocation, registry initialization)
  - -3: Algorithm not found
  - -4: Invalid algorithm type
  - -5: Duplicate OID registration

## Usage Examples

### Initialize and Register Algorithms

```c
CryptoRegistryCtx *registry = NULL;
int result = bn_crypto_registry_init(&registry);
if (result < 0) {
    // Handle error
}

// Register SHA-256 algorithm
result = bn_crypto_registry_register(
    registry,
    "2.16.840.1.101.3.4.2.1", // NIST OID for SHA-256
    BN_CRYPTO_ALG_HASH,
    &sha256_params,
    &sha256_implementation);
if (result < 0) {
    bn_crypto_registry_cleanup(registry);
    // Handle error
}

// Set SHA-256 as the default hash algorithm
result = bn_crypto_registry_set_default(
    registry,
    "2.16.840.1.101.3.4.2.1",
    BN_CRYPTO_ALG_HASH);
if (result < 0) {
    bn_crypto_registry_cleanup(registry);
    // Handle error
}
```

### Algorithm Lookup and Use

```c
CryptoAlgorithm *hash_alg = NULL;
result = bn_crypto_registry_get_default(
    registry,
    BN_CRYPTO_ALG_HASH,
    &hash_alg);
if (result < 0) {
    // Handle error
}

// Use the algorithm
CryptoAlgorithmType type;
const char *oid;
const void *params;
result = bn_crypto_registry_get_info(hash_alg, &type, &oid, &params);
if (result < 0) {
    // Handle error
}

// Call appropriate function based on algorithm type
if (type == BN_CRYPTO_ALG_HASH) {
    // Use hash algorithm
}
```

## Usage in Betanet

The cryptographic registry enables algorithm agility across the protocol:

1. Supporting cryptographic transitions (like the 2027 post-quantum requirement in §2)
2. Facilitating governance-negotiated algorithm changes (§10)
3. Providing OID-keyed access to cryptographic primitives
4. Maintaining wire format compatibility during transitions

## Implementation Requirements

- Thread-safe implementation for concurrent access
- Secure memory handling for cryptographic parameters
- Efficient lookup for performance-critical operations
- Support for all cryptographic primitives specified in §2
- Integration with governance mechanisms (§10)
- Proper version tracking for algorithm upgrades

## Special Cases

- Must support the post-quantum transition in 2027 (§2)
- Must accommodate governance-based cryptographic parameter updates
- Must preserve wire format compatibility during algorithm transitions
- Should provide fallback mechanisms for backward compatibility