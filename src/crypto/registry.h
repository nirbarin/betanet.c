/**
 * Cryptographic Algorithm Registry
 * 
 * This module implements the algorithm agility registry as specified in Section 2
 * of the Betanet 1.1 specification. It enables dynamic selection of cryptographic
 * algorithms and facilitates future algorithm transitions without changing wire formats.
 */

#ifndef BN_CRYPTO_REGISTRY_H
#define BN_CRYPTO_REGISTRY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque registry context structure
 */
typedef struct CryptoRegistryCtx CryptoRegistryCtx;

/**
 * Opaque algorithm structure
 */
typedef struct CryptoAlgorithm CryptoAlgorithm;

/**
 * Supported cryptographic algorithm types
 */
typedef enum {
    BN_CRYPTO_ALG_HASH,       /* Hash functions */
    BN_CRYPTO_ALG_SIGNATURE,  /* Signature schemes */
    BN_CRYPTO_ALG_KDF,        /* Key derivation functions */
    BN_CRYPTO_ALG_ECDH,       /* Key exchange */
    BN_CRYPTO_ALG_AEAD,       /* Authenticated encryption */
    BN_CRYPTO_ALG_PQ_KE       /* Post-quantum key exchange */
} CryptoAlgorithmType;

/**
 * Initialize the cryptographic registry
 *
 * @param[out] ctx Pointer to store the created registry context
 * @return 0 on success, negative value on error:
 *         -1: Invalid parameters (NULL pointers)
 *         -2: Resource errors (memory allocation, registry initialization)
 */
int bn_crypto_registry_init(CryptoRegistryCtx **ctx);

/**
 * Register a new algorithm with the registry
 *
 * @param[in] ctx Registry context
 * @param[in] oid Object Identifier for the algorithm
 * @param[in] type Algorithm type
 * @param[in] params Algorithm-specific parameters
 * @param[in] implementation Function pointers for the implementation
 * @return 0 on success, negative value on error:
 *         -1: Invalid parameters (NULL pointers)
 *         -2: Resource errors (memory allocation)
 *         -4: Invalid algorithm type
 *         -5: Duplicate OID registration
 */
int bn_crypto_registry_register(
    CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithmType type,
    const void *params,
    const void *implementation);

/**
 * Look up an algorithm by OID
 *
 * @param[in] ctx Registry context
 * @param[in] oid Object Identifier to look up
 * @param[out] algorithm Pointer to store the found algorithm
 * @return 0 on success, negative value on error:
 *         -1: Invalid parameters (NULL pointers)
 *         -3: Algorithm not found
 */
int bn_crypto_registry_lookup(
    const CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithm **algorithm);

/**
 * Get the default algorithm for a specific type
 *
 * @param[in] ctx Registry context
 * @param[in] type Algorithm type
 * @param[out] algorithm Pointer to store the default algorithm
 * @return 0 on success, negative value on error:
 *         -1: Invalid parameters (NULL pointers)
 *         -3: No default algorithm set for the specified type
 *         -4: Invalid algorithm type
 */
int bn_crypto_registry_get_default(
    const CryptoRegistryCtx *ctx,
    CryptoAlgorithmType type,
    CryptoAlgorithm **algorithm);

/**
 * Set the default algorithm for a specific type
 *
 * @param[in] ctx Registry context
 * @param[in] oid Object Identifier of the algorithm to set as default
 * @param[in] type Algorithm type
 * @return 0 on success, negative value on error:
 *         -1: Invalid parameters (NULL pointers)
 *         -3: Algorithm not found
 *         -4: Invalid algorithm type
 */
int bn_crypto_registry_set_default(
    CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithmType type);

/**
 * Get information about a registered algorithm
 *
 * @param[in] algorithm Algorithm to get info about
 * @param[out] type Pointer to store the algorithm type
 * @param[out] oid Pointer to store the algorithm OID
 * @param[out] params Pointer to store the algorithm parameters
 * @return 0 on success, negative value on error:
 *         -1: Invalid parameters (NULL pointers)
 */
int bn_crypto_registry_get_info(
    const CryptoAlgorithm *algorithm,
    CryptoAlgorithmType *type,
    const char **oid,
    const void **params);

/**
 * Clean up registry resources
 *
 * @param[in] ctx Registry context to clean up
 * @return 0 on success, negative value on error:
 *         -1: Invalid parameters (NULL pointers)
 */
int bn_crypto_registry_cleanup(CryptoRegistryCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* BN_CRYPTO_REGISTRY_H */