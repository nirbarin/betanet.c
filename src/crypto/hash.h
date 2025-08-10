#ifndef BETANET_CRYPTO_HASH_H_
#define BETANET_CRYPTO_HASH_H_

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Hash context for incremental SHA-256 hashing operations
 */
typedef struct CryptoHashCtx {
    void *state;  /* Opaque pointer to internal state */
} CryptoHashCtx;

/**
 * @brief SHA-256 hash size in bytes
 */
#define CRYPTO_HASH_SIZE_SHA256 32

/**
 * @brief Initialize a hash context for SHA-256
 *
 * Prepares a hash context for incremental SHA-256 operations.
 * Allocates and initializes the internal state needed for hashing.
 *
 * @param ctx Pointer to the hash context to initialize
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameter (NULL pointer)
 *         - -2: Memory allocation error
 *         - -3: Internal initialization error
 *
 * @note The context must be freed with bn_crypto_hash_cleanup when no longer needed
 *
 * @example
 * // Initialize a hash context
 * CryptoHashCtx ctx;
 * int result = bn_crypto_hash_init(&ctx);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_hash_init(CryptoHashCtx *ctx);

/**
 * @brief Update a hash context with new data
 *
 * Processes more data into an already initialized hash context.
 * Can be called multiple times to hash data in chunks.
 *
 * @param ctx Pointer to the hash context
 * @param data Pointer to the data to process
 * @param len Length of the data in bytes
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointers)
 *         - -2: Context not initialized
 *         - -3: Internal hashing error
 *
 * @example
 * // Update hash context with data chunks
 * bn_crypto_hash_update(&ctx, chunk1, chunk1_len);
 * bn_crypto_hash_update(&ctx, chunk2, chunk2_len);
 */
int bn_crypto_hash_update(CryptoHashCtx *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize a hash operation and get the result
 *
 * Completes the hash operation and writes the result to output.
 * The context is automatically cleared after this operation.
 *
 * @param ctx Pointer to the hash context
 * @param output Buffer to receive the 32-byte hash result
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointers)
 *         - -2: Context not initialized
 *         - -3: Internal finalization error
 *
 * @note The context is invalid after this call and must be reinitialized 
 *       before being used again.
 *
 * @example
 * // Finalize hash and get result
 * uint8_t hash[CRYPTO_HASH_SIZE_SHA256];
 * int result = bn_crypto_hash_final(&ctx, hash);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_hash_final(CryptoHashCtx *ctx, uint8_t output[CRYPTO_HASH_SIZE_SHA256]);

/**
 * @brief Perform a one-shot SHA-256 hash operation
 *
 * Computes the SHA-256 hash of a complete message in a single call.
 * This is more efficient than the init/update/final sequence for single-block data.
 *
 * @param data Pointer to the data to hash
 * @param len Length of the data in bytes
 * @param output Buffer to receive the 32-byte hash result
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointers)
 *         - -2: Internal hashing error
 *
 * @example
 * // Hash a complete message
 * uint8_t hash[CRYPTO_HASH_SIZE_SHA256];
 * int result = bn_crypto_hash(message, message_len, hash);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_hash(const uint8_t *data, size_t len, uint8_t output[CRYPTO_HASH_SIZE_SHA256]);

/**
 * @brief Clean a hash context, erasing sensitive data
 *
 * Securely wipes the hash state and frees allocated memory.
 * Should be called if a context is no longer needed before finalization.
 *
 * @param ctx Pointer to the hash context to clear
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameter (NULL pointer)
 *         - -2: Context not initialized
 *
 * @note This function is automatically called by bn_crypto_hash_final
 *
 * @example
 * // Clean up a context that's no longer needed
 * bn_crypto_hash_cleanup(&ctx);
 */
int bn_crypto_hash_cleanup(CryptoHashCtx *ctx);

#endif /* BETANET_CRYPTO_HASH_H_ */