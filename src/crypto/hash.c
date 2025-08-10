#include "hash.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Internal implementation details for hash context
 *
 * This structure holds the libsodium SHA-256 state and any other
 * implementation-specific data needed for the hash operations.
 */
struct crypto_hash_internal_state {
    crypto_hash_sha256_state sodium_state;
};

int bn_crypto_hash_init(CryptoHashCtx *ctx) {
    int result = -1;
    struct crypto_hash_internal_state *state = NULL;
    
    /* Validate parameters */
    if (!ctx) {
        return -1;
    }
    
    /* Allocate internal state */
    state = malloc(sizeof(struct crypto_hash_internal_state));
    if (!state) {
        result = -2;
        goto cleanup;
    }
    
    /* Initialize the sodium hash state */
    if (crypto_hash_sha256_init(&state->sodium_state) != 0) {
        result = -3;
        goto cleanup;
    }
    
    /* Success */
    ctx->state = state;
    return 0;
    
cleanup:
    if (state) {
        sodium_memzero(state, sizeof(struct crypto_hash_internal_state));
        free(state);
    }
    return result;
}

int bn_crypto_hash_update(CryptoHashCtx *ctx, const uint8_t *data, size_t len) {
    /* Validate parameters */
    if (!ctx || !data) {
        return -1;
    }
    
    if (!ctx->state) {
        return -2;
    }
    
    struct crypto_hash_internal_state *state = 
        (struct crypto_hash_internal_state *)ctx->state;
    
    /* Update hash state with new data */
    if (crypto_hash_sha256_update(&state->sodium_state, data, len) != 0) {
        return -3;
    }
    
    return 0;
}

int bn_crypto_hash_final(CryptoHashCtx *ctx, uint8_t output[CRYPTO_HASH_SIZE_SHA256]) {
    int result = -1;
    
    /* Validate parameters */
    if (!ctx || !output) {
        return -1;
    }
    
    if (!ctx->state) {
        return -2;
    }
    
    struct crypto_hash_internal_state *state = 
        (struct crypto_hash_internal_state *)ctx->state;
    
    /* Finalize the hash and get result */
    if (crypto_hash_sha256_final(&state->sodium_state, output) != 0) {
        result = -3;
        goto cleanup;
    }
    
    /* Success */
    result = 0;
    
cleanup:
    /* Clean up and free resources regardless of success or failure */
    if (state) {
        sodium_memzero(state, sizeof(struct crypto_hash_internal_state));
        free(state);
        ctx->state = NULL;
    }
    
    return result;
}

int bn_crypto_hash(const uint8_t *data, size_t len, uint8_t output[CRYPTO_HASH_SIZE_SHA256]) {
    /* Validate parameters */
    if (!data || !output) {
        return -1;
    }
    
    /* Perform one-shot hash operation */
    if (crypto_hash_sha256(output, data, len) != 0) {
        return -2;
    }
    
    return 0;
}

int bn_crypto_hash_cleanup(CryptoHashCtx *ctx) {
    /* Validate parameters */
    if (!ctx) {
        return -1;
    }
    
    if (!ctx->state) {
        return -2;
    }
    
    struct crypto_hash_internal_state *state = 
        (struct crypto_hash_internal_state *)ctx->state;
    
    /* Securely wipe the hash state */
    sodium_memzero(state, sizeof(struct crypto_hash_internal_state));
    free(state);
    ctx->state = NULL;
    
    return 0;
}