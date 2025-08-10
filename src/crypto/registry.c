/**
 * Cryptographic Algorithm Registry Implementation
 * 
 * This file implements the algorithm agility registry as specified in Section 2
 * of the Betanet 1.1 specification.
 */

#include "crypto/registry.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Maximum OID string length */
#define MAX_OID_LENGTH 128

/* Algorithm entry in the registry */
typedef struct AlgorithmEntry {
    char oid[MAX_OID_LENGTH];
    CryptoAlgorithmType type;
    const void *params;
    const void *implementation;
    struct AlgorithmEntry *next;
} AlgorithmEntry;

/* Registry structure */
struct CryptoRegistryCtx {
    AlgorithmEntry *algorithms;
    AlgorithmEntry *default_algs[BN_CRYPTO_ALG_PQ_KE + 1];
    pthread_mutex_t mutex;
};

/* Algorithm structure */
struct CryptoAlgorithm {
    AlgorithmEntry *entry;
};

/* Validate algorithm type */
static int validate_alg_type(CryptoAlgorithmType type) {
    return (type >= BN_CRYPTO_ALG_HASH && type <= BN_CRYPTO_ALG_PQ_KE) ? 0 : -4;
}

/* Initialize the cryptographic registry */
int bn_crypto_registry_init(CryptoRegistryCtx **ctx) {
    if (!ctx) {
        return -1; /* Invalid parameters */
    }

    CryptoRegistryCtx *new_ctx = (CryptoRegistryCtx *)calloc(1, sizeof(CryptoRegistryCtx));
    if (!new_ctx) {
        return -2; /* Resource error */
    }

    /* Initialize mutex for thread safety */
    if (pthread_mutex_init(&new_ctx->mutex, NULL) != 0) {
        free(new_ctx);
        return -2;
    }

    *ctx = new_ctx;
    return 0;
}

/* Register a new algorithm with the registry */
int bn_crypto_registry_register(
    CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithmType type,
    const void *params,
    const void *implementation) {

    if (!ctx || !oid || !implementation) {
        return -1; /* Invalid parameters */
    }

    int type_check = validate_alg_type(type);
    if (type_check < 0) {
        return type_check;
    }

    /* Check OID length */
    if (strlen(oid) >= MAX_OID_LENGTH) {
        return -1;
    }

    int result = 0;
    pthread_mutex_lock(&ctx->mutex);

    /* Check for duplicate OID */
    AlgorithmEntry *current = ctx->algorithms;
    while (current) {
        if (strcmp(current->oid, oid) == 0) {
            result = -5; /* Duplicate OID */
            goto cleanup;
        }
        current = current->next;
    }

    /* Create new entry */
    AlgorithmEntry *new_entry = (AlgorithmEntry *)calloc(1, sizeof(AlgorithmEntry));
    if (!new_entry) {
        result = -2; /* Resource error */
        goto cleanup;
    }

    /* Fill entry data */
    strcpy(new_entry->oid, oid);
    new_entry->type = type;
    new_entry->params = params;
    new_entry->implementation = implementation;

    /* Add to registry */
    new_entry->next = ctx->algorithms;
    ctx->algorithms = new_entry;

    /* If no default is set for this type, set this as default */
    if (!ctx->default_algs[type]) {
        ctx->default_algs[type] = new_entry;
    }

cleanup:
    pthread_mutex_unlock(&ctx->mutex);
    return result;
}

/* Look up an algorithm by OID */
int bn_crypto_registry_lookup(
    const CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithm **algorithm) {

    if (!ctx || !oid || !algorithm) {
        return -1; /* Invalid parameters */
    }

    int result = -3; /* Algorithm not found */
    pthread_mutex_lock((pthread_mutex_t *)&ctx->mutex);

    /* Search for algorithm with matching OID */
    AlgorithmEntry *current = ctx->algorithms;
    while (current) {
        if (strcmp(current->oid, oid) == 0) {
            /* Create algorithm structure */
            CryptoAlgorithm *alg = (CryptoAlgorithm *)malloc(sizeof(CryptoAlgorithm));
            if (!alg) {
                result = -2; /* Resource error */
                goto cleanup;
            }

            alg->entry = current;
            *algorithm = alg;
            result = 0; /* Success */
            break;
        }
        current = current->next;
    }

cleanup:
    pthread_mutex_unlock((pthread_mutex_t *)&ctx->mutex);
    return result;
}

/* Get the default algorithm for a specific type */
int bn_crypto_registry_get_default(
    const CryptoRegistryCtx *ctx,
    CryptoAlgorithmType type,
    CryptoAlgorithm **algorithm) {

    if (!ctx || !algorithm) {
        return -1; /* Invalid parameters */
    }

    int type_check = validate_alg_type(type);
    if (type_check < 0) {
        return type_check;
    }

    int result = 0;
    pthread_mutex_lock((pthread_mutex_t *)&ctx->mutex);

    if (!ctx->default_algs[type]) {
        result = -3; /* No default algorithm set */
        goto cleanup;
    }

    /* Create algorithm structure */
    CryptoAlgorithm *alg = (CryptoAlgorithm *)malloc(sizeof(CryptoAlgorithm));
    if (!alg) {
        result = -2; /* Resource error */
        goto cleanup;
    }

    alg->entry = ctx->default_algs[type];
    *algorithm = alg;

cleanup:
    pthread_mutex_unlock((pthread_mutex_t *)&ctx->mutex);
    return result;
}

/* Set the default algorithm for a specific type */
int bn_crypto_registry_set_default(
    CryptoRegistryCtx *ctx,
    const char *oid,
    CryptoAlgorithmType type) {

    if (!ctx || !oid) {
        return -1; /* Invalid parameters */
    }

    int type_check = validate_alg_type(type);
    if (type_check < 0) {
        return type_check;
    }

    int result = -3; /* Algorithm not found */
    pthread_mutex_lock(&ctx->mutex);

    /* Search for algorithm with matching OID */
    AlgorithmEntry *current = ctx->algorithms;
    while (current) {
        if (strcmp(current->oid, oid) == 0) {
            if (current->type != type) {
                result = -4; /* Type mismatch */
                goto cleanup;
            }

            ctx->default_algs[type] = current;
            result = 0; /* Success */
            break;
        }
        current = current->next;
    }

cleanup:
    pthread_mutex_unlock(&ctx->mutex);
    return result;
}

/* Get information about a registered algorithm */
int bn_crypto_registry_get_info(
    const CryptoAlgorithm *algorithm,
    CryptoAlgorithmType *type,
    const char **oid,
    const void **params) {

    if (!algorithm || !algorithm->entry) {
        return -1; /* Invalid parameters */
    }

    if (type) {
        *type = algorithm->entry->type;
    }

    if (oid) {
        *oid = algorithm->entry->oid;
    }

    if (params) {
        *params = algorithm->entry->params;
    }

    return 0;
}

/* Clean up registry resources */
int bn_crypto_registry_cleanup(CryptoRegistryCtx *ctx) {
    if (!ctx) {
        return -1; /* Invalid parameters */
    }

    /* Acquire mutex to ensure no concurrent access during cleanup */
    pthread_mutex_lock(&ctx->mutex);

    /* Free all algorithm entries */
    AlgorithmEntry *current = ctx->algorithms;
    while (current) {
        AlgorithmEntry *next = current->next;
        free(current);
        current = next;
    }

    /* Release mutex and destroy it */
    pthread_mutex_unlock(&ctx->mutex);
    pthread_mutex_destroy(&ctx->mutex);

    /* Free the registry context */
    free(ctx);

    return 0;
}