#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "crypto/registry.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (Line %d)\n", message, __LINE__); \
            return false; \
        } \
    } while (0)

/* Mock implementation structures for testing */
typedef struct {
    int output_size;
} MockHashParams;

typedef struct {
    int (*hash_func)(const void *data, size_t len, void *out);
} MockHashImpl;

static int mock_hash_func(const void *data, size_t len, void *out) {
    /* Simple mock that copies the first byte of data to output if data exists */
    if (data && len > 0 && out) {
        *(unsigned char *)out = *(const unsigned char *)data;
        return 0;
    }
    return -1;
}

/* Test registry initialization and cleanup */
static bool test_init_cleanup(void) {
    printf("Testing registry initialization and cleanup...\n");
    
    CryptoRegistryCtx *ctx = NULL;
    
    /* Test initialization */
    int result = bn_crypto_registry_init(&ctx);
    TEST_ASSERT(result == 0, "Registry initialization failed");
    TEST_ASSERT(ctx != NULL, "Registry context is NULL after initialization");
    
    /* Test cleanup */
    result = bn_crypto_registry_cleanup(ctx);
    TEST_ASSERT(result == 0, "Registry cleanup failed");
    
    /* Test error handling */
    result = bn_crypto_registry_init(NULL);
    TEST_ASSERT(result < 0, "Init with NULL pointer should fail");
    
    result = bn_crypto_registry_cleanup(NULL);
    TEST_ASSERT(result < 0, "Cleanup with NULL context should fail");
    
    printf("  Initialization and cleanup tests: OK\n");
    return true;
}

/* Test algorithm registration and lookup */
static bool test_registration_lookup(void) {
    printf("Testing algorithm registration and lookup...\n");
    
    CryptoRegistryCtx *ctx = NULL;
    int result = bn_crypto_registry_init(&ctx);
    TEST_ASSERT(result == 0, "Registry initialization failed");
    
    /* Create mock implementations */
    MockHashParams hash_params = { .output_size = 32 };
    MockHashImpl hash_impl = { .hash_func = mock_hash_func };
    
    /* Test registration */
    result = bn_crypto_registry_register(
        ctx, 
        "1.2.3.4.5", 
        BN_CRYPTO_ALG_HASH, 
        &hash_params, 
        &hash_impl);
    TEST_ASSERT(result == 0, "Algorithm registration failed");
    
    /* Test duplicate registration */
    result = bn_crypto_registry_register(
        ctx, 
        "1.2.3.4.5", 
        BN_CRYPTO_ALG_HASH, 
        &hash_params, 
        &hash_impl);
    TEST_ASSERT(result < 0, "Duplicate registration should fail");
    
    /* Test invalid registration parameters */
    result = bn_crypto_registry_register(
        NULL, 
        "1.2.3.4.6", 
        BN_CRYPTO_ALG_HASH, 
        &hash_params, 
        &hash_impl);
    TEST_ASSERT(result < 0, "Registration with NULL context should fail");
    
    result = bn_crypto_registry_register(
        ctx, 
        NULL, 
        BN_CRYPTO_ALG_HASH, 
        &hash_params, 
        &hash_impl);
    TEST_ASSERT(result < 0, "Registration with NULL OID should fail");
    
    result = bn_crypto_registry_register(
        ctx, 
        "1.2.3.4.6", 
        BN_CRYPTO_ALG_HASH, 
        &hash_params, 
        NULL);
    TEST_ASSERT(result < 0, "Registration with NULL implementation should fail");
    
    result = bn_crypto_registry_register(
        ctx, 
        "1.2.3.4.6", 
        (CryptoAlgorithmType)99, 
        &hash_params, 
        &hash_impl);
    TEST_ASSERT(result < 0, "Registration with invalid type should fail");
    
    /* Test lookup */
    CryptoAlgorithm *algorithm = NULL;
    result = bn_crypto_registry_lookup(ctx, "1.2.3.4.5", &algorithm);
    TEST_ASSERT(result == 0, "Algorithm lookup failed");
    TEST_ASSERT(algorithm != NULL, "Algorithm is NULL after lookup");
    
    /* Test lookup for non-existent algorithm */
    result = bn_crypto_registry_lookup(ctx, "non.existent.oid", &algorithm);
    TEST_ASSERT(result < 0, "Lookup for non-existent OID should fail");
    
    /* Test invalid lookup parameters */
    result = bn_crypto_registry_lookup(NULL, "1.2.3.4.5", &algorithm);
    TEST_ASSERT(result < 0, "Lookup with NULL context should fail");
    
    result = bn_crypto_registry_lookup(ctx, NULL, &algorithm);
    TEST_ASSERT(result < 0, "Lookup with NULL OID should fail");
    
    result = bn_crypto_registry_lookup(ctx, "1.2.3.4.5", NULL);
    TEST_ASSERT(result < 0, "Lookup with NULL output pointer should fail");
    
    bn_crypto_registry_cleanup(ctx);
    printf("  Registration and lookup tests: OK\n");
    return true;
}

/* Test default algorithm functionality */
static bool test_default_algorithms(void) {
    printf("Testing default algorithm functionality...\n");
    
    CryptoRegistryCtx *ctx = NULL;
    int result = bn_crypto_registry_init(&ctx);
    TEST_ASSERT(result == 0, "Registry initialization failed");
    
    /* Create mock implementations */
    MockHashParams hash_params1 = { .output_size = 32 };
    MockHashImpl hash_impl1 = { .hash_func = mock_hash_func };
    
    MockHashParams hash_params2 = { .output_size = 64 };
    MockHashImpl hash_impl2 = { .hash_func = mock_hash_func };
    
    /* Register algorithms */
    result = bn_crypto_registry_register(
        ctx, 
        "1.2.3.4.5", 
        BN_CRYPTO_ALG_HASH, 
        &hash_params1, 
        &hash_impl1);
    TEST_ASSERT(result == 0, "First algorithm registration failed");
    
    result = bn_crypto_registry_register(
        ctx, 
        "1.2.3.4.6", 
        BN_CRYPTO_ALG_HASH, 
        &hash_params2, 
        &hash_impl2);
    TEST_ASSERT(result == 0, "Second algorithm registration failed");
    
    /* Test getting default (should be the first registered algorithm) */
    CryptoAlgorithm *algorithm = NULL;
    result = bn_crypto_registry_get_default(ctx, BN_CRYPTO_ALG_HASH, &algorithm);
    TEST_ASSERT(result == 0, "Getting default algorithm failed");
    TEST_ASSERT(algorithm != NULL, "Default algorithm is NULL");
    
    /* Get info from the algorithm and verify it's the first one */
    CryptoAlgorithmType type;
    const char *oid;
    const void *params;
    result = bn_crypto_registry_get_info(algorithm, &type, &oid, &params);
    TEST_ASSERT(result == 0, "Getting algorithm info failed");
    TEST_ASSERT(type == BN_CRYPTO_ALG_HASH, "Algorithm type mismatch");
    TEST_ASSERT(strcmp(oid, "1.2.3.4.5") == 0, "Algorithm OID mismatch");
    TEST_ASSERT(params == &hash_params1, "Algorithm params mismatch");
    
    /* Test setting a different default */
    result = bn_crypto_registry_set_default(ctx, "1.2.3.4.6", BN_CRYPTO_ALG_HASH);
    TEST_ASSERT(result == 0, "Setting default algorithm failed");
    
    /* Test getting the new default */
    algorithm = NULL;
    result = bn_crypto_registry_get_default(ctx, BN_CRYPTO_ALG_HASH, &algorithm);
    TEST_ASSERT(result == 0, "Getting updated default algorithm failed");
    TEST_ASSERT(algorithm != NULL, "Updated default algorithm is NULL");
    
    /* Get info from the algorithm and verify it's the second one */
    result = bn_crypto_registry_get_info(algorithm, &type, &oid, &params);
    TEST_ASSERT(result == 0, "Getting updated algorithm info failed");
    TEST_ASSERT(type == BN_CRYPTO_ALG_HASH, "Updated algorithm type mismatch");
    TEST_ASSERT(strcmp(oid, "1.2.3.4.6") == 0, "Updated algorithm OID mismatch");
    TEST_ASSERT(params == &hash_params2, "Updated algorithm params mismatch");
    
    /* Test setting a non-existent default */
    result = bn_crypto_registry_set_default(ctx, "non.existent.oid", BN_CRYPTO_ALG_HASH);
    TEST_ASSERT(result < 0, "Setting non-existent default should fail");
    
    /* Test getting default for unregistered type */
    result = bn_crypto_registry_get_default(ctx, BN_CRYPTO_ALG_SIGNATURE, &algorithm);
    TEST_ASSERT(result < 0, "Getting default for unregistered type should fail");
    
    /* Test invalid parameters */
    result = bn_crypto_registry_get_default(NULL, BN_CRYPTO_ALG_HASH, &algorithm);
    TEST_ASSERT(result < 0, "Get default with NULL context should fail");
    
    result = bn_crypto_registry_get_default(ctx, BN_CRYPTO_ALG_HASH, NULL);
    TEST_ASSERT(result < 0, "Get default with NULL output pointer should fail");
    
    result = bn_crypto_registry_get_default(ctx, (CryptoAlgorithmType)99, &algorithm);
    TEST_ASSERT(result < 0, "Get default with invalid type should fail");
    
    result = bn_crypto_registry_set_default(NULL, "1.2.3.4.6", BN_CRYPTO_ALG_HASH);
    TEST_ASSERT(result < 0, "Set default with NULL context should fail");
    
    result = bn_crypto_registry_set_default(ctx, NULL, BN_CRYPTO_ALG_HASH);
    TEST_ASSERT(result < 0, "Set default with NULL OID should fail");
    
    result = bn_crypto_registry_set_default(ctx, "1.2.3.4.6", (CryptoAlgorithmType)99);
    TEST_ASSERT(result < 0, "Set default with invalid type should fail");
    
    bn_crypto_registry_cleanup(ctx);
    printf("  Default algorithm tests: OK\n");
    return true;
}

/* Test algorithm info retrieval */
static bool test_algorithm_info(void) {
    printf("Testing algorithm info retrieval...\n");
    
    CryptoRegistryCtx *ctx = NULL;
    int result = bn_crypto_registry_init(&ctx);
    TEST_ASSERT(result == 0, "Registry initialization failed");
    
    /* Create mock implementation */
    MockHashParams hash_params = { .output_size = 32 };
    MockHashImpl hash_impl = { .hash_func = mock_hash_func };
    
    /* Register algorithm */
    result = bn_crypto_registry_register(
        ctx, 
        "1.2.3.4.5", 
        BN_CRYPTO_ALG_HASH, 
        &hash_params, 
        &hash_impl);
    TEST_ASSERT(result == 0, "Algorithm registration failed");
    
    /* Look up the algorithm */
    CryptoAlgorithm *algorithm = NULL;
    result = bn_crypto_registry_lookup(ctx, "1.2.3.4.5", &algorithm);
    TEST_ASSERT(result == 0, "Algorithm lookup failed");
    
    /* Test getting info with all outputs */
    CryptoAlgorithmType type;
    const char *oid;
    const void *params;
    result = bn_crypto_registry_get_info(algorithm, &type, &oid, &params);
    TEST_ASSERT(result == 0, "Getting all algorithm info failed");
    TEST_ASSERT(type == BN_CRYPTO_ALG_HASH, "Algorithm type mismatch");
    TEST_ASSERT(strcmp(oid, "1.2.3.4.5") == 0, "Algorithm OID mismatch");
    TEST_ASSERT(params == &hash_params, "Algorithm params mismatch");
    
    /* Test getting info with partial outputs */
    result = bn_crypto_registry_get_info(algorithm, &type, NULL, NULL);
    TEST_ASSERT(result == 0, "Getting partial algorithm info failed");
    TEST_ASSERT(type == BN_CRYPTO_ALG_HASH, "Algorithm type mismatch in partial info");
    
    result = bn_crypto_registry_get_info(algorithm, NULL, &oid, NULL);
    TEST_ASSERT(result == 0, "Getting partial algorithm info failed");
    TEST_ASSERT(strcmp(oid, "1.2.3.4.5") == 0, "Algorithm OID mismatch in partial info");
    
    result = bn_crypto_registry_get_info(algorithm, NULL, NULL, &params);
    TEST_ASSERT(result == 0, "Getting partial algorithm info failed");
    TEST_ASSERT(params == &hash_params, "Algorithm params mismatch in partial info");
    
    /* Test invalid parameters */
    result = bn_crypto_registry_get_info(NULL, &type, &oid, &params);
    TEST_ASSERT(result < 0, "Get info with NULL algorithm should fail");
    
    bn_crypto_registry_cleanup(ctx);
    printf("  Algorithm info tests: OK\n");
    return true;
}

/**
 * Run all tests
 */
int main(void) {
    printf("===== Crypto Registry Test Suite =====\n");
    
    bool all_passed = true;
    
    all_passed &= test_init_cleanup();
    all_passed &= test_registration_lookup();
    all_passed &= test_default_algorithms();
    all_passed &= test_algorithm_info();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}