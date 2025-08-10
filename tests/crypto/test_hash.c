#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "crypto/hash.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (Line %d)\n", message, __LINE__); \
            return false; \
        } \
    } while (0)

/**
 * Test vector structure for SHA-256 tests
 */
typedef struct {
    const char *input;
    uint8_t expected[CRYPTO_HASH_SIZE_SHA256];
} test_vector_t;

/**
 * Convert a hex string to binary
 */
static void hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    const char *pos = hex;
    for (size_t i = 0; i < bin_len; i++) {
        sscanf(pos, "%2hhx", &bin[i]);
        pos += 2;
    }
}

/**
 * Predefined test vectors for SHA-256
 * From NIST: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
 */
static const test_vector_t test_vectors[] = {
    {
        /* Test vector 1: Empty string */
        "",
        {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 
         0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 
         0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}
    },
    {
        /* Test vector 2: "abc" */
        "abc",
        {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 
         0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 
         0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}
    },
    {
        /* Test vector 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 
         0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 
         0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1}
    },
    {
        /* Test vector 4: "Hello, world!" */
        "Hello, world!",
        {0x31, 0x5f, 0x5b, 0xdb, 0x76, 0xd0, 0x78, 0xc4, 0x3b, 0x8a, 0xc0, 0x06, 
         0x4e, 0x4a, 0x01, 0x64, 0x61, 0x2b, 0x1f, 0xce, 0x77, 0xc8, 0x69, 0x34, 
         0x5b, 0xfc, 0x94, 0xc7, 0x58, 0x94, 0xed, 0xd3}
    }
};

/**
 * Test one-shot SHA-256 hash functionality
 */
static bool test_oneshot_hash(void) {
    printf("Testing one-shot hash function...\n");
    
    uint8_t hash[CRYPTO_HASH_SIZE_SHA256];
    
    for (size_t i = 0; i < sizeof(test_vectors) / sizeof(test_vector_t); i++) {
        const test_vector_t *test = &test_vectors[i];
        
        int result = bn_crypto_hash((const uint8_t *)test->input, strlen(test->input), hash);
        
        TEST_ASSERT(result == 0, "Hash operation failed");
        TEST_ASSERT(memcmp(hash, test->expected, CRYPTO_HASH_SIZE_SHA256) == 0, 
                   "Hash result does not match expected value");
        
        printf("  Vector %zu: OK\n", i + 1);
    }
    
    return true;
}

/**
 * Test incremental SHA-256 hash functionality
 */
static bool test_incremental_hash(void) {
    printf("Testing incremental hash functions...\n");
    
    CryptoHashCtx ctx;
    uint8_t hash[CRYPTO_HASH_SIZE_SHA256];
    
    for (size_t i = 0; i < sizeof(test_vectors) / sizeof(test_vector_t); i++) {
        const test_vector_t *test = &test_vectors[i];
        const char *input = test->input;
        size_t input_len = strlen(input);
        
        int result = bn_crypto_hash_init(&ctx);
        TEST_ASSERT(result == 0, "Hash init failed");
        
        // Split the input into chunks (if long enough)
        if (input_len > 3) {
            size_t chunk1_len = input_len / 3;
            size_t chunk2_len = input_len / 3;
            size_t chunk3_len = input_len - chunk1_len - chunk2_len;
            
            result = bn_crypto_hash_update(&ctx, (const uint8_t *)input, chunk1_len);
            TEST_ASSERT(result == 0, "Hash update (chunk 1) failed");
            
            result = bn_crypto_hash_update(&ctx, (const uint8_t *)(input + chunk1_len), chunk2_len);
            TEST_ASSERT(result == 0, "Hash update (chunk 2) failed");
            
            result = bn_crypto_hash_update(&ctx, (const uint8_t *)(input + chunk1_len + chunk2_len), chunk3_len);
            TEST_ASSERT(result == 0, "Hash update (chunk 3) failed");
        } else {
            result = bn_crypto_hash_update(&ctx, (const uint8_t *)input, input_len);
            TEST_ASSERT(result == 0, "Hash update failed");
        }
        
        result = bn_crypto_hash_final(&ctx, hash);
        TEST_ASSERT(result == 0, "Hash final failed");
        
        TEST_ASSERT(memcmp(hash, test->expected, CRYPTO_HASH_SIZE_SHA256) == 0, 
                   "Incremental hash result does not match expected value");
        
        printf("  Vector %zu: OK\n", i + 1);
    }
    
    return true;
}

/**
 * Test error handling in the hash functions
 */
static bool test_error_handling(void) {
    printf("Testing error handling...\n");
    
    CryptoHashCtx ctx;
    uint8_t hash[CRYPTO_HASH_SIZE_SHA256];
    
    // Test NULL context in init
    int result = bn_crypto_hash_init(NULL);
    TEST_ASSERT(result < 0, "Init with NULL context should fail");
    
    // Test NULL data in update
    result = bn_crypto_hash_init(&ctx);
    TEST_ASSERT(result == 0, "Hash init failed");
    
    result = bn_crypto_hash_update(&ctx, NULL, 10);
    TEST_ASSERT(result < 0, "Update with NULL data should fail");
    
    // Cleanup to avoid memory leaks
    bn_crypto_hash_cleanup(&ctx);
    
    // Test NULL context in update
    result = bn_crypto_hash_update(NULL, (const uint8_t *)"test", 4);
    TEST_ASSERT(result < 0, "Update with NULL context should fail");
    
    // Test NULL output in final
    result = bn_crypto_hash_init(&ctx);
    TEST_ASSERT(result == 0, "Hash init failed");
    
    result = bn_crypto_hash_final(&ctx, NULL);
    TEST_ASSERT(result < 0, "Final with NULL output should fail");
    
    // Cleanup again (context is already cleaned by final)
    
    // Test NULL context in final
    result = bn_crypto_hash_final(NULL, hash);
    TEST_ASSERT(result < 0, "Final with NULL context should fail");
    
    // Test one-shot with NULL data
    result = bn_crypto_hash(NULL, 10, hash);
    TEST_ASSERT(result < 0, "One-shot with NULL data should fail");
    
    // Test one-shot with NULL output
    result = bn_crypto_hash((const uint8_t *)"test", 4, NULL);
    TEST_ASSERT(result < 0, "One-shot with NULL output should fail");
    
    // Test cleanup with NULL context
    result = bn_crypto_hash_cleanup(NULL);
    TEST_ASSERT(result < 0, "Cleanup with NULL context should fail");
    
    printf("  All error cases handled correctly\n");
    return true;
}

/**
 * Run all tests
 */
int main(void) {
    printf("===== SHA-256 Test Suite =====\n");
    
    bool all_passed = true;
    
    all_passed &= test_oneshot_hash();
    all_passed &= test_incremental_hash();
    all_passed &= test_error_handling();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}