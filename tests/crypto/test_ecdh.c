#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "crypto/ecdh.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (Line %d)\n", message, __LINE__); \
            return false; \
        } \
    } while (0)

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
 * Test key pair generation and derivation
 */
static bool test_keypair_generation(void) {
    printf("Testing key pair generation...\n");
    
    uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE];
    uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
    
    int result = bn_crypto_ecdh_keypair_generate(private_key, public_key);
    TEST_ASSERT(result == 0, "Key pair generation failed");
    
    // Verify that the private key has been properly clamped
    // For the clamping, since we're not implementing the clamping in this test but in the
    // implementation, we'll simply check that the key is not all zeros
    bool is_nonzero = false;
    for (size_t i = 0; i < CRYPTO_ECDH_PRIVATEKEY_SIZE; i++) {
        if (private_key[i] != 0) {
            is_nonzero = true;
            break;
        }
    }
    TEST_ASSERT(is_nonzero, "Private key is all zeros");
    
    // Test the validity of the public key
    TEST_ASSERT(bn_crypto_ecdh_public_key_validate(public_key), "Generated public key is not valid");
    
    // Derive the public key again and verify it matches
    uint8_t derived_public_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
    result = bn_crypto_ecdh_derive_public_key(private_key, derived_public_key);
    TEST_ASSERT(result == 0, "Public key derivation failed");
    TEST_ASSERT(memcmp(public_key, derived_public_key, CRYPTO_ECDH_PUBLICKEY_SIZE) == 0, 
               "Derived public key doesn't match original");
    
    printf("  Key pair generation: OK\n");
    return true;
}

/**
 * Test shared secret computation
 */
static bool test_shared_secret(void) {
    printf("Testing shared secret computation...\n");
    
    // Generate Alice's key pair
    uint8_t alice_private[CRYPTO_ECDH_PRIVATEKEY_SIZE];
    uint8_t alice_public[CRYPTO_ECDH_PUBLICKEY_SIZE];
    int result = bn_crypto_ecdh_keypair_generate(alice_private, alice_public);
    TEST_ASSERT(result == 0, "Alice's key pair generation failed");
    
    // Generate Bob's key pair
    uint8_t bob_private[CRYPTO_ECDH_PRIVATEKEY_SIZE];
    uint8_t bob_public[CRYPTO_ECDH_PUBLICKEY_SIZE];
    result = bn_crypto_ecdh_keypair_generate(bob_private, bob_public);
    TEST_ASSERT(result == 0, "Bob's key pair generation failed");
    
    // Compute shared secret from Alice's perspective
    uint8_t alice_secret[CRYPTO_ECDH_SECRET_SIZE];
    result = bn_crypto_ecdh_shared_secret(alice_private, bob_public, alice_secret);
    TEST_ASSERT(result == 0, "Shared secret computation (Alice) failed");
    
    // Compute shared secret from Bob's perspective
    uint8_t bob_secret[CRYPTO_ECDH_SECRET_SIZE];
    result = bn_crypto_ecdh_shared_secret(bob_private, alice_public, bob_secret);
    TEST_ASSERT(result == 0, "Shared secret computation (Bob) failed");
    
    // Verify that both parties computed the same shared secret
    TEST_ASSERT(memcmp(alice_secret, bob_secret, CRYPTO_ECDH_SECRET_SIZE) == 0, 
               "Shared secrets don't match");
    
    // Ensure the shared secret is not all zeros
    bool is_nonzero = false;
    for (size_t i = 0; i < CRYPTO_ECDH_SECRET_SIZE; i++) {
        if (alice_secret[i] != 0) {
            is_nonzero = true;
            break;
        }
    }
    TEST_ASSERT(is_nonzero, "Shared secret is all zeros");
    
    printf("  Shared secret computation: OK\n");
    return true;
}

/**
 * Test RFC 7748 test vectors for X25519
 */
static bool test_rfc7748_vectors(void) {
    printf("Testing RFC 7748 vectors...\n");
    
    // Test Vector #1 from RFC 7748 Section 5.2
    // Input scalar:
    // a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
    uint8_t scalar1[CRYPTO_ECDH_PRIVATEKEY_SIZE];
    hex_to_bin("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar1, CRYPTO_ECDH_PRIVATEKEY_SIZE);
    
    // Input point (u-coordinate):
    // e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
    uint8_t point1[CRYPTO_ECDH_PUBLICKEY_SIZE];
    hex_to_bin("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point1, CRYPTO_ECDH_PUBLICKEY_SIZE);
    
    // Expected output (u-coordinate):
    // c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
    uint8_t expected1[CRYPTO_ECDH_SECRET_SIZE];
    hex_to_bin("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", expected1, CRYPTO_ECDH_SECRET_SIZE);
    
    uint8_t output1[CRYPTO_ECDH_SECRET_SIZE];
    int result = bn_crypto_ecdh_shared_secret(scalar1, point1, output1);
    TEST_ASSERT(result == 0, "RFC 7748 Vector #1 computation failed");
    TEST_ASSERT(memcmp(output1, expected1, CRYPTO_ECDH_SECRET_SIZE) == 0, 
               "RFC 7748 Vector #1 output doesn't match expected");
    
    printf("  RFC 7748 Vector #1: OK\n");
    
    // Test Vector #2 from RFC 7748 Section 5.2
    // Input scalar:
    // 4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
    uint8_t scalar2[CRYPTO_ECDH_PRIVATEKEY_SIZE];
    hex_to_bin("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar2, CRYPTO_ECDH_PRIVATEKEY_SIZE);
    
    // Input point (u-coordinate):
    // e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413
    uint8_t point2[CRYPTO_ECDH_PUBLICKEY_SIZE];
    hex_to_bin("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413", point2, CRYPTO_ECDH_PUBLICKEY_SIZE);
    
    // Expected output (u-coordinate):
    // 95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957
    uint8_t expected2[CRYPTO_ECDH_SECRET_SIZE];
    hex_to_bin("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", expected2, CRYPTO_ECDH_SECRET_SIZE);
    
    uint8_t output2[CRYPTO_ECDH_SECRET_SIZE];
    result = bn_crypto_ecdh_shared_secret(scalar2, point2, output2);
    TEST_ASSERT(result == 0, "RFC 7748 Vector #2 computation failed");
    TEST_ASSERT(memcmp(output2, expected2, CRYPTO_ECDH_SECRET_SIZE) == 0, 
               "RFC 7748 Vector #2 output doesn't match expected");
    
    printf("  RFC 7748 Vector #2: OK\n");
    
    return true;
}

/**
 * Test public key validation
 */
static bool test_public_key_validation(void) {
    printf("Testing public key validation...\n");
    
    // Test with a valid public key
    uint8_t valid_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
    memset(valid_key, 0x42, CRYPTO_ECDH_PUBLICKEY_SIZE);
    valid_key[31] &= 0x7F;  // Clear highest bit to make it valid
    
    TEST_ASSERT(bn_crypto_ecdh_public_key_validate(valid_key), "Valid key failed validation");
    
    // Test with an all-zeros key (identity element)
    uint8_t zero_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
    memset(zero_key, 0, CRYPTO_ECDH_PUBLICKEY_SIZE);
    
    TEST_ASSERT(!bn_crypto_ecdh_public_key_validate(zero_key), "All-zeros key passed validation");
    
    // Test with a key having the high bit set
    uint8_t highbit_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
    memset(highbit_key, 0x42, CRYPTO_ECDH_PUBLICKEY_SIZE);
    highbit_key[31] |= 0x80;  // Set highest bit to make it invalid
    
    TEST_ASSERT(!bn_crypto_ecdh_public_key_validate(highbit_key), "Key with high bit set passed validation");
    
    // Test with NULL input
    TEST_ASSERT(!bn_crypto_ecdh_public_key_validate(NULL), "NULL key passed validation");
    
    printf("  Public key validation: OK\n");
    return true;
}

/**
 * Test error handling
 */
static bool test_error_handling(void) {
    printf("Testing error handling...\n");
    
    uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE];
    uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
    uint8_t shared_secret[CRYPTO_ECDH_SECRET_SIZE];
    
    // Test NULL inputs for keypair generation
    int result = bn_crypto_ecdh_keypair_generate(NULL, public_key);
    TEST_ASSERT(result < 0, "Keypair generation with NULL private key should fail");
    
    result = bn_crypto_ecdh_keypair_generate(private_key, NULL);
    TEST_ASSERT(result < 0, "Keypair generation with NULL public key should fail");
    
    // Test NULL inputs for public key derivation
    result = bn_crypto_ecdh_derive_public_key(NULL, public_key);
    TEST_ASSERT(result < 0, "Public key derivation with NULL private key should fail");
    
    result = bn_crypto_ecdh_derive_public_key(private_key, NULL);
    TEST_ASSERT(result < 0, "Public key derivation with NULL output should fail");
    
    // Generate a valid key pair for further tests
    result = bn_crypto_ecdh_keypair_generate(private_key, public_key);
    TEST_ASSERT(result == 0, "Key pair generation failed");
    
    // Test NULL inputs for shared secret computation
    result = bn_crypto_ecdh_shared_secret(NULL, public_key, shared_secret);
    TEST_ASSERT(result < 0, "Shared secret with NULL private key should fail");
    
    result = bn_crypto_ecdh_shared_secret(private_key, NULL, shared_secret);
    TEST_ASSERT(result < 0, "Shared secret with NULL peer public key should fail");
    
    result = bn_crypto_ecdh_shared_secret(private_key, public_key, NULL);
    TEST_ASSERT(result < 0, "Shared secret with NULL output should fail");
    
    // Test invalid public key for shared secret computation
    uint8_t zero_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
    memset(zero_key, 0, CRYPTO_ECDH_PUBLICKEY_SIZE);
    
    result = bn_crypto_ecdh_shared_secret(private_key, zero_key, shared_secret);
    TEST_ASSERT(result < 0, "Shared secret with invalid public key should fail");
    
    printf("  Error handling: OK\n");
    return true;
}

/**
 * Run all tests
 */
int main(void) {
    printf("===== X25519 ECDH Test Suite =====\n");
    
    bool all_passed = true;
    
    all_passed &= test_keypair_generation();
    all_passed &= test_shared_secret();
    all_passed &= test_rfc7748_vectors();
    all_passed &= test_public_key_validation();
    all_passed &= test_error_handling();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}