#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "crypto/sign.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (Line %d)\n", message, __LINE__); \
            return false; \
        } \
    } while (0)

/**
 * Test keypair generation
 */
static bool test_keypair_generation(void) {
    printf("Testing keypair generation...\n");
    
    uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE];
    uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE];
    
    int result = bn_crypto_sign_keypair_generate(private_key, public_key);
    TEST_ASSERT(result == 0, "Keypair generation failed");
    
    // Verify that the private key is not all zeros
    bool is_nonzero = false;
    for (size_t i = 0; i < CRYPTO_SIGN_PRIVATEKEY_SIZE; i++) {
        if (private_key[i] != 0) {
            is_nonzero = true;
            break;
        }
    }
    TEST_ASSERT(is_nonzero, "Private key is all zeros");
    
    // Verify that the public key is not all zeros
    is_nonzero = false;
    for (size_t i = 0; i < CRYPTO_SIGN_PUBLICKEY_SIZE; i++) {
        if (public_key[i] != 0) {
            is_nonzero = true;
            break;
        }
    }
    TEST_ASSERT(is_nonzero, "Public key is all zeros");
    

    
    printf("  Keypair generation: OK\n");
    return true;
}

/**
 * Test public key derivation
 */
static bool test_public_key_derivation(void) {
    printf("Testing public key derivation...\n");
    
    // Generate a keypair first
    uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE];
    uint8_t original_public_key[CRYPTO_SIGN_PUBLICKEY_SIZE];
    
    int result = bn_crypto_sign_keypair_generate(private_key, original_public_key);
    TEST_ASSERT(result == 0, "Keypair generation failed");
    
    // Derive public key from private key
    uint8_t derived_public_key[CRYPTO_SIGN_PUBLICKEY_SIZE];
    result = bn_crypto_sign_derive_public_key(private_key, derived_public_key);
    TEST_ASSERT(result == 0, "Public key derivation failed");
    
    // Verify that the derived public key matches the original public key
    TEST_ASSERT(memcmp(derived_public_key, original_public_key, CRYPTO_SIGN_PUBLICKEY_SIZE) == 0,
               "Derived public key doesn't match original public key");
    
    printf("  Public key derivation: OK\n");
    return true;
}

/**
 * Test signing and verification
 */
static bool test_sign_and_verify(void) {
    printf("Testing signing and verification...\n");
    
    // Generate a keypair
    uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE];
    uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE];
    
    int result = bn_crypto_sign_keypair_generate(private_key, public_key);
    TEST_ASSERT(result == 0, "Keypair generation failed");
    
    // Test with different message sizes
    const char *messages[] = {
        "",                           // Empty message
        "Hello, world!",              // Short message
        "This is a longer message that will test the signing algorithm with more data than just a few bytes."  // Long message
    };
    
    for (size_t i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
        const uint8_t *message = (const uint8_t *)messages[i];
        size_t message_len = strlen(messages[i]);
        
        // Sign the message
        uint8_t signature[CRYPTO_SIGN_SIGNATURE_SIZE];
        result = bn_crypto_sign(private_key, message, message_len, signature);
        TEST_ASSERT(result == 0, "Signing failed");
        
        // Verify the signature
        bool is_valid = bn_crypto_sign_verify(public_key, message, message_len, signature);
        TEST_ASSERT(is_valid, "Signature verification failed");
        
        // Tamper with the message and verify the signature should fail
        if (message_len > 0) {
            uint8_t *tampered_message = malloc(message_len);
            TEST_ASSERT(tampered_message != NULL, "Message allocation failed");
            
            // Copy the message and modify one byte
            memcpy(tampered_message, message, message_len);
            tampered_message[0] ^= 0x01;  // Flip a bit
            
            is_valid = bn_crypto_sign_verify(public_key, tampered_message, message_len, signature);
            TEST_ASSERT(!is_valid, "Signature verification should fail with tampered message");
            
            free(tampered_message);
        }
        
        // Tamper with the signature and verify should fail
        uint8_t tampered_signature[CRYPTO_SIGN_SIGNATURE_SIZE];
        memcpy(tampered_signature, signature, CRYPTO_SIGN_SIGNATURE_SIZE);
        tampered_signature[0] ^= 0x01;  // Flip a bit
        
        is_valid = bn_crypto_sign_verify(public_key, message, message_len, tampered_signature);
        TEST_ASSERT(!is_valid, "Signature verification should fail with tampered signature");
        
        printf("  Message %zu: OK\n", i + 1);
    }
    
    return true;
}

/**
 * Test batch verification
 */
static bool test_batch_verification(void) {
    printf("Testing batch verification...\n");
    
    // We'll create a few different messages and keypairs
    const size_t num_signatures = 3;
    
    // Generate keypairs
    uint8_t private_keys[num_signatures][CRYPTO_SIGN_PRIVATEKEY_SIZE];
    uint8_t public_keys[num_signatures][CRYPTO_SIGN_PUBLICKEY_SIZE];
    
    for (size_t i = 0; i < num_signatures; i++) {
        int result = bn_crypto_sign_keypair_generate(private_keys[i], public_keys[i]);
        TEST_ASSERT(result == 0, "Keypair generation failed");
    }
    
    // Messages to sign
    const char *messages[] = {
        "Message 1",
        "Message 2",
        "Message 3"
    };
    
    // Create signatures
    uint8_t signatures[num_signatures][CRYPTO_SIGN_SIGNATURE_SIZE];
    
    for (size_t i = 0; i < num_signatures; i++) {
        int result = bn_crypto_sign(private_keys[i], (const uint8_t *)messages[i], strlen(messages[i]), signatures[i]);
        TEST_ASSERT(result == 0, "Signing failed");
    }
    
    // Prepare arrays for batch verification
    const uint8_t *public_key_ptrs[num_signatures];
    const uint8_t *message_ptrs[num_signatures];
    size_t message_lens[num_signatures];
    const uint8_t *signature_ptrs[num_signatures];
    
    for (size_t i = 0; i < num_signatures; i++) {
        public_key_ptrs[i] = public_keys[i];
        message_ptrs[i] = (const uint8_t *)messages[i];
        message_lens[i] = strlen(messages[i]);
        signature_ptrs[i] = signatures[i];
    }
    
    // Perform batch verification
    bool is_valid = bn_crypto_sign_verify_batch(num_signatures, public_key_ptrs, message_ptrs, message_lens, signature_ptrs);
    TEST_ASSERT(is_valid, "Batch verification failed");
    
    // Tamper with one signature and verify the batch should fail
    uint8_t tampered_signatures[num_signatures][CRYPTO_SIGN_SIGNATURE_SIZE];
    const uint8_t *tampered_signature_ptrs[num_signatures];
    
    for (size_t i = 0; i < num_signatures; i++) {
        memcpy(tampered_signatures[i], signatures[i], CRYPTO_SIGN_SIGNATURE_SIZE);
        tampered_signature_ptrs[i] = tampered_signatures[i];
    }
    
    tampered_signatures[0][0] ^= 0x01;  // Flip a bit in the first signature
    
    is_valid = bn_crypto_sign_verify_batch(num_signatures, public_key_ptrs, message_ptrs, message_lens, tampered_signature_ptrs);
    TEST_ASSERT(!is_valid, "Batch verification should fail with tampered signature");
    
    printf("  Batch verification: OK\n");
    return true;
}

/**
 * Test error handling
 */
static bool test_error_handling(void) {
    printf("Testing error handling...\n");
    
    uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE];
    uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE];
    uint8_t signature[CRYPTO_SIGN_SIGNATURE_SIZE];
    const uint8_t message[] = "test message";
    
    // Generate a valid key pair for testing
    int result = bn_crypto_sign_keypair_generate(private_key, public_key);
    TEST_ASSERT(result == 0, "Keypair generation failed");
    
    // Test NULL inputs for keypair generation
    result = bn_crypto_sign_keypair_generate(NULL, public_key);
    TEST_ASSERT(result < 0, "Keypair generation with NULL private key should fail");
    
    result = bn_crypto_sign_keypair_generate(private_key, NULL);
    TEST_ASSERT(result < 0, "Keypair generation with NULL public key should fail");
    
    // Test NULL inputs for public key derivation
    result = bn_crypto_sign_derive_public_key(NULL, public_key);
    TEST_ASSERT(result < 0, "Public key derivation with NULL private key should fail");
    
    result = bn_crypto_sign_derive_public_key(private_key, NULL);
    TEST_ASSERT(result < 0, "Public key derivation with NULL output should fail");
    
    // Test NULL inputs for signing
    result = bn_crypto_sign(NULL, message, sizeof(message), signature);
    TEST_ASSERT(result < 0, "Signing with NULL private key should fail");
    
    result = bn_crypto_sign(private_key, NULL, sizeof(message), signature);
    TEST_ASSERT(result < 0, "Signing with NULL message should fail");
    
    result = bn_crypto_sign(private_key, message, sizeof(message), NULL);
    TEST_ASSERT(result < 0, "Signing with NULL signature output should fail");
    
    // Create a valid signature for verification tests
    result = bn_crypto_sign(private_key, message, sizeof(message), signature);
    TEST_ASSERT(result == 0, "Signing failed");
    
    // Test NULL inputs for verification
    bool is_valid = bn_crypto_sign_verify(NULL, message, sizeof(message), signature);
    TEST_ASSERT(!is_valid, "Verification with NULL public key should fail");
    
    is_valid = bn_crypto_sign_verify(public_key, NULL, sizeof(message), signature);
    TEST_ASSERT(!is_valid, "Verification with NULL message should fail");
    
    is_valid = bn_crypto_sign_verify(public_key, message, sizeof(message), NULL);
    TEST_ASSERT(!is_valid, "Verification with NULL signature should fail");
    
    // Test NULL inputs for batch verification
    const uint8_t *public_keys[1] = { public_key };
    const uint8_t *messages[1] = { message };
    const size_t message_lens[1] = { sizeof(message) };
    const uint8_t *signatures[1] = { signature };
    
    is_valid = bn_crypto_sign_verify_batch(0, public_keys, messages, message_lens, signatures);
    TEST_ASSERT(!is_valid, "Batch verification with zero signatures should fail");
    
    is_valid = bn_crypto_sign_verify_batch(1, NULL, messages, message_lens, signatures);
    TEST_ASSERT(!is_valid, "Batch verification with NULL public keys should fail");
    
    is_valid = bn_crypto_sign_verify_batch(1, public_keys, NULL, message_lens, signatures);
    TEST_ASSERT(!is_valid, "Batch verification with NULL messages should fail");
    
    is_valid = bn_crypto_sign_verify_batch(1, public_keys, messages, NULL, signatures);
    TEST_ASSERT(!is_valid, "Batch verification with NULL message lengths should fail");
    
    is_valid = bn_crypto_sign_verify_batch(1, public_keys, messages, message_lens, NULL);
    TEST_ASSERT(!is_valid, "Batch verification with NULL signatures should fail");
    
    printf("  Error handling: OK\n");
    return true;
}

/**
 * Run all tests
 */
int main(void) {
    printf("===== Ed25519 Signature Test Suite =====\n");
    
    bool all_passed = true;
    
    all_passed &= test_keypair_generation();
    all_passed &= test_public_key_derivation();
    all_passed &= test_sign_and_verify();
    all_passed &= test_batch_verification();
    all_passed &= test_error_handling();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}
