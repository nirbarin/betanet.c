#include "sign.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

int bn_crypto_sign_keypair_generate(uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE],
                                  uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE]) {
    /* Validate parameters */
    if (!private_key || !public_key) {
        return -1;
    }

    /* Initialize libsodium if not initialized yet */
    if (sodium_init() < 0) {
        return -2;
    }

    /* Generate a new Ed25519 key pair using libsodium's direct function */
    unsigned char seed[crypto_sign_SEEDBYTES];
    unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES];

    /* Generate random seed */
    randombytes_buf(seed, sizeof seed);
    
    /* Convert seed to keypair */
    crypto_sign_seed_keypair(ed25519_pk, ed25519_sk, seed);
    
    /* The secret key in libsodium includes both the seed and the public key */
    /* Format the private key as required by our API (seed + public key) */
    memcpy(private_key, seed, crypto_sign_SEEDBYTES);
    memcpy(private_key + crypto_sign_SEEDBYTES, ed25519_pk, crypto_sign_PUBLICKEYBYTES);
    
    /* Copy the public key and ensure the highest bit is cleared */
    memcpy(public_key, ed25519_pk, crypto_sign_PUBLICKEYBYTES);
    public_key[31] &= 0x7F;  /* Clear the highest bit (Ed25519 requirement) */
    
    /* Securely erase sensitive data */
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(ed25519_sk, sizeof ed25519_sk);
    
    return 0;
}

int bn_crypto_sign_derive_public_key(const uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE],
                                   uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE]) {
    /* Validate parameters */
    if (!private_key || !public_key) {
        return -1;
    }

    /* In our format, the public key is stored in the second half of the private key */
    memcpy(public_key, private_key + 32, CRYPTO_SIGN_PUBLICKEY_SIZE);
    
    /* Ensure the highest bit is cleared (Ed25519 requirement) */
    public_key[31] &= 0x7F;
    
    return 0;
}

int bn_crypto_sign(const uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE],
                 const uint8_t *message, size_t message_len,
                 uint8_t signature[CRYPTO_SIGN_SIGNATURE_SIZE]) {
    /* Validate parameters */
    if (!private_key || (!message && message_len > 0) || !signature) {
        return -1;
    }

    /* Initialize libsodium if not initialized yet */
    if (sodium_init() < 0) {
        return -2;
    }
    
    /* The first 32 bytes of our private key is the seed */
    unsigned char seed[crypto_sign_SEEDBYTES];
    memcpy(seed, private_key, crypto_sign_SEEDBYTES);
    
    /* Generate a proper Ed25519 keypair from the seed */
    unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(ed25519_pk, ed25519_sk, seed);
    
    /* Sign the message */
    unsigned long long signature_len;
    int result = crypto_sign_detached(signature, &signature_len, 
                                     message, message_len, 
                                     ed25519_sk);
    
    /* Securely erase sensitive data */
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(ed25519_sk, sizeof ed25519_sk);
    
    if (result != 0) {
        return -3;
    }
    
    return 0;
}

bool bn_crypto_sign_verify(const uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE],
                         const uint8_t *message, size_t message_len,
                         const uint8_t signature[CRYPTO_SIGN_SIGNATURE_SIZE]) {
    /* Validate parameters */
    if (!public_key || (!message && message_len > 0) || !signature) {
        return false;
    }

    /* Initialize libsodium if not initialized yet */
    if (sodium_init() < 0) {
        return false;
    }
    
    /* Verify the signature */
    return (crypto_sign_verify_detached(signature, message, message_len, public_key) == 0);
}

bool bn_crypto_sign_verify_batch(size_t num_signatures,
                               const uint8_t **public_keys,
                               const uint8_t **messages, const size_t *message_lens,
                               const uint8_t **signatures) {
    /* Validate parameters */
    if (!public_keys || !messages || !message_lens || !signatures || num_signatures == 0) {
        return false;
    }

    /* Initialize libsodium if not initialized yet */
    if (sodium_init() < 0) {
        return false;
    }
    
    /* Verify each signature individually */
    for (size_t i = 0; i < num_signatures; i++) {
        if (!public_keys[i] || 
            (!messages[i] && message_lens[i] > 0) || 
            !signatures[i]) {
            return false;
        }
        
        if (crypto_sign_verify_detached(signatures[i], messages[i], 
                                       message_lens[i], public_keys[i]) != 0) {
            return false;
        }
    }
    
    return true;
}
