#include "ecdh.h"
#include <sodium.h>
#include <string.h>

int bn_crypto_ecdh_keypair_generate(uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE],
                                   uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE]) {
    /* Validate parameters */
    if (!private_key || !public_key) {
        return -1;
    }

    /* Generate random bytes for the private key */
    randombytes_buf(private_key, CRYPTO_ECDH_PRIVATEKEY_SIZE);
    /* randombytes_buf doesn't return an error value */

    /* Clamp the private key according to X25519 requirements */
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;

    /* Compute the public key from the private key */
    if (crypto_scalarmult_base(public_key, private_key) != 0) {
        /* Clear the private key on error */
        sodium_memzero(private_key, CRYPTO_ECDH_PRIVATEKEY_SIZE);
        return -3;
    }

    return 0;
}

int bn_crypto_ecdh_derive_public_key(const uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE],
                                   uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE]) {
    /* Validate parameters */
    if (!private_key || !public_key) {
        return -1;
    }

    /* Copy the private key to avoid modifying the original */
    uint8_t clamped_private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE];
    memcpy(clamped_private_key, private_key, CRYPTO_ECDH_PRIVATEKEY_SIZE);

    /* Clamp the private key according to X25519 requirements */
    clamped_private_key[0] &= 248;
    clamped_private_key[31] &= 127;
    clamped_private_key[31] |= 64;

    /* Compute the public key from the private key */
    if (crypto_scalarmult_base(public_key, clamped_private_key) != 0) {
        sodium_memzero(clamped_private_key, CRYPTO_ECDH_PRIVATEKEY_SIZE);
        return -2;
    }

    /* Securely erase the clamped private key */
    sodium_memzero(clamped_private_key, CRYPTO_ECDH_PRIVATEKEY_SIZE);
    return 0;
}

int bn_crypto_ecdh_shared_secret(const uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE],
                               const uint8_t peer_public_key[CRYPTO_ECDH_PUBLICKEY_SIZE],
                               uint8_t shared_secret[CRYPTO_ECDH_SECRET_SIZE]) {
    /* Validate parameters */
    if (!private_key || !peer_public_key || !shared_secret) {
        return -1;
    }

    /* Validate the peer's public key */
    if (!bn_crypto_ecdh_public_key_validate(peer_public_key)) {
        return -2;
    }

    /* Copy the private key to avoid modifying the original */
    uint8_t clamped_private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE];
    memcpy(clamped_private_key, private_key, CRYPTO_ECDH_PRIVATEKEY_SIZE);

    /* Clamp the private key according to X25519 requirements */
    clamped_private_key[0] &= 248;
    clamped_private_key[31] &= 127;
    clamped_private_key[31] |= 64;

    /* Compute the shared secret */
    if (crypto_scalarmult(shared_secret, clamped_private_key, peer_public_key) != 0) {
        /* Clear sensitive data on error */
        sodium_memzero(clamped_private_key, CRYPTO_ECDH_PRIVATEKEY_SIZE);
        sodium_memzero(shared_secret, CRYPTO_ECDH_SECRET_SIZE);
        return -3;
    }

    /* Securely erase the clamped private key */
    sodium_memzero(clamped_private_key, CRYPTO_ECDH_PRIVATEKEY_SIZE);
    return 0;
}

bool bn_crypto_ecdh_public_key_validate(const uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE]) {
    /* Validate parameter */
    if (!public_key) {
        return false;
    }

    /* Check for the all-zeros public key (identity element) */
    bool is_zero = true;
    for (size_t i = 0; i < CRYPTO_ECDH_PUBLICKEY_SIZE; i++) {
        if (public_key[i] != 0) {
            is_zero = false;
            break;
        }
    }
    if (is_zero) {
        return false;
    }

    /* 
     * Additional validation could be implemented here.
     * However, libsodium's crypto_scalarmult already handles invalid
     * points and returns an error, so extensive validation isn't required.
     * 
     * For a more complete validation:
     * 1. Check the public key is not a small-order element
     * 2. Check the highest bit of the last byte is not set
     * 3. Potentially perform a trial multiplication
     */

    /* Basic check that the highest bit is not set (conformance to X25519) */
    if (public_key[31] & 0x80) {
        return false;
    }

    return true;
}