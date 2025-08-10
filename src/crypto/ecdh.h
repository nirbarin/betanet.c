#ifndef BETANET_CRYPTO_ECDH_H_
#define BETANET_CRYPTO_ECDH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Size of an X25519 public key in bytes
 */
#define CRYPTO_ECDH_PUBLICKEY_SIZE 32

/**
 * @brief Size of an X25519 private key in bytes
 */
#define CRYPTO_ECDH_PRIVATEKEY_SIZE 32

/**
 * @brief Size of an X25519 shared secret in bytes
 */
#define CRYPTO_ECDH_SECRET_SIZE 32

/**
 * @brief Generate a new X25519 key pair
 *
 * Creates a new key pair for X25519 Diffie-Hellman key exchange.
 * Both the private and public keys are 32 bytes.
 *
 * @param private_key Buffer to store the generated private key (32 bytes)
 * @param public_key Buffer to store the generated public key (32 bytes)
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointers)
 *         - -2: Random number generation failed
 *         - -3: Key generation failed
 *
 * @note The private key should be kept secret and securely erased when no longer needed
 *
 * @example
 * // Generate a new key pair
 * uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE];
 * uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
 * int result = bn_crypto_ecdh_keypair_generate(private_key, public_key);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_ecdh_keypair_generate(uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE],
                                   uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE]);

/**
 * @brief Generate a public key from a private key
 * 
 * Derives the public key corresponding to a given private key.
 * This function is useful when a private key is generated externally
 * or derived from a seed.
 * 
 * @param private_key The private key to derive from (32 bytes)
 * @param public_key Buffer to store the derived public key (32 bytes)
 * 
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointers)
 *         - -2: Key derivation failed
 * 
 * @example
 * // Derive public key from private key
 * uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE]; // From elsewhere
 * uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE];
 * int result = bn_crypto_ecdh_derive_public_key(private_key, public_key);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_ecdh_derive_public_key(const uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE],
                                   uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE]);

/**
 * @brief Compute a shared secret using X25519
 *
 * Computes a shared secret from a private key and a peer's public key using
 * the X25519 Diffie-Hellman function. This shared secret can be used as input
 * to a key derivation function to generate session keys.
 *
 * @param private_key The user's private key (32 bytes)
 * @param peer_public_key The peer's public key (32 bytes)
 * @param shared_secret Buffer to store the computed shared secret (32 bytes)
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointers)
 *         - -2: Invalid peer public key
 *         - -3: Computation failed
 *
 * @note The raw shared secret should not be used directly as a key,
 *       but should be processed using a key derivation function.
 *
 * @example
 * // Compute a shared secret
 * uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE]; // Your private key
 * uint8_t peer_public_key[CRYPTO_ECDH_PUBLICKEY_SIZE]; // Peer's public key
 * uint8_t shared_secret[CRYPTO_ECDH_SECRET_SIZE];
 * int result = bn_crypto_ecdh_shared_secret(private_key, peer_public_key, shared_secret);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_ecdh_shared_secret(const uint8_t private_key[CRYPTO_ECDH_PRIVATEKEY_SIZE],
                               const uint8_t peer_public_key[CRYPTO_ECDH_PUBLICKEY_SIZE],
                               uint8_t shared_secret[CRYPTO_ECDH_SECRET_SIZE]);

/**
 * @brief Validate an X25519 public key
 *
 * Checks if a given public key is valid for use in X25519.
 * A public key is invalid if it represents a point that:
 *   - Lies on a small subgroup
 *   - Equals the identity element
 *   - Is not on the main curve subgroup
 *
 * @param public_key The public key to validate (32 bytes)
 *
 * @return true if the public key is valid, false otherwise
 *
 * @example
 * // Validate a public key
 * uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE]; // From elsewhere
 * if (!bn_crypto_ecdh_public_key_validate(public_key)) {
 *     // Handle invalid key
 * }
 */
bool bn_crypto_ecdh_public_key_validate(const uint8_t public_key[CRYPTO_ECDH_PUBLICKEY_SIZE]);

#endif /* BETANET_CRYPTO_ECDH_H_ */