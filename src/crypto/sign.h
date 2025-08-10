#ifndef BETANET_CRYPTO_SIGN_H_
#define BETANET_CRYPTO_SIGN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Size of an Ed25519 public key in bytes
 */
#define CRYPTO_SIGN_PUBLICKEY_SIZE 32

/**
 * @brief Size of an Ed25519 private key in bytes (includes public key for performance)
 */
#define CRYPTO_SIGN_PRIVATEKEY_SIZE 64

/**
 * @brief Size of an Ed25519 signature in bytes
 */
#define CRYPTO_SIGN_SIGNATURE_SIZE 64

/**
 * @brief Generate a new Ed25519 key pair
 *
 * Creates a new key pair for Ed25519 signatures.
 * The private key is 64 bytes (includes public key for performance).
 * The public key is 32 bytes.
 *
 * @param private_key Buffer to store the generated private key (64 bytes)
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
 * uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE];
 * uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE];
 * int result = bn_crypto_sign_keypair_generate(private_key, public_key);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_sign_keypair_generate(uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE],
                                  uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE]);

/**
 * @brief Derive a public key from a private key
 *
 * Extracts the public key corresponding to a given private key.
 * This function is useful when only the private key is available.
 *
 * @param private_key The private key to derive from (64 bytes)
 * @param public_key Buffer to store the derived public key (32 bytes)
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointers)
 *         - -2: Key derivation failed
 *
 * @example
 * // Derive public key from private key
 * uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE];
 * int result = bn_crypto_sign_derive_public_key(private_key, public_key);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_sign_derive_public_key(const uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE],
                                   uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE]);

/**
 * @brief Sign a message using an Ed25519 private key
 *
 * Creates an Ed25519 signature for the given message using the provided private key.
 * The signature can later be verified using the corresponding public key.
 *
 * @param private_key The private key to sign with (64 bytes)
 * @param message Pointer to the message to sign
 * @param message_len Length of the message in bytes
 * @param signature Buffer to store the generated signature (64 bytes)
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointers)
 *         - -2: Signing operation failed
 *
 * @note The signature includes both R and S components of the Ed25519 signature
 *
 * @example
 * // Sign a message
 * uint8_t signature[CRYPTO_SIGN_SIGNATURE_SIZE];
 * int result = bn_crypto_sign(private_key, message, message_len, signature);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_crypto_sign(const uint8_t private_key[CRYPTO_SIGN_PRIVATEKEY_SIZE],
                 const uint8_t *message, size_t message_len,
                 uint8_t signature[CRYPTO_SIGN_SIGNATURE_SIZE]);

/**
 * @brief Verify an Ed25519 signature
 *
 * Verifies that a signature was created using the private key corresponding
 * to the provided public key for the given message.
 *
 * @param public_key The public key to verify against (32 bytes)
 * @param message Pointer to the message that was signed
 * @param message_len Length of the message in bytes
 * @param signature The signature to verify (64 bytes)
 *
 * @return true if the signature is valid, false otherwise
 *
 * @example
 * // Verify a signature
 * bool is_valid = bn_crypto_sign_verify(public_key, message, message_len, signature);
 * if (!is_valid) {
 *     // Handle invalid signature
 * }
 */
bool bn_crypto_sign_verify(const uint8_t public_key[CRYPTO_SIGN_PUBLICKEY_SIZE],
                         const uint8_t *message, size_t message_len,
                         const uint8_t signature[CRYPTO_SIGN_SIGNATURE_SIZE]);

/**
 * @brief Verify multiple Ed25519 signatures in batch
 *
 * Efficiently verifies multiple signatures at once, which is faster than
 * verifying each signature individually.
 *
 * @param num_signatures Number of signatures to verify
 * @param public_keys Array of pointers to public keys (each 32 bytes)
 * @param messages Array of pointers to messages
 * @param message_lens Array of message lengths
 * @param signatures Array of pointers to signatures (each 64 bytes)
 *
 * @return true if all signatures are valid, false if any is invalid
 *
 * @note This function is more efficient than verifying signatures individually
 *       when multiple signatures need to be checked.
 *
 * @example
 * // Verify multiple signatures
 * const uint8_t *public_keys[3] = {pk1, pk2, pk3};
 * const uint8_t *messages[3] = {msg1, msg2, msg3};
 * const size_t message_lens[3] = {len1, len2, len3};
 * const uint8_t *signatures[3] = {sig1, sig2, sig3};
 * bool all_valid = bn_crypto_sign_verify_batch(3, public_keys, messages, 
 *                                              message_lens, signatures);
 */
bool bn_crypto_sign_verify_batch(size_t num_signatures,
                               const uint8_t **public_keys,
                               const uint8_t **messages, const size_t *message_lens,
                               const uint8_t **signatures);

#endif /* BETANET_CRYPTO_SIGN_H_ */
