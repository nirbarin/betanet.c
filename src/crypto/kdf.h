#ifndef BETANET_CRYPTO_KDF_H_
#define BETANET_CRYPTO_KDF_H_

#include <stddef.h>
#include <stdint.h>

/**
 * @brief HKDF-Extract function
 *
 * Extracts entropy from input keying material using a salt value.
 * Implements the first step of HKDF as defined in RFC 5869.
 *
 * @param salt Optional salt value (can be NULL if salt_len is 0)
 * @param salt_len Length of the salt in bytes
 * @param ikm Input keying material
 * @param ikm_len Length of the input keying material in bytes
 * @param prk Output pseudorandom key (32 bytes for HKDF-SHA256)
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointer for ikm or prk)
 *         - -2: Internal error during extraction
 *
 * @example
 * // Extract entropy from a shared secret
 * uint8_t prk[32];
 * int result = bn_hkdf_extract(salt, salt_len, shared_secret, secret_len, prk);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_hkdf_extract(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   uint8_t prk[32]);

/**
 * @brief HKDF-Expand function
 *
 * Expands the pseudorandom key to the desired output length using optional context info.
 * Implements the second step of HKDF as defined in RFC 5869.
 *
 * @param prk Pseudorandom key from the extract step (32 bytes for HKDF-SHA256)
 * @param info Optional context and application specific information (can be NULL if info_len is 0)
 * @param info_len Length of the info in bytes
 * @param okm Output keying material
 * @param okm_len Desired length of the output keying material in bytes (maximum 255 * 32 bytes)
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters (NULL pointer for prk or okm)
 *         - -2: Invalid output length (too large for the hash function)
 *         - -3: Internal error during expansion
 *
 * @example
 * // Expand a key to generate 64 bytes of output keying material
 * uint8_t okm[64];
 * int result = bn_hkdf_expand(prk, info, info_len, okm, sizeof(okm));
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_hkdf_expand(const uint8_t prk[32],
                  const uint8_t *info, size_t info_len,
                  uint8_t *okm, size_t okm_len);

/**
 * @brief Combined HKDF Extract and Expand
 *
 * Performs the complete HKDF key derivation in a single call.
 * Combines the extract and expand steps as defined in RFC 5869.
 *
 * @param salt Optional salt value (can be NULL if salt_len is 0)
 * @param salt_len Length of the salt in bytes
 * @param ikm Input keying material
 * @param ikm_len Length of the input keying material in bytes
 * @param info Optional context and application specific information (can be NULL if info_len is 0)
 * @param info_len Length of the info in bytes
 * @param okm Output keying material
 * @param okm_len Desired length of the output keying material in bytes (maximum 255 * 32 bytes)
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters
 *         - -2: Invalid output length
 *         - -3: Internal error during extraction or expansion
 *
 * @example
 * // Derive 32 bytes of key material from a shared secret
 * uint8_t key[32];
 * int result = bn_hkdf(salt, salt_len, shared_secret, secret_len, 
 *                    context, context_len, key, sizeof(key));
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_hkdf(const uint8_t *salt, size_t salt_len,
           const uint8_t *ikm, size_t ikm_len,
           const uint8_t *info, size_t info_len,
           uint8_t *okm, size_t okm_len);

/**
 * @brief HKDF-Expand-Label function (TLS 1.3 style)
 *
 * A specialized version of HKDF-Expand that formats the info parameter
 * according to the TLS 1.3 key derivation specification. Used for compatibility
 * with TLS 1.3 and for Betanet-specific labeled derivation.
 *
 * @param prk Pseudorandom key from the extract step (32 bytes for HKDF-SHA256)
 * @param label String label for the derivation (null-terminated)
 * @param context Optional context value (can be NULL if context_len is 0)
 * @param context_len Length of the context in bytes
 * @param out Output keying material
 * @param out_len Desired length of the output keying material in bytes
 *
 * @return 0 on success, negative value on error
 *         - -1: Invalid parameters
 *         - -2: Invalid output length
 *         - -3: Internal error during expansion
 *
 * @example
 * // Derive key material using TLS 1.3 style label expansion
 * uint8_t key[64];
 * int result = bn_hkdf_expand_label(prk, "htx inner v1", NULL, 0, key, sizeof(key));
 * if (result < 0) {
 *     // Handle error
 * }
 */
int bn_hkdf_expand_label(const uint8_t prk[32],
                        const char *label, const uint8_t *context, size_t context_len,
                        uint8_t *out, size_t out_len);

#endif /* BETANET_CRYPTO_KDF_H_ */