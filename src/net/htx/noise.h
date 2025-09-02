#ifndef BETANET_NET_HTX_NOISE_H_
#define BETANET_NET_HTX_NOISE_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief HTX Noise Protocol Implementation
 * 
 * Implements the Noise XK handshake pattern for end-to-end encryption
 * within HTX connections. Provides secure key exchange and message
 * encryption using the Noise protocol framework.
 */

/** Forward declaration for opaque Noise state */
typedef struct HTXNoiseState HTXNoiseState;

/** Noise protocol constants */
#define HTX_NOISE_KEY_SIZE       32
#define HTX_NOISE_MAC_SIZE       16
#define HTX_NOISE_MAX_MESSAGE    65535

/**
 * @brief Initialize Noise protocol state
 *
 * Creates and initializes a new Noise protocol state for the XK pattern.
 * This is used for end-to-end encryption within HTX connections.
 *
 * @param is_initiator Whether this endpoint initiates the handshake
 * @param static_private_key Local static private key (32 bytes)
 * @param remote_static_public_key Remote static public key (32 bytes, can be NULL for initiator)
 * @param state_out Pointer to store the created state
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_NOISE_FAILURE: Noise protocol initialization failed
 *
 * @note State must be cleaned up with htx_noise_cleanup when no longer needed
 *
 * @example
 * HTXNoiseState *noise_state;
 * uint8_t private_key[32], public_key[32];
 * // ... generate or load keys ...
 * int result = htx_noise_init(true, private_key, public_key, &noise_state);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_noise_init(bool is_initiator, const uint8_t static_private_key[HTX_NOISE_KEY_SIZE],
                   const uint8_t remote_static_public_key[HTX_NOISE_KEY_SIZE],
                   HTXNoiseState **state_out);

/**
 * @brief Clean up Noise protocol state
 *
 * Securely cleans up and frees all resources associated with a Noise state.
 * All cryptographic material is securely wiped.
 *
 * @param state Noise state to clean up
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: state is NULL
 *
 * @example
 * htx_noise_cleanup(noise_state);
 */
int htx_noise_cleanup(HTXNoiseState *state);

/**
 * @brief Check if Noise handshake is complete
 *
 * Returns whether the Noise handshake has completed and the connection
 * is ready for application data encryption.
 *
 * @param state Noise state to check
 *
 * @return true if handshake is complete, false otherwise
 *
 * @example
 * if (htx_noise_is_ready(noise_state)) {
 *     // Can send/receive encrypted data
 * }
 */
bool htx_noise_is_ready(const HTXNoiseState *state);

/**
 * @brief Process incoming handshake data
 *
 * Processes incoming data during the Noise handshake phase.
 * Must be called until htx_noise_is_ready returns true.
 *
 * @param state Noise state
 * @param data Incoming handshake data
 * @param data_len Length of incoming data
 * @param processed_out Number of bytes processed
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_NOISE_FAILURE: Handshake failed
 *
 * @example
 * size_t processed;
 * int result = htx_noise_process_input(noise_state, buffer, len, &processed);
 * if (result < 0) {
 *     // Handle handshake error
 * }
 */
int htx_noise_process_input(HTXNoiseState *state, const uint8_t *data, 
                           size_t data_len, size_t *processed_out);

/**
 * @brief Generate outgoing handshake data
 *
 * Generates any pending handshake data that needs to be sent.
 * Must be called during handshake until htx_noise_is_ready returns true.
 *
 * @param state Noise state
 * @param buffer Buffer to write handshake data to
 * @param buffer_size Size of output buffer
 * @param written_out Number of bytes written
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_BUFFER_TOO_SMALL: Buffer too small
 *         - HTX_ERROR_NOISE_FAILURE: Handshake generation failed
 *
 * @example
 * uint8_t output[4096];
 * size_t written;
 * int result = htx_noise_generate_output(noise_state, output, sizeof(output), &written);
 * if (result == 0 && written > 0) {
 *     // Send written bytes
 * }
 */
int htx_noise_generate_output(HTXNoiseState *state, uint8_t *buffer, 
                             size_t buffer_size, size_t *written_out);

/**
 * @brief Encrypt application data
 *
 * Encrypts application data using the established Noise session keys.
 * Can only be called after htx_noise_is_ready returns true.
 *
 * @param state Noise state
 * @param plaintext Plain text data to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext_out Pointer to store encrypted data (allocated by function)
 * @param ciphertext_len_out Length of encrypted data
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_INVALID_STATE: Handshake not complete
 *         - HTX_ERROR_NOISE_FAILURE: Encryption failed
 *
 * @note Caller must free ciphertext_out when no longer needed
 *
 * @example
 * uint8_t *encrypted;
 * size_t encrypted_len;
 * int result = htx_noise_encrypt(noise_state, message, message_len, 
 *                               &encrypted, &encrypted_len);
 * if (result == 0) {
 *     // Send encrypted data
 *     free(encrypted);
 * }
 */
int htx_noise_encrypt(HTXNoiseState *state, const uint8_t *plaintext, 
                     size_t plaintext_len, uint8_t **ciphertext_out, 
                     size_t *ciphertext_len_out);

/**
 * @brief Decrypt application data
 *
 * Decrypts application data using the established Noise session keys.
 * Can only be called after htx_noise_is_ready returns true.
 *
 * @param state Noise state
 * @param ciphertext Encrypted data to decrypt
 * @param ciphertext_len Length of ciphertext
 * @param plaintext_out Pointer to store decrypted data (allocated by function)
 * @param plaintext_len_out Length of decrypted data
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_INVALID_STATE: Handshake not complete
 *         - HTX_ERROR_NOISE_FAILURE: Decryption failed
 *
 * @note Caller must free plaintext_out when no longer needed
 *
 * @example
 * uint8_t *decrypted;
 * size_t decrypted_len;
 * int result = htx_noise_decrypt(noise_state, encrypted, encrypted_len, 
 *                               &decrypted, &decrypted_len);
 * if (result == 0) {
 *     // Process decrypted data
 *     free(decrypted);
 * }
 */
int htx_noise_decrypt(HTXNoiseState *state, const uint8_t *ciphertext, 
                     size_t ciphertext_len, uint8_t **plaintext_out, 
                     size_t *plaintext_len_out);

/**
 * @brief Rotate Noise session keys
 *
 * Triggers key rotation for forward secrecy. Should be called periodically
 * or in response to KEY_UPDATE frames.
 *
 * @param state Noise state
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: state is NULL
 *         - HTX_ERROR_INVALID_STATE: Handshake not complete
 *         - HTX_ERROR_NOISE_FAILURE: Key rotation failed
 *
 * @example
 * int result = htx_noise_rotate_keys(noise_state);
 * if (result < 0) {
 *     // Handle key rotation error
 * }
 */
int htx_noise_rotate_keys(HTXNoiseState *state);

/**
 * @brief Get Noise handshake hash
 *
 * Returns the handshake hash after a successful handshake completion.
 * This can be used for channel binding or session verification.
 *
 * @param state Noise state
 * @param hash_out Buffer to store handshake hash (32 bytes)
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_INVALID_STATE: Handshake not complete
 *
 * @example
 * uint8_t handshake_hash[32];
 * int result = htx_noise_get_handshake_hash(noise_state, handshake_hash);
 * if (result == 0) {
 *     // Use handshake hash for verification
 * }
 */
int htx_noise_get_handshake_hash(const HTXNoiseState *state, uint8_t hash_out[32]);

#endif /* BETANET_NET_HTX_NOISE_H_ */
