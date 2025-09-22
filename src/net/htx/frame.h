#ifndef BETANET_HTX_FRAME_H_
#define BETANET_HTX_FRAME_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Error codes
#define BN_HTX_SUCCESS 0
#define BN_HTX_ERROR -1
#define BN_HTX_INVALID_FRAME -2
#define BN_HTX_INVALID_TYPE -3
#define BN_HTX_INVALID_LENGTH -4

// Frame types
enum bn_htx_frame_type {
  BN_HTX_FRAME_STREAM = 0,
  BN_HTX_FRAME_PING = 1,
  BN_HTX_FRAME_CLOSE = 2,
  BN_HTX_FRAME_KEY_UPDATE = 3,
  BN_HTX_FRAME_WINDOW_UPDATE = 4
};

// Forward declaration for crypto context
typedef struct bn_htx_crypto_ctx bn_htx_crypto_ctx_t;

// Parsed frame structure
typedef struct bn_htx_frame {
  uint32_t length;  // uint24 length of ciphertext (excl. tag)
  enum bn_htx_frame_type type;
  uint64_t stream_id;  // 0 if not applicable
  bool has_stream_id;
  uint8_t *ciphertext;  // encrypted payload
  size_t ciphertext_len;
  // For decrypted data
  uint8_t *payload;  // decrypted payload for STREAM/CLOSE
  size_t payload_len;
} bn_htx_frame_t;

/**
 * @brief Create a STREAM frame in buffer (plaintext version)
 *
 * Serializes the frame header + plaintext data into buffer. Length field is set to data_len (will be updated after encryption).
 *
 * @param buffer Output buffer
 * @param buffer_size Size of buffer
 * @param stream_id Stream ID
 * @param data Plaintext data
 * @param data_len Length of data
 * @param frame_len Output: length of serialized frame (header + data)
 * @return BN_HTX_SUCCESS on success, negative error code otherwise
 */
int bn_htx_frame_create_stream(uint8_t *buffer, size_t buffer_size, 
                               uint64_t stream_id, const uint8_t *data, 
                               size_t data_len, size_t *frame_len);

/**
 * @brief Create a PING frame in buffer (plaintext version)
 *
 * Serializes the PING frame header into buffer. No payload.
 *
 * @param buffer Output buffer
 * @param buffer_size Size of buffer
 * @param frame_len Output: length of serialized frame (header only)
 * @return BN_HTX_SUCCESS on success, negative error code otherwise
 */
int bn_htx_frame_create_ping(uint8_t *buffer, size_t buffer_size, 
                             size_t *frame_len);

/**
 * @brief Create a CLOSE frame in buffer (plaintext version)
 *
 * Serializes the CLOSE frame header + plaintext reason into buffer.
 *
 * @param buffer Output buffer
 * @param buffer_size Size of buffer
 * @param error_code Error code
 * @param reason Plaintext reason string
 * @param frame_len Output: length of serialized frame
 * @return BN_HTX_SUCCESS on success, negative error code otherwise
 */
int bn_htx_frame_create_close(uint8_t *buffer, size_t buffer_size, 
                              uint16_t error_code, const char *reason, 
                              size_t *frame_len);

/**
 * @brief Create a KEY_UPDATE frame in buffer (plaintext version)
 *
 * Serializes the KEY_UPDATE frame header into buffer. No payload.
 *
 * @param buffer Output buffer
 * @param buffer_size Size of buffer
 * @param frame_len Output: length of serialized frame
 * @return BN_HTX_SUCCESS on success, negative error code otherwise
 */
int bn_htx_frame_create_key_update(uint8_t *buffer, size_t buffer_size, 
                                   size_t *frame_len);

/**
 * @brief Create a WINDOW_UPDATE frame in buffer (plaintext version)
 *
 * Serializes the WINDOW_UPDATE frame header into buffer. No payload.
 *
 * @param buffer Output buffer
 * @param buffer_size Size of buffer
 * @param stream_id Stream ID
 * @param increment Window increment
 * @param frame_len Output: length of serialized frame
 * @return BN_HTX_SUCCESS on success, negative error code otherwise
 */
int bn_htx_frame_create_window_update(uint8_t *buffer, size_t buffer_size, 
                                      uint64_t stream_id, uint32_t increment, 
                                      size_t *frame_len);

/**
 * @brief Parse a received frame from buffer
 *
 * Parses the wire format frame, extracts header and ciphertext.
 *
 * @param buffer Input buffer
 * @param buffer_size Size of buffer
 * @param frame Output frame structure (allocate ciphertext if needed)
 * @param consumed Output: bytes consumed from buffer
 * @return BN_HTX_SUCCESS on success, negative error code otherwise
 */
int bn_htx_frame_parse(const uint8_t *buffer, size_t buffer_size, 
                       bn_htx_frame_t *frame, size_t *consumed);

/**
 * @brief Encrypt a frame
 *
 * Takes a frame with plaintext payload, serializes inner (type + stream_id + payload), encrypts to ciphertext + tag,
 * prepends length, outputs full wire format.
 *
 * @param crypto_ctx Crypto context for encryption
 * @param frame Input frame with plaintext in payload field
 * @param output Output buffer for wire format
 * @param output_size Size of output buffer
 * @param output_len Output: length of output
 * @return BN_HTX_SUCCESS on success, negative error code otherwise
 */
int bn_htx_frame_encrypt(const bn_htx_crypto_ctx_t *crypto_ctx, 
                         bn_htx_frame_t *frame, 
                         uint8_t *output, size_t output_size, 
                         size_t *output_len);

/**
 * @brief Decrypt a frame
 *
 * Takes wire format buffer, parses header, decrypts ciphertext to payload.
 *
 * @param crypto_ctx Crypto context for decryption
 * @param buffer Input wire format buffer
 * @param buffer_size Size of buffer
 * @param frame Output parsed and decrypted frame
 * @return BN_HTX_SUCCESS on success, negative error code otherwise
 */
int bn_htx_frame_decrypt(const bn_htx_crypto_ctx_t *crypto_ctx, 
                         const uint8_t *buffer, size_t buffer_size, 
                         bn_htx_frame_t *frame);

#endif /* BETANET_HTX_FRAME_H_ */
