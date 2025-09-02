#ifndef BETANET_NET_HTX_FRAME_H_
#define BETANET_NET_HTX_FRAME_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief HTX Frame Format Implementation
 * 
 * Implements the inner frame format for HTX protocol multiplexing.
 * Provides stream multiplexing with flow control following the
 * HTTP/2-inspired frame format.
 */

/** Frame type constants */
#define HTX_FRAME_TYPE_STREAM       0x00
#define HTX_FRAME_TYPE_PING         0x01
#define HTX_FRAME_TYPE_CLOSE        0x02
#define HTX_FRAME_TYPE_KEY_UPDATE   0x03
#define HTX_FRAME_TYPE_WINDOW_UPDATE 0x04

/** Frame flags */
#define HTX_FRAME_FLAG_NONE         0x00
#define HTX_FRAME_FLAG_END_STREAM   0x01
#define HTX_FRAME_FLAG_ACK          0x02

/** Frame header size in bytes */
#define HTX_FRAME_HEADER_SIZE       8

/** Maximum frame payload size */
#define HTX_FRAME_MAX_PAYLOAD_SIZE  65535

/** Stream ID mask (29 bits) */
#define HTX_STREAM_ID_MASK          0x1FFFFFFF

/** Forward declaration */
typedef struct HTXFrame HTXFrame;

/**
 * @brief HTX frame structure
 * 
 * Represents a complete HTX frame with header and payload
 */
struct HTXFrame {
    /** Frame header fields */
    uint32_t length;        /* Payload length (24 bits) */
    uint8_t type;           /* Frame type */
    uint8_t flags;          /* Frame flags */
    uint32_t stream_id;     /* Stream identifier (29 bits) */
    
    /** Frame payload */
    uint8_t *payload;       /* Payload data */
    size_t payload_capacity; /* Allocated payload capacity */
};

/**
 * @brief Initialize a new HTX frame
 *
 * Initializes a frame structure with the specified parameters.
 * Allocates memory for the payload if payload_size > 0.
 *
 * @param frame Pointer to frame structure to initialize
 * @param type Frame type
 * @param flags Frame flags
 * @param stream_id Stream identifier
 * @param payload_size Size of payload to allocate
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: frame is NULL or invalid parameters
 *         - HTX_ERROR_FRAME_TOO_LARGE: payload_size exceeds maximum
 *
 * @note Frame must be cleaned up with htx_frame_cleanup when no longer needed
 *
 * @example
 * HTXFrame frame;
 * int result = htx_frame_init(&frame, HTX_FRAME_TYPE_STREAM, 
 *                            HTX_FRAME_FLAG_NONE, 1, 1024);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_frame_init(HTXFrame *frame, uint8_t type, uint8_t flags, 
                   uint32_t stream_id, size_t payload_size);

/**
 * @brief Clean up an HTX frame
 *
 * Frees any allocated memory and securely clears frame data.
 *
 * @param frame Pointer to frame structure to clean up
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: frame is NULL
 *
 * @example
 * htx_frame_cleanup(&frame);
 */
int htx_frame_cleanup(HTXFrame *frame);

/**
 * @brief Parse an HTX frame from raw bytes
 *
 * Parses a complete frame from a buffer containing the frame header
 * and payload. Validates frame format and allocates payload memory.
 *
 * @param buffer Buffer containing frame data
 * @param buffer_size Size of the buffer
 * @param frame_out Pointer to store the parsed frame
 * @param bytes_consumed_out Number of bytes consumed from buffer
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_BUFFER_TOO_SMALL: Buffer too small for complete frame
 *         - HTX_ERROR_PROTOCOL_VIOLATION: Invalid frame format
 *         - HTX_ERROR_FRAME_TOO_LARGE: Frame payload too large
 *
 * @note Frame must be cleaned up with htx_frame_cleanup when no longer needed
 *
 * @example
 * HTXFrame frame;
 * size_t consumed;
 * int result = htx_frame_parse(buffer, buffer_size, &frame, &consumed);
 * if (result < 0) {
 *     // Handle parse error
 * }
 */
int htx_frame_parse(const uint8_t *buffer, size_t buffer_size, 
                    HTXFrame *frame_out, size_t *bytes_consumed_out);

/**
 * @brief Serialize an HTX frame to bytes
 *
 * Serializes a frame structure to wire format in the provided buffer.
 * Includes frame header and payload.
 *
 * @param frame Pointer to frame to serialize
 * @param buffer Buffer to write serialized frame to
 * @param buffer_size Size of the output buffer
 * @param bytes_written_out Number of bytes written to buffer
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_BUFFER_TOO_SMALL: Buffer too small for frame
 *
 * @example
 * uint8_t output[4096];
 * size_t written;
 * int result = htx_frame_serialize(&frame, output, sizeof(output), &written);
 * if (result == 0) {
 *     // Send written bytes
 * }
 */
int htx_frame_serialize(const HTXFrame *frame, uint8_t *buffer, 
                        size_t buffer_size, size_t *bytes_written_out);

/**
 * @brief Set frame payload data
 *
 * Sets the payload data for a frame, reallocating memory if necessary.
 * Existing payload data is replaced.
 *
 * @param frame Pointer to frame
 * @param data Payload data to set
 * @param data_size Size of payload data
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_FRAME_TOO_LARGE: data_size exceeds maximum
 *
 * @example
 * const char *message = "Hello, world!";
 * int result = htx_frame_set_payload(&frame, (const uint8_t*)message, 
 *                                   strlen(message));
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_frame_set_payload(HTXFrame *frame, const uint8_t *data, size_t data_size);

/**
 * @brief Get frame payload data
 *
 * Returns a pointer to the frame's payload data and its size.
 *
 * @param frame Pointer to frame
 * @param data_out Pointer to store payload data pointer
 * @param size_out Pointer to store payload size
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *
 * @example
 * const uint8_t *payload_data;
 * size_t payload_size;
 * int result = htx_frame_get_payload(&frame, &payload_data, &payload_size);
 * if (result == 0) {
 *     // Process payload_data of payload_size bytes
 * }
 */
int htx_frame_get_payload(const HTXFrame *frame, const uint8_t **data_out, size_t *size_out);

/**
 * @brief Calculate total frame size
 *
 * Returns the total size in bytes of the serialized frame including
 * header and payload.
 *
 * @param frame Pointer to frame
 * @param size_out Pointer to store total size
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *
 * @example
 * size_t total_size;
 * int result = htx_frame_get_total_size(&frame, &total_size);
 * if (result == 0) {
 *     printf("Frame size: %zu bytes\n", total_size);
 * }
 */
int htx_frame_get_total_size(const HTXFrame *frame, size_t *size_out);

/**
 * @brief Validate frame format
 *
 * Validates that a frame has valid field values according to the
 * HTX protocol specification.
 *
 * @param frame Pointer to frame to validate
 *
 * @return 0 if frame is valid, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: frame is NULL
 *         - HTX_ERROR_PROTOCOL_VIOLATION: Invalid frame format
 *
 * @example
 * int result = htx_frame_validate(&frame);
 * if (result < 0) {
 *     // Frame is invalid
 * }
 */
int htx_frame_validate(const HTXFrame *frame);

/**
 * @brief Create a STREAM frame
 *
 * Helper function to create a STREAM frame with the specified data.
 *
 * @param stream_id Stream identifier
 * @param data Stream data
 * @param data_size Size of stream data
 * @param end_stream Whether this is the last frame for the stream
 * @param frame_out Pointer to store the created frame
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_FRAME_TOO_LARGE: data_size exceeds maximum
 *
 * @example
 * HTXFrame frame;
 * const char *data = "Hello, world!";
 * int result = htx_frame_create_stream(1, (const uint8_t*)data, 
 *                                     strlen(data), false, &frame);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_frame_create_stream(uint32_t stream_id, const uint8_t *data, 
                           size_t data_size, bool end_stream, HTXFrame *frame_out);

/**
 * @brief Create a PING frame
 *
 * Helper function to create a PING frame with optional payload.
 *
 * @param ack Whether this is a PING ACK frame
 * @param payload Optional 8-byte payload data (can be NULL)
 * @param frame_out Pointer to store the created frame
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: frame_out is NULL
 *
 * @example
 * HTXFrame ping_frame;
 * uint8_t ping_data[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
 * int result = htx_frame_create_ping(false, ping_data, &ping_frame);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_frame_create_ping(bool ack, const uint8_t payload[8], HTXFrame *frame_out);

/**
 * @brief Create a CLOSE frame
 *
 * Helper function to create a CLOSE frame for a stream.
 *
 * @param stream_id Stream identifier
 * @param frame_out Pointer to store the created frame
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: frame_out is NULL
 *
 * @example
 * HTXFrame close_frame;
 * int result = htx_frame_create_close(1, &close_frame);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_frame_create_close(uint32_t stream_id, HTXFrame *frame_out);

/**
 * @brief Create a WINDOW_UPDATE frame
 *
 * Helper function to create a WINDOW_UPDATE frame.
 *
 * @param stream_id Stream identifier (0 for connection-level)
 * @param window_increment Window size increment
 * @param frame_out Pointer to store the created frame
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *
 * @example
 * HTXFrame window_frame;
 * int result = htx_frame_create_window_update(1, 1024, &window_frame);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_frame_create_window_update(uint32_t stream_id, uint32_t window_increment, 
                                  HTXFrame *frame_out);

#endif /* BETANET_NET_HTX_FRAME_H_ */
