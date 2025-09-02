#ifndef BETANET_NET_HTX_HTX_H_
#define BETANET_NET_HTX_HTX_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief HTX Protocol Implementation
 * 
 * HTX (Hidden Transport) provides covert, censorship-resistant communication 
 * that appears to be regular HTTPS traffic. This implementation follows 
 * Section 5 of the Betanet v1.1 specification.
 */

/** Protocol version constants */
#define HTX_VERSION_1_1_0 "1.1.0"
#define HTX_VERSION_1_0_0 "1.0.0"

/** Protocol identifiers */
#define HTX_PROTOCOL_TCP    "/betanet/htx/1.1.0"
#define HTX_PROTOCOL_QUIC   "/betanet/htxquic/1.1.0"
#define HTX_PROTOCOL_LEGACY "/betanet/htx/1.0.0"

/** Maximum message sizes */
#define HTX_MAX_FRAME_SIZE      65535
#define HTX_MAX_STREAM_ID       0x3FFFFFFF
#define HTX_MAX_WINDOW_SIZE     0x7FFFFFFF
#define HTX_HEADER_SIZE         8

/** Error codes */
#define HTX_ERROR_INVALID_PARAM      -1
#define HTX_ERROR_INVALID_STATE      -2
#define HTX_ERROR_BUFFER_TOO_SMALL   -3
#define HTX_ERROR_PROTOCOL_VIOLATION -4
#define HTX_ERROR_STREAM_CLOSED      -5
#define HTX_ERROR_FRAME_TOO_LARGE    -6
#define HTX_ERROR_NOISE_FAILURE      -7
#define HTX_ERROR_TICKET_INVALID     -8

/** Transport types */
typedef enum {
    HTX_TRANSPORT_TCP = 0,
    HTX_TRANSPORT_QUIC = 1
} HTXTransportType;

/** Connection states */
typedef enum {
    HTX_CONN_STATE_INIT = 0,
    HTX_CONN_STATE_HANDSHAKE = 1,
    HTX_CONN_STATE_READY = 2,
    HTX_CONN_STATE_CLOSING = 3,
    HTX_CONN_STATE_CLOSED = 4
} HTXConnectionState;

/** Stream states */
typedef enum {
    HTX_STREAM_STATE_IDLE = 0,
    HTX_STREAM_STATE_OPEN = 1,
    HTX_STREAM_STATE_HALF_CLOSED_LOCAL = 2,
    HTX_STREAM_STATE_HALF_CLOSED_REMOTE = 3,
    HTX_STREAM_STATE_CLOSED = 4
} HTXStreamState;

/** Forward declarations for opaque types */
typedef struct HTXConnection HTXConnection;
typedef struct HTXStream HTXStream;
typedef struct HTXConfig HTXConfig;

/** Callback function types */
typedef void (*HTXDataCallback)(HTXStream *stream, const uint8_t *data, size_t len, void *user_data);
typedef void (*HTXStreamCloseCallback)(HTXStream *stream, void *user_data);
typedef void (*HTXErrorCallback)(HTXConnection *conn, int error_code, const char *error_msg, void *user_data);

/**
 * @brief HTX configuration structure
 * 
 * Contains all configuration parameters needed for HTX connections
 */
struct HTXConfig {
    /** Transport configuration */
    HTXTransportType transport_type;
    const char *origin_domain;      /* Domain to mirror TLS fingerprint from */
    uint16_t local_port;            /* Local port to bind to */
    uint16_t remote_port;           /* Remote port to connect to */
    
    /** Security configuration */
    bool require_access_ticket;     /* Whether to require access tickets */
    uint32_t ticket_lifetime_sec;   /* Ticket lifetime in seconds */
    const char *psk_identity;       /* Pre-shared key identity */
    
    /** Flow control configuration */
    uint32_t initial_window_size;   /* Initial flow control window size */
    uint32_t max_streams;           /* Maximum concurrent streams */
    
    /** Timing configuration */
    uint32_t ping_interval_ms;      /* PING frame interval in milliseconds */
    uint32_t idle_timeout_ms;       /* Connection idle timeout */
    
    /** Callback configuration */
    HTXDataCallback data_callback;
    HTXStreamCloseCallback stream_close_callback;
    HTXErrorCallback error_callback;
    void *user_data;
};

/**
 * @brief Initialize HTX configuration with default values
 *
 * Sets up a configuration structure with sensible defaults for HTX operation.
 *
 * @param config Pointer to configuration structure to initialize
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: config is NULL
 *
 * @example
 * HTXConfig config;
 * int result = htx_config_init(&config);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_config_init(HTXConfig *config);

/**
 * @brief Create a new HTX connection
 *
 * Creates and initializes a new HTX connection with the specified configuration.
 * The connection will be in INIT state and requires handshake completion.
 *
 * @param config Configuration for the connection
 * @param conn_out Pointer to store the created connection
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_INVALID_STATE: Invalid configuration state
 *
 * @note The connection must be freed with htx_connection_destroy when no longer needed
 *
 * @example
 * HTXConfig config;
 * HTXConnection *conn;
 * htx_config_init(&config);
 * int result = htx_connection_create(&config, &conn);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_connection_create(const HTXConfig *config, HTXConnection **conn_out);

/**
 * @brief Destroy an HTX connection
 *
 * Properly closes and cleans up an HTX connection, including all associated
 * streams and cryptographic state.
 *
 * @param conn Connection to destroy
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: conn is NULL
 *
 * @note All streams associated with this connection will be closed
 *
 * @example
 * htx_connection_destroy(conn);
 */
int htx_connection_destroy(HTXConnection *conn);

/**
 * @brief Get the current state of an HTX connection
 *
 * Returns the current state of the connection state machine.
 *
 * @param conn Connection to query
 * @param state_out Pointer to store the current state
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *
 * @example
 * HTXConnectionState state;
 * int result = htx_connection_get_state(conn, &state);
 * if (result == 0 && state == HTX_CONN_STATE_READY) {
 *     // Connection is ready for use
 * }
 */
int htx_connection_get_state(const HTXConnection *conn, HTXConnectionState *state_out);

/**
 * @brief Process incoming data for an HTX connection
 *
 * Processes raw incoming data and updates connection state. This handles
 * TLS decryption, frame parsing, and state machine updates.
 *
 * @param conn Connection to process data for
 * @param data Raw incoming data buffer
 * @param len Length of incoming data
 * @param processed_out Number of bytes processed from input
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_PROTOCOL_VIOLATION: Protocol error in input data
 *         - HTX_ERROR_FRAME_TOO_LARGE: Frame exceeds maximum size
 *
 * @note Callbacks may be triggered during processing
 *
 * @example
 * size_t processed;
 * int result = htx_connection_process_input(conn, buffer, buffer_len, &processed);
 * if (result < 0) {
 *     // Handle protocol error
 * }
 */
int htx_connection_process_input(HTXConnection *conn, const uint8_t *data, 
                                size_t len, size_t *processed_out);

/**
 * @brief Generate outgoing data for an HTX connection
 *
 * Generates any pending outgoing data that needs to be sent on the wire.
 * This includes TLS handshake data, frames, and heartbeats.
 *
 * @param conn Connection to generate output for
 * @param buffer Buffer to write outgoing data to
 * @param buffer_size Size of the output buffer
 * @param written_out Number of bytes written to buffer
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_BUFFER_TOO_SMALL: Output buffer too small
 *
 * @example
 * uint8_t output_buffer[4096];
 * size_t written;
 * int result = htx_connection_generate_output(conn, output_buffer, 
 *                                           sizeof(output_buffer), &written);
 * if (result == 0 && written > 0) {
 *     // Send written bytes on the wire
 * }
 */
int htx_connection_generate_output(HTXConnection *conn, uint8_t *buffer, 
                                  size_t buffer_size, size_t *written_out);

/**
 * @brief Create a new stream on an HTX connection
 *
 * Creates a new multiplexed stream for data transmission. Streams provide
 * independent, ordered data channels within a single HTX connection.
 *
 * @param conn Connection to create stream on
 * @param stream_out Pointer to store the created stream
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: conn is NULL
 *         - HTX_ERROR_INVALID_STATE: Connection not ready for streams
 *
 * @note Stream IDs are automatically assigned
 *
 * @example
 * HTXStream *stream;
 * int result = htx_stream_create(conn, &stream);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_stream_create(HTXConnection *conn, HTXStream **stream_out);

/**
 * @brief Send data on an HTX stream
 *
 * Queues data to be sent on the specified stream. Data will be framed
 * and encrypted before transmission.
 *
 * @param stream Stream to send data on
 * @param data Data buffer to send
 * @param len Length of data to send
 * @param sent_out Number of bytes actually queued for sending
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_STREAM_CLOSED: Stream is closed
 *         - HTX_ERROR_INVALID_STATE: Stream not in valid state for sending
 *
 * @note Data may be queued and sent asynchronously
 *
 * @example
 * size_t sent;
 * int result = htx_stream_send(stream, message, message_len, &sent);
 * if (result < 0) {
 *     // Handle send error
 * }
 */
int htx_stream_send(HTXStream *stream, const uint8_t *data, size_t len, size_t *sent_out);

/**
 * @brief Close an HTX stream
 *
 * Gracefully closes a stream, sending appropriate close frames and
 * updating stream state.
 *
 * @param stream Stream to close
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: stream is NULL
 *
 * @note Stream becomes invalid after this call
 *
 * @example
 * htx_stream_close(stream);
 */
int htx_stream_close(HTXStream *stream);

/**
 * @brief Get the current state of an HTX stream
 *
 * Returns the current state of the stream state machine.
 *
 * @param stream Stream to query
 * @param state_out Pointer to store the current state
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *
 * @example
 * HTXStreamState state;
 * int result = htx_stream_get_state(stream, &state);
 * if (result == 0 && state == HTX_STREAM_STATE_OPEN) {
 *     // Stream is open for data
 * }
 */
int htx_stream_get_state(const HTXStream *stream, HTXStreamState *state_out);

/**
 * @brief Get the stream ID for an HTX stream
 *
 * Returns the unique identifier for this stream within the connection.
 *
 * @param stream Stream to query
 * @param stream_id_out Pointer to store the stream ID
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *
 * @example
 * uint32_t stream_id;
 * int result = htx_stream_get_id(stream, &stream_id);
 * if (result == 0) {
 *     printf("Stream ID: %u\n", stream_id);
 * }
 */
int htx_stream_get_id(const HTXStream *stream, uint32_t *stream_id_out);

/**
 * @brief Update flow control window for a stream
 *
 * Updates the flow control window size for a stream, allowing more data
 * to be received.
 *
 * @param stream Stream to update
 * @param increment Number of bytes to add to window
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *         - HTX_ERROR_INVALID_STATE: Stream in invalid state
 *
 * @example
 * int result = htx_stream_update_window(stream, 1024);
 * if (result < 0) {
 *     // Handle error
 * }
 */
int htx_stream_update_window(HTXStream *stream, uint32_t increment);

#endif /* BETANET_NET_HTX_HTX_H_ */
