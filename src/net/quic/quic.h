/**
 * @file quic.h
 * @brief QUIC transport implementation for Betanet
 * 
 * This module provides QUIC transport functionality over UDP port 443,
 * with support for multiplexed streams, connection migration, and MASQUE
 * CONNECT-UDP for tunneling.
 */

#ifndef BETANET_NET_QUIC_H_
#define BETANET_NET_QUIC_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Error codes for the QUIC transport module
 */
typedef enum {
    BN_QUIC_SUCCESS = 0,
    BN_QUIC_ERROR_INVALID_PARAM = -1,
    BN_QUIC_ERROR_SOCKET_CREATE = -2,
    BN_QUIC_ERROR_CONNECT = -3,
    BN_QUIC_ERROR_TLS_INIT = -4,
    BN_QUIC_ERROR_TLS_HANDSHAKE = -5,
    BN_QUIC_ERROR_SEND = -6,
    BN_QUIC_ERROR_RECV = -7,
    BN_QUIC_ERROR_TIMEOUT = -8,
    BN_QUIC_ERROR_CLOSED = -9,
    BN_QUIC_ERROR_OUT_OF_MEMORY = -10,
    BN_QUIC_ERROR_UNINITIALIZED = -11,
    BN_QUIC_ERROR_STREAM_CREATE = -12,
    BN_QUIC_ERROR_BLOCKED = -13,
    BN_QUIC_ERROR_MASQUE = -14
} bn_quic_error_t;

/**
 * @brief TLS verification mode
 */
typedef enum {
    BN_QUIC_VERIFY_NONE = 0,
    BN_QUIC_VERIFY_PEER = 1,
    BN_QUIC_VERIFY_PEER_STRICT = 2
} bn_quic_verify_mode_t;

/**
 * @brief QUIC stream direction
 */
typedef enum {
    BN_QUIC_STREAM_BIDI = 0,
    BN_QUIC_STREAM_UNI = 1
} bn_quic_stream_direction_t;

/**
 * @brief Configuration for the QUIC transport
 */
typedef struct {
    /** Maximum number of connection retries */
    uint8_t max_retries;
    
    /** Connection timeout in milliseconds */
    uint32_t connect_timeout_ms;
    
    /** Read timeout in milliseconds */
    uint32_t read_timeout_ms;
    
    /** Write timeout in milliseconds */
    uint32_t write_timeout_ms;
    
    /** TLS verification mode */
    bn_quic_verify_mode_t verify_mode;
    
    /** Enable HTTP/3 emulation */
    uint8_t enable_http3_emulation;
    
    /** Enable QUIC v1 (RFC 9000) */
    uint8_t enable_quic_v1;
    
    /** Enable idle timeout in seconds (0 to disable) */
    uint16_t idle_timeout_secs;
    
    /** Maximum concurrent bidirectional streams */
    uint64_t max_concurrent_bidi_streams;
    
    /** Maximum concurrent unidirectional streams */
    uint64_t max_concurrent_uni_streams;
    
    /** TLS CA certificate path (can be NULL for system default) */
    const char *ca_cert_path;
    
    /** Client certificate path (for mutual TLS, can be NULL) */
    const char *client_cert_path;
    
    /** Client private key path (for mutual TLS, can be NULL) */
    const char *client_key_path;
    
    /** Application protocols (ALPN) */
    const char **alpn_protocols;
    
    /** Number of ALPN protocols */
    size_t alpn_protocols_count;
} bn_quic_config_t;

/**
 * @brief QUIC transport context
 * 
 * This structure is opaque to the user and should only be
 * manipulated using the provided API functions.
 */
typedef struct bn_quic_ctx_s bn_quic_ctx_t;

/**
 * @brief QUIC stream context
 * 
 * This structure is opaque to the user and should only be
 * manipulated using the provided API functions.
 */
typedef struct bn_quic_stream_s bn_quic_stream_t;

/**
 * @brief Initialize the QUIC transport module
 * 
 * This function must be called once before using any other functions
 * in this module.
 * 
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_module_init(void);

/**
 * @brief Clean up the QUIC transport module
 * 
 * This function should be called when the program exits to free
 * any resources allocated by the module.
 * 
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_module_cleanup(void);

/**
 * @brief Create a new QUIC transport context
 * 
 * @param ctx Pointer to store the created context
 * @param config Configuration for the QUIC transport
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_create(bn_quic_ctx_t **ctx, const bn_quic_config_t *config);

/**
 * @brief Destroy a QUIC transport context
 * 
 * @param ctx Pointer to the context to destroy
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_destroy(bn_quic_ctx_t *ctx);

/**
 * @brief Connect to a remote host using QUIC
 * 
 * Establishes a QUIC connection to the specified host and port,
 * performs a TLS handshake, and prepares the connection for
 * data transfer.
 * 
 * @param ctx QUIC context
 * @param host Hostname or IP address to connect to
 * @param port Port number to connect to (typically 443)
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_connect(bn_quic_ctx_t *ctx, const char *host, uint16_t port);

/**
 * @brief Open a new QUIC stream
 * 
 * @param ctx QUIC context
 * @param stream Pointer to store the created stream
 * @param direction Stream direction (bidirectional or unidirectional)
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_stream_open(bn_quic_ctx_t *ctx, bn_quic_stream_t **stream, 
                        bn_quic_stream_direction_t direction);

/**
 * @brief Send data on a QUIC stream
 * 
 * @param stream QUIC stream
 * @param data Pointer to the data to send
 * @param len Length of the data to send
 * @param sent Pointer to store the number of bytes sent (can be NULL)
 * @param fin Whether this is the final data on this stream
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_stream_send(bn_quic_stream_t *stream, const uint8_t *data, 
                       size_t len, size_t *sent, bool fin);

/**
 * @brief Receive data from a QUIC stream
 * 
 * @param stream QUIC stream
 * @param buffer Buffer to store the received data
 * @param len Maximum length of data to receive
 * @param received Pointer to store the number of bytes received
 * @param fin Pointer to store whether the stream has been closed by the peer
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_stream_recv(bn_quic_stream_t *stream, uint8_t *buffer, 
                       size_t len, size_t *received, bool *fin);

/**
 * @brief Close a QUIC stream
 * 
 * @param stream QUIC stream
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_stream_close(bn_quic_stream_t *stream);

/**
 * @brief Close a QUIC connection
 * 
 * @param ctx QUIC context
 * @param app_error Whether this is an application error
 * @param error_code Error code to send to the peer
 * @param reason Reason string to send to the peer (can be NULL)
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_close(bn_quic_ctx_t *ctx, bool app_error, 
                 uint64_t error_code, const char *reason);

/**
 * @brief Detect if QUIC is blocked on the current network
 * 
 * @param ctx QUIC context
 * @return true if QUIC appears to be blocked, false otherwise
 */
bool bn_quic_is_blocked(bn_quic_ctx_t *ctx);

/**
 * @brief Implement MASQUE CONNECT-UDP for proxy functionality
 * 
 * Establishes a MASQUE CONNECT-UDP session to proxy UDP traffic
 * through the QUIC connection.
 * 
 * @param ctx QUIC context
 * @param target_host Target hostname or IP address
 * @param target_port Target port number
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_masque_connect_udp(bn_quic_ctx_t *ctx, 
                              const char *target_host, 
                              uint16_t target_port);

/**
 * @brief Get a string representation of a QUIC error code
 * 
 * @param error Error code
 * @return String representation of the error code
 */
const char* bn_quic_error_string(int error);

/**
 * @brief Set default configuration values
 * 
 * Initializes a configuration structure with sensible defaults.
 * 
 * @param config Pointer to the configuration structure to initialize
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_config_default(bn_quic_config_t *config);

/**
 * @brief Process incoming packets for a QUIC connection
 * 
 * This function should be called regularly to process incoming
 * packets and handle connection events.
 * 
 * @param ctx QUIC context
 * @param timeout_ms Maximum time to wait for incoming packets
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_process(bn_quic_ctx_t *ctx, uint32_t timeout_ms);

#endif /* BETANET_NET_QUIC_H_ */