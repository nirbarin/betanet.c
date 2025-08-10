/**
 * @file tcp.h
 * @brief TCP transport implementation for Betanet
 * 
 * This module provides TCP transport functionality with TLS 1.3 encryption,
 * anti-correlation measures, and HTTP/2 emulation for traffic analysis resistance.
 */

#ifndef BETANET_NET_TCP_H_
#define BETANET_NET_TCP_H_

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Error codes for the TCP transport module
 */
typedef enum {
    BN_TCP_SUCCESS = 0,
    BN_TCP_ERROR_INVALID_PARAM = -1,
    BN_TCP_ERROR_SOCKET_CREATE = -2,
    BN_TCP_ERROR_CONNECT = -3,
    BN_TCP_ERROR_TLS_INIT = -4,
    BN_TCP_ERROR_TLS_HANDSHAKE = -5,
    BN_TCP_ERROR_SEND = -6,
    BN_TCP_ERROR_RECV = -7,
    BN_TCP_ERROR_TIMEOUT = -8,
    BN_TCP_ERROR_CLOSED = -9,
    BN_TCP_ERROR_OUT_OF_MEMORY = -10,
    BN_TCP_ERROR_UNINITIALIZED = -11
} bn_tcp_error_t;

/**
 * @brief TLS verification mode
 */
typedef enum {
    BN_TCP_VERIFY_NONE = 0,
    BN_TCP_VERIFY_PEER = 1,
    BN_TCP_VERIFY_PEER_STRICT = 2
} bn_tcp_verify_mode_t;

/**
 * @brief Configuration for the TCP transport
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
    bn_tcp_verify_mode_t verify_mode;
    
    /** Enable anti-correlation measures */
    uint8_t enable_anti_correlation;
    
    /** Enable HTTP/2 emulation */
    uint8_t enable_http2_emulation;
    
    /** TLS CA certificate path (can be NULL for system default) */
    const char *ca_cert_path;
    
    /** Client certificate path (for mutual TLS, can be NULL) */
    const char *client_cert_path;
    
    /** Client private key path (for mutual TLS, can be NULL) */
    const char *client_key_path;
} bn_tcp_config_t;

/**
 * @brief TCP transport context
 * 
 * This structure is opaque to the user and should only be
 * manipulated using the provided API functions.
 */
typedef struct bn_tcp_ctx_s bn_tcp_ctx_t;

/**
 * @brief Initialize the TCP transport module
 * 
 * This function must be called once before using any other functions
 * in this module.
 * 
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_module_init(void);

/**
 * @brief Clean up the TCP transport module
 * 
 * This function should be called when the program exits to free
 * any resources allocated by the module.
 * 
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_module_cleanup(void);

/**
 * @brief Create a new TCP transport context
 * 
 * @param ctx Pointer to store the created context
 * @param config Configuration for the TCP transport
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_create(bn_tcp_ctx_t **ctx, const bn_tcp_config_t *config);

/**
 * @brief Destroy a TCP transport context
 * 
 * @param ctx Pointer to the context to destroy
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_destroy(bn_tcp_ctx_t *ctx);

/**
 * @brief Connect to a remote host using TCP with TLS
 * 
 * Establishes a TCP connection to the specified host and port,
 * performs a TLS handshake, and prepares the connection for
 * data transfer.
 * 
 * @param ctx TCP context
 * @param host Hostname or IP address to connect to
 * @param port Port number to connect to (typically 443)
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_connect(bn_tcp_ctx_t *ctx, const char *host, uint16_t port);

/**
 * @brief Send data over a TCP connection
 * 
 * @param ctx TCP context
 * @param data Pointer to the data to send
 * @param len Length of the data to send
 * @param sent Pointer to store the number of bytes sent (can be NULL)
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_send(bn_tcp_ctx_t *ctx, const uint8_t *data, size_t len, size_t *sent);

/**
 * @brief Receive data from a TCP connection
 * 
 * @param ctx TCP context
 * @param buffer Buffer to store the received data
 * @param len Maximum length of data to receive
 * @param received Pointer to store the number of bytes received
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_recv(bn_tcp_ctx_t *ctx, uint8_t *buffer, size_t len, size_t *received);

/**
 * @brief Close a TCP connection
 * 
 * @param ctx TCP context
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_close(bn_tcp_ctx_t *ctx);

/**
 * @brief Establish a cover connection for anti-correlation
 * 
 * Creates a connection to an unrelated host to make traffic
 * analysis more difficult.
 * 
 * @param host Hostname or IP address of the unrelated host
 * @param port Port number (typically 443)
 * @return Handle to the cover connection or NULL on failure
 */
void* bn_tcp_cover_connect(const char *host, uint16_t port);

/**
 * @brief Close a cover connection
 * 
 * @param handle Handle to the cover connection
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_cover_close(void *handle);

/**
 * @brief Get a string representation of a TCP error code
 * 
 * @param error Error code
 * @return String representation of the error code
 */
const char* bn_tcp_error_string(int error);

/**
 * @brief Set default configuration values
 * 
 * Initializes a configuration structure with sensible defaults.
 * 
 * @param config Pointer to the configuration structure to initialize
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_config_default(bn_tcp_config_t *config);

#endif /* BETANET_NET_TCP_H_ */