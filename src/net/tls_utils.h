/**
 * @file tls_utils.h
 * @brief TLS utility functions for Betanet
 * 
 * This module provides common TLS functionality for secure communication,
 * including certificate verification, cipher selection, and session management.
 */

#ifndef BETANET_NET_TLS_UTILS_H_
#define BETANET_NET_TLS_UTILS_H_

#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>

/**
 * @brief Error codes for TLS utility functions
 */
typedef enum {
    BN_TLS_SUCCESS = 0,
    BN_TLS_ERROR_INVALID_PARAM = -1,
    BN_TLS_ERROR_INIT = -2,
    BN_TLS_ERROR_CONTEXT_CREATE = -3,
    BN_TLS_ERROR_HANDSHAKE = -4,
    BN_TLS_ERROR_VERIFICATION = -5,
    BN_TLS_ERROR_IO = -6,
    BN_TLS_ERROR_CERT = -7,
    BN_TLS_ERROR_MEMORY = -8,
    BN_TLS_ERROR_OPERATION = -9
} bn_tls_error_t;

/**
 * @brief TLS verification mode
 */
typedef enum {
    BN_TLS_VERIFY_NONE = 0,
    BN_TLS_VERIFY_PEER = 1,
    BN_TLS_VERIFY_PEER_STRICT = 2
} bn_tls_verify_mode_t;

/**
 * @brief TLS protocol version
 */
typedef enum {
    BN_TLS_VERSION_1_2 = 0,
    BN_TLS_VERSION_1_3 = 1,
    BN_TLS_VERSION_ALL = 2
} bn_tls_version_t;

/**
 * @brief TLS configuration options
 */
typedef struct {
    /** TLS verification mode */
    bn_tls_verify_mode_t verify_mode;
    
    /** Minimum TLS version */
    bn_tls_version_t min_version;
    
    /** Maximum TLS version */
    bn_tls_version_t max_version;
    
    /** CA certificate path (can be NULL for system default) */
    const char *ca_cert_path;
    
    /** Client certificate path (for mutual TLS, can be NULL) */
    const char *client_cert_path;
    
    /** Client private key path (for mutual TLS, can be NULL) */
    const char *client_key_path;
    
    /** Application protocols (ALPN) */
    const char **alpn_protocols;
    
    /** Number of ALPN protocols */
    size_t alpn_protocols_count;
    
    /** Server name for SNI */
    const char *server_name;
    
    /** Enable session tickets */
    bool enable_session_tickets;
    
    /** Cipher suites (TLS 1.3, can be NULL for defaults) */
    const char *cipher_suites;
    
    /** Ciphers (TLS 1.2, can be NULL for defaults) */
    const char *ciphers;
    
    /** Enable renegotiation (TLS 1.2 only) */
    bool enable_renegotiation;
} bn_tls_config_t;

/**
 * @brief Initialize the TLS utilities module
 * 
 * This function must be called once before using any other functions
 * in this module.
 * 
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_init(void);

/**
 * @brief Clean up the TLS utilities module
 * 
 * This function should be called when the program exits to free
 * any resources allocated by the module.
 * 
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_cleanup(void);

/**
 * @brief Set default TLS configuration values
 * 
 * @param config Pointer to the configuration structure to initialize
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_config_default(bn_tls_config_t *config);

/**
 * @brief Create a new SSL context
 * 
 * @param ssl_ctx Pointer to store the created SSL context
 * @param config TLS configuration
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_create_context(SSL_CTX **ssl_ctx, const bn_tls_config_t *config);

/**
 * @brief Create a new SSL object
 * 
 * @param ssl Pointer to store the created SSL object
 * @param ssl_ctx SSL context
 * @param fd Socket file descriptor
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_create_ssl(SSL **ssl, SSL_CTX *ssl_ctx, int fd);

/**
 * @brief Perform a TLS handshake as a client
 * 
 * @param ssl SSL object
 * @param hostname Hostname for SNI and verification
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_client_handshake(SSL *ssl, const char *hostname);

/**
 * @brief Verify the peer certificate
 * 
 * @param ssl SSL object
 * @param hostname Hostname to verify against
 * @param verify_mode Verification mode
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_verify_peer(SSL *ssl, const char *hostname, bn_tls_verify_mode_t verify_mode);

/**
 * @brief Send data using TLS
 * 
 * @param ssl SSL object
 * @param data Pointer to the data to send
 * @param len Length of the data to send
 * @param sent Pointer to store the number of bytes sent (can be NULL)
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_send(SSL *ssl, const uint8_t *data, size_t len, size_t *sent);

/**
 * @brief Receive data using TLS
 * 
 * @param ssl SSL object
 * @param buffer Buffer to store the received data
 * @param len Maximum length of data to receive
 * @param received Pointer to store the number of bytes received
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_recv(SSL *ssl, uint8_t *buffer, size_t len, size_t *received);

/**
 * @brief Perform a graceful TLS shutdown
 * 
 * @param ssl SSL object
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_shutdown(SSL *ssl);

/**
 * @brief Get the negotiated ALPN protocol
 * 
 * @param ssl SSL object
 * @param protocol Pointer to store the protocol string
 * @param len Pointer to store the protocol string length
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_get_alpn_protocol(SSL *ssl, const unsigned char **protocol, unsigned int *len);

/**
 * @brief Get the negotiated TLS version
 * 
 * @param ssl SSL object
 * @param version Pointer to store the TLS version
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_get_version(SSL *ssl, bn_tls_version_t *version);

/**
 * @brief Get the TLS error string for a given error code
 * 
 * @param error Error code
 * @return String representation of the error code
 */
const char* bn_tls_error_string(int error);

#endif /* BETANET_NET_TLS_UTILS_H_ */