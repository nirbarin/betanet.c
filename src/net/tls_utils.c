/**
 * @file tls_utils.c
 * @brief TLS utility functions for Betanet
 * 
 * This module provides common TLS functionality for secure communication,
 * including certificate verification, cipher selection, and session management.
 */

#include "tls_utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

/**
 * @brief Global module state
 */
static int g_bn_tls_initialized = 0;

/**
 * @brief Default TLS 1.3 cipher suites
 */
static const char *BN_TLS_DEFAULT_CIPHER_SUITES = 
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

/**
 * @brief Default TLS 1.2 ciphers
 */
static const char *BN_TLS_DEFAULT_CIPHERS = 
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";

/**
 * @brief Error strings for TLS errors
 */
static const char *g_bn_tls_error_strings[] = {
    "Success",                       // BN_TLS_SUCCESS
    "Invalid parameter",             // BN_TLS_ERROR_INVALID_PARAM
    "TLS initialization failed",     // BN_TLS_ERROR_INIT
    "SSL context creation failed",   // BN_TLS_ERROR_CONTEXT_CREATE
    "TLS handshake failed",          // BN_TLS_ERROR_HANDSHAKE
    "Certificate verification failed", // BN_TLS_ERROR_VERIFICATION
    "TLS I/O operation failed",      // BN_TLS_ERROR_IO
    "Certificate operation failed",  // BN_TLS_ERROR_CERT
    "Memory allocation failed",      // BN_TLS_ERROR_MEMORY
    "TLS operation failed"           // BN_TLS_ERROR_OPERATION
};

/**
 * @brief Initialize the TLS utilities module
 * 
 * This function must be called once before using any other functions
 * in this module.
 * 
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_init(void) {
    if (g_bn_tls_initialized) {
        return BN_TLS_SUCCESS;
    }
    
    // Initialize OpenSSL
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) == 0) {
        return BN_TLS_ERROR_INIT;
    }
    
    // Seed the random number generator
    if (!RAND_poll()) {
        return BN_TLS_ERROR_INIT;
    }
    
    g_bn_tls_initialized = 1;
    return BN_TLS_SUCCESS;
}

/**
 * @brief Clean up the TLS utilities module
 * 
 * This function should be called when the program exits to free
 * any resources allocated by the module.
 * 
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_cleanup(void) {
    if (!g_bn_tls_initialized) {
        return BN_TLS_SUCCESS;
    }
    
    // OpenSSL cleanup is handled automatically with the modern API
    
    g_bn_tls_initialized = 0;
    return BN_TLS_SUCCESS;
}

/**
 * @brief Set default TLS configuration values
 * 
 * @param config Pointer to the configuration structure to initialize
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_config_default(bn_tls_config_t *config) {
    if (!config) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    memset(config, 0, sizeof(bn_tls_config_t));
    
    config->verify_mode = BN_TLS_VERIFY_PEER;
    config->min_version = BN_TLS_VERSION_1_2;
    config->max_version = BN_TLS_VERSION_1_3;
    config->ca_cert_path = NULL;         // Use system default
    config->client_cert_path = NULL;     // No client cert by default
    config->client_key_path = NULL;      // No client key by default
    config->alpn_protocols = NULL;
    config->alpn_protocols_count = 0;
    config->server_name = NULL;
    config->enable_session_tickets = true;
    config->cipher_suites = BN_TLS_DEFAULT_CIPHER_SUITES;
    config->ciphers = BN_TLS_DEFAULT_CIPHERS;
    config->enable_renegotiation = false;
    
    return BN_TLS_SUCCESS;
}

/**
 * @brief Convert a TLS version enum to OpenSSL version
 * 
 * @param version TLS version enum
 * @return OpenSSL version value
 */
static int bn_tls_version_to_openssl(bn_tls_version_t version) {
    switch (version) {
        case BN_TLS_VERSION_1_2:
            return TLS1_2_VERSION;
        case BN_TLS_VERSION_1_3:
            return TLS1_3_VERSION;
        case BN_TLS_VERSION_ALL:
            return 0; // Let OpenSSL handle it
        default:
            return TLS1_2_VERSION; // Default to TLS 1.2
    }
}

/**
 * @brief Create a new SSL context
 * 
 * @param ssl_ctx Pointer to store the created SSL context
 * @param config TLS configuration
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_create_context(SSL_CTX **ssl_ctx, const bn_tls_config_t *config) {
    if (!ssl_ctx || !config) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    if (!g_bn_tls_initialized) {
        return BN_TLS_ERROR_INIT;
    }
    
    // Create SSL context
    const SSL_METHOD *method = TLS_client_method();
    if (!method) {
        return BN_TLS_ERROR_CONTEXT_CREATE;
    }
    
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        return BN_TLS_ERROR_CONTEXT_CREATE;
    }
    
    // Set TLS version range
    int min_version = bn_tls_version_to_openssl(config->min_version);
    int max_version = bn_tls_version_to_openssl(config->max_version);
    
    if (min_version > 0 && SSL_CTX_set_min_proto_version(ctx, min_version) != 1) {
        SSL_CTX_free(ctx);
        return BN_TLS_ERROR_CONTEXT_CREATE;
    }
    
    if (max_version > 0 && SSL_CTX_set_max_proto_version(ctx, max_version) != 1) {
        SSL_CTX_free(ctx);
        return BN_TLS_ERROR_CONTEXT_CREATE;
    }
    
    // Configure certificate verification
    switch (config->verify_mode) {
        case BN_TLS_VERIFY_NONE:
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
            break;
            
        case BN_TLS_VERIFY_PEER:
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            break;
            
        case BN_TLS_VERIFY_PEER_STRICT:
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
            break;
            
        default:
            SSL_CTX_free(ctx);
            return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    // Load CA certificates
    if (config->ca_cert_path) {
        if (SSL_CTX_load_verify_locations(ctx, config->ca_cert_path, NULL) != 1) {
            SSL_CTX_free(ctx);
            return BN_TLS_ERROR_CERT;
        }
    } else {
        // Use default system CA certificates
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            SSL_CTX_free(ctx);
            return BN_TLS_ERROR_CERT;
        }
    }
    
    // Load client certificate and key if provided (for mutual TLS)
    if (config->client_cert_path && config->client_key_path) {
        if (SSL_CTX_use_certificate_file(ctx, config->client_cert_path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, config->client_key_path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            SSL_CTX_free(ctx);
            return BN_TLS_ERROR_CERT;
        }
    }
    
    // Configure TLS 1.3 cipher suites
    if (config->cipher_suites) {
        if (SSL_CTX_set_ciphersuites(ctx, config->cipher_suites) != 1) {
            SSL_CTX_free(ctx);
            return BN_TLS_ERROR_CONTEXT_CREATE;
        }
    }
    
    // Configure TLS 1.2 ciphers
    if (config->ciphers) {
        if (SSL_CTX_set_cipher_list(ctx, config->ciphers) != 1) {
            SSL_CTX_free(ctx);
            return BN_TLS_ERROR_CONTEXT_CREATE;
        }
    }
    
    // Configure session tickets
    if (!config->enable_session_tickets) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    }
    
    // Configure renegotiation
    if (!config->enable_renegotiation) {
        SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
    }
    
    // Configure ALPN if protocols are provided
    if (config->alpn_protocols && config->alpn_protocols_count > 0) {
        // Prepare ALPN protocol list
        unsigned char *alpn_data = NULL;
        size_t alpn_len = 0;
        
        // Calculate required size
        for (size_t i = 0; i < config->alpn_protocols_count; i++) {
            size_t proto_len = strlen(config->alpn_protocols[i]);
            if (proto_len > 255) {
                SSL_CTX_free(ctx);
                return BN_TLS_ERROR_INVALID_PARAM;
            }
            alpn_len += proto_len + 1; // +1 for length byte
        }
        
        // Allocate memory for ALPN data
        alpn_data = (unsigned char *)malloc(alpn_len);
        if (!alpn_data) {
            SSL_CTX_free(ctx);
            return BN_TLS_ERROR_MEMORY;
        }
        
        // Construct ALPN data
        unsigned char *p = alpn_data;
        for (size_t i = 0; i < config->alpn_protocols_count; i++) {
            size_t proto_len = strlen(config->alpn_protocols[i]);
            *p++ = (unsigned char)proto_len;
            memcpy(p, config->alpn_protocols[i], proto_len);
            p += proto_len;
        }
        
        // Set ALPN protocols
        int ret = SSL_CTX_set_alpn_protos(ctx, alpn_data, alpn_len);
        free(alpn_data);
        
        if (ret != 0) {
            SSL_CTX_free(ctx);
            return BN_TLS_ERROR_CONTEXT_CREATE;
        }
    }
    
    *ssl_ctx = ctx;
    return BN_TLS_SUCCESS;
}

/**
 * @brief Create a new SSL object
 * 
 * @param ssl Pointer to store the created SSL object
 * @param ssl_ctx SSL context
 * @param fd Socket file descriptor
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_create_ssl(SSL **ssl, SSL_CTX *ssl_ctx, int fd) {
    if (!ssl || !ssl_ctx || fd < 0) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    // Create SSL object
    SSL *new_ssl = SSL_new(ssl_ctx);
    if (!new_ssl) {
        return BN_TLS_ERROR_MEMORY;
    }
    
    // Set up SSL connection
    if (SSL_set_fd(new_ssl, fd) != 1) {
        SSL_free(new_ssl);
        return BN_TLS_ERROR_IO;
    }
    
    *ssl = new_ssl;
    return BN_TLS_SUCCESS;
}

/**
 * @brief Perform a TLS handshake as a client
 * 
 * @param ssl SSL object
 * @param hostname Hostname for SNI and verification
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_client_handshake(SSL *ssl, const char *hostname) {
    if (!ssl) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    // Set hostname for SNI
    if (hostname) {
        SSL_set_tlsext_host_name(ssl, hostname);
        
        // Set hostname for verification
        SSL_set1_host(ssl, hostname);
    }
    
    // Perform TLS handshake
    if (SSL_connect(ssl) != 1) {
        return BN_TLS_ERROR_HANDSHAKE;
    }
    
    return BN_TLS_SUCCESS;
}

/**
 * @brief Verify the peer certificate
 * 
 * @param ssl SSL object
 * @param hostname Hostname to verify against
 * @param verify_mode Verification mode
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_verify_peer(SSL *ssl, const char *hostname, bn_tls_verify_mode_t verify_mode) {
    if (!ssl) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    if (verify_mode == BN_TLS_VERIFY_NONE) {
        return BN_TLS_SUCCESS;
    }
    
    // Get peer certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        if (verify_mode == BN_TLS_VERIFY_PEER_STRICT) {
            return BN_TLS_ERROR_VERIFICATION;
        }
        return BN_TLS_SUCCESS;
    }
    
    // Release certificate
    X509_free(cert);
    
    // Verify certificate
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        return BN_TLS_ERROR_VERIFICATION;
    }
    
    return BN_TLS_SUCCESS;
}

/**
 * @brief Send data using TLS
 * 
 * @param ssl SSL object
 * @param data Pointer to the data to send
 * @param len Length of the data to send
 * @param sent Pointer to store the number of bytes sent (can be NULL)
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_send(SSL *ssl, const uint8_t *data, size_t len, size_t *sent) {
    if (!ssl || !data || len == 0) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    int ret = SSL_write(ssl, data, len);
    if (ret <= 0) {
        int ssl_err = SSL_get_error(ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
            if (sent) {
                *sent = 0;
            }
            return BN_TLS_ERROR_IO;
        } else {
            return BN_TLS_ERROR_IO;
        }
    }
    
    if (sent) {
        *sent = ret;
    }
    
    return BN_TLS_SUCCESS;
}

/**
 * @brief Receive data using TLS
 * 
 * @param ssl SSL object
 * @param buffer Buffer to store the received data
 * @param len Maximum length of data to receive
 * @param received Pointer to store the number of bytes received
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_recv(SSL *ssl, uint8_t *buffer, size_t len, size_t *received) {
    if (!ssl || !buffer || len == 0 || !received) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    int ret = SSL_read(ssl, buffer, len);
    if (ret <= 0) {
        int ssl_err = SSL_get_error(ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            *received = 0;
            return BN_TLS_ERROR_IO;
        } else if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            // Connection closed by peer
            *received = 0;
            return BN_TLS_SUCCESS;
        } else {
            *received = 0;
            return BN_TLS_ERROR_IO;
        }
    }
    
    *received = ret;
    return BN_TLS_SUCCESS;
}

/**
 * @brief Perform a graceful TLS shutdown
 * 
 * @param ssl SSL object
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_shutdown(SSL *ssl) {
    if (!ssl) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    int ret = SSL_shutdown(ssl);
    if (ret < 0) {
        return BN_TLS_ERROR_IO;
    }
    
    // SSL_shutdown may need to be called again for bidirectional shutdown
    if (ret == 0) {
        ret = SSL_shutdown(ssl);
        if (ret < 0) {
            return BN_TLS_ERROR_IO;
        }
    }
    
    return BN_TLS_SUCCESS;
}

/**
 * @brief Get the negotiated ALPN protocol
 * 
 * @param ssl SSL object
 * @param protocol Pointer to store the protocol string
 * @param len Pointer to store the protocol string length
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_get_alpn_protocol(SSL *ssl, const unsigned char **protocol, unsigned int *len) {
    if (!ssl || !protocol || !len) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    SSL_get0_alpn_selected(ssl, protocol, len);
    
    if (*len == 0) {
        return BN_TLS_ERROR_OPERATION;
    }
    
    return BN_TLS_SUCCESS;
}

/**
 * @brief Get the negotiated TLS version
 * 
 * @param ssl SSL object
 * @param version Pointer to store the TLS version
 * @return BN_TLS_SUCCESS on success, error code otherwise
 */
int bn_tls_get_version(SSL *ssl, bn_tls_version_t *version) {
    if (!ssl || !version) {
        return BN_TLS_ERROR_INVALID_PARAM;
    }
    
    int ssl_version = SSL_version(ssl);
    
    switch (ssl_version) {
        case TLS1_2_VERSION:
            *version = BN_TLS_VERSION_1_2;
            break;
            
        case TLS1_3_VERSION:
            *version = BN_TLS_VERSION_1_3;
            break;
            
        default:
            return BN_TLS_ERROR_OPERATION;
    }
    
    return BN_TLS_SUCCESS;
}

/**
 * @brief Get the TLS error string for a given error code
 * 
 * @param error Error code
 * @return String representation of the error code
 */
const char* bn_tls_error_string(int error) {
    if (error >= 0 || error < -9) {
        return "Unknown error";
    }
    
    return g_bn_tls_error_strings[-error];
}