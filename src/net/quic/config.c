/**
 * @file config.c
 * @brief Configuration functions for QUIC transport
 * 
 * This file contains functions for managing QUIC transport configuration.
 */

#include "internal.h"
#include <sys/time.h>
#include <openssl/rand.h>

/**
 * @brief Set default configuration values
 * 
 * Initializes a configuration structure with sensible defaults.
 * 
 * @param config Pointer to the configuration structure to initialize
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_config_default(bn_quic_config_t *config) {
    if (!config) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Set default connection parameters */
    config->max_retries = 3;
    config->connect_timeout_ms = 5000;  /* 5 seconds */
    config->read_timeout_ms = 30000;    /* 30 seconds */
    config->write_timeout_ms = 30000;   /* 30 seconds */
    config->verify_mode = BN_QUIC_VERIFY_PEER;
    config->enable_http3_emulation = 1; /* Enable HTTP/3 emulation by default for traffic analysis resistance */
    config->enable_quic_v1 = 1;         /* Enable QUIC v1 (RFC 9000) by default */
    config->idle_timeout_secs = 30;     /* 30 seconds idle timeout */
    config->max_concurrent_bidi_streams = 100;
    config->max_concurrent_uni_streams = 100;
    
    /* Default to system CA certificates */
    config->ca_cert_path = NULL;
    config->client_cert_path = NULL;
    config->client_key_path = NULL;
    
    /* Default ALPN protocols (HTTP/3) */
    static const char *default_alpns[] = {"h3", "h3-29"};
    config->alpn_protocols = default_alpns;
    config->alpn_protocols_count = 2;
    
    return BN_QUIC_SUCCESS;
}

/**
 * @brief Get a string representation of a QUIC error code
 * 
 * @param error Error code
 * @return String representation of the error code
 */
const char* bn_quic_error_string(int error) {
    switch (error) {
        case BN_QUIC_SUCCESS:
            return "Success";
        case BN_QUIC_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case BN_QUIC_ERROR_SOCKET_CREATE:
            return "Failed to create socket";
        case BN_QUIC_ERROR_CONNECT:
            return "Connection failed";
        case BN_QUIC_ERROR_TLS_INIT:
            return "TLS initialization failed";
        case BN_QUIC_ERROR_TLS_HANDSHAKE:
            return "TLS handshake failed";
        case BN_QUIC_ERROR_SEND:
            return "Send failed";
        case BN_QUIC_ERROR_RECV:
            return "Receive failed";
        case BN_QUIC_ERROR_TIMEOUT:
            return "Operation timed out";
        case BN_QUIC_ERROR_CLOSED:
            return "Connection closed";
        case BN_QUIC_ERROR_OUT_OF_MEMORY:
            return "Out of memory";
        case BN_QUIC_ERROR_UNINITIALIZED:
            return "Module not initialized";
        case BN_QUIC_ERROR_STREAM_CREATE:
            return "Failed to create stream";
        case BN_QUIC_ERROR_BLOCKED:
            return "Operation would block";
        case BN_QUIC_ERROR_MASQUE:
            return "MASQUE protocol error";
        default:
            return "Unknown error";
    }
}

/**
 * @brief Convert an ngtcp2 error code to a bn_quic_error_t
 * 
 * @param ngtcp2_error Error code from ngtcp2
 * @return Corresponding bn_quic_error_t value
 */
int bn_quic_map_error(int ngtcp2_error) {
    switch (ngtcp2_error) {
        case 0:
            return BN_QUIC_SUCCESS;
        case NGTCP2_ERR_NOBUF:
            return BN_QUIC_ERROR_INVALID_PARAM;
        case NGTCP2_ERR_INVALID_ARGUMENT:
            return BN_QUIC_ERROR_INVALID_PARAM;
        case NGTCP2_ERR_CONN_ID_BLOCKED:
            return BN_QUIC_ERROR_STREAM_CREATE;
        case NGTCP2_ERR_PROTO:
            return BN_QUIC_ERROR_RECV;
        case NGTCP2_ERR_INVALID_STATE:
            return BN_QUIC_ERROR_UNINITIALIZED;
        case NGTCP2_ERR_STREAM_STATE:
            return BN_QUIC_ERROR_STREAM_CREATE;
        case NGTCP2_ERR_STREAM_LIMIT:
            return BN_QUIC_ERROR_STREAM_CREATE;
        case NGTCP2_ERR_STREAM_ID_BLOCKED:
            return BN_QUIC_ERROR_STREAM_CREATE;
        case NGTCP2_ERR_FLOW_CONTROL:
            return BN_QUIC_ERROR_SEND;
        case NGTCP2_ERR_CONNECTION_ID_LIMIT:
            return BN_QUIC_ERROR_CONNECT;
        case NGTCP2_ERR_CRYPTO:
            return BN_QUIC_ERROR_TLS_INIT; // Maps to both TLS init and handshake
        case NGTCP2_ERR_STREAM_SHUT_WR:
            return BN_QUIC_ERROR_STREAM_CREATE;
        case NGTCP2_ERR_STREAM_NOT_FOUND:
            return BN_QUIC_ERROR_STREAM_CREATE;
        case NGTCP2_ERR_STREAM_IN_USE:
            return BN_QUIC_ERROR_SEND;
        case NGTCP2_ERR_CLOSING:
        case NGTCP2_ERR_DRAINING:
            return BN_QUIC_ERROR_CLOSED;
        case NGTCP2_ERR_TRANSPORT_PARAM:
            return BN_QUIC_ERROR_CONNECT;
        case NGTCP2_ERR_FATAL:
            return BN_QUIC_ERROR_CONNECT;
        case NGTCP2_ERR_CALLBACK_FAILURE:
            return BN_QUIC_ERROR_INVALID_PARAM;
        default:
            if (ngtcp2_error < 0) {
                return BN_QUIC_ERROR_INVALID_PARAM;
            } else {
                return BN_QUIC_SUCCESS;
            }
    }
}

/**
 * @brief Generate random bytes for cryptographic use
 * 
 * @param buf Buffer to fill with random bytes
 * @param len Number of bytes to generate
 * @return 0 on success, negative error code on failure
 */
int bn_quic_random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Use OpenSSL's RAND_bytes for cryptographically secure random data */
    if (RAND_bytes(buf, (int)len) != 1) {
        /* Fallback to /dev/urandom if OpenSSL fails */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            return BN_QUIC_ERROR_INVALID_PARAM;
        }
        
        ssize_t bytes_read = read(fd, buf, len);
        close(fd);
        
        if (bytes_read != (ssize_t)len) {
            return BN_QUIC_ERROR_INVALID_PARAM;
        }
    }
    
    return BN_QUIC_SUCCESS;
}

/**
 * @brief Get current timestamp in milliseconds
 * 
 * @return Current time in milliseconds since epoch
 */
uint64_t bn_quic_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

/**
 * @brief Check if a connection is expired based on idle timeout
 * 
 * @param ctx QUIC context
 * @return true if connection is expired, false otherwise
 */
bool bn_quic_is_expired(bn_quic_ctx_t *ctx) {
    if (!ctx || ctx->config.idle_timeout_secs == 0) {
        return false;
    }
    
    uint64_t now_ms = bn_quic_now_ms();
    uint64_t idle_ms = now_ms - ctx->last_activity_ms;
    uint64_t timeout_ms = (uint64_t)ctx->config.idle_timeout_secs * 1000;
    
    return idle_ms >= timeout_ms;
}

/**
 * @brief Initialize TLS with ngtcp2
 * 
 * @param ctx QUIC context
 * @param host Hostname to connect to (for client verification)
 * @return int BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_init_tls(bn_quic_ctx_t *ctx, const char *host) {
    if (!ctx) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Create SSL context */
    ctx->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ctx->ssl_ctx) {
        return BN_QUIC_ERROR_TLS_INIT;
    }
    
    /* Set minimum TLS version to 1.3 as required by QUIC */
    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
    
    /* Configure certificate verification */
    if (ctx->config.verify_mode == BN_QUIC_VERIFY_NONE) {
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
    } else if (ctx->config.verify_mode == BN_QUIC_VERIFY_PEER) {
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else if (ctx->config.verify_mode == BN_QUIC_VERIFY_PEER_STRICT) {
        SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    
    /* Load CA certificates if specified */
    if (ctx->config.ca_cert_path) {
        if (!SSL_CTX_load_verify_locations(ctx->ssl_ctx, ctx->config.ca_cert_path, NULL)) {
            SSL_CTX_free(ctx->ssl_ctx);
            ctx->ssl_ctx = NULL;
            return BN_QUIC_ERROR_TLS_INIT;
        }
    } else {
        /* Use system default CA certificates */
        if (!SSL_CTX_set_default_verify_paths(ctx->ssl_ctx)) {
            SSL_CTX_free(ctx->ssl_ctx);
            ctx->ssl_ctx = NULL;
            return BN_QUIC_ERROR_TLS_INIT;
        }
    }
    
    /* Load client certificate and key if specified (for mutual TLS) */
    if (ctx->config.client_cert_path && ctx->config.client_key_path) {
        if (!SSL_CTX_use_certificate_file(ctx->ssl_ctx, ctx->config.client_cert_path, SSL_FILETYPE_PEM) ||
            !SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, ctx->config.client_key_path, SSL_FILETYPE_PEM) ||
            !SSL_CTX_check_private_key(ctx->ssl_ctx)) {
            SSL_CTX_free(ctx->ssl_ctx);
            ctx->ssl_ctx = NULL;
            return BN_QUIC_ERROR_TLS_INIT;
        }
    }
    
    /* Create SSL object */
    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if (!ctx->ssl) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
        return BN_QUIC_ERROR_TLS_INIT;
    }
    
    /* Set SNI (Server Name Indication) for client connections */
    if (!ctx->flags.is_server && host) {
        SSL_set_tlsext_host_name(ctx->ssl, host);
    }
    
    /* Set ALPN protocols */
    if (ctx->config.alpn_protocols_count > 0) {
        uint8_t alpn_data[256];
        size_t alpn_len = 0;
        
        for (size_t i = 0; i < ctx->config.alpn_protocols_count; i++) {
            size_t protocol_len = strlen(ctx->config.alpn_protocols[i]);
            
            /* Check if we have enough space in the buffer */
            if (alpn_len + protocol_len + 1 > sizeof(alpn_data)) {
                SSL_free(ctx->ssl);
                SSL_CTX_free(ctx->ssl_ctx);
                ctx->ssl = NULL;
                ctx->ssl_ctx = NULL;
                return BN_QUIC_ERROR_TLS_INIT;
            }
            
            /* Format: length byte followed by protocol name */
            alpn_data[alpn_len++] = (uint8_t)protocol_len;
            memcpy(alpn_data + alpn_len, ctx->config.alpn_protocols[i], protocol_len);
            alpn_len += protocol_len;
        }
        
        SSL_set_alpn_protos(ctx->ssl, alpn_data, (unsigned int)alpn_len);
    }
    
    /* Set connection as data pointer in SSL for callbacks */
    SSL_set_app_data(ctx->ssl, ctx);
    
    /* Setup ngtcp2 crypto callbacks */
    ngtcp2_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    
    /* Set crypto related callbacks */
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.recv_stream_data = bn_ngtcp2_recv_stream_data;
    callbacks.stream_close = bn_ngtcp2_stream_close;
    
    return BN_QUIC_SUCCESS;
}

/**
 * @brief ngtcp2 callback for receiving crypto data
 */
int bn_ngtcp2_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                              uint64_t offset, const uint8_t *data,
                              size_t datalen, void *user_data) {    bn_quic_ctx_t *ctx = (bn_quic_ctx_t *)user_data;
    
    if (!ctx || !ctx->ssl) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    /* Map the crypto level to appropriate SSL object */
    SSL *ssl = ctx->ssl;
    
    /* Process the crypto data with the SSL object */
    int ret = ngtcp2_crypto_read_write_crypto_data(
        conn, level, data, datalen);
    
    if (ret != 0) {
        return ret;
    }
    
    return 0;
}

/**
 * @brief ngtcp2 callback for receiving stream data
 */
int bn_ngtcp2_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                             int64_t stream_id, uint64_t offset,
                             const uint8_t *data, size_t datalen,
                             void *user_data, void *stream_user_data) {
    /* In our implementation, stream data is buffered by ngtcp2 and read
     * explicitly by the application using bn_quic_stream_recv.
     * This callback is mainly for tracking purposes.
     */
    
    /* We don't need to do anything here as the data will be read later */
    return 0;
}

/**
 * @brief ngtcp2 callback for handling stream state changes
 */
int bn_ngtcp2_stream_close(ngtcp2_conn *conn, uint32_t flags,
                         int64_t stream_id, uint64_t app_error_code,
                         void *user_data, void *stream_user_data) {
    /* This callback is called when a stream is closed by the peer
     * The stream is automatically marked as closed in ngtcp2
     */
    
    /* We don't need to do anything special here as the stream state
     * will be detected when the application tries to read/write to it
     */
    return 0;
}

/**
 * @brief ngtcp2 callback for handling connection close
 */
int bn_ngtcp2_connection_close(ngtcp2_conn *conn, uint32_t flags,
                             uint64_t error_code, uint8_t frame_type,
                             const uint8_t *reason, size_t reason_len,
                             void *user_data) {
    bn_quic_ctx_t *ctx = (bn_quic_ctx_t *)user_data;
    
    if (!ctx) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    
    /* Mark the connection as closed */
    ctx->flags.connection_closed = 1;
    
    return 0;
}