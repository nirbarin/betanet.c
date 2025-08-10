/**
 * @file tcp.c
 * @brief TCP transport implementation for Betanet
 * 
 * This module provides TCP transport functionality with TLS 1.3 encryption,
 * anti-correlation measures, and HTTP/2 emulation for traffic analysis resistance.
 */

#include "tcp.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/**
 * @brief Default TCP configuration values
 */
#define BN_TCP_DEFAULT_MAX_RETRIES          3
#define BN_TCP_DEFAULT_CONNECT_TIMEOUT_MS   5000
#define BN_TCP_DEFAULT_READ_TIMEOUT_MS      10000
#define BN_TCP_DEFAULT_WRITE_TIMEOUT_MS     5000

/**
 * @brief Anti-correlation parameters
 */
#define BN_TCP_COVER_MIN_RETRY_DELAY_MS     200
#define BN_TCP_COVER_MAX_RETRY_DELAY_MS     1200
#define BN_TCP_COVER_MIN_START_DELAY_MS     0
#define BN_TCP_COVER_MAX_START_DELAY_MS     1000
#define BN_TCP_COVER_MIN_HTX_DELAY_MS       100
#define BN_TCP_COVER_MAX_HTX_DELAY_MS       700
#define BN_TCP_COVER_MIN_LIFETIME_S         3
#define BN_TCP_COVER_MAX_LIFETIME_S         15
#define BN_TCP_COVER_MIN_CONNECTIONS        2
#define BN_TCP_COVER_MAX_RETRIES_PER_MIN    2

/**
 * @brief Internal TCP context structure
 */
struct bn_tcp_ctx_s {
    int socket;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    bn_tcp_config_t config;
    int connected;
    time_t connect_time;
    uint8_t retry_count;
};

/**
 * @brief Cover connection context
 */
typedef struct {
    bn_tcp_ctx_t *tcp_ctx;
    time_t creation_time;
    time_t expiry_time;
} bn_tcp_cover_ctx_t;

/**
 * @brief Global module state
 */
static int g_bn_tcp_initialized = 0;

/**
 * @brief Error strings for TCP errors
 */
static const char *g_bn_tcp_error_strings[] = {
    "Success",                       // BN_TCP_SUCCESS
    "Invalid parameter",             // BN_TCP_ERROR_INVALID_PARAM
    "Socket creation failed",        // BN_TCP_ERROR_SOCKET_CREATE
    "Connection failed",             // BN_TCP_ERROR_CONNECT
    "TLS initialization failed",     // BN_TCP_ERROR_TLS_INIT
    "TLS handshake failed",          // BN_TCP_ERROR_TLS_HANDSHAKE
    "Send operation failed",         // BN_TCP_ERROR_SEND
    "Receive operation failed",      // BN_TCP_ERROR_RECV
    "Operation timed out",           // BN_TCP_ERROR_TIMEOUT
    "Connection closed",             // BN_TCP_ERROR_CLOSED
    "Out of memory",                 // BN_TCP_ERROR_OUT_OF_MEMORY
    "Module not initialized"         // BN_TCP_ERROR_UNINITIALIZED
};

/**
 * @brief Generate a random number in the specified range [min, max]
 * 
 * @param min Minimum value
 * @param max Maximum value
 * @return Random number in the range [min, max]
 */
static int bn_tcp_random_range(int min, int max) {
    unsigned int rand_val;
    if (RAND_bytes((unsigned char *)&rand_val, sizeof(rand_val)) != 1) {
        // Fallback to less secure random if OpenSSL fails
        rand_val = rand();
    }
    return min + (rand_val % (max - min + 1));
}

/**
 * @brief Set socket to non-blocking mode
 * 
 * @param sock Socket file descriptor
 * @return 0 on success, -1 on failure
 */
static int bn_tcp_set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

/**
 * @brief Set socket timeout options
 * 
 * @param sock Socket file descriptor
 * @param timeout_ms Timeout in milliseconds
 * @param for_recv Set timeout for receive operations if 1, send operations if 0
 * @return 0 on success, -1 on failure
 */
static int bn_tcp_set_timeout(int sock, int timeout_ms, int for_recv) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int optname = for_recv ? SO_RCVTIMEO : SO_SNDTIMEO;
    return setsockopt(sock, SOL_SOCKET, optname, &tv, sizeof(tv));
}

/**
 * @brief Initialize the TCP transport module
 * 
 * This function must be called once before using any other functions
 * in this module.
 * 
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_module_init(void) {
    if (g_bn_tcp_initialized) {
        return BN_TCP_SUCCESS;
    }
    
    // Initialize OpenSSL
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) == 0) {
        return BN_TCP_ERROR_TLS_INIT;
    }
    
    // Seed the random number generator
    if (!RAND_poll()) {
        return BN_TCP_ERROR_TLS_INIT;
    }
    
    // Initialize random number generator for non-crypto operations
    srand((unsigned int)time(NULL));
    
    g_bn_tcp_initialized = 1;
    return BN_TCP_SUCCESS;
}

/**
 * @brief Clean up the TCP transport module
 * 
 * This function should be called when the program exits to free
 * any resources allocated by the module.
 * 
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_module_cleanup(void) {
    if (!g_bn_tcp_initialized) {
        return BN_TCP_ERROR_UNINITIALIZED;
    }
    
    // OpenSSL cleanup is handled automatically with the modern API
    
    g_bn_tcp_initialized = 0;
    return BN_TCP_SUCCESS;
}

/**
 * @brief Set default configuration values
 * 
 * Initializes a configuration structure with sensible defaults.
 * 
 * @param config Pointer to the configuration structure to initialize
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_config_default(bn_tcp_config_t *config) {
    if (!config) {
        return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    memset(config, 0, sizeof(bn_tcp_config_t));
    
    config->max_retries = BN_TCP_DEFAULT_MAX_RETRIES;
    config->connect_timeout_ms = BN_TCP_DEFAULT_CONNECT_TIMEOUT_MS;
    config->read_timeout_ms = BN_TCP_DEFAULT_READ_TIMEOUT_MS;
    config->write_timeout_ms = BN_TCP_DEFAULT_WRITE_TIMEOUT_MS;
    config->verify_mode = BN_TCP_VERIFY_PEER;
    config->enable_anti_correlation = 1;
    config->enable_http2_emulation = 1;
    config->ca_cert_path = NULL;       // Use system default
    config->client_cert_path = NULL;   // No client cert by default
    config->client_key_path = NULL;    // No client key by default
    
    return BN_TCP_SUCCESS;
}

/**
 * @brief Create a new TCP transport context
 * 
 * @param ctx Pointer to store the created context
 * @param config Configuration for the TCP transport
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_create(bn_tcp_ctx_t **ctx, const bn_tcp_config_t *config) {
    if (!ctx || !config) {
        return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    if (!g_bn_tcp_initialized) {
        return BN_TCP_ERROR_UNINITIALIZED;
    }
    
    bn_tcp_ctx_t *new_ctx = (bn_tcp_ctx_t *)calloc(1, sizeof(bn_tcp_ctx_t));
    if (!new_ctx) {
        return BN_TCP_ERROR_OUT_OF_MEMORY;
    }
    
    // Copy configuration
    memcpy(&new_ctx->config, config, sizeof(bn_tcp_config_t));
    
    // Initialize socket to invalid value
    new_ctx->socket = -1;
    
    // Create SSL context
    const SSL_METHOD *method = TLS_client_method();
    if (!method) {
        free(new_ctx);
        return BN_TCP_ERROR_TLS_INIT;
    }
    
    new_ctx->ssl_ctx = SSL_CTX_new(method);
    if (!new_ctx->ssl_ctx) {
        free(new_ctx);
        return BN_TCP_ERROR_TLS_INIT;
    }
    
    // Set TLS 1.3 as the only allowed protocol
    if (SSL_CTX_set_min_proto_version(new_ctx->ssl_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(new_ctx->ssl_ctx, TLS1_3_VERSION) != 1) {
        SSL_CTX_free(new_ctx->ssl_ctx);
        free(new_ctx);
        return BN_TCP_ERROR_TLS_INIT;
    }
    
    // Configure certificate verification
    switch (config->verify_mode) {
        case BN_TCP_VERIFY_NONE:
            SSL_CTX_set_verify(new_ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
            break;
            
        case BN_TCP_VERIFY_PEER:
            SSL_CTX_set_verify(new_ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
            break;
            
        case BN_TCP_VERIFY_PEER_STRICT:
            SSL_CTX_set_verify(new_ctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
            break;
            
        default:
            SSL_CTX_free(new_ctx->ssl_ctx);
            free(new_ctx);
            return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    // Load CA certificates
    if (config->ca_cert_path) {
        if (SSL_CTX_load_verify_locations(new_ctx->ssl_ctx, config->ca_cert_path, NULL) != 1) {
            SSL_CTX_free(new_ctx->ssl_ctx);
            free(new_ctx);
            return BN_TCP_ERROR_TLS_INIT;
        }
    } else {
        // Use default system CA certificates
        if (SSL_CTX_set_default_verify_paths(new_ctx->ssl_ctx) != 1) {
            SSL_CTX_free(new_ctx->ssl_ctx);
            free(new_ctx);
            return BN_TCP_ERROR_TLS_INIT;
        }
    }
    
    // Load client certificate and key if provided (for mutual TLS)
    if (config->client_cert_path && config->client_key_path) {
        if (SSL_CTX_use_certificate_file(new_ctx->ssl_ctx, config->client_cert_path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(new_ctx->ssl_ctx, config->client_key_path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(new_ctx->ssl_ctx) != 1) {
            SSL_CTX_free(new_ctx->ssl_ctx);
            free(new_ctx);
            return BN_TCP_ERROR_TLS_INIT;
        }
    }
    
    // Configure ciphers for TLS 1.3
    // Only set secure cipher suites
    if (SSL_CTX_set_ciphersuites(new_ctx->ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1) {
        SSL_CTX_free(new_ctx->ssl_ctx);
        free(new_ctx);
        return BN_TCP_ERROR_TLS_INIT;
    }
    
    // Enable HTTP/2 ALPN if required
    if (config->enable_http2_emulation) {
        unsigned char alpn[] = "\x02h2";
        if (SSL_CTX_set_alpn_protos(new_ctx->ssl_ctx, alpn, sizeof(alpn) - 1) != 0) {
            SSL_CTX_free(new_ctx->ssl_ctx);
            free(new_ctx);
            return BN_TCP_ERROR_TLS_INIT;
        }
    }
    
    *ctx = new_ctx;
    return BN_TCP_SUCCESS;
}

/**
 * @brief Destroy a TCP transport context
 * 
 * @param ctx Pointer to the context to destroy
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_destroy(bn_tcp_ctx_t *ctx) {
    if (!ctx) {
        return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    // Close connection if open
    if (ctx->connected) {
        bn_tcp_close(ctx);
    }
    
    // Free SSL context
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
    }
    
    // Free the context
    free(ctx);
    
    return BN_TCP_SUCCESS;
}

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
int bn_tcp_connect(bn_tcp_ctx_t *ctx, const char *host, uint16_t port) {
    if (!ctx || !host) {
        return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    if (ctx->connected) {
        bn_tcp_close(ctx);
    }
    
    // Resolve hostname
    struct addrinfo hints, *result, *rp;
    char port_str[6];
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP socket
    hints.ai_flags = 0;
    hints.ai_protocol = 0;           // Any protocol
    
    snprintf(port_str, sizeof(port_str), "%u", port);
    
    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        return BN_TCP_ERROR_CONNECT;
    }
    
    // Try each address until we successfully connect
    int sock = -1;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) {
            continue;
        }
        
        // Set socket timeouts
        if (bn_tcp_set_timeout(sock, ctx->config.connect_timeout_ms, 0) != 0 ||
            bn_tcp_set_timeout(sock, ctx->config.read_timeout_ms, 1) != 0) {
            close(sock);
            sock = -1;
            continue;
        }
        
        // Set TCP options
        int flag = 1;
        if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0) {
            close(sock);
            sock = -1;
            continue;
        }
        
        // Connect to server
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) {
            break; // Success
        }
        
        close(sock);
        sock = -1;
    }
    
    freeaddrinfo(result);
    
    if (sock == -1) {
        // No address succeeded
        ctx->retry_count++;
        if (ctx->retry_count > ctx->config.max_retries) {
            ctx->retry_count = 0;
            return BN_TCP_ERROR_CONNECT;
        }
        
        // Add random delay before retry if anti-correlation is enabled
        if (ctx->config.enable_anti_correlation) {
            int delay_ms = bn_tcp_random_range(BN_TCP_COVER_MIN_RETRY_DELAY_MS, 
                                              BN_TCP_COVER_MAX_RETRY_DELAY_MS);
            struct timespec ts;
            ts.tv_sec = delay_ms / 1000;
            ts.tv_nsec = (delay_ms % 1000) * 1000000;
            nanosleep(&ts, NULL);
        }
        
        return BN_TCP_ERROR_CONNECT;
    }
    
    // Create SSL object
    ctx->ssl = SSL_new(ctx->ssl_ctx);
    if (!ctx->ssl) {
        close(sock);
        return BN_TCP_ERROR_TLS_INIT;
    }
    
    // Set hostname for SNI
    SSL_set_tlsext_host_name(ctx->ssl, host);
    
    // Set hostname for verification
    SSL_set1_host(ctx->ssl, host);
    
    // Set up SSL connection
    if (SSL_set_fd(ctx->ssl, sock) != 1) {
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        close(sock);
        return BN_TCP_ERROR_TLS_INIT;
    }
    
    // Perform TLS handshake
    if (SSL_connect(ctx->ssl) != 1) {
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        close(sock);
        return BN_TCP_ERROR_TLS_HANDSHAKE;
    }
    
    // Verify certificate if required
    if (ctx->config.verify_mode != BN_TCP_VERIFY_NONE) {
        X509 *cert = SSL_get_peer_certificate(ctx->ssl);
        if (!cert) {
            SSL_free(ctx->ssl);
            ctx->ssl = NULL;
            close(sock);
            return BN_TCP_ERROR_TLS_HANDSHAKE;
        }
        
        X509_free(cert);
        
        long verify_result = SSL_get_verify_result(ctx->ssl);
        if (verify_result != X509_V_OK) {
            SSL_free(ctx->ssl);
            ctx->ssl = NULL;
            close(sock);
            return BN_TCP_ERROR_TLS_HANDSHAKE;
        }
    }
    
    // Store socket
    ctx->socket = sock;
    ctx->connected = 1;
    ctx->connect_time = time(NULL);
    ctx->retry_count = 0;
    
    return BN_TCP_SUCCESS;
}

/**
 * @brief Send data over a TCP connection
 * 
 * @param ctx TCP context
 * @param data Pointer to the data to send
 * @param len Length of the data to send
 * @param sent Pointer to store the number of bytes sent (can be NULL)
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_send(bn_tcp_ctx_t *ctx, const uint8_t *data, size_t len, size_t *sent) {
    if (!ctx || !data || len == 0) {
        return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->connected || !ctx->ssl) {
        return BN_TCP_ERROR_CLOSED;
    }
    
    int ret = SSL_write(ctx->ssl, data, len);
    if (ret <= 0) {
        int ssl_err = SSL_get_error(ctx->ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
            return BN_TCP_ERROR_TIMEOUT;
        } else {
            bn_tcp_close(ctx);
            return BN_TCP_ERROR_SEND;
        }
    }
    
    if (sent) {
        *sent = ret;
    }
    
    return BN_TCP_SUCCESS;
}

/**
 * @brief Receive data from a TCP connection
 * 
 * @param ctx TCP context
 * @param buffer Buffer to store the received data
 * @param len Maximum length of data to receive
 * @param received Pointer to store the number of bytes received
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_recv(bn_tcp_ctx_t *ctx, uint8_t *buffer, size_t len, size_t *received) {
    if (!ctx || !buffer || len == 0 || !received) {
        return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->connected || !ctx->ssl) {
        return BN_TCP_ERROR_CLOSED;
    }
    
    int ret = SSL_read(ctx->ssl, buffer, len);
    if (ret <= 0) {
        int ssl_err = SSL_get_error(ctx->ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            *received = 0;
            return BN_TCP_ERROR_TIMEOUT;
        } else if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            // Connection closed by peer
            bn_tcp_close(ctx);
            *received = 0;
            return BN_TCP_ERROR_CLOSED;
        } else {
            bn_tcp_close(ctx);
            *received = 0;
            return BN_TCP_ERROR_RECV;
        }
    }
    
    *received = ret;
    return BN_TCP_SUCCESS;
}

/**
 * @brief Close a TCP connection
 * 
 * @param ctx TCP context
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_close(bn_tcp_ctx_t *ctx) {
    if (!ctx) {
        return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->connected) {
        return BN_TCP_SUCCESS;
    }
    
    // Shutdown SSL connection
    if (ctx->ssl) {
        SSL_shutdown(ctx->ssl);
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }
    
    // Close socket
    if (ctx->socket != -1) {
        close(ctx->socket);
        ctx->socket = -1;
    }
    
    ctx->connected = 0;
    
    return BN_TCP_SUCCESS;
}

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
void* bn_tcp_cover_connect(const char *host, uint16_t port) {
    if (!host || !g_bn_tcp_initialized) {
        return NULL;
    }
    
    // Create cover connection context
    bn_tcp_cover_ctx_t *cover_ctx = (bn_tcp_cover_ctx_t *)calloc(1, sizeof(bn_tcp_cover_ctx_t));
    if (!cover_ctx) {
        return NULL;
    }
    
    // Create TCP context with default configuration
    bn_tcp_config_t config;
    bn_tcp_config_default(&config);
    
    // Modify configuration for cover connection
    config.max_retries = 1;  // Only try once
    config.enable_anti_correlation = 0;  // Avoid recursive cover connections
    
    int ret = bn_tcp_create(&cover_ctx->tcp_ctx, &config);
    if (ret != BN_TCP_SUCCESS) {
        free(cover_ctx);
        return NULL;
    }
    
    // Connect to host
    ret = bn_tcp_connect(cover_ctx->tcp_ctx, host, port);
    if (ret != BN_TCP_SUCCESS) {
        bn_tcp_destroy(cover_ctx->tcp_ctx);
        free(cover_ctx);
        return NULL;
    }
    
    // Set up expiry time
    cover_ctx->creation_time = time(NULL);
    int lifetime = bn_tcp_random_range(BN_TCP_COVER_MIN_LIFETIME_S, BN_TCP_COVER_MAX_LIFETIME_S);
    cover_ctx->expiry_time = cover_ctx->creation_time + lifetime;
    
    return cover_ctx;
}

/**
 * @brief Close a cover connection
 * 
 * @param handle Handle to the cover connection
 * @return BN_TCP_SUCCESS on success, error code otherwise
 */
int bn_tcp_cover_close(void *handle) {
    if (!handle) {
        return BN_TCP_ERROR_INVALID_PARAM;
    }
    
    bn_tcp_cover_ctx_t *cover_ctx = (bn_tcp_cover_ctx_t *)handle;
    
    // Close TCP connection
    if (cover_ctx->tcp_ctx) {
        bn_tcp_destroy(cover_ctx->tcp_ctx);
    }
    
    // Free cover context
    free(cover_ctx);
    
    return BN_TCP_SUCCESS;
}

/**
 * @brief Get a string representation of a TCP error code
 * 
 * @param error Error code
 * @return String representation of the error code
 */
const char* bn_tcp_error_string(int error) {
    if (error >= 0 || error < -11) {
        return "Unknown error";
    }
    
    return g_bn_tcp_error_strings[-error];
}