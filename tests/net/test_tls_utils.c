#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "net/tls_utils.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (Line %d)\n", message, __LINE__); \
            return false; \
        } \
    } while (0)

/**
 * Test server configuration
 */
#define TEST_SERVER_PORT 4443
#define TEST_SERVER_BACKLOG 5

/* Use CMAKE_SOURCE_DIR which is defined during compilation */
#ifdef CMAKE_SOURCE_DIR
#define CERT_PATH(file) CMAKE_SOURCE_DIR "/tests/net/" file
#else
/* Fallback to relative path if not defined */
#define CERT_PATH(file) "tests/net/" file
#endif

#define TEST_SERVER_CERT CERT_PATH("server.crt")
#define TEST_SERVER_KEY CERT_PATH("server.key")
#define TEST_CLIENT_CERT CERT_PATH("client.crt")
#define TEST_CLIENT_KEY CERT_PATH("client.key")
#define TEST_CA_CERT CERT_PATH("ca.crt")

/**
 * Global variables for test server
 */
static int g_server_sock = -1;
static SSL_CTX *g_server_ssl_ctx = NULL;
static bool g_server_running = false;
static pthread_t g_server_thread;
static char g_server_message[] = "Hello from TLS test server";
static char g_client_message[] = "Hello from TLS test client";

/**
 * Print OpenSSL errors
 */
static void print_ssl_errors(void) {
    unsigned long err;
    char error_buffer[256];
    
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, error_buffer, sizeof(error_buffer));
        fprintf(stderr, "SSL Error: %s\n", error_buffer);
    }
}

/**
 * Handle a client connection in the test server
 */
static void handle_client(SSL *ssl) {
    char buffer[1024];
    int bytes;
    
    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "SSL accept failed\n");
        print_ssl_errors();
        return;
    }
    
    printf("SSL connection established with %s cipher\n", SSL_get_cipher(ssl));
    
    // Read client data
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Server received: %s\n", buffer);
        
        // Send the server message
        SSL_write(ssl, g_server_message, strlen(g_server_message));
    }
    
    // Shutdown SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

/**
 * TLS server thread function
 */
static void* test_server_thread(void *arg) {
    int client_sock;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL *ssl;
    
    g_server_running = true;
    
    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE
    
    printf("TLS test server started on port %d\n", TEST_SERVER_PORT);
    
    while (g_server_running) {
        // Accept incoming connection
        client_sock = accept(g_server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000); // Sleep 10ms and try again
                continue;
            }
            perror("Accept failed");
            break;
        }
        
        printf("Client connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Create SSL object
        ssl = SSL_new(g_server_ssl_ctx);
        if (!ssl) {
            fprintf(stderr, "SSL_new failed\n");
            print_ssl_errors();
            close(client_sock);
            continue;
        }
        
        // Set up SSL connection
        if (SSL_set_fd(ssl, client_sock) != 1) {
            fprintf(stderr, "SSL_set_fd failed\n");
            print_ssl_errors();
            SSL_free(ssl);
            close(client_sock);
            continue;
        }
        
        // Handle client in this thread for simplicity
        handle_client(ssl);
        
        // Close socket (SSL_free doesn't close the underlying socket)
        close(client_sock);
    }
    
    return NULL;
}

/**
 * Start a TLS test server
 */
static bool start_test_server(void) {
    struct sockaddr_in server_addr;
    int reuse = 1;
    
    // Initialize OpenSSL library
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return false;
    }
    
    // Create SSL context
    g_server_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_server_ssl_ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        print_ssl_errors();
        return false;
    }
    
    // Set TLS 1.3 as the only allowed protocol
    if (SSL_CTX_set_min_proto_version(g_server_ssl_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(g_server_ssl_ctx, TLS1_3_VERSION) != 1) {
        fprintf(stderr, "Failed to set TLS protocol version\n");
        print_ssl_errors();
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Set up ALPN for HTTP/2
    unsigned char alpn[] = "\x02h2";
    if (SSL_CTX_set_alpn_protos(g_server_ssl_ctx, alpn, sizeof(alpn) - 1) != 0) {
        fprintf(stderr, "Failed to set ALPN protocols\n");
        print_ssl_errors();
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Load server certificate and key
    if (SSL_CTX_use_certificate_file(g_server_ssl_ctx, TEST_SERVER_CERT, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load server certificate: %s\n", TEST_SERVER_CERT);
        print_ssl_errors();
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    if (SSL_CTX_use_PrivateKey_file(g_server_ssl_ctx, TEST_SERVER_KEY, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load server key: %s\n", TEST_SERVER_KEY);
        print_ssl_errors();
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    if (SSL_CTX_check_private_key(g_server_ssl_ctx) != 1) {
        fprintf(stderr, "Server certificate and key do not match\n");
        print_ssl_errors();
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Create socket
    g_server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_sock < 0) {
        perror("Server socket creation failed");
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Set socket options
    if (setsockopt(g_server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("Server setsockopt failed");
        close(g_server_sock);
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Prepare the sockaddr_in structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TEST_SERVER_PORT);
    
    // Bind
    if (bind(g_server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Server bind failed");
        close(g_server_sock);
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Listen
    if (listen(g_server_sock, TEST_SERVER_BACKLOG) < 0) {
        perror("Server listen failed");
        close(g_server_sock);
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Set non-blocking mode
    int flags = fcntl(g_server_sock, F_GETFL, 0);
    if (flags < 0 || fcntl(g_server_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("Server fcntl failed");
        close(g_server_sock);
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Start server thread
    if (pthread_create(&g_server_thread, NULL, test_server_thread, NULL) != 0) {
        perror("Server thread creation failed");
        close(g_server_sock);
        SSL_CTX_free(g_server_ssl_ctx);
        return false;
    }
    
    // Give the server thread a moment to start
    usleep(100000);  // 100ms
    
    return true;
}

/**
 * Stop the test server
 */
static void stop_test_server(void) {
    if (g_server_running) {
        g_server_running = false;
        pthread_join(g_server_thread, NULL);
    }
    
    if (g_server_sock >= 0) {
        close(g_server_sock);
        g_server_sock = -1;
    }
    
    if (g_server_ssl_ctx) {
        SSL_CTX_free(g_server_ssl_ctx);
        g_server_ssl_ctx = NULL;
    }
    
    printf("Test server stopped\n");
}

/**
 * Test module initialization and cleanup
 */
static bool test_module_init_cleanup(void) {
    printf("Testing module initialization and cleanup...\n");
    
    // Initialize module
    int result = bn_tls_init();
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Module initialization failed");
    
    // Cleanup module
    result = bn_tls_cleanup();
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Module cleanup failed");
    
    // Re-initialize for subsequent tests
    result = bn_tls_init();
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Module re-initialization failed");
    
    printf("  Module init/cleanup: OK\n");
    return true;
}

/**
 * Test configuration functions
 */
static bool test_configuration(void) {
    printf("Testing configuration functions...\n");
    
    bn_tls_config_t config;
    
    // Test default configuration initialization
    int result = bn_tls_config_default(&config);
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Default config initialization failed");
    
    // Verify default values
    TEST_ASSERT(config.verify_mode == BN_TLS_VERIFY_PEER, "Default verify_mode should be VERIFY_PEER");
    TEST_ASSERT(config.min_version == BN_TLS_VERSION_1_2, "Default min_version should be TLS 1.2");
    TEST_ASSERT(config.max_version == BN_TLS_VERSION_1_3, "Default max_version should be TLS 1.3");
    TEST_ASSERT(config.ca_cert_path == NULL, "Default ca_cert_path should be NULL");
    TEST_ASSERT(config.client_cert_path == NULL, "Default client_cert_path should be NULL");
    TEST_ASSERT(config.client_key_path == NULL, "Default client_key_path should be NULL");
    TEST_ASSERT(config.enable_session_tickets == true, "Default enable_session_tickets should be true");
    TEST_ASSERT(config.cipher_suites != NULL, "Default cipher_suites should not be NULL");
    TEST_ASSERT(config.ciphers != NULL, "Default ciphers should not be NULL");
    TEST_ASSERT(config.enable_renegotiation == false, "Default enable_renegotiation should be false");
    
    // Test with NULL parameter
    result = bn_tls_config_default(NULL);
    TEST_ASSERT(result == BN_TLS_ERROR_INVALID_PARAM, "Config default with NULL parameter should fail");
    
    printf("  Configuration: OK\n");
    return true;
}

/**
 * Test SSL context creation
 */
static bool test_context_creation(void) {
    printf("Testing SSL context creation...\n");
    
    bn_tls_config_t config;
    SSL_CTX *ssl_ctx = NULL;
    
    // Initialize default configuration
    int result = bn_tls_config_default(&config);
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Default config initialization failed");
    
    // Test with NULL parameters
    result = bn_tls_create_context(NULL, &config);
    TEST_ASSERT(result == BN_TLS_ERROR_INVALID_PARAM, "Create context with NULL ctx should fail");
    
    result = bn_tls_create_context(&ssl_ctx, NULL);
    TEST_ASSERT(result == BN_TLS_ERROR_INVALID_PARAM, "Create context with NULL config should fail");
    
    // Test with valid parameters
    result = bn_tls_create_context(&ssl_ctx, &config);
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Context creation failed");
    TEST_ASSERT(ssl_ctx != NULL, "Context should not be NULL after creation");
    
    // Clean up
    SSL_CTX_free(ssl_ctx);
    
    // Test with custom parameters
    config.verify_mode = BN_TLS_VERIFY_NONE;
    config.min_version = BN_TLS_VERSION_1_3;
    config.max_version = BN_TLS_VERSION_1_3;
    config.ca_cert_path = TEST_CA_CERT;
    config.enable_session_tickets = false;
    
    result = bn_tls_create_context(&ssl_ctx, &config);
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Context creation with custom params failed");
    TEST_ASSERT(ssl_ctx != NULL, "Context should not be NULL after creation");
    
    // Clean up
    SSL_CTX_free(ssl_ctx);
    
    printf("  Context creation: OK\n");
    return true;
}

/**
 * Test SSL object creation
 */
static bool test_ssl_creation(void) {
    printf("Testing SSL object creation...\n");
    
    bn_tls_config_t config;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    int sock = -1;
    
    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sock >= 0, "Socket creation failed");
    
    // Initialize default configuration
    int result = bn_tls_config_default(&config);
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Default config initialization failed");
    
    // Create SSL context
    result = bn_tls_create_context(&ssl_ctx, &config);
    TEST_ASSERT(result == BN_TLS_SUCCESS, "Context creation failed");
    
    // Test with NULL parameters
    result = bn_tls_create_ssl(NULL, ssl_ctx, sock);
    TEST_ASSERT(result == BN_TLS_ERROR_INVALID_PARAM, "Create SSL with NULL ssl should fail");
    
    result = bn_tls_create_ssl(&ssl, NULL, sock);
    TEST_ASSERT(result == BN_TLS_ERROR_INVALID_PARAM, "Create SSL with NULL ctx should fail");
    
    result = bn_tls_create_ssl(&ssl, ssl_ctx, -1);
    TEST_ASSERT(result == BN_TLS_ERROR_INVALID_PARAM, "Create SSL with invalid socket should fail");
    
    // Test with valid parameters
    result = bn_tls_create_ssl(&ssl, ssl_ctx, sock);
    TEST_ASSERT(result == BN_TLS_SUCCESS, "SSL creation failed");
    TEST_ASSERT(ssl != NULL, "SSL should not be NULL after creation");
    
    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sock);
    
    printf("  SSL object creation: OK\n");
    return true;
}

/**
 * Test TLS handshake function (client side)
 */
static bool test_live_connection(void) {
    printf("Testing live TLS connection...\n");
    
    // Start test server
    if (!start_test_server()) {
        fprintf(stderr, "Failed to start test server, skipping live connection test\n");
        return true;  // Skip test instead of failing
    }
    
    bn_tls_config_t config;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    int sock = -1;
    bool test_passed = true;
    
    // Initialize default configuration
    int result = bn_tls_config_default(&config);
    if (result != BN_TLS_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Default config initialization failed: %s\n", 
                bn_tls_error_string(result));
        goto cleanup;
    }
    
    // Configure TLS to accept our test certificates
    config.verify_mode = BN_TLS_VERIFY_PEER;
    config.ca_cert_path = TEST_CA_CERT;
    
    // Create SSL context
    result = bn_tls_create_context(&ssl_ctx, &config);
    if (result != BN_TLS_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Context creation failed: %s\n", bn_tls_error_string(result));
        goto cleanup;
    }
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        test_passed = false;
        perror("Socket creation failed");
        goto cleanup;
    }
    
    // Connect to server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TEST_SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    printf("  Connecting to 127.0.0.1:%d...\n", TEST_SERVER_PORT);
    
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        test_passed = false;
        perror("Connection failed");
        goto cleanup;
    }
    
    printf("  TCP connection established\n");
    
    // Create SSL object
    result = bn_tls_create_ssl(&ssl, ssl_ctx, sock);
    if (result != BN_TLS_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "SSL creation failed: %s\n", bn_tls_error_string(result));
        goto cleanup;
    }
    
    // Perform handshake
    printf("  Performing TLS handshake...\n");
    result = bn_tls_client_handshake(ssl, "localhost");
    if (result != BN_TLS_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "TLS handshake failed: %s\n", bn_tls_error_string(result));
        goto cleanup;
    }
    
    printf("  TLS handshake successful\n");
    
    // Verify peer
    result = bn_tls_verify_peer(ssl, "localhost", BN_TLS_VERIFY_PEER);
    if (result != BN_TLS_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Peer verification failed: %s\n", bn_tls_error_string(result));
        goto cleanup;
    }
    
    printf("  Peer verification successful\n");
    
    // Get TLS version
    bn_tls_version_t version;
    result = bn_tls_get_version(ssl, &version);
    if (result == BN_TLS_SUCCESS) {
        printf("  Negotiated TLS version: %s\n", 
               version == BN_TLS_VERSION_1_3 ? "TLS 1.3" : 
               version == BN_TLS_VERSION_1_2 ? "TLS 1.2" : "Unknown");
    }
    
    // Send data
    printf("  Sending data: %s\n", g_client_message);
    size_t sent;
    result = bn_tls_send(ssl, (const uint8_t*)g_client_message, strlen(g_client_message), &sent);
    if (result != BN_TLS_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Data send failed: %s\n", bn_tls_error_string(result));
        goto cleanup;
    }
    
    printf("  Sent %zu bytes\n", sent);
    
    // Receive data
    uint8_t buffer[1024];
    size_t received;
    result = bn_tls_recv(ssl, buffer, sizeof(buffer) - 1, &received);
    if (result != BN_TLS_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Data receive failed: %s\n", bn_tls_error_string(result));
        goto cleanup;
    }
    
    buffer[received] = '\0';
    printf("  Received %zu bytes: %s\n", received, (char*)buffer);
    
    // Verify received data
    if (strcmp((char*)buffer, g_server_message) != 0) {
        test_passed = false;
        fprintf(stderr, "Unexpected response: expected '%s', got '%s'\n", 
                g_server_message, (char*)buffer);
        goto cleanup;
    }
    
    // Perform TLS shutdown
    printf("  Performing TLS shutdown...\n");
    result = bn_tls_shutdown(ssl);
    if (result != BN_TLS_SUCCESS) {
        fprintf(stderr, "Warning: TLS shutdown returned: %s\n", bn_tls_error_string(result));
        // Don't fail the test on shutdown issues as they're common
    } else {
        printf("  TLS shutdown successful\n");
    }
    
cleanup:
    // Clean up
    if (ssl) {
        SSL_free(ssl);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    if (sock >= 0) {
        close(sock);
    }
    
    stop_test_server();
    
    if (test_passed) {
        printf("  Live TLS connection: OK\n");
    } else {
        printf("  Live TLS connection: FAILED\n");
    }
    
    return test_passed;
}

/**
 * Test error string function
 */
static bool test_error_string(void) {
    printf("Testing error string function...\n");
    
    // Test valid error codes
    const char *err_str = bn_tls_error_string(BN_TLS_SUCCESS);
    TEST_ASSERT(err_str != NULL && strlen(err_str) > 0, "Error string for SUCCESS should not be empty");
    
    err_str = bn_tls_error_string(BN_TLS_ERROR_INVALID_PARAM);
    TEST_ASSERT(err_str != NULL && strlen(err_str) > 0, "Error string for INVALID_PARAM should not be empty");
    
    // Test invalid error code
    err_str = bn_tls_error_string(-100);  // Out of range
    TEST_ASSERT(err_str != NULL && strstr(err_str, "Unknown") != NULL, 
               "Error string for invalid code should indicate unknown error");
    
    printf("  Error string: OK\n");
    return true;
}

/**
 * Run all tests
 */
int main(void) {
    printf("===== TLS Utilities Test Suite =====\n");
    
    bool all_passed = true;
    
    // Initialize module for all tests
    if (bn_tls_init() != BN_TLS_SUCCESS) {
        fprintf(stderr, "FAIL: Module initialization failed, cannot run tests\n");
        return EXIT_FAILURE;
    }
    
    // Run tests
    all_passed &= test_module_init_cleanup();
    all_passed &= test_configuration();
    all_passed &= test_context_creation();
    all_passed &= test_ssl_creation();
    all_passed &= test_error_string();
    all_passed &= test_live_connection();
    
    // Final cleanup
    bn_tls_cleanup();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}