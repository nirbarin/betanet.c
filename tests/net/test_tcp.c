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
#include "net/tcp.h"

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
#define TEST_SERVER_CERT "tests/net/server.crt"
#define TEST_SERVER_KEY "tests/net/server.key"
#define TEST_CLIENT_CERT "tests/net/client.crt"
#define TEST_CLIENT_KEY "tests/net/client.key"
#define TEST_CA_CERT "tests/net/ca.crt"

/**
 * Global variables for test server
 */
static int g_server_sock = -1;
static SSL_CTX *g_server_ssl_ctx = NULL;
static bool g_server_running = false;
static pthread_t g_server_thread;
static char g_server_message[] = "Hello from test server";
static char g_client_message[] = "Hello from test client";

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
 * Test basic module initialization and cleanup
 */
static bool test_module_init_cleanup(void) {
    printf("Testing module initialization and cleanup...\n");
    
    // Initialize module
    int result = bn_tcp_module_init();
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Module initialization failed");
    
    // Cleanup module
    result = bn_tcp_module_cleanup();
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Module cleanup failed");
    
    // Re-initialize for subsequent tests
    result = bn_tcp_module_init();
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Module re-initialization failed");
    
    printf("  Module init/cleanup: OK\n");
    return true;
}

/**
 * Test context creation and destruction
 */
static bool test_context_create_destroy(void) {
    printf("Testing context creation and destruction...\n");
    
    bn_tcp_ctx_t *ctx = NULL;
    bn_tcp_config_t config;
    
    // Test with NULL parameters
    int result = bn_tcp_create(NULL, NULL);
    TEST_ASSERT(result == BN_TCP_ERROR_INVALID_PARAM, "Create with NULL parameters should fail");
    
    // Initialize default configuration
    result = bn_tcp_config_default(&config);
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Default config initialization failed");
    
    // Create context with valid config
    result = bn_tcp_create(&ctx, &config);
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Context creation failed");
    TEST_ASSERT(ctx != NULL, "Context pointer should not be NULL after creation");
    
    // Destroy context
    result = bn_tcp_destroy(ctx);
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Context destruction failed");
    
    // Test destroy with NULL parameter
    result = bn_tcp_destroy(NULL);
    TEST_ASSERT(result == BN_TCP_ERROR_INVALID_PARAM, "Destroy with NULL parameter should fail");
    
    printf("  Context creation/destruction: OK\n");
    return true;
}

/**
 * Test configuration functions
 */
static bool test_configuration(void) {
    printf("Testing configuration functions...\n");
    
    bn_tcp_config_t config;
    
    // Test default configuration initialization
    int result = bn_tcp_config_default(&config);
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Default config initialization failed");
    
    // Verify default values
    TEST_ASSERT(config.max_retries > 0, "Default max_retries should be positive");
    TEST_ASSERT(config.connect_timeout_ms > 0, "Default connect_timeout_ms should be positive");
    TEST_ASSERT(config.read_timeout_ms > 0, "Default read_timeout_ms should be positive");
    TEST_ASSERT(config.write_timeout_ms > 0, "Default write_timeout_ms should be positive");
    
    // Test with NULL parameter
    result = bn_tcp_config_default(NULL);
    TEST_ASSERT(result == BN_TCP_ERROR_INVALID_PARAM, "Config default with NULL parameter should fail");
    
    printf("  Configuration: OK\n");
    return true;
}

/**
 * Test error string function
 */
static bool test_error_string(void) {
    printf("Testing error string function...\n");
    
    // Test valid error codes
    const char *err_str = bn_tcp_error_string(BN_TCP_SUCCESS);
    TEST_ASSERT(err_str != NULL && strlen(err_str) > 0, "Error string for SUCCESS should not be empty");
    
    err_str = bn_tcp_error_string(BN_TCP_ERROR_INVALID_PARAM);
    TEST_ASSERT(err_str != NULL && strlen(err_str) > 0, "Error string for INVALID_PARAM should not be empty");
    
    // Test invalid error code
    err_str = bn_tcp_error_string(-100);  // Out of range
    TEST_ASSERT(err_str != NULL && strstr(err_str, "Unknown") != NULL, 
               "Error string for invalid code should indicate unknown error");
    
    printf("  Error string: OK\n");
    return true;
}

/**
 * Test basic connection functions
 */
static bool test_basic_connection(void) {
    printf("Testing basic connection functions...\n");
    
    bn_tcp_ctx_t *ctx = NULL;
    bn_tcp_config_t config;
    
    // Initialize default configuration
    int result = bn_tcp_config_default(&config);
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Default config initialization failed");
    
    // Create context
    result = bn_tcp_create(&ctx, &config);
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Context creation failed");
    
    // Test connect with NULL parameters
    result = bn_tcp_connect(NULL, "localhost", 443);
    TEST_ASSERT(result == BN_TCP_ERROR_INVALID_PARAM, "Connect with NULL context should fail");
    
    result = bn_tcp_connect(ctx, NULL, 443);
    TEST_ASSERT(result == BN_TCP_ERROR_INVALID_PARAM, "Connect with NULL host should fail");
    
    // Test send/recv with NULL context
    uint8_t buffer[128];
    size_t bytes;
    result = bn_tcp_send(NULL, (uint8_t*)"test", 4, &bytes);
    TEST_ASSERT(result == BN_TCP_ERROR_INVALID_PARAM, "Send with NULL context should fail");
    
    result = bn_tcp_recv(NULL, buffer, sizeof(buffer), &bytes);
    TEST_ASSERT(result == BN_TCP_ERROR_INVALID_PARAM, "Recv with NULL context should fail");
    
    // Test send/recv without connection
    result = bn_tcp_send(ctx, (uint8_t*)"test", 4, &bytes);
    TEST_ASSERT(result == BN_TCP_ERROR_CLOSED, "Send without connection should fail");
    
    result = bn_tcp_recv(ctx, buffer, sizeof(buffer), &bytes);
    TEST_ASSERT(result == BN_TCP_ERROR_CLOSED, "Recv without connection should fail");
    
    // Test close without connection
    result = bn_tcp_close(ctx);
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Close without connection should succeed");
    
    // Clean up
    result = bn_tcp_destroy(ctx);
    TEST_ASSERT(result == BN_TCP_SUCCESS, "Context destruction failed");
    
    printf("  Basic connection functions: OK\n");
    return true;
}

/**
 * Test anti-correlation functions
 */
static bool test_anti_correlation(void) {
    printf("Testing anti-correlation functions...\n");
    
    // Test cover connection with NULL parameters
    void* handle = bn_tcp_cover_connect(NULL, 443);
    TEST_ASSERT(handle == NULL, "Cover connect with NULL host should fail");
    
    // Test cover close with NULL handle
    int result = bn_tcp_cover_close(NULL);
    TEST_ASSERT(result == BN_TCP_ERROR_INVALID_PARAM, "Cover close with NULL handle should fail");
    
    printf("  Anti-correlation: OK\n");
    return true;
}

/**
 * Test live connection to TLS server
 */
static bool test_live_connection(void) {
    printf("Testing live connection to TLS server...\n");
    
    // Start test server
    if (!start_test_server()) {
        fprintf(stderr, "Failed to start test server, skipping live connection test\n");
        return true;  // Skip test instead of failing
    }
    
    bn_tcp_ctx_t *ctx = NULL;
    bn_tcp_config_t config;
    uint8_t buffer[128];
    size_t bytes;
    bool test_passed = true;
    
    // Initialize default configuration
    int result = bn_tcp_config_default(&config);
    if (result != BN_TCP_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Default config initialization failed: %s\n", 
                bn_tcp_error_string(result));
        goto cleanup;
    }
    
    // Set shorter timeouts for testing
    config.connect_timeout_ms = 2000;
    config.read_timeout_ms = 2000;
    config.write_timeout_ms = 2000;
    
    // Configure TLS to accept our test certificates
    config.verify_mode = BN_TCP_VERIFY_PEER;
    config.ca_cert_path = TEST_CA_CERT;
    
    // Create context
    result = bn_tcp_create(&ctx, &config);
    if (result != BN_TCP_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Context creation failed: %s\n", bn_tcp_error_string(result));
        goto cleanup;
    }
    
    // Connect to test server
    printf("  Connecting to localhost:%d...\n", TEST_SERVER_PORT);
    result = bn_tcp_connect(ctx, "localhost", TEST_SERVER_PORT);
    if (result != BN_TCP_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Connection failed: %s\n", bn_tcp_error_string(result));
        goto cleanup;
    }
    
    printf("  Connected successfully\n");
    
    // Send data to server
    printf("  Sending data: %s\n", g_client_message);
    result = bn_tcp_send(ctx, (uint8_t*)g_client_message, strlen(g_client_message), &bytes);
    if (result != BN_TCP_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Send failed: %s\n", bn_tcp_error_string(result));
        goto cleanup;
    }
    
    printf("  Sent %zu bytes\n", bytes);
    
    // Receive response
    result = bn_tcp_recv(ctx, buffer, sizeof(buffer) - 1, &bytes);
    if (result != BN_TCP_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Receive failed: %s\n", bn_tcp_error_string(result));
        goto cleanup;
    }
    
    buffer[bytes] = '\0';
    printf("  Received %zu bytes: %s\n", bytes, buffer);
    
    // Verify response
    if (strcmp((char*)buffer, g_server_message) != 0) {
        test_passed = false;
        fprintf(stderr, "Unexpected response: expected '%s', got '%s'\n", 
                g_server_message, buffer);
        goto cleanup;
    }
    
    // Close connection
    result = bn_tcp_close(ctx);
    if (result != BN_TCP_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Close failed: %s\n", bn_tcp_error_string(result));
        goto cleanup;
    }
    
cleanup:
    // Clean up
    if (ctx) {
        bn_tcp_destroy(ctx);
    }
    
    stop_test_server();
    
    if (test_passed) {
        printf("  Live connection: OK\n");
    } else {
        printf("  Live connection: FAILED\n");
    }
    
    return test_passed;
}

/**
 * Run all tests
 */
int main(void) {
    printf("===== TCP Transport Test Suite =====\n");
    
    bool all_passed = true;
    
    // Initialize module for all tests
    if (bn_tcp_module_init() != BN_TCP_SUCCESS) {
        fprintf(stderr, "FAIL: Module initialization failed, cannot run tests\n");
        return EXIT_FAILURE;
    }
    
    // Run tests
    all_passed &= test_module_init_cleanup();
    all_passed &= test_context_create_destroy();
    all_passed &= test_configuration();
    all_passed &= test_error_string();
    all_passed &= test_basic_connection();
    all_passed &= test_anti_correlation();
    all_passed &= test_live_connection();
    
    // Final cleanup
    bn_tcp_module_cleanup();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}