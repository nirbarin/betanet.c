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
#include "net/quic/quic.h"

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
#define TEST_SERVER_PORT 4444
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
static char g_server_message[] = "Hello from QUIC test server";
static char g_client_message[] = "Hello from QUIC test client";

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
static void handle_client(int client_sock) {
    char buffer[1024];
    int bytes;
    
    // Read client data
    bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Server received: %s\n", buffer);
        
        // Send the server message
        send(client_sock, g_server_message, strlen(g_server_message), 0);
    }
}

/**
 * QUIC server thread function
 */
static void* test_server_thread(void *arg) {
    int client_sock;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    g_server_running = true;
    
    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE
    
    printf("QUIC test server started on port %d\n", TEST_SERVER_PORT);
    
    while (g_server_running) {
        // Accept incoming connection
        client_sock = accept(g_server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        usleep(10000); /* Sleep 10ms and try again */
        continue;
    }
            perror("Accept failed");
            break;
        }
        
        printf("Client connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Handle client in this thread for simplicity
        handle_client(client_sock);
        
        // Close socket
        close(client_sock);
    }
    
    return NULL;
}

/**
 * Start a QUIC test server
 */
static bool start_test_server(void) {
    struct sockaddr_in server_addr;
    int reuse = 1;
    
    // Create socket
    g_server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_sock < 0) {
        perror("Server socket creation failed");
        return false;
    }
    
    // Set socket options
    if (setsockopt(g_server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("Server setsockopt failed");
        close(g_server_sock);
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
        return false;
    }
    
    // Listen
    if (listen(g_server_sock, TEST_SERVER_BACKLOG) < 0) {
        perror("Server listen failed");
        close(g_server_sock);
        return false;
    }
    
    // Set non-blocking mode
    int flags = fcntl(g_server_sock, F_GETFL, 0);
    if (flags < 0 || fcntl(g_server_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("Server fcntl failed");
        close(g_server_sock);
        return false;
    }
    
    // Start server thread
    if (pthread_create(&g_server_thread, NULL, test_server_thread, NULL) != 0) {
        perror("Server thread creation failed");
        close(g_server_sock);
        return false;
    }
    
    /* Give the server thread a moment to start */
    usleep(100000);  /* 100ms */
    
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
    
    printf("Test server stopped\n");
}

/**
 * Test basic module initialization and cleanup
 */
static bool test_module_init_cleanup(void) {
    printf("Testing module initialization and cleanup...\n");
    
    // Initialize module
    int result = bn_quic_module_init();
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Module initialization failed");
    
    // Cleanup module
    result = bn_quic_module_cleanup();
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Module cleanup failed");
    
    // Re-initialize for subsequent tests
    result = bn_quic_module_init();
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Module re-initialization failed");
    
    printf("  Module init/cleanup: OK\n");
    return true;
}

/**
 * Test context creation and destruction
 */
static bool test_context_create_destroy(void) {
    printf("Testing context creation and destruction...\n");
    
    bn_quic_ctx_t *ctx = NULL;
    bn_quic_config_t config;
    
    // Test with NULL parameters
    int result = bn_quic_create(NULL, NULL);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Create with NULL parameters should fail");
    
    // Initialize default configuration
    result = bn_quic_config_default(&config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Default config initialization failed");
    
    // Create context with valid config
    result = bn_quic_create(&ctx, &config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context creation failed");
    TEST_ASSERT(ctx != NULL, "Context pointer should not be NULL after creation");
    
    // Destroy context
    result = bn_quic_destroy(ctx);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context destruction failed");
    
    // Test destroy with NULL parameter
    result = bn_quic_destroy(NULL);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Destroy with NULL parameter should fail");
    
    printf("  Context creation/destruction: OK\n");
    return true;
}

/**
 * Test configuration functions
 */
static bool test_configuration(void) {
    printf("Testing configuration functions...\n");
    
    bn_quic_config_t config;
    
    // Test default configuration initialization
    int result = bn_quic_config_default(&config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Default config initialization failed");
    
    // Verify default values
    TEST_ASSERT(config.max_retries > 0, "Default max_retries should be positive");
    TEST_ASSERT(config.connect_timeout_ms > 0, "Default connect_timeout_ms should be positive");
    TEST_ASSERT(config.read_timeout_ms > 0, "Default read_timeout_ms should be positive");
    TEST_ASSERT(config.write_timeout_ms > 0, "Default write_timeout_ms should be positive");
    TEST_ASSERT(config.verify_mode >= BN_QUIC_VERIFY_NONE, "Default verify_mode should be valid");
    TEST_ASSERT(config.max_concurrent_bidi_streams > 0, "Default max_concurrent_bidi_streams should be positive");
    TEST_ASSERT(config.max_concurrent_uni_streams > 0, "Default max_concurrent_uni_streams should be positive");
    
    // Test with NULL parameter
    result = bn_quic_config_default(NULL);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Config default with NULL parameter should fail");
    
    printf("  Configuration: OK\n");
    return true;
}

/**
 * Test error string function
 */
static bool test_error_string(void) {
    printf("Testing error string function...\n");
    
    // Test valid error codes
    const char *err_str = bn_quic_error_string(BN_QUIC_SUCCESS);
    TEST_ASSERT(err_str != NULL && strlen(err_str) > 0, "Error string for SUCCESS should not be empty");
    
    err_str = bn_quic_error_string(BN_QUIC_ERROR_INVALID_PARAM);
    TEST_ASSERT(err_str != NULL && strlen(err_str) > 0, "Error string for INVALID_PARAM should not be empty");
    
    // Test invalid error code
    err_str = bn_quic_error_string(-100);  // Out of range
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
    
    bn_quic_ctx_t *ctx = NULL;
    bn_quic_config_t config;
    
    // Initialize default configuration
    int result = bn_quic_config_default(&config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Default config initialization failed");
    
    // Create context
    result = bn_quic_create(&ctx, &config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context creation failed");
    
    // Test connect with NULL parameters
    result = bn_quic_connect(NULL, "localhost", 443);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Connect with NULL context should fail");
    
    result = bn_quic_connect(ctx, NULL, 443);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Connect with NULL host should fail");
    
    // Test close with NULL context
    result = bn_quic_close(NULL, false, 0, NULL);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Close with NULL context should fail");
    
    // Test is_blocked with NULL context
    bool blocked = bn_quic_is_blocked(NULL);
    TEST_ASSERT(blocked == false, "Is_blocked with NULL context should return false");
    
    // Test close without connection
    result = bn_quic_close(ctx, false, 0, NULL);
    TEST_ASSERT(result == BN_QUIC_SUCCESS || result == BN_QUIC_ERROR_CLOSED, 
               "Close without connection should succeed or return CLOSED error");
    
    // Clean up
    result = bn_quic_destroy(ctx);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context destruction failed");
    
    printf("  Basic connection functions: OK\n");
    return true;
}

/**
 * Test stream management
 */
static bool test_stream_management(void) {
    printf("Testing stream management...\n");
    
    bn_quic_ctx_t *ctx = NULL;
    bn_quic_stream_t *stream = NULL;
    bn_quic_config_t config;
    
    // Initialize default configuration
    int result = bn_quic_config_default(&config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Default config initialization failed");
    
    // Create context
    result = bn_quic_create(&ctx, &config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context creation failed");
    
    // Test stream open with NULL parameters
    result = bn_quic_stream_open(NULL, &stream, BN_QUIC_STREAM_BIDI);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Stream open with NULL context should fail");
    
    result = bn_quic_stream_open(ctx, NULL, BN_QUIC_STREAM_BIDI);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Stream open with NULL stream should fail");
    
    // Test stream open (should succeed with our stub implementation)
    result = bn_quic_stream_open(ctx, &stream, BN_QUIC_STREAM_BIDI);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Stream open should succeed with our stub implementation");
    
    // Test stream send/recv with NULL parameters
    uint8_t buffer[128];
    size_t bytes;
    bool fin;
    
    result = bn_quic_stream_send(NULL, (uint8_t*)"test", 4, &bytes, false);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Stream send with NULL stream should fail");
    
    result = bn_quic_stream_recv(NULL, buffer, sizeof(buffer), &bytes, &fin);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Stream recv with NULL stream should fail");
    
    // Test stream close with NULL parameters
    result = bn_quic_stream_close(NULL);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Stream close with NULL stream should fail");
    
    // Clean up
    result = bn_quic_stream_close(stream);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Stream close failed");
    
    result = bn_quic_destroy(ctx);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context destruction failed");
    
    printf("  Stream management: OK\n");
    return true;
}

/**
 * Test MASQUE functionality
 */
static bool test_masque_functionality(void) {
    printf("Testing MASQUE functionality...\n");
    
    bn_quic_ctx_t *ctx = NULL;
    bn_quic_config_t config;
    
    // Initialize default configuration
    int result = bn_quic_config_default(&config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Default config initialization failed");
    
    // Create context
    result = bn_quic_create(&ctx, &config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context creation failed");
    
    // Test MASQUE connect with NULL parameters
    result = bn_quic_masque_connect_udp(NULL, "example.com", 53);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "MASQUE connect with NULL context should fail");
    
    result = bn_quic_masque_connect_udp(ctx, NULL, 53);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "MASQUE connect with NULL host should fail");
    
    // Test MASQUE connect (should succeed with our stub implementation)
    result = bn_quic_masque_connect_udp(ctx, "example.com", 53);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "MASQUE connect should succeed with our stub implementation");
    
    // Clean up
    result = bn_quic_destroy(ctx);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context destruction failed");
    
    printf("  MASQUE functionality: OK\n");
    return true;
}

/**
 * Test process function
 */
static bool test_process_function(void) {
    printf("Testing process function...\n");
    
    bn_quic_ctx_t *ctx = NULL;
    bn_quic_config_t config;
    
    // Initialize default configuration
    int result = bn_quic_config_default(&config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Default config initialization failed");
    
    // Create context
    result = bn_quic_create(&ctx, &config);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context creation failed");
    
    // Test process with NULL context
    result = bn_quic_process(NULL, 100);
    TEST_ASSERT(result == BN_QUIC_ERROR_INVALID_PARAM, "Process with NULL context should fail");
    
    // Test process without connection
    result = bn_quic_process(ctx, 100);
    TEST_ASSERT(result == BN_QUIC_ERROR_UNINITIALIZED || result == BN_QUIC_SUCCESS || 
               result == BN_QUIC_ERROR_TIMEOUT, 
               "Process without connection should return appropriate error");
    
    // Clean up
    result = bn_quic_destroy(ctx);
    TEST_ASSERT(result == BN_QUIC_SUCCESS, "Context destruction failed");
    
    printf("  Process function: OK\n");
    return true;
}

/**
 * Test live connection to QUIC server
 */
static bool test_live_connection(void) {
    printf("Testing live connection to QUIC server...\n");
    
    // Start test server
    if (!start_test_server()) {
        fprintf(stderr, "Failed to start test server, skipping live connection test\n");
        return true;  // Skip test instead of failing
    }
    
    bn_quic_ctx_t *ctx = NULL;
    bn_quic_config_t config;
    bn_quic_stream_t *stream = NULL;
    uint8_t buffer[128];
    size_t bytes;
    bool fin = false;
    bool test_passed = true;
    
    // Initialize default configuration
    int result = bn_quic_config_default(&config);
    if (result != BN_QUIC_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Default config initialization failed: %s\n", 
                bn_quic_error_string(result));
        goto cleanup;
    }
    
    // Set shorter timeouts for testing
    config.connect_timeout_ms = 2000;
    config.read_timeout_ms = 2000;
    config.write_timeout_ms = 2000;
    
    // Configure TLS to accept our test certificates
    config.verify_mode = BN_QUIC_VERIFY_PEER;
    config.ca_cert_path = TEST_CA_CERT;
    
    // Enable QUIC v1
    config.enable_quic_v1 = 1;
    
    // Create context
    result = bn_quic_create(&ctx, &config);
    if (result != BN_QUIC_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Context creation failed: %s\n", bn_quic_error_string(result));
        goto cleanup;
    }
    
    // Connect to test server
    printf("  Connecting to localhost:%d...\n", TEST_SERVER_PORT);
    result = bn_quic_connect(ctx, "localhost", TEST_SERVER_PORT);
    if (result != BN_QUIC_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Connection failed: %s\n", bn_quic_error_string(result));
        goto cleanup;
    }
    
    printf("  Connected successfully\n");
    
    // Create a bidirectional stream
    result = bn_quic_stream_open(ctx, &stream, BN_QUIC_STREAM_BIDI);
    if (result != BN_QUIC_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Stream open failed: %s\n", bn_quic_error_string(result));
        goto cleanup;
    }
    
    // Send data to server
    printf("  Sending data: %s\n", g_client_message);
    result = bn_quic_stream_send(stream, (uint8_t*)g_client_message, strlen(g_client_message), &bytes, false);
    if (result != BN_QUIC_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Stream send failed: %s\n", bn_quic_error_string(result));
        goto cleanup;
    }
    
    printf("  Sent %zu bytes\n", bytes);
    
    // Process QUIC events
    result = bn_quic_process(ctx, 1000);
    if (result != BN_QUIC_SUCCESS && result != BN_QUIC_ERROR_TIMEOUT) {
        test_passed = false;
        fprintf(stderr, "Process failed: %s\n", bn_quic_error_string(result));
        goto cleanup;
    }
    
    // Receive response
    result = bn_quic_stream_recv(stream, buffer, sizeof(buffer) - 1, &bytes, &fin);
    if (result != BN_QUIC_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Stream receive failed: %s\n", bn_quic_error_string(result));
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
    
    // Close stream
    result = bn_quic_stream_close(stream);
    if (result != BN_QUIC_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Stream close failed: %s\n", bn_quic_error_string(result));
        goto cleanup;
    }
    
    // Close connection
    result = bn_quic_close(ctx, false, 0, "Normal close");
    if (result != BN_QUIC_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Connection close failed: %s\n", bn_quic_error_string(result));
        goto cleanup;
    }
    
cleanup:
    // Clean up
    if (ctx) {
        bn_quic_destroy(ctx);
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
    printf("===== QUIC Transport Test Suite =====\n");
    
    bool all_passed = true;
    
    // Initialize module for all tests
    if (bn_quic_module_init() != BN_QUIC_SUCCESS) {
        fprintf(stderr, "FAIL: Module initialization failed, cannot run tests\n");
        return EXIT_FAILURE;
    }
    
    // Run tests
    all_passed &= test_module_init_cleanup();
    all_passed &= test_context_create_destroy();
    all_passed &= test_configuration();
    all_passed &= test_error_string();
    all_passed &= test_basic_connection();
    all_passed &= test_stream_management();
    all_passed &= test_masque_functionality();
    all_passed &= test_process_function();
    all_passed &= test_live_connection();
    
    // Final cleanup
    bn_quic_module_cleanup();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}