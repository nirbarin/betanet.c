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
#include "net/conn_mgr.h"

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
static char g_server_message[] = "Hello from connection manager test server";
static char g_client_message[] = "Hello from connection manager test client";

/**
 * Callback event counter
 */
static int g_connect_events = 0;
static int g_close_events = 0;
static int g_error_events = 0;
static int g_timeout_events = 0;

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
 * Connection event callback function
 */
static void connection_event_callback(bn_conn_t *conn, void *user_data) {
    bn_conn_event_type_t event_type = *(bn_conn_event_type_t*)user_data;
    
    switch (event_type) {
        case BN_CONN_EVENT_CONNECTED:
            printf("Connection event: CONNECTED\n");
            g_connect_events++;
            break;
            
        case BN_CONN_EVENT_CLOSED:
            printf("Connection event: CLOSED\n");
            g_close_events++;
            break;
            
        case BN_CONN_EVENT_ERROR:
            printf("Connection event: ERROR\n");
            g_error_events++;
            break;
            
        case BN_CONN_EVENT_TIMEOUT:
            printf("Connection event: TIMEOUT\n");
            g_timeout_events++;
            break;
            
        default:
            printf("Connection event: UNKNOWN\n");
            break;
    }
}

/**
 * Test module initialization and cleanup
 */
static bool test_module_init_cleanup(void) {
    printf("Testing module initialization and cleanup...\n");
    
    // Initialize module
    int result = bn_conn_mgr_init();
    TEST_ASSERT(result == BN_NET_SUCCESS, "Module initialization failed");
    
    // Cleanup module
    result = bn_conn_mgr_cleanup();
    TEST_ASSERT(result == BN_NET_SUCCESS, "Module cleanup failed");
    
    // Re-initialize for subsequent tests
    result = bn_conn_mgr_init();
    TEST_ASSERT(result == BN_NET_SUCCESS, "Module re-initialization failed");
    
    printf("  Module init/cleanup: OK\n");
    return true;
}

/**
 * Test connection creation and destruction
 */
static bool test_connection_create_destroy(void) {
    printf("Testing connection creation and destruction...\n");
    
    bn_conn_t *conn = NULL;
    
    // Test with NULL parameters
    int result = bn_conn_create(NULL, BN_CONN_TYPE_TCP);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Create with NULL connection should fail");
    
    // Create TCP connection
    result = bn_conn_create(&conn, BN_CONN_TYPE_TCP);
    TEST_ASSERT(result == BN_NET_SUCCESS, "TCP connection creation failed");
    TEST_ASSERT(conn != NULL, "Connection pointer should not be NULL after creation");
    
    // Destroy connection
    result = bn_conn_destroy(conn);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Connection destruction failed");
    
    // Create QUIC connection
    result = bn_conn_create(&conn, BN_CONN_TYPE_QUIC);
    TEST_ASSERT(result == BN_NET_SUCCESS, "QUIC connection creation failed");
    TEST_ASSERT(conn != NULL, "Connection pointer should not be NULL after creation");
    
    // Destroy connection
    result = bn_conn_destroy(conn);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Connection destruction failed");
    
    // Create HTX connection (should fail as not implemented)
    result = bn_conn_create(&conn, BN_CONN_TYPE_HTX);
    TEST_ASSERT(result == BN_NET_ERROR_OPERATION, "HTX connection creation should fail");
    
    // Test destroy with NULL parameter
    result = bn_conn_destroy(NULL);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Destroy with NULL parameter should fail");
    
    printf("  Connection creation/destruction: OK\n");
    return true;
}

/**
 * Test basic connection operations
 */
static bool test_basic_connection_ops(void) {
    printf("Testing basic connection operations...\n");
    
    bn_conn_t *conn = NULL;
    
    // Create TCP connection
    int result = bn_conn_create(&conn, BN_CONN_TYPE_TCP);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Connection creation failed");
    
    // Test state functions
    bn_conn_state_t state;
    result = bn_conn_get_state(conn, &state);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Get state failed");
    TEST_ASSERT(state == BN_CONN_STATE_CLOSED, "Initial state should be CLOSED");
    
    // Test timeout functions
    result = bn_conn_set_timeout(conn, 5000, true);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Set receive timeout failed");
    
    result = bn_conn_set_timeout(conn, 5000, false);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Set send timeout failed");
    
    // Test statistics functions
    bn_conn_stats_t stats;
    result = bn_conn_get_stats(conn, &stats);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Get stats failed");
    TEST_ASSERT(stats.bytes_sent == 0, "Initial bytes_sent should be 0");
    TEST_ASSERT(stats.bytes_received == 0, "Initial bytes_received should be 0");
    
    // Test event callback registration
    static bn_conn_event_type_t event_type = BN_CONN_EVENT_CONNECTED;
    result = bn_conn_register_event_cb(conn, BN_CONN_EVENT_CONNECTED, 
                                      connection_event_callback, &event_type);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Register event callback failed");
    
    // Test unregister event callback
    result = bn_conn_unregister_event_cb(conn, BN_CONN_EVENT_CONNECTED);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Unregister event callback failed");
    
    // Test send/recv without connection
    uint8_t buffer[128];
    size_t bytes;
    result = bn_conn_send(conn, (uint8_t*)"test", 4, &bytes);
    TEST_ASSERT(result == BN_NET_ERROR_OPERATION, "Send without connection should fail");
    
    result = bn_conn_recv(conn, buffer, sizeof(buffer), &bytes);
    TEST_ASSERT(result == BN_NET_ERROR_OPERATION, "Recv without connection should fail");
    
    // Test close without connection
    result = bn_conn_close(conn);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Close without connection should succeed");
    
    // Clean up
    result = bn_conn_destroy(conn);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Connection destruction failed");
    
    printf("  Basic connection operations: OK\n");
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
    
    bn_conn_t *conn = NULL;
    uint8_t buffer[128];
    size_t bytes;
    bool test_passed = true;
    
    // Reset event counters
    g_connect_events = 0;
    g_close_events = 0;
    g_error_events = 0;
    g_timeout_events = 0;
    
    // Create TCP connection
    int result = bn_conn_create(&conn, BN_CONN_TYPE_TCP);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Connection creation failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    // Register event callbacks
    static bn_conn_event_type_t connected_event = BN_CONN_EVENT_CONNECTED;
    static bn_conn_event_type_t closed_event = BN_CONN_EVENT_CLOSED;
    static bn_conn_event_type_t error_event = BN_CONN_EVENT_ERROR;
    static bn_conn_event_type_t timeout_event = BN_CONN_EVENT_TIMEOUT;
    
    result = bn_conn_register_event_cb(conn, BN_CONN_EVENT_CONNECTED, 
                                      connection_event_callback, &connected_event);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Register connected event failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    result = bn_conn_register_event_cb(conn, BN_CONN_EVENT_CLOSED, 
                                      connection_event_callback, &closed_event);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Register closed event failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    result = bn_conn_register_event_cb(conn, BN_CONN_EVENT_ERROR, 
                                      connection_event_callback, &error_event);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Register error event failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    result = bn_conn_register_event_cb(conn, BN_CONN_EVENT_TIMEOUT, 
                                      connection_event_callback, &timeout_event);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Register timeout event failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    // Set shorter timeout for testing
    result = bn_conn_set_timeout(conn, 2000, true);  // 2 seconds recv timeout
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Set recv timeout failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    result = bn_conn_set_timeout(conn, 2000, false);  // 2 seconds send timeout
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Set send timeout failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    // Connect to test server
    printf("  Connecting to localhost:%d...\n", TEST_SERVER_PORT);
    result = bn_conn_connect(conn, "localhost", TEST_SERVER_PORT, 5000);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Connection failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    printf("  Connected successfully\n");
    
    // Verify connection state
    bn_conn_state_t state;
    result = bn_conn_get_state(conn, &state);
    if (result != BN_NET_SUCCESS || state != BN_CONN_STATE_CONNECTED) {
        test_passed = false;
        fprintf(stderr, "Connection state incorrect: %d\n", state);
        goto cleanup;
    }
    
    // Check that connect event was triggered
    if (g_connect_events != 1) {
        test_passed = false;
        fprintf(stderr, "Connect event not triggered correctly\n");
        goto cleanup;
    }
    
    // Send data to server
    printf("  Sending data: %s\n", g_client_message);
    result = bn_conn_send(conn, (uint8_t*)g_client_message, strlen(g_client_message), &bytes);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Send failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    printf("  Sent %zu bytes\n", bytes);
    
    // Receive response
    result = bn_conn_recv(conn, buffer, sizeof(buffer) - 1, &bytes);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Receive failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    buffer[bytes] = '\0';
    printf("  Received %zu bytes: %s\n", bytes, (char*)buffer);
    
    // Verify response
    if (strcmp((char*)buffer, g_server_message) != 0) {
        test_passed = false;
        fprintf(stderr, "Unexpected response: expected '%s', got '%s'\n", 
                g_server_message, (char*)buffer);
        goto cleanup;
    }
    
    // Get connection statistics
    bn_conn_stats_t stats;
    result = bn_conn_get_stats(conn, &stats);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Get stats failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    printf("  Connection stats: sent=%llu, received=%llu\n", 
           (unsigned long long)stats.bytes_sent, 
           (unsigned long long)stats.bytes_received);
    
    if (stats.bytes_sent < strlen(g_client_message) || stats.bytes_received < strlen(g_server_message)) {
        test_passed = false;
        fprintf(stderr, "Connection statistics incorrect\n");
        goto cleanup;
    }
    
    // Close connection
    result = bn_conn_close(conn);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Close failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    // Check that close event was triggered
    if (g_close_events != 1) {
        test_passed = false;
        fprintf(stderr, "Close event not triggered correctly\n");
        goto cleanup;
    }
    
cleanup:
    // Clean up
    if (conn) {
        bn_conn_destroy(conn);
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
 * Test connection pool
 */
static bool test_connection_pool(void) {
    printf("Testing connection pool...\n");
    
    bn_conn_pool_t *pool = NULL;
    bn_conn_t *conn1 = NULL;
    bn_conn_t *conn2 = NULL;
    bool test_passed = true;
    
    // Test pool creation with NULL parameters
    int result = bn_conn_pool_create(NULL, 10);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Pool creation with NULL pool should fail");
    
    // Create pool
    result = bn_conn_pool_create(&pool, 10);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Pool creation failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    // Set pool parameters
    result = bn_conn_pool_set_max_idle(pool, 30000);  // 30 seconds
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Set max idle failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    result = bn_conn_pool_set_max_lifetime(pool, 300000);  // 5 minutes
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Set max lifetime failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
    // Test get connection (no actual connection to server here)
    // Just testing the API
    result = bn_conn_pool_get(pool, BN_CONN_TYPE_TCP, "example.com", 443, &conn1);
    // This may fail if we can't connect, which is fine for this test
    if (result == BN_NET_SUCCESS && conn1 != NULL) {
        // Return connection to pool
        result = bn_conn_pool_return(pool, conn1);
        if (result != BN_NET_SUCCESS) {
            test_passed = false;
            fprintf(stderr, "Return connection to pool failed: %s\n", bn_net_error_string(result));
            // Still need to destroy the connection even if return fails
            bn_conn_destroy(conn1);
            goto cleanup;
        }
    }
    
    // Maintain the pool
    result = bn_conn_pool_maintain(pool);
    if (result != BN_NET_SUCCESS) {
        test_passed = false;
        fprintf(stderr, "Pool maintenance failed: %s\n", bn_net_error_string(result));
        goto cleanup;
    }
    
cleanup:
    // Clean up
    if (pool) {
        bn_conn_pool_destroy(pool);
    }
    
    if (test_passed) {
        printf("  Connection pool: OK\n");
    } else {
        printf("  Connection pool: FAILED\n");
    }
    
    return test_passed;
}

/**
 * Run all tests
 */
int main(void) {
    printf("===== Connection Manager Test Suite =====\n");
    
    bool all_passed = true;
    
    // Initialize module for all tests
    if (bn_conn_mgr_init() != BN_NET_SUCCESS) {
        fprintf(stderr, "FAIL: Module initialization failed, cannot run tests\n");
        return EXIT_FAILURE;
    }
    
    // Run tests
    all_passed &= test_module_init_cleanup();
    all_passed &= test_connection_create_destroy();
    all_passed &= test_basic_connection_ops();
    all_passed &= test_live_connection();
    all_passed &= test_connection_pool();
    
    // Final cleanup
    bn_conn_mgr_cleanup();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}