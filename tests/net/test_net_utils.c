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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "net/net_utils.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (Line %d)\n", message, __LINE__); \
            return false; \
        } \
    } while (0)

/**
 * Test address resolution
 */
static bool test_address_resolution(void) {
    printf("Testing address resolution...\n");
    
    bn_net_addr_t addr;
    
    // Test with NULL parameters
    int result = bn_net_resolve_addr(NULL, 80, &addr, true);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Resolution with NULL hostname should fail");
    
    result = bn_net_resolve_addr("example.com", 80, NULL, true);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Resolution with NULL address should fail");
    
    // Test with localhost
    result = bn_net_resolve_addr("localhost", 8080, &addr, true);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Resolution of localhost failed");
    TEST_ASSERT(addr.port == 8080, "Port in resolved address doesn't match");
    
    // Test with IP address directly
    result = bn_net_resolve_addr("127.0.0.1", 443, &addr, false);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Resolution of 127.0.0.1 failed");
    TEST_ASSERT(addr.family == AF_INET, "Address family should be AF_INET");
    TEST_ASSERT(addr.port == 443, "Port in resolved address doesn't match");
    TEST_ASSERT(strcmp(addr.ip_str, "127.0.0.1") == 0, "IP string doesn't match");
    
    // Test with IPv6 address if IPv6 is enabled
    result = bn_net_resolve_addr("::1", 443, &addr, true);
    if (result == BN_NET_SUCCESS) {
        TEST_ASSERT(addr.family == AF_INET6, "Address family should be AF_INET6");
        TEST_ASSERT(addr.port == 443, "Port in resolved address doesn't match");
        TEST_ASSERT(strcmp(addr.ip_str, "::1") == 0, "IP string doesn't match");
    } else {
        // IPv6 may not be available, that's okay
        printf("  Note: IPv6 resolution not available, skipping IPv6 test\n");
    }
    
    printf("  Address resolution: OK\n");
    return true;
}

/**
 * Test socket creation and options
 */
static bool test_socket_creation(void) {
    printf("Testing socket creation and options...\n");
    
    bn_net_socket_options_t options;
    int sock = -1;
    
    // Test options initialization
    int result = bn_net_socket_options_init(NULL);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Options init with NULL should fail");
    
    result = bn_net_socket_options_init(&options);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Options initialization failed");
    
    // Test socket creation with NULL options
    result = bn_net_create_socket(AF_INET, SOCK_STREAM, 0, NULL, &sock);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Socket creation with NULL options failed");
    TEST_ASSERT(sock >= 0, "Socket descriptor should be valid");
    close(sock);
    sock = -1;
    
    // Test socket creation with custom options
    options.tcp_nodelay = true;
    options.keep_alive = true;
    options.reuse_addr = true;
    options.non_blocking = true;
    
    result = bn_net_create_socket(AF_INET, SOCK_STREAM, 0, &options, &sock);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Socket creation with custom options failed");
    TEST_ASSERT(sock >= 0, "Socket descriptor should be valid");
    
    // Test applying options to existing socket
    result = bn_net_apply_socket_options(sock, &options);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Applying socket options failed");
    
    // Test setting socket timeout
    result = bn_net_set_socket_timeout(sock, 1000, true);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Setting receive timeout failed");
    
    result = bn_net_set_socket_timeout(sock, 1000, false);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Setting send timeout failed");
    
    // Test setting non-blocking mode
    result = bn_net_set_nonblocking(sock, true);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Setting non-blocking mode failed");
    
    result = bn_net_set_nonblocking(sock, false);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Setting blocking mode failed");
    
    // Test socket readability check
    bool readable = false;
    result = bn_net_is_socket_readable(sock, 0, &readable);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Socket readability check failed");
    
    // Test socket writability check
    bool writable = false;
    result = bn_net_is_socket_writable(sock, 0, &writable);
    TEST_ASSERT(result == BN_NET_SUCCESS, "Socket writability check failed");
    
    // Clean up
    close(sock);
    
    printf("  Socket creation and options: OK\n");
    return true;
}

/**
 * Test IP address checking
 */
static bool test_ip_address_check(void) {
    printf("Testing IP address checking...\n");
    
    // Test IPv4 addresses
    TEST_ASSERT(bn_net_is_ip_address("127.0.0.1") == true, "127.0.0.1 should be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("192.168.1.1") == true, "192.168.1.1 should be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("8.8.8.8") == true, "8.8.8.8 should be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("255.255.255.255") == true, "255.255.255.255 should be recognized as an IP");
    
    // Test IPv6 addresses
    TEST_ASSERT(bn_net_is_ip_address("::1") == true, "::1 should be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("2001:db8::1") == true, "2001:db8::1 should be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("fe80::1") == true, "fe80::1 should be recognized as an IP");
    
    // Test invalid IP addresses
    TEST_ASSERT(bn_net_is_ip_address("localhost") == false, "localhost should not be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("example.com") == false, "example.com should not be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("256.256.256.256") == false, "256.256.256.256 should not be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("1.2.3") == false, "1.2.3 should not be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address("") == false, "Empty string should not be recognized as an IP");
    TEST_ASSERT(bn_net_is_ip_address(NULL) == false, "NULL should not be recognized as an IP");
    
    printf("  IP address checking: OK\n");
    return true;
}

/**
 * Test address to string conversion
 */
static bool test_addr_to_string(void) {
    printf("Testing address to string conversion...\n");
    
    struct sockaddr_in ipv4_addr;
    struct sockaddr_in6 ipv6_addr;
    char buffer[128];
    
    // Setup IPv4 address
    memset(&ipv4_addr, 0, sizeof(ipv4_addr));
    ipv4_addr.sin_family = AF_INET;
    ipv4_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "192.168.1.1", &ipv4_addr.sin_addr);
    
    // Test IPv4 address conversion
    int result = bn_net_addr_to_string((struct sockaddr*)&ipv4_addr, sizeof(ipv4_addr), buffer, sizeof(buffer), false);
    TEST_ASSERT(result == BN_NET_SUCCESS, "IPv4 address conversion failed");
    TEST_ASSERT(strcmp(buffer, "192.168.1.1") == 0, "IPv4 address string doesn't match");
    
    // Test IPv4 address conversion with port
    result = bn_net_addr_to_string((struct sockaddr*)&ipv4_addr, sizeof(ipv4_addr), buffer, sizeof(buffer), true);
    TEST_ASSERT(result == BN_NET_SUCCESS, "IPv4 address with port conversion failed");
    TEST_ASSERT(strcmp(buffer, "192.168.1.1:8080") == 0, "IPv4 address with port string doesn't match");
    
    // Setup IPv6 address
    memset(&ipv6_addr, 0, sizeof(ipv6_addr));
    ipv6_addr.sin6_family = AF_INET6;
    ipv6_addr.sin6_port = htons(443);
    inet_pton(AF_INET6, "2001:db8::1", &ipv6_addr.sin6_addr);
    
    // Test IPv6 address conversion
    result = bn_net_addr_to_string((struct sockaddr*)&ipv6_addr, sizeof(ipv6_addr), buffer, sizeof(buffer), false);
    TEST_ASSERT(result == BN_NET_SUCCESS, "IPv6 address conversion failed");
    TEST_ASSERT(strcmp(buffer, "2001:db8::1") == 0, "IPv6 address string doesn't match");
    
    // Test IPv6 address conversion with port
    result = bn_net_addr_to_string((struct sockaddr*)&ipv6_addr, sizeof(ipv6_addr), buffer, sizeof(buffer), true);
    TEST_ASSERT(result == BN_NET_SUCCESS, "IPv6 address with port conversion failed");
    TEST_ASSERT(strcmp(buffer, "[2001:db8::1]:443") == 0, "IPv6 address with port string doesn't match");
    
    // Test with NULL parameters
    result = bn_net_addr_to_string(NULL, 0, buffer, sizeof(buffer), false);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Address to string with NULL address should fail");
    
    result = bn_net_addr_to_string((struct sockaddr*)&ipv4_addr, sizeof(ipv4_addr), NULL, 0, false);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Address to string with NULL buffer should fail");
    
    printf("  Address to string conversion: OK\n");
    return true;
}

/**
 * Test random functions
 */
static bool test_random_functions(void) {
    printf("Testing random functions...\n");
    
    // Test random bytes generation
    uint8_t buffer[16];
    int result = bn_net_random_bytes(buffer, sizeof(buffer));
    TEST_ASSERT(result == BN_NET_SUCCESS, "Random bytes generation failed");
    
    // Test with NULL parameters
    result = bn_net_random_bytes(NULL, 16);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Random bytes with NULL buffer should fail");
    
    result = bn_net_random_bytes(buffer, 0);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Random bytes with zero length should fail");
    
    // Test random integer generation
    int min = 10, max = 20;
    for (int i = 0; i < 100; i++) {
        int rand_val = bn_net_random_int(min, max);
        TEST_ASSERT(rand_val >= min && rand_val <= max, "Random integer out of range");
    }
    
    // Test with min > max (should return min)
    int rand_val = bn_net_random_int(20, 10);
    TEST_ASSERT(rand_val == 20, "Random integer with min > max should return min");
    
    printf("  Random functions: OK\n");
    return true;
}

/**
 * Test error handling functions
 */
static bool test_error_handling(void) {
    printf("Testing error handling functions...\n");
    
    // Test error string function
    const char *err_str = bn_net_error_string(BN_NET_SUCCESS);
    TEST_ASSERT(err_str != NULL && strlen(err_str) > 0, "Error string for SUCCESS should not be empty");
    
    err_str = bn_net_error_string(BN_NET_ERROR_INVALID_PARAM);
    TEST_ASSERT(err_str != NULL && strlen(err_str) > 0, "Error string for INVALID_PARAM should not be empty");
    
    // Test with invalid error code
    err_str = bn_net_error_string(-100);  // Out of range
    TEST_ASSERT(err_str != NULL && strstr(err_str, "Unknown") != NULL, 
               "Error string for invalid code should indicate unknown error");
    
    // Test last error string function
    char error_buffer[256];
    int result = bn_net_get_last_error_string(error_buffer, sizeof(error_buffer));
    TEST_ASSERT(result == BN_NET_SUCCESS, "Getting last error string failed");
    
    // Test with NULL parameters
    result = bn_net_get_last_error_string(NULL, 0);
    TEST_ASSERT(result == BN_NET_ERROR_INVALID_PARAM, "Last error string with NULL buffer should fail");
    
    printf("  Error handling functions: OK\n");
    return true;
}

/**
 * Run all tests
 */
int main(void) {
    printf("===== Network Utilities Test Suite =====\n");
    
    bool all_passed = true;
    
    // Run tests
    all_passed &= test_address_resolution();
    all_passed &= test_socket_creation();
    all_passed &= test_ip_address_check();
    all_passed &= test_addr_to_string();
    all_passed &= test_random_functions();
    all_passed &= test_error_handling();
    
    if (all_passed) {
        printf("===== All tests PASSED =====\n");
        return EXIT_SUCCESS;
    } else {
        printf("===== Some tests FAILED =====\n");
        return EXIT_FAILURE;
    }
}