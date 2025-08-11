/**
 * @file net_utils.h
 * @brief Network utility functions for Betanet
 * 
 * This module provides common utility functions for network operations,
 * including address resolution, socket configuration, and error handling.
 */

#ifndef BETANET_NET_UTILS_H_
#define BETANET_NET_UTILS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * @brief Error codes for network utility functions
 */
typedef enum {
    BN_NET_SUCCESS = 0,
    BN_NET_ERROR_INVALID_PARAM = -1,
    BN_NET_ERROR_MEMORY = -2,
    BN_NET_ERROR_RESOLUTION = -3,
    BN_NET_ERROR_SOCKET = -4,
    BN_NET_ERROR_CONNECTION = -5,
    BN_NET_ERROR_TIMEOUT = -6,
    BN_NET_ERROR_OPERATION = -7,
    BN_NET_ERROR_TLS = -8
} bn_net_error_t;

/**
 * @brief Network address information
 */
typedef struct {
    /** Socket address storage (can hold IPv4 or IPv6) */
    struct sockaddr_storage addr;
    
    /** Address length */
    socklen_t addr_len;
    
    /** Address family (AF_INET or AF_INET6) */
    int family;
    
    /** IP address string representation */
    char ip_str[INET6_ADDRSTRLEN];
    
    /** Port number */
    uint16_t port;
} bn_net_addr_t;

/**
 * @brief Socket options
 */
typedef struct {
    /** Enable TCP_NODELAY (disable Nagle's algorithm) */
    bool tcp_nodelay;
    
    /** Enable keep-alive */
    bool keep_alive;
    
    /** Keep-alive idle time in seconds */
    int keep_alive_idle;
    
    /** Keep-alive interval in seconds */
    int keep_alive_interval;
    
    /** Keep-alive probe count */
    int keep_alive_count;
    
    /** Receive timeout in milliseconds */
    uint32_t recv_timeout_ms;
    
    /** Send timeout in milliseconds */
    uint32_t send_timeout_ms;
    
    /** Receive buffer size (0 for default) */
    int recv_buffer_size;
    
    /** Send buffer size (0 for default) */
    int send_buffer_size;
    
    /** Allow address reuse */
    bool reuse_addr;
    
    /** Allow port reuse */
    bool reuse_port;
    
    /** Set non-blocking mode */
    bool non_blocking;
} bn_net_socket_options_t;

/**
 * @brief Initialize default socket options
 * 
 * @param options Pointer to options structure to initialize
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_socket_options_init(bn_net_socket_options_t *options);

/**
 * @brief Resolve hostname to address information
 * 
 * @param hostname Hostname or IP address to resolve
 * @param port Port number
 * @param addr Pointer to store address information
 * @param ipv6_enabled Whether to enable IPv6 resolution
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_resolve_addr(const char *hostname, uint16_t port, 
                       bn_net_addr_t *addr, bool ipv6_enabled);

/**
 * @brief Create a socket with specified options
 * 
 * @param family Address family (AF_INET or AF_INET6)
 * @param type Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @param protocol Protocol (IPPROTO_TCP or IPPROTO_UDP)
 * @param options Socket options (can be NULL for defaults)
 * @param sock_out Pointer to store the created socket
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_create_socket(int family, int type, int protocol,
                        const bn_net_socket_options_t *options,
                        int *sock_out);

/**
 * @brief Apply socket options to an existing socket
 * 
 * @param sock Socket file descriptor
 * @param options Socket options
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_apply_socket_options(int sock, const bn_net_socket_options_t *options);

/**
 * @brief Set socket timeout for send or receive operations
 * 
 * @param sock Socket file descriptor
 * @param timeout_ms Timeout in milliseconds
 * @param for_recv Set timeout for receive operations if true, send operations if false
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_set_socket_timeout(int sock, uint32_t timeout_ms, bool for_recv);

/**
 * @brief Set socket to non-blocking mode
 * 
 * @param sock Socket file descriptor
 * @param non_blocking Whether to set non-blocking mode
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_set_nonblocking(int sock, bool non_blocking);

/**
 * @brief Check if a socket has data available for reading
 * 
 * @param sock Socket file descriptor
 * @param timeout_ms Maximum time to wait (0 for immediate return)
 * @param readable Pointer to store whether data is available
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_is_socket_readable(int sock, uint32_t timeout_ms, bool *readable);

/**
 * @brief Check if a socket is ready for writing
 * 
 * @param sock Socket file descriptor
 * @param timeout_ms Maximum time to wait (0 for immediate return)
 * @param writable Pointer to store whether socket is writable
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_is_socket_writable(int sock, uint32_t timeout_ms, bool *writable);

/**
 * @brief Check if a hostname is an IP address
 * 
 * @param hostname Hostname to check
 * @return true if the hostname is an IP address, false otherwise
 */
bool bn_net_is_ip_address(const char *hostname);

/**
 * @brief Convert socket address to string representation
 * 
 * @param addr Socket address
 * @param addr_len Address length
 * @param buffer Buffer to store the string representation
 * @param buffer_len Buffer length
 * @param with_port Whether to include port number in output
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_addr_to_string(const struct sockaddr *addr, socklen_t addr_len,
                         char *buffer, size_t buffer_len, bool with_port);

/**
 * @brief Generate random bytes securely
 * 
 * @param buffer Buffer to store random bytes
 * @param length Number of random bytes to generate
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_random_bytes(uint8_t *buffer, size_t length);

/**
 * @brief Generate a random integer within a specified range
 * 
 * @param min Minimum value (inclusive)
 * @param max Maximum value (inclusive)
 * @return Random integer in the range [min, max]
 */
int bn_net_random_int(int min, int max);

/**
 * @brief Get a string representation of a network error code
 * 
 * @param error Error code
 * @return String representation of the error code
 */
const char* bn_net_error_string(int error);

/**
 * @brief Get the last socket error as a string
 * 
 * @param buffer Buffer to store the error string
 * @param buffer_len Buffer length
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_get_last_error_string(char *buffer, size_t buffer_len);

#endif /* BETANET_NET_UTILS_H_ */