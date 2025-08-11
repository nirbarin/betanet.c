/**
 * @file net_utils.c
 * @brief Network utility functions for Betanet
 * 
 * This module provides common utility functions for network operations,
 * including address resolution, socket configuration, and error handling.
 */

#include "net_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <poll.h>

/**
 * @brief Error strings for network utility functions
 */
static const char *g_bn_net_error_strings[] = {
    "Success",                      // BN_NET_SUCCESS
    "Invalid parameter",            // BN_NET_ERROR_INVALID_PARAM
    "Memory allocation failure",    // BN_NET_ERROR_MEMORY
    "Host resolution failure",      // BN_NET_ERROR_RESOLUTION
    "Socket operation failure",     // BN_NET_ERROR_SOCKET
    "Connection failure",           // BN_NET_ERROR_CONNECTION
    "Operation timed out",          // BN_NET_ERROR_TIMEOUT
    "Network operation failure",    // BN_NET_ERROR_OPERATION
    "TLS operation failure"         // BN_NET_ERROR_TLS
};

/**
 * @brief Initialize default socket options
 * 
 * @param options Pointer to options structure to initialize
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_socket_options_init(bn_net_socket_options_t *options) {
    if (!options) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    memset(options, 0, sizeof(bn_net_socket_options_t));
    
    // Set sensible defaults
    options->tcp_nodelay = true;
    options->keep_alive = true;
    options->keep_alive_idle = 60;        // 60 seconds
    options->keep_alive_interval = 10;    // 10 seconds
    options->keep_alive_count = 6;        // 6 probes
    options->recv_timeout_ms = 10000;     // 10 seconds
    options->send_timeout_ms = 5000;      // 5 seconds
    options->recv_buffer_size = 0;        // Use system default
    options->send_buffer_size = 0;        // Use system default
    options->reuse_addr = true;
    options->reuse_port = false;          // Less commonly needed
    options->non_blocking = false;        // Blocking by default
    
    return BN_NET_SUCCESS;
}

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
                       bn_net_addr_t *addr, bool ipv6_enabled) {
    if (!hostname || !addr) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    struct addrinfo hints, *result, *rp;
    char port_str[6];
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = ipv6_enabled ? AF_UNSPEC : AF_INET;  // IPv4/IPv6 or IPv4 only
    hints.ai_socktype = SOCK_STREAM;                       // TCP socket
    hints.ai_flags = AI_ADDRCONFIG;                        // Only return addresses we can use
    hints.ai_protocol = 0;                                 // Any protocol
    
    snprintf(port_str, sizeof(port_str), "%u", port);
    
    int ret = getaddrinfo(hostname, port_str, &hints, &result);
    if (ret != 0) {
        return BN_NET_ERROR_RESOLUTION;
    }
    
    // Find the first usable address (prefer IPv4 if both are available)
    struct addrinfo *ipv4_result = NULL;
    struct addrinfo *ipv6_result = NULL;
    
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET && !ipv4_result) {
            ipv4_result = rp;
        } else if (rp->ai_family == AF_INET6 && !ipv6_result) {
            ipv6_result = rp;
        }
    }
    
    // Use IPv4 if available, otherwise IPv6
    rp = ipv4_result ? ipv4_result : ipv6_result;
    
    if (!rp) {
        freeaddrinfo(result);
        return BN_NET_ERROR_RESOLUTION;
    }
    
    // Copy address information
    memset(addr, 0, sizeof(bn_net_addr_t));
    memcpy(&addr->addr, rp->ai_addr, rp->ai_addrlen);
    addr->addr_len = rp->ai_addrlen;
    addr->family = rp->ai_family;
    
    // Convert address to string
    if (rp->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
        inet_ntop(AF_INET, &ipv4->sin_addr, addr->ip_str, sizeof(addr->ip_str));
        addr->port = ntohs(ipv4->sin_port);
    } else if (rp->ai_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
        inet_ntop(AF_INET6, &ipv6->sin6_addr, addr->ip_str, sizeof(addr->ip_str));
        addr->port = ntohs(ipv6->sin6_port);
    }
    
    freeaddrinfo(result);
    return BN_NET_SUCCESS;
}

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
                        int *sock_out) {
    if (!sock_out) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    // Create socket
    int sock = socket(family, type, protocol);
    if (sock < 0) {
        return BN_NET_ERROR_SOCKET;
    }
    
    // Apply options if provided
    if (options) {
        int result = bn_net_apply_socket_options(sock, options);
        if (result != BN_NET_SUCCESS) {
            close(sock);
            return result;
        }
    }
    
    *sock_out = sock;
    return BN_NET_SUCCESS;
}

/**
 * @brief Apply socket options to an existing socket
 * 
 * @param sock Socket file descriptor
 * @param options Socket options
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_apply_socket_options(int sock, const bn_net_socket_options_t *options) {
    if (sock < 0 || !options) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    // TCP_NODELAY (disable Nagle's algorithm)
    if (options->tcp_nodelay) {
        int flag = 1;
        if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0) {
            return BN_NET_ERROR_SOCKET;
        }
    }
    
    // Keep-alive
    if (options->keep_alive) {
        int flag = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) != 0) {
            return BN_NET_ERROR_SOCKET;
        }
        
        // Set keep-alive parameters (may not be supported on all systems)
#ifdef TCP_KEEPIDLE
        if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, 
                      &options->keep_alive_idle, sizeof(options->keep_alive_idle)) != 0) {
            // Non-critical, continue anyway
        }
#endif

#ifdef TCP_KEEPINTVL
        if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, 
                      &options->keep_alive_interval, sizeof(options->keep_alive_interval)) != 0) {
            // Non-critical, continue anyway
        }
#endif

#ifdef TCP_KEEPCNT
        if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, 
                      &options->keep_alive_count, sizeof(options->keep_alive_count)) != 0) {
            // Non-critical, continue anyway
        }
#endif
    }
    
    // Receive timeout
    if (options->recv_timeout_ms > 0) {
        if (bn_net_set_socket_timeout(sock, options->recv_timeout_ms, true) != BN_NET_SUCCESS) {
            return BN_NET_ERROR_SOCKET;
        }
    }
    
    // Send timeout
    if (options->send_timeout_ms > 0) {
        if (bn_net_set_socket_timeout(sock, options->send_timeout_ms, false) != BN_NET_SUCCESS) {
            return BN_NET_ERROR_SOCKET;
        }
    }
    
    // Receive buffer size
    if (options->recv_buffer_size > 0) {
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, 
                      &options->recv_buffer_size, sizeof(options->recv_buffer_size)) != 0) {
            return BN_NET_ERROR_SOCKET;
        }
    }
    
    // Send buffer size
    if (options->send_buffer_size > 0) {
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, 
                      &options->send_buffer_size, sizeof(options->send_buffer_size)) != 0) {
            return BN_NET_ERROR_SOCKET;
        }
    }
    
    // Address reuse
    if (options->reuse_addr) {
        int flag = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0) {
            return BN_NET_ERROR_SOCKET;
        }
    }
    
    // Port reuse
    if (options->reuse_port) {
#ifdef SO_REUSEPORT
        int flag = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) != 0) {
            return BN_NET_ERROR_SOCKET;
        }
#endif
    }
    
    // Non-blocking mode
    if (options->non_blocking) {
        if (bn_net_set_nonblocking(sock, true) != BN_NET_SUCCESS) {
            return BN_NET_ERROR_SOCKET;
        }
    }
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Set socket timeout for send or receive operations
 * 
 * @param sock Socket file descriptor
 * @param timeout_ms Timeout in milliseconds
 * @param for_recv Set timeout for receive operations if true, send operations if false
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_set_socket_timeout(int sock, uint32_t timeout_ms, bool for_recv) {
    if (sock < 0) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int optname = for_recv ? SO_RCVTIMEO : SO_SNDTIMEO;
    if (setsockopt(sock, SOL_SOCKET, optname, &tv, sizeof(tv)) != 0) {
        return BN_NET_ERROR_SOCKET;
    }
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Set socket to non-blocking mode
 * 
 * @param sock Socket file descriptor
 * @param non_blocking Whether to set non-blocking mode
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_set_nonblocking(int sock, bool non_blocking) {
    if (sock < 0) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        return BN_NET_ERROR_SOCKET;
    }
    
    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    if (fcntl(sock, F_SETFL, flags) == -1) {
        return BN_NET_ERROR_SOCKET;
    }
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Check if a socket has data available for reading
 * 
 * @param sock Socket file descriptor
 * @param timeout_ms Maximum time to wait (0 for immediate return)
 * @param readable Pointer to store whether data is available
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_is_socket_readable(int sock, uint32_t timeout_ms, bool *readable) {
    if (sock < 0 || !readable) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;
    
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
        return BN_NET_ERROR_SOCKET;
    } else if (ret == 0) {
        *readable = false;
        return BN_NET_SUCCESS;
    }
    
    *readable = (pfd.revents & POLLIN) != 0;
    return BN_NET_SUCCESS;
}

/**
 * @brief Check if a socket is ready for writing
 * 
 * @param sock Socket file descriptor
 * @param timeout_ms Maximum time to wait (0 for immediate return)
 * @param writable Pointer to store whether socket is writable
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_is_socket_writable(int sock, uint32_t timeout_ms, bool *writable) {
    if (sock < 0 || !writable) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
        return BN_NET_ERROR_SOCKET;
    } else if (ret == 0) {
        *writable = false;
        return BN_NET_SUCCESS;
    }
    
    *writable = (pfd.revents & POLLOUT) != 0;
    return BN_NET_SUCCESS;
}

/**
 * @brief Check if a hostname is an IP address
 * 
 * @param hostname Hostname to check
 * @return true if the hostname is an IP address, false otherwise
 */
bool bn_net_is_ip_address(const char *hostname) {
    if (!hostname) {
        return false;
    }
    
    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;
    
    // Check if it's a valid IPv4 address
    if (inet_pton(AF_INET, hostname, &ipv4_addr) == 1) {
        return true;
    }
    
    // Check if it's a valid IPv6 address
    if (inet_pton(AF_INET6, hostname, &ipv6_addr) == 1) {
        return true;
    }
    
    return false;
}

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
                         char *buffer, size_t buffer_len, bool with_port) {
    if (!addr || !buffer || buffer_len == 0) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    char ip_str[INET6_ADDRSTRLEN];
    uint16_t port = 0;
    
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &ipv4->sin_addr, ip_str, sizeof(ip_str));
        port = ntohs(ipv4->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &ipv6->sin6_addr, ip_str, sizeof(ip_str));
        port = ntohs(ipv6->sin6_port);
    } else {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    if (with_port) {
        if (addr->sa_family == AF_INET) {
            snprintf(buffer, buffer_len, "%s:%d", ip_str, port);
        } else {
            snprintf(buffer, buffer_len, "[%s]:%d", ip_str, port);
        }
    } else {
        snprintf(buffer, buffer_len, "%s", ip_str);
    }
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Generate random bytes securely
 * 
 * @param buffer Buffer to store random bytes
 * @param length Number of random bytes to generate
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_random_bytes(uint8_t *buffer, size_t length) {
    if (!buffer || length == 0) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    if (RAND_bytes(buffer, length) != 1) {
        return BN_NET_ERROR_OPERATION;
    }
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Generate a random integer within a specified range
 * 
 * @param min Minimum value (inclusive)
 * @param max Maximum value (inclusive)
 * @return Random integer in the range [min, max]
 */
int bn_net_random_int(int min, int max) {
    if (min >= max) {
        return min;
    }
    
    unsigned int rand_val;
    if (RAND_bytes((unsigned char *)&rand_val, sizeof(rand_val)) != 1) {
        // Fallback to less secure random if OpenSSL fails
        rand_val = rand();
    }
    
    return min + (rand_val % (max - min + 1));
}

/**
 * @brief Get a string representation of a network error code
 * 
 * @param error Error code
 * @return String representation of the error code
 */
const char* bn_net_error_string(int error) {
    if (error >= 0 || error < -8) {
        return "Unknown error";
    }
    
    return g_bn_net_error_strings[-error];
}

/**
 * @brief Get the last socket error as a string
 * 
 * @param buffer Buffer to store the error string
 * @param buffer_len Buffer length
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_net_get_last_error_string(char *buffer, size_t buffer_len) {
    if (!buffer || buffer_len == 0) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    // Get the last error
    int err = errno;
    
    // Convert to string
    if (strerror_r(err, buffer, buffer_len) != 0) {
        snprintf(buffer, buffer_len, "Error %d", err);
        return BN_NET_ERROR_OPERATION;
    }
    
    return BN_NET_SUCCESS;
}