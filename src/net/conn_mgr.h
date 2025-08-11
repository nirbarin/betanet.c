/**
 * @file conn_mgr.h
 * @brief Connection manager for Betanet
 * 
 * This module provides a unified interface for managing network connections,
 * with support for connection pooling, monitoring, and statistics.
 */

#ifndef BETANET_NET_CONN_MGR_H_
#define BETANET_NET_CONN_MGR_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "net_utils.h"

/**
 * @brief Connection types
 */
typedef enum {
    BN_CONN_TYPE_TCP,     // TCP with TLS
    BN_CONN_TYPE_QUIC,    // QUIC over UDP
    BN_CONN_TYPE_HTX      // HTX protocol (over TCP or QUIC)
} bn_conn_type_t;

/**
 * @brief Connection state
 */
typedef enum {
    BN_CONN_STATE_CLOSED,         // Connection is closed
    BN_CONN_STATE_CONNECTING,     // Connection is being established
    BN_CONN_STATE_CONNECTED,      // Connection is established and ready
    BN_CONN_STATE_CLOSING,        // Connection is in the process of closing
    BN_CONN_STATE_ERROR           // Connection encountered an error
} bn_conn_state_t;

/**
 * @brief Connection statistics
 */
typedef struct {
    /** Time when connection was established */
    uint64_t connect_time_ms;
    
    /** Time when connection was closed (0 if still open) */
    uint64_t close_time_ms;
    
    /** Number of bytes sent */
    uint64_t bytes_sent;
    
    /** Number of bytes received */
    uint64_t bytes_received;
    
    /** Number of successful read operations */
    uint32_t read_ops;
    
    /** Number of successful write operations */
    uint32_t write_ops;
    
    /** Number of read timeouts */
    uint32_t read_timeouts;
    
    /** Number of write timeouts */
    uint32_t write_timeouts;
    
    /** Number of errors encountered */
    uint32_t errors;
    
    /** Round-trip time in milliseconds (last measured) */
    uint32_t rtt_ms;
} bn_conn_stats_t;

/**
 * @brief Connection handle (opaque)
 */
typedef struct bn_conn_s bn_conn_t;

/**
 * @brief Connection pool (opaque)
 */
typedef struct bn_conn_pool_s bn_conn_pool_t;

/**
 * @brief Connection event callback type
 * 
 * @param conn Connection handle
 * @param user_data User data pointer passed during registration
 */
typedef void (*bn_conn_event_cb)(bn_conn_t *conn, void *user_data);

/**
 * @brief Connection event types
 */
typedef enum {
    BN_CONN_EVENT_CONNECTED,    // Connection established
    BN_CONN_EVENT_CLOSED,       // Connection closed gracefully
    BN_CONN_EVENT_ERROR,        // Connection error occurred
    BN_CONN_EVENT_TIMEOUT       // Connection operation timed out
} bn_conn_event_type_t;

/**
 * @brief Initialize the connection manager
 * 
 * This function must be called before using any other functions
 * in this module.
 * 
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_mgr_init(void);

/**
 * @brief Clean up the connection manager
 * 
 * This function should be called when the program exits to free
 * any resources allocated by the module.
 * 
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_mgr_cleanup(void);

/**
 * @brief Create a new connection
 * 
 * @param conn_out Pointer to store the created connection handle
 * @param type Connection type
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_create(bn_conn_t **conn_out, bn_conn_type_t type);

/**
 * @brief Destroy a connection
 * 
 * @param conn Connection handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_destroy(bn_conn_t *conn);

/**
 * @brief Connect to a remote host
 * 
 * @param conn Connection handle
 * @param host Hostname or IP address
 * @param port Port number
 * @param timeout_ms Connection timeout in milliseconds
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_connect(bn_conn_t *conn, const char *host, uint16_t port, uint32_t timeout_ms);

/**
 * @brief Close a connection
 * 
 * @param conn Connection handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_close(bn_conn_t *conn);

/**
 * @brief Send data over a connection
 * 
 * @param conn Connection handle
 * @param data Pointer to the data to send
 * @param len Length of the data to send
 * @param sent Pointer to store the number of bytes sent (can be NULL)
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_send(bn_conn_t *conn, const uint8_t *data, size_t len, size_t *sent);

/**
 * @brief Receive data from a connection
 * 
 * @param conn Connection handle
 * @param buffer Buffer to store the received data
 * @param len Maximum length of data to receive
 * @param received Pointer to store the number of bytes received
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_recv(bn_conn_t *conn, uint8_t *buffer, size_t len, size_t *received);

/**
 * @brief Get connection state
 * 
 * @param conn Connection handle
 * @param state Pointer to store the connection state
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_get_state(bn_conn_t *conn, bn_conn_state_t *state);

/**
 * @brief Get connection statistics
 * 
 * @param conn Connection handle
 * @param stats Pointer to store the connection statistics
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_get_stats(bn_conn_t *conn, bn_conn_stats_t *stats);

/**
 * @brief Set connection timeout
 * 
 * @param conn Connection handle
 * @param timeout_ms Timeout in milliseconds
 * @param for_recv Set timeout for receive operations if true, send operations if false
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_set_timeout(bn_conn_t *conn, uint32_t timeout_ms, bool for_recv);

/**
 * @brief Register a callback for connection events
 * 
 * @param conn Connection handle
 * @param event_type Event type
 * @param callback Callback function
 * @param user_data User data pointer to pass to the callback
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_register_event_cb(bn_conn_t *conn, bn_conn_event_type_t event_type, 
                             bn_conn_event_cb callback, void *user_data);

/**
 * @brief Unregister a callback for connection events
 * 
 * @param conn Connection handle
 * @param event_type Event type
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_unregister_event_cb(bn_conn_t *conn, bn_conn_event_type_t event_type);

/**
 * @brief Create a connection pool
 * 
 * @param pool_out Pointer to store the created pool handle
 * @param max_conns Maximum number of connections in the pool
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_create(bn_conn_pool_t **pool_out, size_t max_conns);

/**
 * @brief Destroy a connection pool
 * 
 * @param pool Connection pool handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_destroy(bn_conn_pool_t *pool);

/**
 * @brief Get a connection from the pool
 * 
 * @param pool Connection pool handle
 * @param type Connection type
 * @param host Hostname or IP address
 * @param port Port number
 * @param conn_out Pointer to store the connection handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_get(bn_conn_pool_t *pool, bn_conn_type_t type,
                    const char *host, uint16_t port, bn_conn_t **conn_out);

/**
 * @brief Return a connection to the pool
 * 
 * @param pool Connection pool handle
 * @param conn Connection handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_return(bn_conn_pool_t *pool, bn_conn_t *conn);

/**
 * @brief Set the maximum idle time for connections in the pool
 * 
 * @param pool Connection pool handle
 * @param max_idle_ms Maximum idle time in milliseconds
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_set_max_idle(bn_conn_pool_t *pool, uint32_t max_idle_ms);

/**
 * @brief Set the maximum lifetime for connections in the pool
 * 
 * @param pool Connection pool handle
 * @param max_lifetime_ms Maximum lifetime in milliseconds
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_set_max_lifetime(bn_conn_pool_t *pool, uint32_t max_lifetime_ms);

/**
 * @brief Perform maintenance on the connection pool
 * 
 * Closes idle connections that have exceeded their maximum idle time
 * and connections that have exceeded their maximum lifetime.
 * 
 * @param pool Connection pool handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_maintain(bn_conn_pool_t *pool);

/**
 * @brief Trigger an event on a connection
 * 
 * @param conn Connection handle
 * @param event_type Event type
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_trigger_event(bn_conn_t *conn, bn_conn_event_type_t event_type);

#endif /* BETANET_NET_CONN_MGR_H_ */