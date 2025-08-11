/**
 * @file conn_mgr.c
 * @brief Connection manager for Betanet
 * 
 * This module provides a unified interface for managing network connections,
 * with support for connection pooling, monitoring, and statistics.
 */

#include "conn_mgr.h"
#include "tcp.h"
#include "quic/quic.h"
#include "net_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <openssl/err.h>

/**
 * @brief Maximum number of event callbacks per connection
 */
#define BN_CONN_MAX_CALLBACKS 8

/**
 * @brief Default connection pool settings
 */
#define BN_CONN_POOL_DEFAULT_MAX_CONNS     16
#define BN_CONN_POOL_DEFAULT_MAX_IDLE_MS   60000  // 60 seconds
#define BN_CONN_POOL_DEFAULT_MAX_LIFE_MS   600000 // 10 minutes

/**
 * @brief Connection event callback structure
 */
typedef struct {
    bn_conn_event_type_t event_type;
    bn_conn_event_cb callback;
    void *user_data;
    bool in_use;
} bn_conn_callback_t;

/**
 * @brief Internal connection structure
 */
struct bn_conn_s {
    bn_conn_type_t type;
    bn_conn_state_t state;
    bn_conn_stats_t stats;
    
    // Connection information
    char host[256];
    uint16_t port;
    
    // Protocol-specific data
    union {
        bn_tcp_ctx_t *tcp_ctx;
        bn_quic_ctx_t *quic_ctx;
        void *htx_ctx;  // Future HTX protocol context
    } protocol;
    
    // Event callbacks
    bn_conn_callback_t callbacks[BN_CONN_MAX_CALLBACKS];
    
    // Mutex for thread safety
    pthread_mutex_t mutex;
    
    // Timeouts
    uint32_t connect_timeout_ms;
    uint32_t recv_timeout_ms;
    uint32_t send_timeout_ms;
    
    // Pool info
    struct bn_conn_pool_s *parent_pool;
    bool in_use;
    uint64_t last_used_ms;
    uint64_t creation_ms;
};

/**
 * @brief Pool entry structure
 */
typedef struct {
    bn_conn_t *conn;
    bool in_use;
} bn_conn_pool_entry_t;

/**
 * @brief Internal connection pool structure
 */
struct bn_conn_pool_s {
    bn_conn_pool_entry_t *entries;
    size_t max_conns;
    size_t current_size;
    
    uint32_t max_idle_ms;
    uint32_t max_lifetime_ms;
    
    pthread_mutex_t mutex;
};

/**
 * @brief Global module state
 */
static int g_bn_conn_mgr_initialized = 0;

/**
 * @brief Get current time in milliseconds
 * 
 * @return Current time in milliseconds
 */
static uint64_t bn_conn_get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/**
 * @brief Get connection state
 * 
 * @param conn Connection handle
 * @param state Pointer to store the connection state
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_get_state(bn_conn_t *conn, bn_conn_state_t *state) {
    if (!conn || !state) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->mutex);
    *state = conn->state;
    pthread_mutex_unlock(&conn->mutex);
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Get connection statistics
 * 
 * @param conn Connection handle
 * @param stats Pointer to store the connection statistics
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_get_stats(bn_conn_t *conn, bn_conn_stats_t *stats) {
    if (!conn || !stats) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->mutex);
    memcpy(stats, &conn->stats, sizeof(bn_conn_stats_t));
    pthread_mutex_unlock(&conn->mutex);
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Set connection timeout
 * 
 * @param conn Connection handle
 * @param timeout_ms Timeout in milliseconds
 * @param for_recv Set timeout for receive operations if true, send operations if false
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_set_timeout(bn_conn_t *conn, uint32_t timeout_ms, bool for_recv) {
    if (!conn || timeout_ms == 0) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->mutex);
    
    if (for_recv) {
        conn->recv_timeout_ms = timeout_ms;
    } else {
        conn->send_timeout_ms = timeout_ms;
    }
    
    // Apply the timeout to the underlying protocol
    int result = BN_NET_ERROR_OPERATION;
    
    switch (conn->type) {
        case BN_CONN_TYPE_TCP: {
            if (conn->protocol.tcp_ctx) {
                // TCP timeouts are applied on send/receive operations
                result = BN_NET_SUCCESS;
            }
            break;
        }
        
        case BN_CONN_TYPE_QUIC: {
            if (conn->protocol.quic_ctx) {
                // QUIC timeouts are applied on stream operations
                result = BN_NET_SUCCESS;
            }
            break;
        }
        
        case BN_CONN_TYPE_HTX:
            // HTX protocol not yet implemented
            result = BN_NET_ERROR_OPERATION;
            break;
    }
    
    pthread_mutex_unlock(&conn->mutex);
    return result;
}

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
                             bn_conn_event_cb callback, void *user_data) {
    if (!conn || !callback) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->mutex);
    
    // Find an available callback slot
    int slot = -1;
    for (int i = 0; i < BN_CONN_MAX_CALLBACKS; i++) {
        if (!conn->callbacks[i].in_use) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&conn->mutex);
        return BN_NET_ERROR_OPERATION;
    }
    
    // Register the callback
    conn->callbacks[slot].event_type = event_type;
    conn->callbacks[slot].callback = callback;
    conn->callbacks[slot].user_data = user_data;
    conn->callbacks[slot].in_use = true;
    
    pthread_mutex_unlock(&conn->mutex);
    return BN_NET_SUCCESS;
}

/**
 * @brief Unregister a callback for connection events
 * 
 * @param conn Connection handle
 * @param event_type Event type
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_unregister_event_cb(bn_conn_t *conn, bn_conn_event_type_t event_type) {
    if (!conn) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->mutex);
    
    // Find callbacks for the specified event type
    bool found = false;
    for (int i = 0; i < BN_CONN_MAX_CALLBACKS; i++) {
        if (conn->callbacks[i].in_use && conn->callbacks[i].event_type == event_type) {
            conn->callbacks[i].in_use = false;
            found = true;
        }
    }
    
    pthread_mutex_unlock(&conn->mutex);
    
    if (!found) {
        return BN_NET_ERROR_OPERATION;
    }
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Create a connection pool
 * 
 * @param pool_out Pointer to store the created pool handle
 * @param max_conns Maximum number of connections in the pool
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_create(bn_conn_pool_t **pool_out, size_t max_conns) {
    if (!pool_out) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    if (!g_bn_conn_mgr_initialized) {
        return BN_NET_ERROR_OPERATION;
    }
    
    if (max_conns == 0) {
        max_conns = BN_CONN_POOL_DEFAULT_MAX_CONNS;
    }
    
    bn_conn_pool_t *pool = (bn_conn_pool_t *)calloc(1, sizeof(bn_conn_pool_t));
    if (!pool) {
        return BN_NET_ERROR_MEMORY;
    }
    
    pool->entries = (bn_conn_pool_entry_t *)calloc(max_conns, sizeof(bn_conn_pool_entry_t));
    if (!pool->entries) {
        free(pool);
        return BN_NET_ERROR_MEMORY;
    }
    
    pool->max_conns = max_conns;
    pool->current_size = 0;
    pool->max_idle_ms = BN_CONN_POOL_DEFAULT_MAX_IDLE_MS;
    pool->max_lifetime_ms = BN_CONN_POOL_DEFAULT_MAX_LIFE_MS;
    
    // Initialize mutex
    if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
        free(pool->entries);
        free(pool);
        return BN_NET_ERROR_OPERATION;
    }
    
    *pool_out = pool;
    return BN_NET_SUCCESS;
}

/**
 * @brief Destroy a connection pool
 * 
 * @param pool Connection pool handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_destroy(bn_conn_pool_t *pool) {
    if (!pool) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&pool->mutex);
    
    // Close and destroy all connections in the pool
    for (size_t i = 0; i < pool->current_size; i++) {
        if (pool->entries[i].conn) {
            // Remove parent pool reference to prevent returning to pool during destroy
            pool->entries[i].conn->parent_pool = NULL;
            bn_conn_destroy(pool->entries[i].conn);
            pool->entries[i].conn = NULL;
            pool->entries[i].in_use = false;
        }
    }
    
    free(pool->entries);
    
    pthread_mutex_unlock(&pool->mutex);
    
    // Destroy mutex
    pthread_mutex_destroy(&pool->mutex);
    
    // Free pool structure
    free(pool);
    
    return BN_NET_SUCCESS;
}

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
                    const char *host, uint16_t port, bn_conn_t **conn_out) {
    if (!pool || !host || !conn_out) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&pool->mutex);
    
    // First, try to find an existing connection to the same host and port
    for (size_t i = 0; i < pool->current_size; i++) {
        bn_conn_t *conn = pool->entries[i].conn;
        
        if (conn && !pool->entries[i].in_use && 
            conn->type == type && 
            conn->state == BN_CONN_STATE_CONNECTED &&
            strcmp(conn->host, host) == 0 && 
            conn->port == port) {
            
            // Check if the connection has been idle for too long
            uint64_t now = bn_conn_get_time_ms();
            if (now - conn->last_used_ms > pool->max_idle_ms ||
                now - conn->creation_ms > pool->max_lifetime_ms) {
                // Connection too old, close it and look for another
                bn_conn_close(conn);
                continue;
            }
            
            // Found a suitable connection, mark it as in use
            pool->entries[i].in_use = true;
            conn->in_use = true;
            conn->last_used_ms = now;
            
            pthread_mutex_unlock(&pool->mutex);
            *conn_out = conn;
            return BN_NET_SUCCESS;
        }
    }
    
    // No suitable connection found, create a new one
    bn_conn_t *new_conn = NULL;
    int result = bn_conn_create(&new_conn, type);
    
    if (result != BN_NET_SUCCESS || !new_conn) {
        pthread_mutex_unlock(&pool->mutex);
        return result;
    }
    
    // Add the new connection to the pool
    size_t slot = pool->current_size;
    if (slot >= pool->max_conns) {
        // Pool is full, try to find a closed connection to replace
        bool found = false;
        for (size_t i = 0; i < pool->current_size; i++) {
            if (pool->entries[i].conn && 
                !pool->entries[i].in_use &&
                pool->entries[i].conn->state == BN_CONN_STATE_CLOSED) {
                // Found a closed connection to replace
                bn_conn_destroy(pool->entries[i].conn);
                slot = i;
                found = true;
                break;
            }
        }
        
        if (!found) {
            // No suitable slot found, fail
            bn_conn_destroy(new_conn);
            pthread_mutex_unlock(&pool->mutex);
            return BN_NET_ERROR_OPERATION;
        }
    } else {
        // Using a new slot, increase the size
        pool->current_size++;
    }
    
    // Connect to the host
    result = bn_conn_connect(new_conn, host, port, 0);
    
    if (result != BN_NET_SUCCESS) {
        bn_conn_destroy(new_conn);
        if (slot == pool->current_size - 1) {
            // If we were using a new slot, decrease the size
            pool->current_size--;
        }
        pthread_mutex_unlock(&pool->mutex);
        return result;
    }
    
    // Add connection to the pool
    new_conn->parent_pool = pool;
    pool->entries[slot].conn = new_conn;
    pool->entries[slot].in_use = true;
    
    pthread_mutex_unlock(&pool->mutex);
    
    *conn_out = new_conn;
    return BN_NET_SUCCESS;
}

/**
 * @brief Return a connection to the pool
 * 
 * @param pool Connection pool handle
 * @param conn Connection handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_return(bn_conn_pool_t *pool, bn_conn_t *conn) {
    if (!pool || !conn) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    // Check if the connection belongs to this pool
    if (conn->parent_pool != pool) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&pool->mutex);
    
    // Find the connection in the pool
    bool found = false;
    for (size_t i = 0; i < pool->current_size; i++) {
        if (pool->entries[i].conn == conn) {
            // Mark the connection as not in use
            pool->entries[i].in_use = false;
            conn->in_use = false;
            conn->last_used_ms = bn_conn_get_time_ms();
            found = true;
            break;
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
    
    if (!found) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Set the maximum idle time for connections in the pool
 * 
 * @param pool Connection pool handle
 * @param max_idle_ms Maximum idle time in milliseconds
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_set_max_idle(bn_conn_pool_t *pool, uint32_t max_idle_ms) {
    if (!pool) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&pool->mutex);
    pool->max_idle_ms = max_idle_ms;
    pthread_mutex_unlock(&pool->mutex);
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Set the maximum lifetime for connections in the pool
 * 
 * @param pool Connection pool handle
 * @param max_lifetime_ms Maximum lifetime in milliseconds
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_set_max_lifetime(bn_conn_pool_t *pool, uint32_t max_lifetime_ms) {
    if (!pool) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&pool->mutex);
    pool->max_lifetime_ms = max_lifetime_ms;
    pthread_mutex_unlock(&pool->mutex);
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Perform maintenance on the connection pool
 * 
 * Closes idle connections that have exceeded their maximum idle time
 * and connections that have exceeded their maximum lifetime.
 * 
 * @param pool Connection pool handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_pool_maintain(bn_conn_pool_t *pool) {
    if (!pool) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&pool->mutex);
    
    uint64_t now = bn_conn_get_time_ms();
    
    for (size_t i = 0; i < pool->current_size; i++) {
        bn_conn_t *conn = pool->entries[i].conn;
        
        if (conn && !pool->entries[i].in_use) {
            // Check if the connection has been idle for too long
            if (now - conn->last_used_ms > pool->max_idle_ms ||
                now - conn->creation_ms > pool->max_lifetime_ms) {
                // Close and destroy the connection
                bn_conn_close(conn);
                bn_conn_destroy(conn);
                pool->entries[i].conn = NULL;
                
                // Compact the pool if this was the last connection
                if (i == pool->current_size - 1) {
                    pool->current_size--;
                    while (pool->current_size > 0 && 
                           pool->entries[pool->current_size - 1].conn == NULL) {
                        pool->current_size--;
                    }
                }
            }
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
    return BN_NET_SUCCESS;
}

/**
 * @brief Trigger an event on a connection
 * 
 * @param conn Connection handle
 * @param event_type Event type
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_trigger_event(bn_conn_t *conn, bn_conn_event_type_t event_type) {
    if (!conn) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->mutex);
    
    for (int i = 0; i < BN_CONN_MAX_CALLBACKS; i++) {
        if (conn->callbacks[i].in_use && conn->callbacks[i].event_type == event_type) {
            bn_conn_event_cb callback = conn->callbacks[i].callback;
            void *user_data = conn->callbacks[i].user_data;
            
            // Release the lock while calling the callback to avoid deadlocks
            pthread_mutex_unlock(&conn->mutex);
            
            if (callback) {
                callback(conn, user_data);
            }
            
            pthread_mutex_lock(&conn->mutex);
        }
    }
    
    pthread_mutex_unlock(&conn->mutex);
    return BN_NET_SUCCESS;
}

/**
 * @brief Initialize the connection manager
 * 
 * This function must be called once before using any other functions
 * in this module.
 * 
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_mgr_init(void) {
    if (g_bn_conn_mgr_initialized) {
        return BN_NET_SUCCESS;
    }
    
    // Initialize TCP module
    int ret = bn_tcp_module_init();
    if (ret != BN_TCP_SUCCESS) {
        return BN_NET_ERROR_OPERATION;
    }
    
    // Initialize QUIC module
    ret = bn_quic_module_init();
    if (ret != BN_QUIC_SUCCESS) {
        bn_tcp_module_cleanup();
        return BN_NET_ERROR_OPERATION;
    }
    
    // Initialize random seed
    srand((unsigned int)time(NULL));
    
    g_bn_conn_mgr_initialized = 1;
    return BN_NET_SUCCESS;
}

/**
 * @brief Clean up the connection manager
 * 
 * This function should be called when the program exits to free
 * any resources allocated by the module.
 * 
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_mgr_cleanup(void) {
    if (!g_bn_conn_mgr_initialized) {
        return BN_NET_ERROR_OPERATION;
    }
    
    // Clean up QUIC module
    bn_quic_module_cleanup();
    
    // Clean up TCP module
    bn_tcp_module_cleanup();
    
    g_bn_conn_mgr_initialized = 0;
    return BN_NET_SUCCESS;
}

/**
 * @brief Create a new connection
 * 
 * @param conn_out Pointer to store the created connection handle
 * @param type Connection type
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_create(bn_conn_t **conn_out, bn_conn_type_t type) {
    if (!conn_out) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    if (!g_bn_conn_mgr_initialized) {
        return BN_NET_ERROR_OPERATION;
    }
    
    bn_conn_t *conn = (bn_conn_t *)calloc(1, sizeof(bn_conn_t));
    if (!conn) {
        return BN_NET_ERROR_MEMORY;
    }
    
    // Initialize connection structure
    conn->type = type;
    conn->state = BN_CONN_STATE_CLOSED;
    memset(&conn->stats, 0, sizeof(bn_conn_stats_t));
    conn->connect_timeout_ms = 5000;   // Default 5 seconds
    conn->recv_timeout_ms = 10000;     // Default 10 seconds
    conn->send_timeout_ms = 5000;      // Default 5 seconds
    conn->parent_pool = NULL;
    conn->in_use = true;
    conn->creation_ms = bn_conn_get_time_ms();
    conn->last_used_ms = conn->creation_ms;
    
    // Initialize mutex
    if (pthread_mutex_init(&conn->mutex, NULL) != 0) {
        free(conn);
        return BN_NET_ERROR_OPERATION;
    }
    
    // Initialize protocol-specific data
    switch (type) {
        case BN_CONN_TYPE_TCP: {
            bn_tcp_config_t config;
            bn_tcp_config_default(&config);
            
            // Configure TCP connection
            config.connect_timeout_ms = conn->connect_timeout_ms;
            config.read_timeout_ms = conn->recv_timeout_ms;
            config.write_timeout_ms = conn->send_timeout_ms;
            
            int ret = bn_tcp_create(&conn->protocol.tcp_ctx, &config);
            if (ret != BN_TCP_SUCCESS) {
                pthread_mutex_destroy(&conn->mutex);
                free(conn);
                return BN_NET_ERROR_OPERATION;
            }
            break;
        }
        
        case BN_CONN_TYPE_QUIC: {
            bn_quic_config_t config;
            bn_quic_config_default(&config);
            
            // Configure QUIC connection
            config.connect_timeout_ms = conn->connect_timeout_ms;
            config.read_timeout_ms = conn->recv_timeout_ms;
            config.write_timeout_ms = conn->send_timeout_ms;
            
            int ret = bn_quic_create(&conn->protocol.quic_ctx, &config);
            if (ret != BN_QUIC_SUCCESS) {
                pthread_mutex_destroy(&conn->mutex);
                free(conn);
                return BN_NET_ERROR_OPERATION;
            }
            break;
        }
        
        case BN_CONN_TYPE_HTX:
            // HTX protocol not yet implemented
            pthread_mutex_destroy(&conn->mutex);
            free(conn);
            return BN_NET_ERROR_OPERATION;
            
        default:
            pthread_mutex_destroy(&conn->mutex);
            free(conn);
            return BN_NET_ERROR_INVALID_PARAM;
    }
    
    *conn_out = conn;
    return BN_NET_SUCCESS;
}

/**
 * @brief Close a connection
 * 
 * @param conn Connection handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_close(bn_conn_t *conn) {
    if (!conn) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    if (conn->state == BN_CONN_STATE_CLOSED) {
        return BN_NET_SUCCESS;
    }
    
    pthread_mutex_lock(&conn->mutex);
    conn->state = BN_CONN_STATE_CLOSING;
    pthread_mutex_unlock(&conn->mutex);
    
    int result = BN_NET_ERROR_OPERATION;
    
    // Close using the appropriate protocol
    switch (conn->type) {
        case BN_CONN_TYPE_TCP: {
            int ret = bn_tcp_close(conn->protocol.tcp_ctx);
            if (ret == BN_TCP_SUCCESS) {
                result = BN_NET_SUCCESS;
            }
            break;
        }
        
        case BN_CONN_TYPE_QUIC: {
            int ret = bn_quic_close(conn->protocol.quic_ctx, false, 0, NULL);
            if (ret == BN_QUIC_SUCCESS) {
                result = BN_NET_SUCCESS;
            }
            break;
        }
        
        case BN_CONN_TYPE_HTX:
            // HTX protocol not yet implemented
            result = BN_NET_ERROR_OPERATION;
            break;
    }
    
    pthread_mutex_lock(&conn->mutex);
    conn->state = BN_CONN_STATE_CLOSED;
    conn->stats.close_time_ms = bn_conn_get_time_ms();
    conn->last_used_ms = conn->stats.close_time_ms;
    pthread_mutex_unlock(&conn->mutex);
    
    // Trigger closed event
    bn_conn_trigger_event(conn, BN_CONN_EVENT_CLOSED);
    
    return result;
}

/**
 * @brief Send data over a connection
 * 
 * @param conn Connection handle
 * @param data Pointer to the data to send
 * @param len Length of the data to send
 * @param sent Pointer to store the number of bytes sent (can be NULL)
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_send(bn_conn_t *conn, const uint8_t *data, size_t len, size_t *sent) {
    if (!conn || !data || len == 0) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != BN_CONN_STATE_CONNECTED) {
        return BN_NET_ERROR_OPERATION;
    }
    
    int result = BN_NET_ERROR_OPERATION;
    size_t bytes_sent = 0;
    
    // Send using the appropriate protocol
    switch (conn->type) {
        case BN_CONN_TYPE_TCP: {
            size_t tcp_sent = 0;
            int ret = bn_tcp_send(conn->protocol.tcp_ctx, data, len, &tcp_sent);
            
            if (ret == BN_TCP_SUCCESS) {
                bytes_sent = tcp_sent;
                result = BN_NET_SUCCESS;
            } else if (ret == BN_TCP_ERROR_TIMEOUT) {
                pthread_mutex_lock(&conn->mutex);
                conn->stats.write_timeouts++;
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger timeout event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_TIMEOUT);
                
                result = BN_NET_ERROR_TIMEOUT;
            } else {
                pthread_mutex_lock(&conn->mutex);
                conn->stats.errors++;
                conn->state = BN_CONN_STATE_ERROR;
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger error event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_ERROR);
                
                result = BN_NET_ERROR_OPERATION;
            }
            break;
        }
        
        case BN_CONN_TYPE_QUIC: {
            // For QUIC, we need to open a stream first
            bn_quic_stream_t *stream = NULL;
            int ret = bn_quic_stream_open(conn->protocol.quic_ctx, &stream, BN_QUIC_STREAM_BIDI);
            
            if (ret == BN_QUIC_SUCCESS && stream != NULL) {
                size_t quic_sent = 0;
                ret = bn_quic_stream_send(stream, data, len, &quic_sent, true);
                
                if (ret == BN_QUIC_SUCCESS) {
                    bytes_sent = quic_sent;
                    result = BN_NET_SUCCESS;
                } else if (ret == BN_QUIC_ERROR_TIMEOUT) {
                    pthread_mutex_lock(&conn->mutex);
                    conn->stats.write_timeouts++;
                    pthread_mutex_unlock(&conn->mutex);
                    
                    // Trigger timeout event
                    bn_conn_trigger_event(conn, BN_CONN_EVENT_TIMEOUT);
                    
                    result = BN_NET_ERROR_TIMEOUT;
                } else {
                    pthread_mutex_lock(&conn->mutex);
                    conn->stats.errors++;
                    conn->state = BN_CONN_STATE_ERROR;
                    pthread_mutex_unlock(&conn->mutex);
                    
                    // Trigger error event
                    bn_conn_trigger_event(conn, BN_CONN_EVENT_ERROR);
                    
                    result = BN_NET_ERROR_OPERATION;
                }
                
                // Close the stream
                bn_quic_stream_close(stream);
            } else {
                pthread_mutex_lock(&conn->mutex);
                conn->stats.errors++;
                pthread_mutex_unlock(&conn->mutex);
                
                result = BN_NET_ERROR_OPERATION;
            }
            break;
        }
        
        case BN_CONN_TYPE_HTX:
            // HTX protocol not yet implemented
            result = BN_NET_ERROR_OPERATION;
            break;
    }
    
    // Update statistics on success
    if (result == BN_NET_SUCCESS) {
        pthread_mutex_lock(&conn->mutex);
        conn->stats.bytes_sent += bytes_sent;
        conn->stats.write_ops++;
        conn->last_used_ms = bn_conn_get_time_ms();
        pthread_mutex_unlock(&conn->mutex);
        
        if (sent) {
            *sent = bytes_sent;
        }
    }
    
    return result;
}

/**
 * @brief Receive data from a connection
 * 
 * @param conn Connection handle
 * @param buffer Buffer to store the received data
 * @param len Maximum length of data to receive
 * @param received Pointer to store the number of bytes received
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_recv(bn_conn_t *conn, uint8_t *buffer, size_t len, size_t *received) {
    if (!conn || !buffer || len == 0 || !received) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != BN_CONN_STATE_CONNECTED) {
        return BN_NET_ERROR_OPERATION;
    }
    
    int result = BN_NET_ERROR_OPERATION;
    size_t bytes_received = 0;
    
    // Receive using the appropriate protocol
    switch (conn->type) {
        case BN_CONN_TYPE_TCP: {
            int ret = bn_tcp_recv(conn->protocol.tcp_ctx, buffer, len, &bytes_received);
            
            if (ret == BN_TCP_SUCCESS) {
                result = BN_NET_SUCCESS;
            } else if (ret == BN_TCP_ERROR_TIMEOUT) {
                pthread_mutex_lock(&conn->mutex);
                conn->stats.read_timeouts++;
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger timeout event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_TIMEOUT);
                
                result = BN_NET_ERROR_TIMEOUT;
            } else if (ret == BN_TCP_ERROR_CLOSED) {
                pthread_mutex_lock(&conn->mutex);
                conn->state = BN_CONN_STATE_CLOSED;
                conn->stats.close_time_ms = bn_conn_get_time_ms();
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger closed event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_CLOSED);
                
                result = BN_NET_ERROR_CONNECTION;
            } else {
                pthread_mutex_lock(&conn->mutex);
                conn->stats.errors++;
                conn->state = BN_CONN_STATE_ERROR;
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger error event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_ERROR);
                
                result = BN_NET_ERROR_OPERATION;
            }
            break;
        }
        
        case BN_CONN_TYPE_QUIC: {
            // For QUIC, we need to open a stream first
            bn_quic_stream_t *stream = NULL;
            int ret = bn_quic_stream_open(conn->protocol.quic_ctx, &stream, BN_QUIC_STREAM_BIDI);
            
            if (ret == BN_QUIC_SUCCESS && stream != NULL) {
                bool fin = false;
                ret = bn_quic_stream_recv(stream, buffer, len, &bytes_received, &fin);
                
                if (ret == BN_QUIC_SUCCESS) {
                    result = BN_NET_SUCCESS;
                    
                    if (fin) {
                        // Stream closed by peer
                        bn_quic_stream_close(stream);
                    }
                } else if (ret == BN_QUIC_ERROR_TIMEOUT) {
                    pthread_mutex_lock(&conn->mutex);
                    conn->stats.read_timeouts++;
                    pthread_mutex_unlock(&conn->mutex);
                    
                    // Trigger timeout event
                    bn_conn_trigger_event(conn, BN_CONN_EVENT_TIMEOUT);
                    
                    result = BN_NET_ERROR_TIMEOUT;
                } else {
                    pthread_mutex_lock(&conn->mutex);
                    conn->stats.errors++;
                    conn->state = BN_CONN_STATE_ERROR;
                    pthread_mutex_unlock(&conn->mutex);
                    
                    // Trigger error event
                    bn_conn_trigger_event(conn, BN_CONN_EVENT_ERROR);
                    
                    result = BN_NET_ERROR_OPERATION;
                }
                
                // Close the stream if not already closed
                if (ret != BN_QUIC_SUCCESS || !fin) {
                    bn_quic_stream_close(stream);
                }
            } else {
                pthread_mutex_lock(&conn->mutex);
                conn->stats.errors++;
                pthread_mutex_unlock(&conn->mutex);
                
                result = BN_NET_ERROR_OPERATION;
            }
            break;
        }
        
        case BN_CONN_TYPE_HTX:
            // HTX protocol not yet implemented
            result = BN_NET_ERROR_OPERATION;
            break;
    }
    
    // Update statistics on success
    if (result == BN_NET_SUCCESS) {
        pthread_mutex_lock(&conn->mutex);
        conn->stats.bytes_received += bytes_received;
        conn->stats.read_ops++;
        conn->last_used_ms = bn_conn_get_time_ms();
        pthread_mutex_unlock(&conn->mutex);
        
        *received = bytes_received;
    } else {
        *received = 0;
    }
    
    return result;
}

/**
 * @brief Destroy a connection
 * 
 * @param conn Connection handle
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_destroy(bn_conn_t *conn) {
    if (!conn) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    // Close connection if still open
    if (conn->state != BN_CONN_STATE_CLOSED && conn->state != BN_CONN_STATE_ERROR) {
        bn_conn_close(conn);
    }
    
    // Free protocol-specific resources
    switch (conn->type) {
        case BN_CONN_TYPE_TCP:
            if (conn->protocol.tcp_ctx) {
                bn_tcp_destroy(conn->protocol.tcp_ctx);
                conn->protocol.tcp_ctx = NULL;
            }
            break;
            
        case BN_CONN_TYPE_QUIC:
            if (conn->protocol.quic_ctx) {
                bn_quic_destroy(conn->protocol.quic_ctx);
                conn->protocol.quic_ctx = NULL;
            }
            break;
            
        case BN_CONN_TYPE_HTX:
            // HTX protocol not yet implemented
            break;
    }
    
    // Destroy mutex
    pthread_mutex_destroy(&conn->mutex);
    
    // Free connection structure
    free(conn);
    
    return BN_NET_SUCCESS;
}

/**
 * @brief Connect to a remote host
 * 
 * @param conn Connection handle
 * @param host Hostname or IP address
 * @param port Port number
 * @param timeout_ms Connection timeout in milliseconds
 * @return BN_NET_SUCCESS on success, error code otherwise
 */
int bn_conn_connect(bn_conn_t *conn, const char *host, uint16_t port, uint32_t timeout_ms) {
    if (!conn || !host) {
        return BN_NET_ERROR_INVALID_PARAM;
    }
    
    if (conn->state == BN_CONN_STATE_CONNECTED || conn->state == BN_CONN_STATE_CONNECTING) {
        return BN_NET_ERROR_OPERATION;
    }
    
    // Update connection info
    pthread_mutex_lock(&conn->mutex);
    
    strncpy(conn->host, host, sizeof(conn->host) - 1);
    conn->host[sizeof(conn->host) - 1] = '\0';
    conn->port = port;
    
    if (timeout_ms > 0) {
        conn->connect_timeout_ms = timeout_ms;
    }
    
    conn->state = BN_CONN_STATE_CONNECTING;
    conn->last_used_ms = bn_conn_get_time_ms();
    
    pthread_mutex_unlock(&conn->mutex);
    
    int result = BN_NET_ERROR_OPERATION;
    
    // Connect using the appropriate protocol
    switch (conn->type) {
        case BN_CONN_TYPE_TCP: {
            // Update TCP timeout
            bn_tcp_config_t config;
            bn_tcp_config_default(&config);
            config.connect_timeout_ms = conn->connect_timeout_ms;
            
            int ret = bn_tcp_connect(conn->protocol.tcp_ctx, host, port);
            if (ret == BN_TCP_SUCCESS) {
                pthread_mutex_lock(&conn->mutex);
                conn->state = BN_CONN_STATE_CONNECTED;
                conn->stats.connect_time_ms = bn_conn_get_time_ms();
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger connected event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_CONNECTED);
                
                result = BN_NET_SUCCESS;
            } else {
                pthread_mutex_lock(&conn->mutex);
                conn->state = BN_CONN_STATE_ERROR;
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger error event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_ERROR);
                
                result = BN_NET_ERROR_CONNECTION;
            }
            break;
        }
        
        case BN_CONN_TYPE_QUIC: {
            // Update QUIC timeout
            bn_quic_config_t config;
            bn_quic_config_default(&config);
            config.connect_timeout_ms = conn->connect_timeout_ms;
            
            int ret = bn_quic_connect(conn->protocol.quic_ctx, host, port);
            if (ret == BN_QUIC_SUCCESS) {
                pthread_mutex_lock(&conn->mutex);
                conn->state = BN_CONN_STATE_CONNECTED;
                conn->stats.connect_time_ms = bn_conn_get_time_ms();
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger connected event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_CONNECTED);
                
                result = BN_NET_SUCCESS;
            } else {
                pthread_mutex_lock(&conn->mutex);
                conn->state = BN_CONN_STATE_ERROR;
                pthread_mutex_unlock(&conn->mutex);
                
                // Trigger error event
                bn_conn_trigger_event(conn, BN_CONN_EVENT_ERROR);
                
                result = BN_NET_ERROR_CONNECTION;
            }
            break;
        }
        
        case BN_CONN_TYPE_HTX:
            // HTX protocol not yet implemented
            pthread_mutex_lock(&conn->mutex);
            conn->state = BN_CONN_STATE_ERROR;
            pthread_mutex_unlock(&conn->mutex);
            result = BN_NET_ERROR_OPERATION;
            break;
    }
    
    return result;
}