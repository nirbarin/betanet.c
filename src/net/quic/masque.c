/**
 * @file masque.c
 * @brief MASQUE protocol support for QUIC
 * 
 * This file contains implementation of MASQUE protocol (CONNECT-UDP)
 * for tunneling UDP traffic over QUIC.
 * 
 * MASQUE is specified in draft-ietf-masque-connect-udp.
 */

#include "internal.h"

/* Compatibility macro for ngtcp2 function */
#define bn_ngtcp2_writev_datagram(conn, flags, dgram_id, vec, veclen, ts) \
    ngtcp2_conn_writev_datagram((conn), NULL, NULL, NULL, 0, NULL, (flags), (dgram_id), (vec), (veclen), (ts))
#include <stdio.h>
#include <string.h>

/* HTTP/3 headers for CONNECT-UDP */
#define MASQUE_METHOD "CONNECT-UDP"
#define MASQUE_SCHEME "https"
#define MASQUE_PATH "/.well-known/masque/udp"
#define MASQUE_VERSION "HTTP/3"

/* Max length for MASQUE headers */
#define MASQUE_MAX_HEADER_SIZE 2048

/* MASQUE session states */
typedef enum {
    MASQUE_STATE_INIT,
    MASQUE_STATE_CONNECTING,
    MASQUE_STATE_CONNECTED,
    MASQUE_STATE_FAILED,
    MASQUE_STATE_CLOSED
} masque_state_t;

/* MASQUE session data */
typedef struct {
    masque_state_t state;
    bn_quic_stream_t *control_stream;
    bn_quic_stream_t *data_stream;
    char target_host[256];
    uint16_t target_port;
    uint32_t session_id;
} masque_session_t;

/**
 * @brief Generate a simple HTTP/3 CONNECT-UDP request
 * 
 * @param target_host Target hostname
 * @param target_port Target port
 * @param buffer Buffer to store the request
 * @param buffer_size Size of the buffer
 * @return int Length of the request or negative error code
 */
static int masque_generate_connect_request(const char *target_host, 
                                           uint16_t target_port, 
                                           char *buffer, 
                                           size_t buffer_size) {
    if (!target_host || !buffer || buffer_size < MASQUE_MAX_HEADER_SIZE) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Format the request */
    int len = snprintf(buffer, buffer_size,
                      "%s %s HTTP/3\r\n"
                      "Host: %s:%u\r\n"
                      "Target-Host: %s\r\n"
                      "Target-Port: %u\r\n"
                      "Connection: keep-alive\r\n"
                      "\r\n",
                      MASQUE_METHOD, MASQUE_PATH,
                      target_host, target_port,
                      target_host, target_port);
    
    if (len < 0 || (size_t)len >= buffer_size) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    return len;
}

/**
 * @brief Parse a simple HTTP/3 response
 * 
 * @param response Response buffer
 * @param response_len Length of response
 * @return int 0 if successful, negative error code otherwise
 */
static int masque_parse_response(const char *response, size_t response_len) {
    if (!response || response_len == 0) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Simple check for "200 OK" in the response */
    const char *status_line = response;
    const char *end_of_line = strstr(status_line, "\r\n");
    
    if (!end_of_line) {
        return BN_QUIC_ERROR_MASQUE;
    }
    
    size_t line_len = end_of_line - status_line;
    
    /* Check for "HTTP/3 200" in the status line */
    if (line_len < 10 || strncmp(status_line + line_len - 3, "200", 3) != 0) {
        return BN_QUIC_ERROR_MASQUE;
    }
    
    return BN_QUIC_SUCCESS;
}

/**
 * @brief Implement MASQUE CONNECT-UDP for proxy functionality
 * 
 * Establishes a MASQUE CONNECT-UDP session to proxy UDP traffic
 * through the QUIC connection.
 * 
 * @param ctx QUIC context
 * @param target_host Target hostname or IP address
 * @param target_port Target port number
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_masque_connect_udp(bn_quic_ctx_t *ctx, 
                              const char *target_host, 
                              uint16_t target_port) {
    if (!ctx || !target_host || !ctx->conn) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Check if connection is established */
    if (!ctx->flags.handshake_complete || ctx->flags.connection_closed) {
        return BN_QUIC_ERROR_CONNECT;
    }
    
    /* Allocate MASQUE session data */
    masque_session_t *session = calloc(1, sizeof(masque_session_t));
    if (!session) {
        return BN_QUIC_ERROR_OUT_OF_MEMORY;
    }
    
    /* Store target information */
    strncpy(session->target_host, target_host, sizeof(session->target_host) - 1);
    session->target_port = target_port;
    
    /* Generate a session ID */
    session->session_id = (uint32_t)bn_quic_now_ms() & 0xFFFFFFFF;
    ctx->masque_session_id = session->session_id;
    
    /* Open a bidirectional control stream */
    bn_quic_stream_t *control_stream;
    int ret = bn_quic_stream_open(ctx, &control_stream, BN_QUIC_STREAM_BIDI);
    if (ret != BN_QUIC_SUCCESS) {
        free(session);
        return ret;
    }
    
    session->control_stream = control_stream;
    session->state = MASQUE_STATE_CONNECTING;
    
    /* Generate CONNECT-UDP request */
    char request[MASQUE_MAX_HEADER_SIZE];
    int request_len = masque_generate_connect_request(target_host, target_port, 
                                                   request, sizeof(request));
    if (request_len < 0) {
        bn_quic_stream_close(control_stream);
        free(session);
        return BN_QUIC_ERROR_MASQUE;
    }
    
    /* Send request */
    size_t sent;
    ret = bn_quic_stream_send(control_stream, (const uint8_t *)request, 
                            request_len, &sent, false);
    if (ret != BN_QUIC_SUCCESS || sent != (size_t)request_len) {
        bn_quic_stream_close(control_stream);
        free(session);
        return ret != BN_QUIC_SUCCESS ? ret : BN_QUIC_ERROR_SEND;
    }
    
    /* Read response */
    uint8_t response[MASQUE_MAX_HEADER_SIZE];
    size_t received;
    bool fin;
    
    /* Wait for response with timeout */
    uint64_t start_time = bn_quic_now_ms();
    
    while (1) {
        ret = bn_quic_stream_recv(control_stream, response, sizeof(response), 
                               &received, &fin);
        
        if (ret != BN_QUIC_SUCCESS) {
            bn_quic_stream_close(control_stream);
            free(session);
            return ret;
        }
        
        if (received > 0) {
            /* Got some data, parse it */
            ret = masque_parse_response((const char *)response, received);
            if (ret != BN_QUIC_SUCCESS) {
                bn_quic_stream_close(control_stream);
                free(session);
                return ret;
            }
            
            /* Response successful, break out of loop */
            break;
        }
        
        /* Check for timeout */
        uint64_t now = bn_quic_now_ms();
        if (now - start_time > ctx->config.connect_timeout_ms) {
            bn_quic_stream_close(control_stream);
            free(session);
            return BN_QUIC_ERROR_TIMEOUT;
        }
        
        /* Small delay to avoid tight loop */
        struct timespec ts = {0, 5000000}; // 5ms
        nanosleep(&ts, NULL);
        
        /* Process more packets */
        bn_quic_process(ctx, 0);
    }
    
    /* Open a bidirectional data stream */
    bn_quic_stream_t *data_stream;
    ret = bn_quic_stream_open(ctx, &data_stream, BN_QUIC_STREAM_BIDI);
    if (ret != BN_QUIC_SUCCESS) {
        bn_quic_stream_close(control_stream);
        free(session);
        return ret;
    }
    
    session->data_stream = data_stream;
    session->state = MASQUE_STATE_CONNECTED;
    
    /* Store session data in context */
    free(session); // We don't store the session data for now, just the ID
    
    return BN_QUIC_SUCCESS;
}

/**
 * @brief Send a UDP datagram through a MASQUE session
 * 
 * @param ctx QUIC context
 * @param data UDP datagram data
 * @param len Length of the datagram
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_masque_send_datagram(bn_quic_ctx_t *ctx, 
                                const uint8_t *data, 
                                size_t len) {
    if (!ctx || !data || len == 0 || !ctx->conn || 
        ctx->masque_session_id == 0) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* For now, we use ngtcp2's datagram extension if available */
    ngtcp2_vec vec = {
        .base = (uint8_t *)data,
        .len = len
    };
    
    ssize_t datagram_id = bn_ngtcp2_writev_datagram(ctx->conn, 
                                                 0, 0, &vec, 1,
                                                 bn_quic_now_ms());    
    if (datagram_id < 0) {
        if (datagram_id == NGTCP2_ERR_INVALID_STATE ||
            datagram_id == NGTCP2_ERR_INVALID_ARGUMENT) {
            return BN_QUIC_ERROR_INVALID_PARAM;
        } else if (datagram_id == NGTCP2_ERR_NOBUF ||
                 datagram_id == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            return BN_QUIC_ERROR_BLOCKED;
        }
        return bn_quic_map_error((int)datagram_id);
    }
    
    /* Send any pending packets */
    return bn_quic_send_pending(ctx);
}

/**
 * @brief Receive a UDP datagram from a MASQUE session
 * 
 * @param ctx QUIC context
 * @param buffer Buffer to store the datagram
 * @param len Maximum length of the buffer
 * @param received Pointer to store the number of bytes received
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_masque_recv_datagram(bn_quic_ctx_t *ctx, 
                                uint8_t *buffer, 
                                size_t len, 
                                size_t *received) {
    if (!ctx || !buffer || len == 0 || !received || !ctx->conn || 
        ctx->masque_session_id == 0) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Process any pending packets */
    int ret = bn_quic_process(ctx, 0);
    if (ret != BN_QUIC_SUCCESS && ret != BN_QUIC_ERROR_TIMEOUT) {
        return ret;
    }
    
    /* For ngtcp2, datagram data is likely delivered in a callback
     * For now, we'll return a "not implemented" error
     */
    if (received) {
        *received = 0;
    }
    
    return BN_QUIC_ERROR_UNINITIALIZED; // Not yet implemented
}