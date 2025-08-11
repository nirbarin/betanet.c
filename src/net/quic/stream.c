/**
 * @file stream.c
 * @brief Stream operations for QUIC transport
 * 
 * This file contains functions for creating and managing QUIC streams.
 */

#include "internal.h"

/* Compatibility macro for ngtcp2 function */
#define bn_ngtcp2_writev_stream(conn, stream_id, flags, vec, veclen, ts) \
    ngtcp2_conn_writev_stream_versioned(conn, NULL, 0, NULL, NULL, 0, NULL, flags, stream_id, vec, veclen, ts)
#include <stdio.h>

/**
 * @brief Open a new QUIC stream
 * 
 * @param ctx QUIC context
 * @param stream Pointer to store the created stream
 * @param direction Stream direction (bidirectional or unidirectional)
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_stream_open(bn_quic_ctx_t *ctx, bn_quic_stream_t **stream, 
                        bn_quic_stream_direction_t direction) {
    if (!ctx || !stream || !ctx->conn) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Check if connection is established */
    if (!ctx->flags.handshake_complete || ctx->flags.connection_closed) {
        return BN_QUIC_ERROR_CONNECT;
    }
    
    /* Allocate stream structure */
    bn_quic_stream_t *new_stream = calloc(1, sizeof(bn_quic_stream_t));
    if (!new_stream) {
        return BN_QUIC_ERROR_OUT_OF_MEMORY;
    }
    
    /* Open stream with requested direction */
    int64_t stream_id;
    if (direction == BN_QUIC_STREAM_BIDI) {
        int ret = ngtcp2_conn_open_bidi_stream(ctx->conn, &stream_id, NULL);
        if (ret != 0) {
            free(new_stream);
            return bn_quic_map_error(ret);
        }
    } else {
        int ret = ngtcp2_conn_open_uni_stream(ctx->conn, &stream_id, NULL);
        if (ret != 0) {
            free(new_stream);
            return bn_quic_map_error(ret);
        }
    }
    
    /* Initialize stream structure */
    new_stream->ctx = ctx;
    new_stream->stream_id = stream_id;
    new_stream->direction = direction;
    
    /* Return the created stream */
    *stream = new_stream;
    
    return BN_QUIC_SUCCESS;
}

/**
 * @brief Send data on a QUIC stream
 * 
 * @param stream QUIC stream
 * @param data Pointer to the data to send
 * @param len Length of the data to send
 * @param sent Pointer to store the number of bytes sent (can be NULL)
 * @param fin Whether this is the final data on this stream
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_stream_send(bn_quic_stream_t *stream, const uint8_t *data, 
                        size_t len, size_t *sent, bool fin) {
    if (!stream || !data || !stream->ctx || !stream->ctx->conn) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Check if stream or connection is closed */
    if (stream->flags.closed_locally || stream->flags.fin_sent || 
        stream->ctx->flags.connection_closed) {
        return BN_QUIC_ERROR_CLOSED;
    }
    
    /* Send data on stream */
    uint32_t flags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
    
    ngtcp2_vec vec = {
        .base = (uint8_t *)data,
        .len = len
    };
    
    /* Write stream data */
    int64_t bytes_sent = bn_ngtcp2_writev_stream(stream->ctx->conn, 
                                              stream->stream_id,
                                              flags,
                                              &vec, 1,
                                              bn_quic_now_ms());    
    if (bytes_sent < 0) {
        if (bytes_sent == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            /* Stream is blocked, try again later */
            if (sent) {
                *sent = 0;
            }
            return BN_QUIC_ERROR_BLOCKED;
        }
        return bn_quic_map_error((int)bytes_sent);
    }
    
    /* Update stream state if FIN was sent */
    if (fin && bytes_sent == (int64_t)len) {
        stream->flags.fin_sent = 1;
    }
    
    /* Return number of bytes sent if requested */
    if (sent) {
        *sent = (size_t)bytes_sent;
    }
    
    /* Send packets immediately */
    int ret = bn_quic_send_pending(stream->ctx);
    if (ret != BN_QUIC_SUCCESS) {
        return ret;
    }
    
    return BN_QUIC_SUCCESS;
}

/**
 * @brief Receive data from a QUIC stream
 * 
 * @param stream QUIC stream
 * @param buffer Buffer to store the received data
 * @param len Maximum length of data to receive
 * @param received Pointer to store the number of bytes received
 * @param fin Pointer to store whether the stream has been closed by the peer
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_stream_recv(bn_quic_stream_t *stream, uint8_t *buffer, 
                        size_t len, size_t *received, bool *fin) {
    if (!stream || !buffer || !received || !fin || !stream->ctx || 
        !stream->ctx->conn) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    /* Check if stream is closed */
    if (stream->flags.closed_by_peer || stream->flags.fin_received) {
        *received = 0;
        *fin = true;
        return BN_QUIC_SUCCESS;
    }
    
    /* Check if connection is closed */
    if (stream->ctx->flags.connection_closed) {
        return BN_QUIC_ERROR_CLOSED;
    }
    
    /* Process any pending packets */
    int ret = bn_quic_process(stream->ctx, 0);
    if (ret != BN_QUIC_SUCCESS && ret != BN_QUIC_ERROR_TIMEOUT) {
        return ret;
    }
    
    /* Receive data from stream */
    uint32_t flags = 0;
    
    /* For ngtcp2, stream data is delivered in the callback, not via a direct read function.
     * We need to implement a buffer mechanism that stores data received in callbacks.
     * For now, we'll return a "not implemented" error
     */
    if (received) {
        *received = 0;
    }
    if (fin) {
        *fin = false;
    }
    
    return BN_QUIC_ERROR_UNINITIALIZED; // Not yet implemented
}

/**
 * @brief Close a QUIC stream
 * 
 * @param stream QUIC stream
 * @return BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_stream_close(bn_quic_stream_t *stream) {
    if (!stream || !stream->ctx || !stream->ctx->conn) {
        return BN_QUIC_ERROR_INVALID_PARAM;
    }
    
    if (stream->flags.closed_locally) {
        /* Stream already closed locally, just free the structure */
        free(stream);
        return BN_QUIC_SUCCESS;
    }
    
    /* Shutdown the stream in the write direction if not already done */
    if (!stream->flags.fin_sent) {
        int ret = ngtcp2_conn_shutdown_stream(stream->ctx->conn, 0, 
                                          stream->stream_id, 0);
        if (ret != 0 && ret != NGTCP2_ERR_STREAM_NOT_FOUND && 
            ret != NGTCP2_ERR_STREAM_SHUT_WR) {
            /* Ignore if stream was not found or already shut down */
            free(stream);
            return bn_quic_map_error(ret);
        }
        
        stream->flags.fin_sent = 1;
    }
    
    /* Mark stream as closed locally */
    stream->flags.closed_locally = 1;
    
    /* Send any pending data */
    int ret = bn_quic_send_pending(stream->ctx);
    
    /* Free the stream structure */
    free(stream);
    
    if (ret != BN_QUIC_SUCCESS && ret != BN_QUIC_ERROR_TIMEOUT) {
        return ret;
    }
    
    return BN_QUIC_SUCCESS;
}