#include "htx.h"
#include "frame.h"
#include "noise.h"
#include "ticket.h"
#include "origin_mirror.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>

/* Forward declarations for internal functions */
static int htx_connection_process_frames(HTXConnection *conn, const uint8_t *data, 
                                        size_t len, size_t *processed_out);
static int htx_connection_handle_frame(HTXConnection *conn, const HTXFrame *frame);
static int htx_connection_handle_stream_frame(HTXConnection *conn, const HTXFrame *frame);
static int htx_connection_handle_ping_frame(HTXConnection *conn, const HTXFrame *frame);
static int htx_connection_handle_close_frame(HTXConnection *conn, const HTXFrame *frame);
static int htx_connection_handle_window_update_frame(HTXConnection *conn, const HTXFrame *frame);
static int htx_connection_handle_key_update_frame(HTXConnection *conn, const HTXFrame *frame);
static int htx_connection_generate_frames(HTXConnection *conn, uint8_t *buffer, 
                                         size_t buffer_size, size_t *written_out);
static int htx_connection_queue_frame(HTXConnection *conn, const HTXFrame *frame);

/**
 * @brief Internal stream structure
 */
struct HTXStream {
    uint32_t stream_id;
    HTXStreamState state;
    HTXConnection *connection;
    
    /* Flow control */
    uint32_t send_window;
    uint32_t recv_window;
    
    /* Data queues */
    uint8_t *send_buffer;
    size_t send_buffer_size;
    size_t send_buffer_used;
    
    struct HTXStream *next;
};

/**
 * @brief Internal connection structure
 */
struct HTXConnection {
    HTXConfig config;
    HTXConnectionState state;
    
    /* Transport layer */
    int socket_fd;
    HTXNoiseState *noise_state;
    HTXOriginMirror *origin_mirror;
    HTXTicketManager *ticket_manager;
    
    /* Stream management */
    struct HTXStream *streams;
    uint32_t next_stream_id;
    uint32_t stream_count;
    pthread_mutex_t streams_mutex;
    
    /* Flow control */
    uint32_t connection_send_window;
    uint32_t connection_recv_window;
    
    /* Outgoing data queue */
    uint8_t *output_buffer;
    size_t output_buffer_size;
    size_t output_buffer_used;
    
    /* Timing */
    time_t last_ping_sent;
    time_t last_activity;
    
    /* Threading */
    pthread_mutex_t connection_mutex;
};

/**
 * @brief Default configuration values
 */
#define HTX_DEFAULT_WINDOW_SIZE     65535
#define HTX_DEFAULT_MAX_STREAMS     100
#define HTX_DEFAULT_PING_INTERVAL   30000  /* 30 seconds */
#define HTX_DEFAULT_IDLE_TIMEOUT    300000 /* 5 minutes */
#define HTX_DEFAULT_TICKET_LIFETIME 3600   /* 1 hour */

int htx_config_init(HTXConfig *config) {
    if (!config) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    memset(config, 0, sizeof(HTXConfig));
    
    config->transport_type = HTX_TRANSPORT_TCP;
    config->require_access_ticket = false;
    config->ticket_lifetime_sec = HTX_DEFAULT_TICKET_LIFETIME;
    config->initial_window_size = HTX_DEFAULT_WINDOW_SIZE;
    config->max_streams = HTX_DEFAULT_MAX_STREAMS;
    config->ping_interval_ms = HTX_DEFAULT_PING_INTERVAL;
    config->idle_timeout_ms = HTX_DEFAULT_IDLE_TIMEOUT;
    
    return 0;
}

int htx_connection_create(const HTXConfig *config, HTXConnection **conn_out) {
    HTXConnection *conn = NULL;
    int result = HTX_ERROR_INVALID_PARAM;
    
    if (!config || !conn_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    /* Validate configuration */
    if (!config->origin_domain) {
        return HTX_ERROR_INVALID_STATE;
    }
    
    conn = calloc(1, sizeof(HTXConnection));
    if (!conn) {
        return HTX_ERROR_ALLOCATION_FAILED;
    }

    result = HTX_ERROR_INVALID_PARAM;  // Set default error for cleanup path
    
    /* Copy configuration */
    memcpy(&conn->config, config, sizeof(HTXConfig));
    
    /* Initialize connection state */
    conn->state = HTX_CONN_STATE_INIT;
    conn->next_stream_id = 1;
    conn->connection_send_window = config->initial_window_size;
    conn->connection_recv_window = config->initial_window_size;
    
    /* Initialize mutexes */
    /* Initialize mutexes */
    int mutex1_init = 0, mutex2_init = 0;
    if (pthread_mutex_init(&conn->connection_mutex, NULL) != 0) {
        result = HTX_ERROR_INVALID_PARAM;
        goto cleanup;
    }
    mutex1_init = 1;

    if (pthread_mutex_init(&conn->streams_mutex, NULL) != 0) {
        result = HTX_ERROR_INVALID_PARAM;
        goto cleanup;
    }
    mutex2_init = 1;

    /* … other setup code … */

cleanup:
    if (conn) {
        if (conn->output_buffer) {
            free(conn->output_buffer);
        }
        if (mutex2_init) pthread_mutex_destroy(&conn->streams_mutex);
        if (mutex1_init) pthread_mutex_destroy(&conn->connection_mutex);
        free(conn);
    }
    
    /* Allocate output buffer */
    conn->output_buffer_size = 4096;
    conn->output_buffer = malloc(conn->output_buffer_size);
    if (!conn->output_buffer) {
        result = HTX_ERROR_INVALID_PARAM;
        goto cleanup;
    }
    
    /* Initialize timing */
    conn->last_activity = time(NULL);
    
    *conn_out = conn;
    return 0;
    
cleanup:
    if (conn) {
        if (conn->output_buffer) {
            free(conn->output_buffer);
        }
        pthread_mutex_destroy(&conn->connection_mutex);
        pthread_mutex_destroy(&conn->streams_mutex);
        free(conn);
    }
    return result;
}

int htx_connection_destroy(HTXConnection *conn) {
    if (!conn) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->connection_mutex);
    
    /* Close all streams */
    pthread_mutex_lock(&conn->streams_mutex);
    struct HTXStream *stream = conn->streams;
    while (stream) {
        struct HTXStream *next = stream->next;
        if (stream->send_buffer) {
            memset(stream->send_buffer, 0, stream->send_buffer_size);
            free(stream->send_buffer);
        }
        memset(stream, 0, sizeof(struct HTXStream));
        free(stream);
        stream = next;
    }
    pthread_mutex_unlock(&conn->streams_mutex);
    
    /* Clean up connection resources */
    if (conn->noise_state) {
        htx_noise_cleanup(conn->noise_state);
    }
    
    if (conn->origin_mirror) {
        htx_origin_mirror_cleanup(conn->origin_mirror);
    }
    
    if (conn->ticket_manager) {
        htx_ticket_manager_cleanup(conn->ticket_manager);
    }
    
    if (conn->output_buffer) {
        memset(conn->output_buffer, 0, conn->output_buffer_size);
        free(conn->output_buffer);
    }
    
    if (conn->socket_fd > 0) {
        close(conn->socket_fd);
    }
    
    pthread_mutex_unlock(&conn->connection_mutex);
    pthread_mutex_destroy(&conn->connection_mutex);
    pthread_mutex_destroy(&conn->streams_mutex);
    
    memset(conn, 0, sizeof(HTXConnection));
    free(conn);
    
    return 0;
}

int htx_connection_get_state(const HTXConnection *conn, HTXConnectionState *state_out) {
    if (!conn || !state_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    *state_out = conn->state;
    return 0;
}

int htx_connection_process_input(HTXConnection *conn, const uint8_t *data, 
                                size_t len, size_t *processed_out) {
    if (!conn || !data || !processed_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->connection_mutex);
    
    size_t total_processed = 0;
    int result = 0;
    
    /* Update activity timestamp */
    conn->last_activity = time(NULL);
    
    /* Process based on connection state */
    switch (conn->state) {
        case HTX_CONN_STATE_INIT:
        case HTX_CONN_STATE_HANDSHAKE:
            /* Handle TLS and Noise handshake */
            if (conn->noise_state) {
                size_t noise_processed = 0;
                result = htx_noise_process_input(conn->noise_state, data, len, &noise_processed);
                total_processed += noise_processed;
                
                if (result == 0 && htx_noise_is_ready(conn->noise_state)) {
                    conn->state = HTX_CONN_STATE_READY;
                }
            }
            break;
            
        case HTX_CONN_STATE_READY:
            /* Process encrypted HTX frames */
            result = htx_connection_process_frames(conn, data, len, &total_processed);
            break;
            
        case HTX_CONN_STATE_CLOSING:
        case HTX_CONN_STATE_CLOSED:
            /* Ignore data for closed connections */
            total_processed = len;
            break;
            
        default:
            result = HTX_ERROR_INVALID_STATE;
            break;
    }
    
    *processed_out = total_processed;
    
    pthread_mutex_unlock(&conn->connection_mutex);
    return result;
}

/**
 * @brief Internal function to process HTX frames
 */
static int htx_connection_process_frames(HTXConnection *conn, const uint8_t *data, 
                                        size_t len, size_t *processed_out) {
    size_t total_processed = 0;
    int result = 0;
    
    /* Decrypt data if we have encrypted transport */
    uint8_t *decrypted_data = NULL;
    size_t decrypted_len = 0;
    
    if (conn->noise_state && htx_noise_is_ready(conn->noise_state)) {
        result = htx_noise_decrypt(conn->noise_state, data, len, 
                                  &decrypted_data, &decrypted_len);
        if (result < 0) {
            return HTX_ERROR_NOISE_FAILURE;
        }
    } else {
        /* Direct frame processing for testing */
        /* For unencrypted data, we need to copy to maintain const-correctness */
        decrypted_data = malloc(len);
        if (!decrypted_data) {
            return HTX_ERROR_ALLOCATION_FAILED;
        }
        memcpy(decrypted_data, data, len);
        decrypted_len = len;
    }
    
    /* Process frames from decrypted data */
    size_t offset = 0;
    while (offset < decrypted_len) {
        HTXFrame frame;
        size_t frame_consumed = 0;
        
        result = htx_frame_parse(decrypted_data + offset, decrypted_len - offset,
                                &frame, &frame_consumed);
        if (result < 0) {
            if (result == HTX_ERROR_BUFFER_TOO_SMALL) {
                /* Need more data */
                break;
            }
            /* Protocol error */
            htx_frame_cleanup(&frame);
            break;
        }
        
        /* Validate frame */
        result = htx_frame_validate(&frame);
        if (result < 0) {
            htx_frame_cleanup(&frame);
            result = HTX_ERROR_PROTOCOL_VIOLATION;
            break;
        }
        
        /* Process frame based on type */
        result = htx_connection_handle_frame(conn, &frame);
        htx_frame_cleanup(&frame);
        
        if (result < 0) {
            break;
        }
        
        offset += frame_consumed;
    }
    
    /* Clean up decrypted data if allocated */
    /* track whether noise decryption actually allocated a new buffer */
    bool decrypted_allocated = false;

    if (conn->noise_state && htx_noise_is_ready(conn->noise_state)) {
        result = htx_noise_decrypt(conn->noise_state, data, len,
                                  &decrypted_data, &decrypted_len);
        if (result < 0) {
            return HTX_ERROR_NOISE_FAILURE;
        }
        decrypted_allocated = true;
    } else {
        decrypted_data = (uint8_t *)data;
        decrypted_len  = len;
    }

    /* only zero & free if we really allocated a separate buffer */
    if (decrypted_allocated && decrypted_data) {
        memset(decrypted_data, 0, decrypted_len);
        free(decrypted_data);
    }
    
    *processed_out = total_processed;
    return result;
}

/**
 * @brief Internal function to handle individual frames
 */
static int htx_connection_handle_frame(HTXConnection *conn, const HTXFrame *frame) {
    int result = 0;
    
    switch (frame->type) {
        case HTX_FRAME_TYPE_STREAM:
            result = htx_connection_handle_stream_frame(conn, frame);
            break;
            
        case HTX_FRAME_TYPE_PING:
            result = htx_connection_handle_ping_frame(conn, frame);
            break;
            
        case HTX_FRAME_TYPE_CLOSE:
            result = htx_connection_handle_close_frame(conn, frame);
            break;
            
        case HTX_FRAME_TYPE_WINDOW_UPDATE:
            result = htx_connection_handle_window_update_frame(conn, frame);
            break;
            
        case HTX_FRAME_TYPE_KEY_UPDATE:
            result = htx_connection_handle_key_update_frame(conn, frame);
            break;
            
        default:
            /* Unknown frame types are ignored */
            result = 0;
            break;
    }
    
    return result;
}

int htx_connection_generate_output(HTXConnection *conn, uint8_t *buffer, 
                                  size_t buffer_size, size_t *written_out) {
    if (!conn || !buffer || !written_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&conn->connection_mutex);
    
    size_t total_written = 0;
    int result = 0;
    
    /* Generate output based on connection state */
    switch (conn->state) {
        case HTX_CONN_STATE_INIT:
        case HTX_CONN_STATE_HANDSHAKE:
            /* Generate handshake data */
            if (conn->noise_state) {
                result = htx_noise_generate_output(conn->noise_state, buffer, 
                                                  buffer_size, &total_written);
            }
            break;
            
        case HTX_CONN_STATE_READY:
            /* Generate pending frames and heartbeats */
            result = htx_connection_generate_frames(conn, buffer, buffer_size, &total_written);
            break;
            
        case HTX_CONN_STATE_CLOSING:
        case HTX_CONN_STATE_CLOSED:
            /* No output for closed connections */
            total_written = 0;
            break;
            
        default:
            result = HTX_ERROR_INVALID_STATE;
            break;
    }
    
    *written_out = total_written;
    
    pthread_mutex_unlock(&conn->connection_mutex);
    return result;
}

int htx_stream_create(HTXConnection *conn, HTXStream **stream_out) {
    if (!conn || !stream_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    if (conn->state != HTX_CONN_STATE_READY) {
        return HTX_ERROR_INVALID_STATE;
    }
    
    pthread_mutex_lock(&conn->streams_mutex);
    
    /* Check stream limit */
    if (conn->stream_count >= conn->config.max_streams) {
        pthread_mutex_unlock(&conn->streams_mutex);
        return HTX_ERROR_INVALID_STATE;
    }
    
    /* Allocate new stream */
    struct HTXStream *stream = calloc(1, sizeof(struct HTXStream));
    if (!stream) {
        pthread_mutex_unlock(&conn->streams_mutex);
        return HTX_ERROR_INVALID_PARAM;
    }
    
    /* Initialize stream */
    stream->stream_id = conn->next_stream_id;
    conn->next_stream_id += 2; /* Client streams are odd */
    stream->state = HTX_STREAM_STATE_IDLE;
    stream->connection = conn;
    stream->send_window = conn->config.initial_window_size;
    stream->recv_window = conn->config.initial_window_size;
    
    /* Add to stream list */
    stream->next = conn->streams;
    conn->streams = stream;
    conn->stream_count++;
    
    *stream_out = stream;
    
    pthread_mutex_unlock(&conn->streams_mutex);
    return 0;
}

int htx_stream_send(HTXStream *stream, const uint8_t *data, size_t len, size_t *sent_out) {
    if (!stream || !data || !sent_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    if (stream->state == HTX_STREAM_STATE_CLOSED) {
        return HTX_ERROR_STREAM_CLOSED;
    }
    
    /* For now, create a simple STREAM frame */
    HTXFrame frame;
    int result = htx_frame_create_stream(stream->stream_id, data, len, false, &frame);
    if (result < 0) {
        return result;
    }
    
    /* Queue frame for transmission */
    result = htx_connection_queue_frame(stream->connection, &frame);
    htx_frame_cleanup(&frame);
    
    if (result == 0) {
        *sent_out = len;
        stream->state = HTX_STREAM_STATE_OPEN;
    }
    
    return result;
}

int htx_stream_close(HTXStream *stream) {
    if (!stream) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    /* Create close frame */
    HTXFrame frame;
    int result = htx_frame_create_close(stream->stream_id, &frame);
    if (result < 0) {
        return result;
    }
    
    /* Queue frame for transmission */
    result = htx_connection_queue_frame(stream->connection, &frame);
    htx_frame_cleanup(&frame);
    
    if (result == 0) {
        stream->state = HTX_STREAM_STATE_CLOSED;
    }
    
    return result;
}

int htx_stream_get_state(const HTXStream *stream, HTXStreamState *state_out) {
    if (!stream || !state_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    *state_out = stream->state;
    return 0;
}

int htx_stream_get_id(const HTXStream *stream, uint32_t *stream_id_out) {
    if (!stream || !stream_id_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    *stream_id_out = stream->stream_id;
    return 0;
}

int htx_stream_update_window(HTXStream *stream, uint32_t increment) {
    if (!stream || increment == 0) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    if (stream->state == HTX_STREAM_STATE_CLOSED) {
        return HTX_ERROR_INVALID_STATE;
    }
    
    /* Create window update frame */
    HTXFrame frame;
    int result = htx_frame_create_window_update(stream->stream_id, increment, &frame);
    if (result < 0) {
        return result;
    }
    
    /* Queue frame for transmission */
    result = htx_connection_queue_frame(stream->connection, &frame);
    htx_frame_cleanup(&frame);
    
    if (result == 0) {
        stream->recv_window += increment;
    }
    
    return result;
}

/**
 * @brief Internal function implementations
 */

static int htx_connection_handle_stream_frame(HTXConnection *conn, const HTXFrame *frame) {
    /* Find the stream */
    pthread_mutex_lock(&conn->streams_mutex);
    struct HTXStream *stream = conn->streams;
    while (stream && stream->stream_id != frame->stream_id) {
        stream = stream->next;
    }
    pthread_mutex_unlock(&conn->streams_mutex);
    
    if (!stream) {
        /* Stream not found - could be a new incoming stream */
        return 0;
    }
    
    /* Deliver data to application */
    if (frame->length > 0 && conn->config.data_callback) {
        const uint8_t *payload_data;
        size_t payload_size;
        htx_frame_get_payload(frame, &payload_data, &payload_size);
        conn->config.data_callback(stream, payload_data, payload_size, conn->config.user_data);
    }
    
    /* Handle end of stream */
    if (frame->flags & HTX_FRAME_FLAG_END_STREAM) {
        stream->state = HTX_STREAM_STATE_HALF_CLOSED_REMOTE;
        if (conn->config.stream_close_callback) {
            conn->config.stream_close_callback(stream, conn->config.user_data);
        }
    }
    
    return 0;
}

static int htx_connection_handle_ping_frame(HTXConnection *conn, const HTXFrame *frame) {
    if (!(frame->flags & HTX_FRAME_FLAG_ACK)) {
        /* Send PING ACK */
        HTXFrame ping_ack;
        const uint8_t *payload_data = NULL;
        size_t payload_size = 0;
        
        htx_frame_get_payload(frame, &payload_data, &payload_size);
        uint8_t ping_payload[8] = {0};
        if (payload_size == 8) {
            memcpy(ping_payload, payload_data, 8);
        }
        
        int result = htx_frame_create_ping(true, payload_size > 0 ? ping_payload : NULL, &ping_ack);
        if (result == 0) {
            htx_connection_queue_frame(conn, &ping_ack);
            htx_frame_cleanup(&ping_ack);
        }
    }
    
    return 0;
}

static int htx_connection_handle_close_frame(HTXConnection *conn, const HTXFrame *frame) {
    /* Find and close the stream */
    pthread_mutex_lock(&conn->streams_mutex);
    struct HTXStream *stream = conn->streams;
    while (stream && stream->stream_id != frame->stream_id) {
        stream = stream->next;
    }
    
    if (stream) {
        stream->state = HTX_STREAM_STATE_CLOSED;
        if (conn->config.stream_close_callback) {
            conn->config.stream_close_callback(stream, conn->config.user_data);
        }
    }
    pthread_mutex_unlock(&conn->streams_mutex);
    
    return 0;
}

static int htx_connection_handle_window_update_frame(HTXConnection *conn, const HTXFrame *frame) {
    if (frame->length != 4) {
        return HTX_ERROR_PROTOCOL_VIOLATION;
    }
    
    const uint8_t *payload_data;
    size_t payload_size;
    htx_frame_get_payload(frame, &payload_data, &payload_size);
    
    uint32_t increment = ntohl(*(uint32_t*)payload_data);
    if (increment == 0) {
        return HTX_ERROR_PROTOCOL_VIOLATION;
    }
    
    if (frame->stream_id == 0) {
        /* Connection-level window update */
        conn->connection_send_window += increment;
    } else {
        /* Stream-level window update */
        pthread_mutex_lock(&conn->streams_mutex);
        struct HTXStream *stream = conn->streams;
        while (stream && stream->stream_id != frame->stream_id) {
            stream = stream->next;
        }
        
        if (stream) {
            stream->send_window += increment;
        }
        pthread_mutex_unlock(&conn->streams_mutex);
    }
    
    return 0;
}

static int htx_connection_handle_key_update_frame(HTXConnection *conn, const HTXFrame *frame) {
    /* Trigger key rotation in Noise protocol */
    if (conn->noise_state) {
        return htx_noise_rotate_keys(conn->noise_state);
    }
    return 0;
}

static int htx_connection_generate_frames(HTXConnection *conn, uint8_t *buffer, 
                                         size_t buffer_size, size_t *written_out) {
    size_t total_written = 0;
    
    /* Copy any queued output data */
    if (conn->output_buffer_used > 0) {
        size_t to_copy = conn->output_buffer_used;
        if (to_copy > buffer_size) {
            to_copy = buffer_size;
        }
        
        memcpy(buffer, conn->output_buffer, to_copy);
        
        /* Remove copied data from queue */
        if (to_copy < conn->output_buffer_used) {
            memmove(conn->output_buffer, conn->output_buffer + to_copy, 
                   conn->output_buffer_used - to_copy);
        }
        conn->output_buffer_used -= to_copy;
        total_written += to_copy;
    }
    
    /* Generate periodic PING frames */
    time_t now = time(NULL);
    if ((now - conn->last_ping_sent) * 1000 >= conn->config.ping_interval_ms) {
        if (total_written + HTX_FRAME_HEADER_SIZE <= buffer_size) {
            HTXFrame ping_frame;
            if (htx_frame_create_ping(false, NULL, &ping_frame) == 0) {
                size_t frame_written = 0;
                if (htx_frame_serialize(&ping_frame, buffer + total_written, 
                                       buffer_size - total_written, &frame_written) == 0) {
                    total_written += frame_written;
                    conn->last_ping_sent = now;
                }
                htx_frame_cleanup(&ping_frame);
            }
        }
    }
    
    *written_out = total_written;
    return 0;
}

static int htx_connection_queue_frame(HTXConnection *conn, const HTXFrame *frame) {
    size_t frame_size;
    int result = htx_frame_get_total_size(frame, &frame_size);
    if (result < 0) {
        return result;
    }
    
    /* Ensure output buffer has space */
    if (conn->output_buffer_used + frame_size > conn->output_buffer_size) {
        size_t new_size = conn->output_buffer_size * 2;
        while (new_size < conn->output_buffer_used + frame_size) {
            new_size *= 2;
        }
        
        uint8_t *new_buffer = realloc(conn->output_buffer, new_size);
        if (!new_buffer) {
            return HTX_ERROR_INVALID_PARAM;
        }
        
        conn->output_buffer = new_buffer;
        conn->output_buffer_size = new_size;
    }
    
    /* Serialize frame to output buffer */
    size_t written = 0;
    result = htx_frame_serialize(frame, conn->output_buffer + conn->output_buffer_used,
                                conn->output_buffer_size - conn->output_buffer_used, &written);
    if (result == 0) {
        conn->output_buffer_used += written;
    }
    
    return result;
}
