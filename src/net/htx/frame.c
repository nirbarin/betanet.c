#include "frame.h"
#include "htx.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/**
 * @brief Write a 24-bit value to buffer in network byte order
 */
static void write_uint24(uint8_t *buffer, uint32_t value) {
    buffer[0] = (value >> 16) & 0xFF;
    buffer[1] = (value >> 8) & 0xFF;
    buffer[2] = value & 0xFF;
}

/**
 * @brief Read a 24-bit value from buffer in network byte order
 */
static uint32_t read_uint24(const uint8_t *buffer) {
    return ((uint32_t)buffer[0] << 16) | 
           ((uint32_t)buffer[1] << 8) | 
           ((uint32_t)buffer[2]);
}

int htx_frame_init(HTXFrame *frame, uint8_t type, uint8_t flags, 
                   uint32_t stream_id, size_t payload_size) {
    if (!frame) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    if (payload_size > HTX_FRAME_MAX_PAYLOAD_SIZE) {
        return HTX_ERROR_FRAME_TOO_LARGE;
    }
    
    if ((stream_id & ~HTX_STREAM_ID_MASK) != 0) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    memset(frame, 0, sizeof(HTXFrame));
    
    frame->length = payload_size;
    frame->type = type;
    frame->flags = flags;
    frame->stream_id = stream_id;
    
    if (payload_size > 0) {
        frame->payload = malloc(payload_size);
    if (payload_size > 0) {
        frame->payload = malloc(payload_size);
        if (!frame->payload) {
            return HTX_ERROR_ALLOCATION_FAILED;
        }
        /* ... */
    }
        frame->payload_capacity = payload_size;
    }
    
    return 0;
}

int htx_frame_cleanup(HTXFrame *frame) {
    if (!frame) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    if (frame->payload) {
        memset(frame->payload, 0, frame->payload_capacity);
        free(frame->payload);
        frame->payload = NULL;
    }
    
    memset(frame, 0, sizeof(HTXFrame));
    return 0;
}

int htx_frame_parse(const uint8_t *buffer, size_t buffer_size, 
                    HTXFrame *frame_out, size_t *bytes_consumed_out) {
    if (!buffer || !frame_out || !bytes_consumed_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    if (buffer_size < HTX_FRAME_HEADER_SIZE) {
        return HTX_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Parse frame header */
    uint32_t length = read_uint24(buffer);
    uint8_t type = buffer[3];
    uint8_t flags = buffer[4];
    uint32_t stream_id = ntohl(*(uint32_t*)(buffer + 4)) & HTX_STREAM_ID_MASK;
    
    /* Validate frame parameters */
    if (length > HTX_FRAME_MAX_PAYLOAD_SIZE) {
        return HTX_ERROR_FRAME_TOO_LARGE;
    }
    
    if (buffer_size < HTX_FRAME_HEADER_SIZE + length) {
        return HTX_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Initialize frame structure */
    int result = htx_frame_init(frame_out, type, flags, stream_id, length);
    if (result < 0) {
        return result;
    }
    
    /* Copy payload data if present */
    if (length > 0) {
        memcpy(frame_out->payload, buffer + HTX_FRAME_HEADER_SIZE, length);
    }
    
    *bytes_consumed_out = HTX_FRAME_HEADER_SIZE + length;
    return 0;
}

int htx_frame_serialize(const HTXFrame *frame, uint8_t *buffer, 
                        size_t buffer_size, size_t *bytes_written_out) {
    if (!frame || !buffer || !bytes_written_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    size_t total_size = HTX_FRAME_HEADER_SIZE + frame->length;
    if (buffer_size < total_size) {
        return HTX_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Write frame header */
    write_uint24(buffer, frame->length);
    buffer[3] = frame->type;
    /* Write frame header */
    write_uint24(buffer, frame->length);
    buffer[3] = frame->type;
    /* Write flags and stream ID (preserve reserved bit as 0) */
    uint32_t flags_and_stream_id = (((uint32_t)frame->flags) << 24) |
                                   (frame->stream_id & HTX_STREAM_ID_MASK);
    uint32_t stream_id_network = htonl(flags_and_stream_id);
    memcpy(buffer + 4, &stream_id_network, 4);
    
    /* Copy payload if present */
    if (frame->length > 0 && frame->payload) {
        memcpy(buffer + HTX_FRAME_HEADER_SIZE, frame->payload, frame->length);
    }
    
    *bytes_written_out = total_size;
    return 0;
}

int htx_frame_set_payload(HTXFrame *frame, const uint8_t *data, size_t data_size) {
    if (!frame) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    if (data_size > HTX_FRAME_MAX_PAYLOAD_SIZE) {
        return HTX_ERROR_FRAME_TOO_LARGE;
    }
    
    /* Reallocate payload buffer if needed */
    if (data_size > frame->payload_capacity) {
        uint8_t *new_payload = realloc(frame->payload, data_size);
        if (!new_payload) {
            return HTX_ERROR_INVALID_PARAM;
        }
        frame->payload = new_payload;
        frame->payload_capacity = data_size;
    }
    
    /* Copy data and update length */
    if (data_size > 0 && data) {
        memcpy(frame->payload, data, data_size);
    }
    frame->length = data_size;
    
    return 0;
}

int htx_frame_get_payload(const HTXFrame *frame, const uint8_t **data_out, size_t *size_out) {
    if (!frame || !data_out || !size_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    *data_out = frame->payload;
    *size_out = frame->length;
    return 0;
}

int htx_frame_get_total_size(const HTXFrame *frame, size_t *size_out) {
    if (!frame || !size_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    *size_out = HTX_FRAME_HEADER_SIZE + frame->length;
    return 0;
}

int htx_frame_validate(const HTXFrame *frame) {
    if (!frame) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    /* Check payload size */
    if (frame->length > HTX_FRAME_MAX_PAYLOAD_SIZE) {
        return HTX_ERROR_PROTOCOL_VIOLATION;
    }
    
    /* Check stream ID range */
    if ((frame->stream_id & ~HTX_STREAM_ID_MASK) != 0) {
        return HTX_ERROR_PROTOCOL_VIOLATION;
    }
    
    /* Type-specific validation */
    switch (frame->type) {
        case HTX_FRAME_TYPE_STREAM:
            /* STREAM frames can have any valid stream ID > 0 */
            if (frame->stream_id == 0) {
                return HTX_ERROR_PROTOCOL_VIOLATION;
            }
            break;
            
        case HTX_FRAME_TYPE_PING:
            /* PING frames must have stream ID 0 and payload of 0 or 8 bytes */
            if (frame->stream_id != 0) {
                return HTX_ERROR_PROTOCOL_VIOLATION;
            }
            if (frame->length != 0 && frame->length != 8) {
                return HTX_ERROR_PROTOCOL_VIOLATION;
            }
            break;
            
        case HTX_FRAME_TYPE_CLOSE:
            /* CLOSE frames must have valid stream ID > 0 and no payload */
            if (frame->stream_id == 0 || frame->length != 0) {
                return HTX_ERROR_PROTOCOL_VIOLATION;
            }
            break;
            
        case HTX_FRAME_TYPE_KEY_UPDATE:
            /* KEY_UPDATE frames must have stream ID 0 and no payload */
            if (frame->stream_id != 0 || frame->length != 0) {
                return HTX_ERROR_PROTOCOL_VIOLATION;
            }
            break;
            
        case HTX_FRAME_TYPE_WINDOW_UPDATE:
            /* WINDOW_UPDATE frames must have 4-byte payload */
            if (frame->length != 4) {
                return HTX_ERROR_PROTOCOL_VIOLATION;
            }
            break;
            
        default:
            /* Unknown frame types are invalid */
            return HTX_ERROR_PROTOCOL_VIOLATION;
    }
    
    return 0;
}

int htx_frame_create_stream(uint32_t stream_id, const uint8_t *data, 
                           size_t data_size, bool end_stream, HTXFrame *frame_out) {
    if (!frame_out || stream_id == 0) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    uint8_t flags = end_stream ? HTX_FRAME_FLAG_END_STREAM : HTX_FRAME_FLAG_NONE;
    
    int result = htx_frame_init(frame_out, HTX_FRAME_TYPE_STREAM, flags, 
                               stream_id, data_size);
    if (result < 0) {
        return result;
    }
    
    if (data_size > 0 && data) {
        memcpy(frame_out->payload, data, data_size);
    }
    
    return 0;
}

int htx_frame_create_ping(bool ack, const uint8_t payload[8], HTXFrame *frame_out) {
    if (!frame_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    uint8_t flags = ack ? HTX_FRAME_FLAG_ACK : HTX_FRAME_FLAG_NONE;
    size_t payload_size = payload ? 8 : 0;
    
    int result = htx_frame_init(frame_out, HTX_FRAME_TYPE_PING, flags, 0, payload_size);
    if (result < 0) {
        return result;
    }
    
    if (payload) {
        memcpy(frame_out->payload, payload, 8);
    }
    
    return 0;
}

int htx_frame_create_close(uint32_t stream_id, HTXFrame *frame_out) {
    if (!frame_out || stream_id == 0) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    return htx_frame_init(frame_out, HTX_FRAME_TYPE_CLOSE, HTX_FRAME_FLAG_NONE, 
                         stream_id, 0);
}

int htx_frame_create_window_update(uint32_t stream_id, uint32_t window_increment, 
                                  HTXFrame *frame_out) {
    if (!frame_out || window_increment == 0) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    int result = htx_frame_init(frame_out, HTX_FRAME_TYPE_WINDOW_UPDATE, 
                               HTX_FRAME_FLAG_NONE, stream_id, 4);
    if (result < 0) {
        return result;
    }
    
    /* Write window increment in network byte order */
    uint32_t increment_network = htonl(window_increment);
    memcpy(frame_out->payload, &increment_network, 4);
    
    return 0;
}
