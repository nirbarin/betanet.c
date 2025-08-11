/**
 * @file internal.h
 * @brief Internal definitions for QUIC transport implementation
 * 
 * This header contains internal structures and function declarations
 * that are used by the QUIC transport implementation.
 */

#ifndef BETANET_NET_QUIC_INTERNAL_H_
#define BETANET_NET_QUIC_INTERNAL_H_

#include "quic.h"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/**
 * @brief Maximum size of a QUIC datagram
 * 
 * This value is chosen to ensure that the packet will fit within the
 * typical MTU without fragmentation, including all headers.
 */
#define BN_QUIC_MAX_DATAGRAM_SIZE 1350

/**
 * @brief Default QUIC protocol version (RFC 9000)
 */
#define BN_QUIC_PROTOCOL_VERSION NGTCP2_PROTO_VER_V1

/**
 * @brief Length of the connection ID in bytes
 */
#define BN_QUIC_CONN_ID_LEN 16

/**
 * @brief Maximum number of QUIC packets to process in a single call
 */
#define BN_QUIC_MAX_BATCH_SIZE 16

/**
 * @brief Minimum interval between packet processing in milliseconds
 */
#define BN_QUIC_MIN_PROCESS_INTERVAL_MS 5

/**
 * @brief Path validation ID for the default path
 */
#define BN_QUIC_DEFAULT_PATH_ID 0

/**
 * @brief Internal QUIC transport context structure
 */
struct bn_quic_ctx_s {
    /** ngtcp2 connection handle */
    ngtcp2_conn *conn;
    
    /** SSL context for the connection */
    SSL_CTX *ssl_ctx;
    
    /** SSL object for the connection */
    SSL *ssl;
    
    /** UDP socket file descriptor */
    int sock;
    
    /** Peer address */
    struct sockaddr_storage peer_addr;
    
    /** Peer address length */
    socklen_t peer_addr_len;
    
    /** Local address */
    struct sockaddr_storage local_addr;
    
    /** Local address length */
    socklen_t local_addr_len;
    
    /** Connection configuration */
    bn_quic_config_t config;
    
    /** Connection state */
    struct {
        /** Whether the TLS handshake is complete */
        uint8_t handshake_complete:1;
        
        /** Whether the connection is closed */
        uint8_t connection_closed:1;
        
        /** Whether QUIC appears to be blocked on the network */
        uint8_t quic_blocked:1;
        
        /** Whether this is a server connection */
        uint8_t is_server:1;
        
        /** Reserved for future use */
        uint8_t reserved:4;
    } flags;
    
    /** Local connection ID */
    ngtcp2_cid scid;
    
    /** Remote connection ID (if known) */
    ngtcp2_cid dcid;
    
    /** Time of last packet send/receive in milliseconds since epoch */
    uint64_t last_activity_ms;
    
    /** Number of connection attempts */
    uint8_t connection_attempts;
    
    /** MASQUE session ID (if using MASQUE) */
    uint32_t masque_session_id;
    
    /** Buffer for sending packets */
    uint8_t send_buf[BN_QUIC_MAX_DATAGRAM_SIZE];
    
    /** Crypto stream send buffer */
    uint8_t crypto_send_buf[BN_QUIC_MAX_DATAGRAM_SIZE];
    
    /** Crypto stream send buffer length */
    size_t crypto_send_buf_len;
    
    /** Crypto stream send buffer offset */
    size_t crypto_send_buf_offset;
    
    /** Path validation buffer for receiving validation data */
    uint8_t path_validation_buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
};

/**
 * @brief Internal QUIC stream structure
 */
struct bn_quic_stream_s {
    /** Parent connection context */
    bn_quic_ctx_t *ctx;
    
    /** Stream ID assigned by ngtcp2 */
    int64_t stream_id;
    
    /** Stream direction */
    bn_quic_stream_direction_t direction;
    
    /** Stream state */
    struct {
        /** Whether the stream is closed locally */
        uint8_t closed_locally:1;
        
        /** Whether the stream is closed by the peer */
        uint8_t closed_by_peer:1;
        
        /** Whether a FIN has been received */
        uint8_t fin_received:1;
        
        /** Whether a FIN has been sent */
        uint8_t fin_sent:1;
        
        /** Reserved for future use */
        uint8_t reserved:4;
    } flags;
};

/**
 * @brief Generate random bytes for cryptographic use
 * 
 * @param buf Buffer to fill with random bytes
 * @param len Number of bytes to generate
 * @return int 0 on success, negative error code on failure
 */
int bn_quic_random_bytes(uint8_t *buf, size_t len);

/**
 * @brief Process handshake for a QUIC connection
 * 
 * @param ctx QUIC context
 * @param timeout_ms Maximum time to wait for handshake completion
 * @return int BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_process_handshake(bn_quic_ctx_t *ctx, uint32_t timeout_ms);

/**
 * @brief Send any pending packets for a QUIC connection
 * 
 * @param ctx QUIC context
 * @return int BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_send_pending(bn_quic_ctx_t *ctx);

/**
 * @brief Get current timestamp in milliseconds
 * 
 * @return uint64_t Current time in milliseconds since epoch
 */
uint64_t bn_quic_now_ms(void);

/**
 * @brief Convert an ngtcp2 error code to a bn_quic_error_t
 * 
 * @param ngtcp2_error Error code from ngtcp2
 * @return int Corresponding bn_quic_error_t value
 */
int bn_quic_map_error(int ngtcp2_error);

/**
 * @brief Check if a connection is expired based on idle timeout
 * 
 * @param ctx QUIC context
 * @return bool true if connection is expired, false otherwise
 */
bool bn_quic_is_expired(bn_quic_ctx_t *ctx);

/**
 * @brief Initialize TLS with ngtcp2
 * 
 * @param ctx QUIC context
 * @param host Hostname to connect to (for client verification)
 * @return int BN_QUIC_SUCCESS on success, error code otherwise
 */
int bn_quic_init_tls(bn_quic_ctx_t *ctx, const char *host);

/**
 * @brief ngtcp2 callback for receiving crypto data
 */
int bn_ngtcp2_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                              uint64_t offset, const uint8_t *data,
                              size_t datalen, void *user_data);
/**
 * @brief ngtcp2 callback for receiving stream data
 */
int bn_ngtcp2_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                             int64_t stream_id, uint64_t offset,
                             const uint8_t *data, size_t datalen,
                             void *user_data, void *stream_user_data);

/**
 * @brief ngtcp2 callback for handling stream state changes
 */
int bn_ngtcp2_stream_close(ngtcp2_conn *conn, uint32_t flags,
                         int64_t stream_id, uint64_t app_error_code,
                         void *user_data, void *stream_user_data);

/**
 * @brief ngtcp2 callback for handling connection close
 */
int bn_ngtcp2_connection_close(ngtcp2_conn *conn, uint32_t flags,
                             uint64_t error_code, uint8_t frame_type,
                             const uint8_t *reason, size_t reason_len,
                             void *user_data);

#endif /* BETANET_NET_QUIC_INTERNAL_H_ */