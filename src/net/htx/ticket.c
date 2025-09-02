#include "ticket.h"
#include "htx.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>
/**
 * @brief Basic HTX Ticket Manager structure
 */
struct HTXTicketManager {
    uint8_t secret_key[32];
    uint32_t lifetime_sec;
};

/**
 * @brief Basic HTX Access Ticket structure
 */
struct HTXAccessTicket {
    uint64_t timestamp;
    uint8_t nonce[HTX_TICKET_NONCE_SIZE];
    uint8_t mac[HTX_TICKET_MAC_SIZE];
};

int htx_ticket_manager_init(const uint8_t secret_key[32], uint32_t lifetime_sec, 
                           HTXTicketManager **manager_out) {
    if (!secret_key || !manager_out) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    HTXTicketManager *manager = calloc(1, sizeof(HTXTicketManager));
    if (!manager) {
        return HTX_ERROR_NO_MEMORY;
    }
    
    memcpy(manager->secret_key, secret_key, 32);
    manager->lifetime_sec = lifetime_sec;
    
    *manager_out = manager;
    return 0;
}

int htx_ticket_manager_cleanup(HTXTicketManager *manager) {
    if (!manager) {
        return HTX_ERROR_INVALID_PARAM;
    }
    
    sodium_memzero(manager, sizeof(HTXTicketManager));
    free(manager);
    return 0;
}

int htx_ticket_validate(HTXTicketManager *manager, const uint8_t *ticket_data, 
                       size_t ticket_size) {
    if (!manager || !ticket_data) {
        return HTX_ERROR_INVALID_PARAM;
    }

    if (ticket_size != HTX_TICKET_SIZE) {
        return HTX_ERROR_TICKET_INVALID;
    }

    /* Layout: [8B timestamp_be][HTX_TICKET_NONCE_SIZE nonce][HTX_TICKET_MAC_SIZE mac] */
    const size_t TS_LEN = 8;
    const size_t NONCE_OFF = TS_LEN;
    const size_t MAC_OFF = TS_LEN + HTX_TICKET_NONCE_SIZE;

    /* Decode timestamp (big-endian) without alignment assumptions */
    uint64_t ticket_time = 0;
    for (size_t i = 0; i < TS_LEN; ++i) {
        ticket_time = (ticket_time << 8) | ticket_data[i];
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) {
        return HTX_ERROR_TICKET_INVALID;
    }
    uint64_t now_u = (uint64_t)now;
    if (now_u < ticket_time) {
        return HTX_ERROR_TICKET_INVALID;
    }
    if ((now_u - ticket_time) > (uint64_t)manager->lifetime_sec) {
        return HTX_ERROR_TICKET_INVALID;
    }

    /* MAC = HMAC-SHA256(timestamp||nonce) with manager->secret_key */
    unsigned char calc_mac[HTX_TICKET_MAC_SIZE];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, manager->secret_key, sizeof(manager->secret_key));
    crypto_auth_hmacsha256_update(&st, ticket_data, TS_LEN + HTX_TICKET_NONCE_SIZE);
    crypto_auth_hmacsha256_final(&st, calc_mac);

    int mac_ok = sodium_memcmp(calc_mac, ticket_data + MAC_OFF, HTX_TICKET_MAC_SIZE) == 0;
    sodium_memzero(calc_mac, sizeof(calc_mac));
    if (!mac_ok) {
        return HTX_ERROR_TICKET_INVALID;
    }

    /* TODO (follow-up): enforce replay protection for (timestamp, nonce) */
    return 0;
}
