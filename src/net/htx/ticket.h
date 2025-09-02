#ifndef BETANET_NET_HTX_TICKET_H_
#define BETANET_NET_HTX_TICKET_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief HTX Access Ticket Implementation
 * 
 * Implements access ticket authentication for HTX connections.
 * Provides replay protection and rate limiting through cryptographic tickets.
 */

/** Forward declarations for opaque types */
typedef struct HTXTicketManager HTXTicketManager;
typedef struct HTXAccessTicket HTXAccessTicket;

/** Ticket constants */
#define HTX_TICKET_SIZE          64
#define HTX_TICKET_NONCE_SIZE    16
#define HTX_TICKET_MAC_SIZE      16

/**
 * @brief Initialize ticket manager
 *
 * Creates a new ticket manager for validating and issuing access tickets.
 *
 * @param secret_key Secret key for ticket generation (32 bytes)
 * @param lifetime_sec Ticket lifetime in seconds
 * @param manager_out Pointer to store created manager
 *
 * @return 0 on success, negative value on error
 *         - HTX_ERROR_INVALID_PARAM: Invalid parameters
 *
 * @example
 * HTXTicketManager *manager;
 * uint8_t secret[32];
 * // ... generate secret ...
 * int result = htx_ticket_manager_init(secret, 3600, &manager);
 */
int htx_ticket_manager_init(const uint8_t secret_key[32], uint32_t lifetime_sec, 
                           HTXTicketManager **manager_out);

/**
 * @brief Clean up ticket manager
 *
 * Cleans up and frees a ticket manager.
 *
 * @param manager Ticket manager to clean up
 *
 * @return 0 on success, negative value on error
 */
int htx_ticket_manager_cleanup(HTXTicketManager *manager);

/**
 * @brief Validate an access ticket
 *
 * Validates an access ticket for authenticity and freshness.
 *
 * @param manager Ticket manager
 * @param ticket_data Raw ticket data
 * @param ticket_size Size of ticket data
 *
 * @return 0 if valid, negative value on error
 *         - HTX_ERROR_TICKET_INVALID: Ticket is invalid or expired
 */
int htx_ticket_validate(HTXTicketManager *manager, const uint8_t *ticket_data, 
                       size_t ticket_size);

#endif /* BETANET_NET_HTX_TICKET_H_ */
