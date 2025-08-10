# HTX Access Ticket Implementation

## Overview

The `ticket.c/h` files implement the access ticket mechanism for HTX, providing a bootstrap authentication system that allows clients to prove authorization to use the HTX service.

## File Information

- **Files**: `src/net/htx/ticket.c`, `src/net/htx/ticket.h`
- **Purpose**: Implement the access ticket bootstrap mechanism
- **Specification Reference**: Section 5.2 (Access-Ticket Bootstrap)

## Access Ticket Protocol

The access ticket protocol creates a replay-bound authentication token that allows clients to access HTX services:

1. Decoy site publishes:
   - `ticketPub` (X25519, 32B)
   - `ticketKeyID` (8B)
   - Carrier policy (cookie/query/body proportions)

2. Client performs these steps:
   - Generate `cliPriv/cliPub` (X25519)
   - Generate 32-byte `nonce32`
   - Compute `sharedSecret = X25519(cliPriv, ticketPub)`
   - Compute `hour = floor(unixTime/3600)` (UTC)
   - Compute `salt = SHA256("betanet-ticket-v1" ‖ ticketKeyID ‖ uint64_be(hour))`
   - Compute `accessTicket = HKDF(sharedSecret, salt, "", 32)`
   - Choose carrier method per policy
   - Send ticket via chosen carrier with variable-length padding

3. Server verifies:
   - Recompute for `hour ∈ {now-1, now, now+1}`
   - Reject duplicates for tuple `(cliPub, hour)` within 2h
   - Enforce per-/24 IPv4 and /56 IPv6 token buckets

## API

The ticket module should expose functions for:

1. Generating access tickets (client)
2. Validating access tickets (server)
3. Managing carrier selection and formatting

Expected function prototypes include:

```c
// Client: Parse carrier policy from header
int bn_ticket_parse_policy(const char *policy_header, bn_ticket_policy *policy);

// Client: Generate a new access ticket
int bn_ticket_generate(const uint8_t *ticket_pub, const uint8_t *ticket_key_id,
                      const bn_ticket_policy *policy,
                      bn_ticket_data *ticket);

// Client: Format ticket for the selected carrier
int bn_ticket_format(const bn_ticket_data *ticket, bn_ticket_carrier carrier,
                    const char *site_name, uint8_t *output, size_t *output_len);

// Server: Extract ticket from carrier
int bn_ticket_extract(bn_ticket_carrier carrier, const uint8_t *data, size_t data_len,
                     bn_ticket_data *ticket);

// Server: Verify access ticket
int bn_ticket_verify(const bn_ticket_data *ticket, const uint8_t *server_priv,
                    const uint8_t *ticket_key_id, uint64_t current_time);

// Server: Check for replay
bool bn_ticket_is_replay(const bn_ticket_data *ticket);

// Server: Check rate limits
bool bn_ticket_check_rate_limit(const bn_ticket_data *ticket, const char *client_ip);
```

## Usage in Betanet

The access ticket mechanism is used for:

1. Initial authentication to HTX services (§5.2)
2. Preventing unauthorized access
3. Limiting abuse through replay protection
4. Rate-limiting to prevent DoS attacks

## Implementation Requirements

- **Carrier Methods**:
  - **Cookie**: `Cookie: <site-name>=Base64URL(0x01 ‖ cliPub32 ‖ ticketKeyID8 ‖ nonce32 ‖ accessTicket32 ‖ pad)`
  - **Query parameter**: `...?bn1=<Base64URL(payload)>`
  - **Body (POST)**: `Content-Type: application/x-www-form-urlencoded` with `bn1=<Base64URL(payload)>`

- **Carrier Selection**:
  - Must select carrier based on proportions in the policy
  - Must use variable-length padding in range 24..64 bytes
  - Must support `__Host-` prefix for cookies

- **Verification**:
  - Must verify `hour ∈ {now-1, now, now+1}`
  - Must reject duplicates for tuple `(cliPub, hour)` within 2h
  - Must enforce per-/24 IPv4 and /56 IPv6 token buckets

- **Parsing**:
  - Must parse fields in order: `version, cliPub32, ticketKeyID8, nonce32, accessTicket32`
  - Must ignore trailing bytes (padding)
  - Must accept padding range 24..64 bytes

- **Failure Handling**:
  - On duplicate rejection, client should rotate `cliPub`
  - On failure, server must serve only decoy content