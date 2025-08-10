# Alias Ledger Implementation

## Overview

The `ledger.c/h` files implement the human-readable alias ledger functionality for the Betanet naming and trust layer, providing a secure and resilient name registration system.

## File Information

- **Files**: `src/naming/ledger.c`, `src/naming/ledger.h`
- **Purpose**: Implement the human-readable alias ledger
- **Specification Reference**: Section 8.2 (Human-Readable Alias Ledger)

## Ledger Mechanism

As specified in §8.2, the alias ledger uses a finality-bound 2-of-3 consensus mechanism with liveness guarantees:

1. A record is **valid** if an identical payload hash appears **finalized** on at least **2 of 3** chains:
   - **Handshake** L1: ≥ 12 confirmations and not reorged for ≥ 1 hour
   - **Filecoin FVM**: chain reports **finalized**
   - **Ethereum L2 "Raven-Names"**: block marked **finalized** by the rollup

2. Record payload format (UTF-8):
   ```
   betanet1 pk=<hex32> seq=<u64> sig=<base64sig> exp=<unixSec>
   ```

3. Liveness rule: If fewer than 2 chains provide finality for ≥ 14 days, nodes may accept an **Emergency Advance** when:
   - A quorum certificate with ≥ 67% of effective governance weight exists
   - The certificate is anchored once on any available chain
   - When 2-of-3 finality resumes, the first finalized record at ≥ seq supersedes emergency records

## API

The ledger module should expose functions for:

1. Initializing the ledger subsystem
2. Registering and updating aliases
3. Looking up aliases
4. Verifying record validity
5. Handling emergency advances

Expected function prototypes include:

```c
// Initialize the ledger subsystem
int bn_ledger_init(bn_ledger_ctx *ctx);

// Register a new alias
int bn_ledger_register(bn_ledger_ctx *ctx,
                      const char *alias,
                      const uint8_t *pubkey,
                      uint64_t expiration,
                      bn_ledger_record *record);

// Update an existing alias
int bn_ledger_update(bn_ledger_ctx *ctx,
                    const char *alias,
                    const bn_ledger_record *old_record,
                    uint64_t new_expiration,
                    bn_ledger_record *new_record);

// Look up an alias
int bn_ledger_lookup(bn_ledger_ctx *ctx,
                    const char *alias,
                    bn_ledger_record *record);

// Verify a ledger record's validity
bool bn_ledger_verify_record(bn_ledger_ctx *ctx,
                            const bn_ledger_record *record);

// Format a ledger record as a string
int bn_ledger_record_to_string(const bn_ledger_record *record,
                              char *buffer,
                              size_t buffer_size);

// Parse a ledger record from a string
int bn_ledger_record_from_string(const char *str,
                                bn_ledger_record *record);

// Sign a ledger record
int bn_ledger_sign_record(bn_ledger_record *record,
                         const uint8_t *private_key);

// Verify a ledger record's signature
bool bn_ledger_verify_signature(const bn_ledger_record *record);

// Check finality status across chains
int bn_ledger_check_finality(bn_ledger_ctx *ctx,
                            const bn_ledger_record *record,
                            bool *is_finalized);

// Process an emergency advance
int bn_ledger_process_emergency_advance(bn_ledger_ctx *ctx,
                                       const char *alias,
                                       const bn_ledger_record *record,
                                       const bn_quorum_cert *cert);

// Clean up the ledger subsystem
void bn_ledger_cleanup(bn_ledger_ctx *ctx);
```

## Usage in Betanet

The alias ledger functionality is used for:

1. Mapping human-readable names to self-certifying IDs (§8.2)
2. Providing secure name registration and updates
3. Ensuring resilience against blockchain failures
4. Supporting decentralized name resolution

## Implementation Requirements

- **Record Format**:
  - Must use the format `betanet1 pk=<hex32> seq=<u64> sig=<base64sig> exp=<unixSec>`
  - `seq` must increase monotonically per `pk`
  - Higher `seq` wins for conflicts once finality condition is met

- **Finality Verification**:
  - Must verify finality on at least 2 of 3 chains
  - Must apply specific finality criteria for each chain
  - Must enforce 2-of-3 finality rule

- **Liveness Rule**:
  - Must implement the Emergency Advance mechanism
  - Must verify quorum certificates have ≥ 67% of effective governance weight
  - Must anchor certificates on at least one available chain
  - Must supersede emergency records when 2-of-3 finality resumes