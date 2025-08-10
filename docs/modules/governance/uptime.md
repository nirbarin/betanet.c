# Uptime Scoring Implementation

## Overview

The `uptime.c/h` files implement the node uptime scoring functionality for the Betanet governance system, providing a measure of node reliability for voting purposes.

## File Information

- **Files**: `src/governance/uptime.c`, `src/governance/uptime.h`
- **Purpose**: Implement node uptime scoring
- **Specification Reference**: Section 10.1 (Node Uptime Score)

## Uptime Score Formula

As specified in §10.1, the uptime score is calculated as:

```
score = log2(1 + seconds_uptime / 86_400)   // capped at 16
```

This formula:
- Uses a logarithmic scale to reward consistent uptime
- Divides by 86,400 (seconds in a day) to normalize
- Caps the maximum score at 16

## API

The uptime module should expose functions for:

1. Tracking node uptime
2. Calculating uptime scores
3. Managing attestations of uptime

Expected function prototypes include:

```c
// Initialize the uptime scoring subsystem
int bn_uptime_init(bn_uptime_ctx *ctx);

// Record node online status
int bn_uptime_record_online(bn_uptime_ctx *ctx,
                           const bn_peer_id *peer_id,
                           uint64_t timestamp);

// Calculate uptime score for a node
double bn_uptime_calculate_score(bn_uptime_ctx *ctx,
                                const bn_peer_id *peer_id);

// Create an uptime attestation
int bn_uptime_create_attestation(bn_uptime_ctx *ctx,
                                const bn_peer_id *peer_id,
                                uint64_t seconds_uptime,
                                bn_uptime_attestation *attestation);

// Verify an uptime attestation
bool bn_uptime_verify_attestation(bn_uptime_ctx *ctx,
                                 const bn_uptime_attestation *attestation);

// Add an uptime attestation for a peer
int bn_uptime_add_attestation(bn_uptime_ctx *ctx,
                             const bn_peer_id *peer_id,
                             const bn_uptime_attestation *attestation);

// Get the maximum possible uptime score
double bn_uptime_max_score(void);

// Clean up the uptime scoring subsystem
void bn_uptime_cleanup(bn_uptime_ctx *ctx);
```

## Usage in Betanet

The uptime scoring functionality is used for:

1. Measuring node reliability and contribution to the network (§10.1)
2. Contributing to voting power calculation (§10.2)
3. Incentivizing consistent node operation
4. Supporting the governance system

## Implementation Requirements

- **Score Calculation**:
  - Must implement the formula `score = log2(1 + seconds_uptime / 86_400)`
  - Must cap the maximum score at 16
  - Must handle corner cases (zero uptime, very short uptime)

- **Attestation Management**:
  - Should support signed attestations from other nodes
  - Should verify the validity of attestations
  - Should consider the recency and distribution of attestations

- **Security Considerations**:
  - Must prevent artificial inflation of uptime
  - Should validate timestamps to prevent backdating
  - Should consider distributed verification of uptime claims

- **Data Management**:
  - Should efficiently store and update uptime records
  - Should handle clock skew and synchronization issues
  - Should prune very old uptime records