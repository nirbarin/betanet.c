# Quorum Implementation

## Overview

The `quorum.c/h` files implement the quorum and proposal handling functionality for the Betanet governance system, providing mechanisms for network-wide decision making.

## File Information

- **Files**: `src/governance/quorum.c`, `src/governance/quorum.h`
- **Purpose**: Implement quorum and proposal handling
- **Specification Reference**: Sections 10.3 (Quorum, Diversity & Partition Safety) and 10.4 (Upgrade Delay)

## Quorum Requirements

As specified in §10.3, a proposal passes when **all** of these conditions hold:

1. `Σ weight(ACK) ≥ 0.67 × Σ weight(active_nodes_14d)`, where `active_nodes_14d` are nodes seen on HTX within 14 days
2. ACKs span ≥ 24 distinct AS groups and ≥ 3 SCION ISDs; no single AS contributes > 20% nor single Org > 25% of ACK weight
3. ACKs are observed over ≥ 2 disjoint path classes per §4 with consistent reachability (median loss < 2%)
4. A partition check confirms the median path diversity and ACK composition did not degrade by > 20% in the 7 days prior to close

After threshold is reached, activation waits ≥ 30 days (§10.4). If §10.3 fails at any time ≥ 7 days before activation, activation is deferred until criteria are met for 7 consecutive days.

## API

The quorum module should expose functions for:

1. Creating and managing proposals
2. Collecting and verifying votes
3. Checking quorum and diversity requirements
4. Handling proposal activation

Expected function prototypes include:

```c
// Initialize the quorum subsystem
int bn_quorum_init(bn_quorum_ctx *ctx);

// Create a new proposal
int bn_quorum_create_proposal(bn_quorum_ctx *ctx,
                             const uint8_t *proposal_data,
                             size_t data_len,
                             bn_proposal *proposal);

// Submit a vote (ACK) for a proposal
int bn_quorum_submit_vote(bn_quorum_ctx *ctx,
                         const bn_proposal_id *proposal_id,
                         const bn_peer_id *peer_id,
                         bool ack,
                         const uint8_t *signature);

// Check if a proposal has reached quorum
bool bn_quorum_check(bn_quorum_ctx *ctx,
                    const bn_proposal_id *proposal_id);

// Check diversity requirements for a proposal
bool bn_quorum_check_diversity(bn_quorum_ctx *ctx,
                              const bn_proposal_id *proposal_id,
                              bn_diversity_status *status);

// Check path reachability for a proposal
bool bn_quorum_check_reachability(bn_quorum_ctx *ctx,
                                 const bn_proposal_id *proposal_id);

// Perform partition check for a proposal
bool bn_quorum_check_partition(bn_quorum_ctx *ctx,
                              const bn_proposal_id *proposal_id);

// Check activation eligibility for a proposal
bool bn_quorum_check_activation(bn_quorum_ctx *ctx,
                               const bn_proposal_id *proposal_id);

// Get proposal status
int bn_quorum_get_status(bn_quorum_ctx *ctx,
                        const bn_proposal_id *proposal_id,
                        bn_proposal_status *status);

// Calculate activation time for a proposal
int bn_quorum_calc_activation_time(bn_quorum_ctx *ctx,
                                  const bn_proposal_id *proposal_id,
                                  uint64_t *activation_time);

// Clean up the quorum subsystem
void bn_quorum_cleanup(bn_quorum_ctx *ctx);
```

## Usage in Betanet

The quorum functionality is used for:

1. Making governance decisions for the network (§10.3, §10.4)
2. Approving protocol upgrades
3. Ensuring broad consensus across diverse participants
4. Preventing network partitions and ensuring continued operation

## Implementation Requirements

- **Quorum Checking**:
  - Must verify that total ACK weight ≥ 67% of active nodes in last 14 days
  - Must verify AS and ISD diversity requirements
  - Must verify that no single AS contributes > 20% nor single Org > 25% of ACK weight

- **Path Diversity**:
  - Must check that ACKs are observed over ≥ 2 disjoint path classes
  - Must verify consistent reachability (median loss < 2%)
  - Must perform partition check to ensure diversity hasn't degraded by > 20% in 7 days

- **Activation Management**:
  - Must enforce ≥ 30 day waiting period after threshold
  - Must defer activation if requirements fail ≥ 7 days before activation
  - Must verify criteria are met for 7 consecutive days to resume activation

- **Security Considerations**:
  - Must verify signatures on votes
  - Must prevent double-voting
  - Must ensure proper weighting according to §10.2
  - Should be resistant to Sybil attacks