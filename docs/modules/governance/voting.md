# Voting Power Implementation

## Overview

The `voting.c/h` files implement the voting power calculation functionality for the Betanet governance system, providing a weighted voting mechanism with anti-concentration measures.

## File Information

- **Files**: `src/governance/voting.c`, `src/governance/voting.h`
- **Purpose**: Implement voting power calculation
- **Specification Reference**: Section 10.2 (Voting Power & Anti-Concentration)

## Voting Power Formula

As specified in §10.2, the raw voting power is calculated as:

```
vote_weight_raw = uptime_score + log10(total_ecash_staked / 1_000 sat + 1)
```

Anti-concentration caps are then applied:
- **Per-AS cap**: The sum of `vote_weight_raw` across all nodes within the same L1 AS is capped to 20% of the global total
- **Per-Org cap**: Nodes mapped to the same RPKI organisation are capped to 25% combined

The effective weight is then:
```
vote_weight = min(vote_weight_raw, caps)
```

## API

The voting module should expose functions for:

1. Calculating raw and effective voting power
2. Applying anti-concentration caps
3. Managing stakeholder information

Expected function prototypes include:

```c
// Initialize the voting power subsystem
int bn_voting_init(bn_voting_ctx *ctx);

// Calculate raw voting power for a node
double bn_voting_calculate_raw(double uptime_score,
                              uint64_t total_ecash_staked);

// Apply anti-concentration caps
int bn_voting_apply_caps(bn_voting_ctx *ctx,
                        const bn_peer_id *peer_id,
                        double raw_weight,
                        double *effective_weight);

// Register a node with its AS and organization
int bn_voting_register_node(bn_voting_ctx *ctx,
                           const bn_peer_id *peer_id,
                           const char *as_id,
                           const char *org_id);

// Update a node's staked amount
int bn_voting_update_stake(bn_voting_ctx *ctx,
                          const bn_peer_id *peer_id,
                          uint64_t staked_amount);

// Get the effective voting weight for a node
int bn_voting_get_weight(bn_voting_ctx *ctx,
                        const bn_peer_id *peer_id,
                        double *weight);

// Calculate the total voting weight in the network
int bn_voting_calculate_total(bn_voting_ctx *ctx,
                             double *total_weight);

// Get the per-AS weight sum
int bn_voting_get_as_weight(bn_voting_ctx *ctx,
                           const char *as_id,
                           double *weight);

// Get the per-Org weight sum
int bn_voting_get_org_weight(bn_voting_ctx *ctx,
                            const char *org_id,
                            double *weight);

// Clean up the voting power subsystem
void bn_voting_cleanup(bn_voting_ctx *ctx);
```

## Usage in Betanet

The voting power functionality is used for:

1. Determining node influence in governance decisions (§10.2)
2. Preventing centralization of control
3. Balancing influence between different stakeholders
4. Supporting the quorum system for proposals

## Implementation Requirements

- **Weight Calculation**:
  - Must implement the formula `vote_weight_raw = uptime_score + log10(total_ecash_staked / 1_000 sat + 1)`
  - Must handle corner cases (zero stake, very small stake)

- **Anti-Concentration Caps**:
  - Must implement per-AS cap of 20% of global total
  - Must implement per-Org cap of 25% of global total
  - Must calculate `vote_weight = min(vote_weight_raw, caps)`

- **AS and Org Mapping**:
  - Must maintain a mapping of nodes to AS identifiers
  - Must maintain a mapping of nodes to organization identifiers
  - Should validate AS information against routing data
  - Should validate organization information against RPKI or equivalent attestations

- **Data Management**:
  - Should efficiently store and update voting weight information
  - Should handle dynamic changes to node stake and uptime
  - Should periodically recalculate caps as the network evolves