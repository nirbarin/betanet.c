# Trust Computation Implementation

## Overview

The `trust.c/h` files implement the peer trust computation functionality for the Betanet privacy layer, providing mechanisms to evaluate the trustworthiness of peers for use in the balanced privacy mode.

## File Information

- **Files**: `src/privacy/trust.c`, `src/privacy/trust.h`
- **Purpose**: Implement peer trust computation algorithms
- **Specification Reference**: Section 7.3 (Peer-Trust)

## Trust Computation

As specified in §7.3, peer trust is computed from:

1. Uptime attestations signed by ≥ 8 distinct AS groups over a 30-day window
2. Observed relay behavior
3. Staked ecash capped by per-AS limits (L7 §10.2)

The balanced privacy mode uses ≥ 2 hops until peer-trust ≥ 0.8.

## API

The trust module should expose functions for:

1. Initializing the trust computation subsystem
2. Adding and verifying attestations
3. Updating trust scores based on observations
4. Calculating overall trust scores

Expected function prototypes include:

```c
// Initialize the trust computation subsystem
int bn_trust_init(bn_trust_ctx *ctx);

// Add an uptime attestation for a peer
int bn_trust_add_attestation(bn_trust_ctx *ctx,
                            const bn_peer_id *peer_id,
                            const bn_attestation *attestation);

// Verify an attestation signature
bool bn_trust_verify_attestation(const bn_attestation *attestation);

// Update trust based on observed behavior
int bn_trust_update_observation(bn_trust_ctx *ctx,
                               const bn_peer_id *peer_id,
                               bn_observation_type type,
                               double value);

// Update trust based on staked ecash
int bn_trust_update_stake(bn_trust_ctx *ctx,
                         const bn_peer_id *peer_id,
                         uint64_t staked_amount);

// Calculate the overall trust score for a peer
double bn_trust_calculate_score(bn_trust_ctx *ctx,
                               const bn_peer_id *peer_id);

// Check if a peer's trust score exceeds a threshold
bool bn_trust_exceeds_threshold(bn_trust_ctx *ctx,
                               const bn_peer_id *peer_id,
                               double threshold);

// Get the trust score for a peer
int bn_trust_get_score(bn_trust_ctx *ctx,
                      const bn_peer_id *peer_id,
                      double *score);

// Clean up the trust computation subsystem
void bn_trust_cleanup(bn_trust_ctx *ctx);
```

## Usage in Betanet

The trust computation functionality is used for:

1. Determining when to reduce the number of mix hops in balanced mode (§7.3)
2. Evaluating the reliability of peers
3. Incentivizing good behavior through trust scoring
4. Penalizing misbehaving nodes

## Implementation Requirements

- **Attestation Requirements**:
  - Must verify attestations from ≥ 8 distinct AS groups
  - Must consider attestations over a 30-day window
  - Must validate signatures on attestations

- **Observed Behavior**:
  - Must track and evaluate relay behavior
  - Should account for successful vs. failed relays
  - Should consider latency and other performance metrics

- **Stake Consideration**:
  - Must account for staked ecash
  - Must apply per-AS limits as specified in §10.2
  - Should handle stake verification securely

- **Score Calculation**:
  - Must combine attestations, observations, and stake
  - Must apply appropriate weighting
  - Must enforce the threshold of 0.8 for balanced mode
  - The precise combination is implementation-defined, but thresholds are normative