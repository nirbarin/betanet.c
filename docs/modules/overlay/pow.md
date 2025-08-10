# Proof of Work Implementation

## Overview

The `pow.c/h` files implement the proof-of-work anti-abuse mechanisms for the Betanet overlay mesh, providing protection against DoS attacks and resource exhaustion.

## File Information

- **Files**: `src/overlay/pow.c`, `src/overlay/pow.h`
- **Purpose**: Implement proof-of-work algorithms for anti-abuse
- **Specification Reference**: Sections 6.3 (Bootstrap Discovery), 6.5 (Adaptive Anti-Abuse)

## Proof of Work Mechanism

Proof-of-work is used to:

1. Prevent abuse of bootstrap discovery responders
2. Rate-limit resource-intensive operations
3. Adaptively adjust difficulty based on network conditions

As specified in §6.3 and §6.5:
- Bootstrap responders require PoW with initial difficulty ≥ 22 bits
- Difficulty is adaptive based on load
- Rate limits apply per /24 IPv4, /56 IPv6, and per-AS aggregates
- No bucket may exceed 5% of responder capacity
- Verification must be constant-time

## API

The PoW module should expose functions for:

1. Generating proofs of work
2. Verifying proofs of work
3. Adjusting difficulty based on load
4. Managing rate limits

Expected function prototypes include:

```c
// Initialize the PoW subsystem
int bn_pow_init(bn_pow_ctx *ctx);

// Generate a proof of work for data
int bn_pow_generate(const uint8_t *data, 
                   size_t data_len, 
                   uint32_t difficulty_bits,
                   uint8_t *nonce, 
                   size_t nonce_size,
                   size_t *nonce_len);

// Verify a proof of work
bool bn_pow_verify(const uint8_t *data, 
                  size_t data_len, 
                  const uint8_t *nonce, 
                  size_t nonce_len,
                  uint32_t difficulty_bits);

// Update difficulty based on current load
int bn_pow_adjust_difficulty(bn_pow_ctx *ctx, 
                            uint32_t *difficulty_bits);

// Initialize rate limiter
int bn_pow_rate_limit_init(bn_pow_rate_limit *rate_limit, 
                          const char *prefix_type,
                          uint32_t max_capacity_percentage);

// Check if a request would exceed rate limits
bool bn_pow_rate_limit_check(bn_pow_rate_limit *rate_limit, 
                            const char *prefix,
                            uint32_t request_cost);

// Record a request against rate limits
int bn_pow_rate_limit_record(bn_pow_rate_limit *rate_limit, 
                            const char *prefix,
                            uint32_t request_cost);

// Clean up the PoW subsystem
void bn_pow_cleanup(bn_pow_ctx *ctx);
```

## Usage in Betanet

The proof-of-work functionality is used for:

1. Protecting bootstrap responders (§6.3)
2. Adaptively adjusting to network load (§6.5)
3. Enforcing fair resource allocation
4. Preventing DoS attacks and resource exhaustion

## Implementation Requirements

- **PoW Algorithm**:
  - Must be memory-hard to prevent ASIC advantages
  - Must be efficient to verify
  - Verification must be constant-time for security

- **Difficulty Requirements**:
  - Initial difficulty must be ≥ 22 bits
  - Must adjust adaptively per §6.5

- **Rate Limiting**:
  - Must maintain sliding-window metrics
  - Must adjust difficulty to keep accept rate at the 95th percentile of capacity
  - Must apply limits per /24 IPv4, /56 IPv6, and per-AS aggregates
  - No bucket may exceed 5% of responder capacity

- **Performance**:
  - Verification should be optimized for performance
  - Generation may be more computationally intensive to create asymmetry