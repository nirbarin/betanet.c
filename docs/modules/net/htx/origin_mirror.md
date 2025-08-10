# HTX Origin Mirroring Implementation

## Overview

The `origin_mirror.c/h` files implement the origin mirroring functionality for HTX, enabling the protocol to disguise its TLS handshake to match that of a legitimate front origin.

## File Information

- **Files**: `src/net/htx/origin_mirror.c`, `src/net/htx/origin_mirror.h`
- **Purpose**: Implement origin mirroring for TLS fingerprint matching
- **Specification Reference**: Section 5.1 (Outer TLS 1.3 Handshake)

## Origin Mirroring Mechanism

Origin mirroring allows HTX to blend in with legitimate HTTPS traffic by precisely matching the TLS fingerprint characteristics of a legitimate front origin:

1. **Fingerprint Classes**:
   - JA3/JA4 fingerprint family
   - ALPN set and ordering
   - TLS extension order
   - GREASE usage patterns
   - HTTP/2 SETTINGS values
   - HTTP/3 availability

2. **Per-Connection Calibration**:
   - Pre-flight connection to the same origin (or same CDN POP)
   - Measurement of the origin's TLS characteristics
   - Application of these characteristics to the HTX connection

3. **Tolerance Enforcement**:
   - ALPN set and order must match exactly
   - Extension order must match exactly
   - H2 SETTINGS values must be within ±15% of calibrated origin values
   - For fixed values, exact match is required

## API

The origin mirroring module should expose functions for:

1. Calibrating against a front origin
2. Configuring a TLS context to match the origin
3. Validating that tolerances are met

Expected function prototypes include:

```c
// Perform calibration against a front origin
int bn_origin_calibrate(const char *origin_host, uint16_t origin_port,
                       bn_origin_profile *profile);

// Configure a TLS context to match the origin profile
int bn_origin_configure_tls(SSL_CTX *ctx, const bn_origin_profile *profile);

// Validate that a TLS connection meets tolerances
bool bn_origin_validate_tolerances(SSL *ssl, const bn_origin_profile *profile);

// Parse CDN POP information to ensure matching calibration
int bn_origin_parse_cdn_pop(const char *headers, bn_cdn_pop_info *pop_info);

// Configure client hello with matching characteristics
int bn_origin_configure_client_hello(SSL *ssl, const bn_origin_profile *profile);

// Configure HTTP/2 settings to match origin
int bn_origin_configure_h2_settings(nghttp2_settings_entry *settings,
                                  size_t *num_settings,
                                  const bn_origin_profile *profile);
```

## Usage in Betanet

Origin mirroring is used for:

1. Making HTX connections appear identical to legitimate web traffic (§5.1)
2. Preventing detection through TLS fingerprinting
3. Adapting to different front origins for increased diversity

## Implementation Requirements

- **Calibration Requirements**:
  - Must perform per-connection calibration pre-flight
  - Any deviation must fail closed
  - If origin presents geo/POP variance, must calibrate against the same POP
  - If unknown, calibration must be repeated until equality is achieved

- **Tolerance Requirements**:
  - ALPN set and order must match exactly
  - Extension order must match exactly
  - H2 SETTINGS values must be within ±15% where origin publishes variable ranges
  - Otherwise, must match exactly

- **Protocol Selection**:
  - ALPN selection must match the origin
  - Fixed global distributions are prohibited

- **Session Handling**:
  - Session resumption must follow origin policy
  - 0-RTT must not be used for HTX initiation

- **HTTP/2 Emulation**:
  - PING cadence must be random in [10s, 60s] with ±10% jitter
  - PRIORITY frames should follow origin's baseline rate
  - If unknown, send on [0.5%, 3%] of connections at random
  - Idle padding: if no DATA for [200ms, 1200ms], send [0, 3KiB] dummy encrypted DATA