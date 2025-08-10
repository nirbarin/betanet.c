# Cryptography Module

The Cryptography module implements the core cryptographic primitives specified in Section 2 of the Betanet specification.

## Overview

This module provides the following cryptographic primitives:

| Purpose             | Primitive                                          | Files |
| ------------------- | -------------------------------------------------- | ----- |
| Hash                | **SHA-256** (32)                                   | [hash.c/h](hash.md) |
| AEAD                | **ChaCha20-Poly1305** (IETF, 12-B nonce, 16-B tag) | Implemented in [noise.c/h](../net/noise.md) |
| KDF                 | **HKDF-SHA256**                                    | [kdf.c/h](kdf.md) |
| Signatures          | **Ed25519**                                        | [sign.c/h](sign.md) |
| Diffie–Hellman      | **X25519**                                         | [ecdh.c/h](ecdh.md) |
| Post-quantum hybrid | **X25519-Kyber768** (hybrid)                       | [pq/hybrid.c/h, pq/kyber.c/h](pq.md) |

## Post-Quantum Requirements

From *2027-01-01*, the **inner** key agreement (L2 §5.3) **MUST** be hybrid X25519-Kyber768. The **outer** TLS handshake (L2 §5.1) **MUST** mirror the front origin and **MUST NOT** advertise PQ that diverges from the origin's canonical fingerprint.

## Algorithm Agility

Implementations **MUST** expose a registry of cryptographic parameters keyed by OIDs; future substitutions **MUST** be negotiated via governance (L7) without changing wire formats where lengths permit. See [registry.c/h](registry.md) for implementation details.

## Files

- [hash.c/h](hash.md) - SHA-256 implementation
- [ecdh.c/h](ecdh.md) - X25519 Diffie-Hellman implementation
- [kdf.c/h](kdf.md) - HKDF-SHA256 implementation
- [sign.c/h](sign.md) - Ed25519 signature implementation
- [pq/kyber.c/h](pq.md) - Kyber768 implementation
- [pq/hybrid.c/h](pq.md) - X25519-Kyber768 hybrid implementation
- [registry.c/h](registry.md) - Cryptographic algorithm registry