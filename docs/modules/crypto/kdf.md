# KDF Implementation (HKDF-SHA256)

## Overview

The `kdf.c/h` files implement the HKDF-SHA256 key derivation function as specified in the Betanet 1.1 specification.

## File Information

- **Files**: `src/crypto/kdf.c`, `src/crypto/kdf.h`
- **Purpose**: Provide HKDF-SHA256 key derivation functionality
- **Specification Reference**: Section 2 (Cryptography)

## API

The KDF module should expose functions for:

1. Extract phase (extract entropy from input keying material)
2. Expand phase (expand the extracted key into output keying material)
3. Combined extract-and-expand operation

Expected function prototypes include:

```c
// HKDF-Extract function
int bn_hkdf_extract(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   uint8_t prk[32]);

// HKDF-Expand function
int bn_hkdf_expand(const uint8_t prk[32],
                  const uint8_t *info, size_t info_len,
                  uint8_t *okm, size_t okm_len);

// Combined HKDF Extract and Expand
int bn_hkdf(const uint8_t *salt, size_t salt_len,
           const uint8_t *ikm, size_t ikm_len,
           const uint8_t *info, size_t info_len,
           uint8_t *okm, size_t okm_len);

// HKDF-Expand-Label (for TLS 1.3 compatibility)
int bn_hkdf_expand_label(const uint8_t prk[32],
                        const char *label, const uint8_t *context, size_t context_len,
                        uint8_t *out, size_t out_len);
```

## Usage in Betanet

HKDF-SHA256 is used throughout the protocol for:

1. Access ticket derivation (§5.2): `accessTicket = HKDF(sharedSecret, salt, "", 32)`
2. Key derivation in the Noise XK handshake (§5.3)
3. Inner key derivation: `K0 = HKDF-Expand-Label(TLS-Exporter, "htx inner v1", "", 64)`
4. Nonce salt derivation: `NS = HKDF(K0*, "ns", "", 12)`
5. Rekeying operations: `K' = HKDF(K, "next", transcript_hash, 64)`

## Implementation Requirements

- Must follow RFC 5869 (HKDF)
- Must handle TLS 1.3 style label expansion for compatibility with the origin mirroring requirements
- Constant-time implementation to prevent timing attacks
- Should leverage the SHA-256 implementation in `hash.c/h`