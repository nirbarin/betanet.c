# HTX Noise Protocol Implementation

## Overview

The `noise.c/h` files implement the Noise Protocol XK pattern for the HTX protocol, providing the inner encryption layer that secures all communication within an HTX session.

## File Information

- **Files**: `src/net/htx/noise.c`, `src/net/htx/noise.h`
- **Purpose**: Implement the Noise XK protocol for inner encryption
- **Specification Reference**: Section 5.3 (Noise XK Handshake & Inner Keys)

## Noise XK Pattern

The Noise XK pattern provides mutual authentication and forward secrecy:
- X: Sender transmits a static key to the responder (one-way authentication)
- K: Sender knows responder's static key in advance (pre-authentication)

```
Noise_XK_25519_ChaChaPoly_SHA256
  <- s
  ...
  -> e, es
  <- e, ee
  -> s, se
```

## API

The Noise module should expose functions for:

1. Initializing Noise protocol contexts
2. Performing the handshake
3. Encrypting and decrypting data
4. Managing key rotation

Expected function prototypes include:

```c
// Initialize a Noise protocol context for the initiator
int bn_noise_init_initiator(bn_noise_ctx *ctx, const uint8_t *remote_static_key);

// Initialize a Noise protocol context for the responder
int bn_noise_init_responder(bn_noise_ctx *ctx, const uint8_t *local_static_key);

// Generate the first handshake message (-> e, es)
int bn_noise_write_message_1(bn_noise_ctx *ctx, uint8_t *output, size_t *output_len);

// Process the first handshake message and generate the second (<- e, ee)
int bn_noise_read_message_1_and_write_message_2(bn_noise_ctx *ctx, 
                                              const uint8_t *input, size_t input_len,
                                              uint8_t *output, size_t *output_len);

// Process the second handshake message and generate the third (-> s, se)
int bn_noise_read_message_2_and_write_message_3(bn_noise_ctx *ctx,
                                              const uint8_t *input, size_t input_len,
                                              uint8_t *output, size_t *output_len);

// Process the third handshake message
int bn_noise_read_message_3(bn_noise_ctx *ctx, const uint8_t *input, size_t input_len);

// Derive transport keys after handshake
int bn_noise_derive_keys(bn_noise_ctx *ctx, bn_htx_crypto_ctx *crypto_ctx);

// Encrypt data using the derived keys
int bn_noise_encrypt(bn_htx_crypto_ctx *crypto_ctx, uint64_t counter,
                    const uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *ciphertext, size_t *ciphertext_len);

// Decrypt data using the derived keys
int bn_noise_decrypt(bn_htx_crypto_ctx *crypto_ctx, uint64_t counter,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    uint8_t *plaintext, size_t *plaintext_len);

// Perform key rotation
int bn_noise_rotate_keys(bn_htx_crypto_ctx *crypto_ctx, const uint8_t *transcript_hash);
```

## Usage in Betanet

The Noise protocol is used for:

1. Establishing the inner encrypted tunnel in HTX (§5.3)
2. Securing all communication against surveillance
3. Providing forward secrecy through key rotation
4. Supporting post-quantum security (from 2027-01-01)

## Implementation Requirements

- **Protocol**:
  - Must implement Noise XK pattern
  - Must use ChaCha20-Poly1305 for AEAD
  - Must use SHA-256 for hashing

- **Hybrid Post-Quantum**:
  - From 2027-01-01, must use X25519-Kyber768 hybrid
  - Prior to that, X25519 is recommended

- **Key Derivation**:
  - Must derive `K0 = HKDF-Expand-Label(TLS-Exporter, "htx inner v1", "", 64)`
  - Must split per direction: `K0c` and `K0s`
  - Must derive per-direction nonce salt `NS = HKDF(K0*, "ns", "", 12)`

- **AEAD Nonce Construction**:
  - Must construct nonce as `nonce = NS XOR (LE64(counter) ‖ LE32(0))`
  - Counter starts at 0 and increments per frame

- **Rekeying Requirements** (must meet all):
  - Send `KEY_UPDATE` when any threshold is reached:
    - ≥ 8 GiB of data
    - ≥ 2¹⁶ frames
    - ≥ 1 hour since last rekey
  - New keys: `K' = HKDF(K, "next", transcript_hash, 64)`
  - Must reset counter and derive new `NS'`

- **Ordering Requirements**:
  - Receivers must accept `KEY_UPDATE` out-of-order relative to data frames
  - Must discard frames that verify only under the previous key after receiving and acknowledging `KEY_UPDATE`
  - Senders must cease using the old key immediately after transmitting `KEY_UPDATE`