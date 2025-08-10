# Quorum Certificate Implementation

## Overview

The `quorum.c/h` files implement the quorum certificate functionality for the Betanet naming and trust layer, providing a mechanism for emergency advances when the alias ledger's blockchain finality is unavailable.

## File Information

- **Files**: `src/naming/quorum.c`, `src/naming/quorum.h`
- **Purpose**: Implement quorum certificates for liveness
- **Specification Reference**: Section 8.2 (Human-Readable Alias Ledger)

## Quorum Certificate Format

As specified in §8.2, the quorum certificate is a CBOR map:

```
{ payloadHash, epoch, signers[], weights[], sigs[] }
```

Each `sig` is Ed25519 over `("bn-aa1" ‖ payloadHash ‖ epoch)`. Verifiers must validate weights per §10.2–§10.3 and reject duplicates or lower-epoch certificates.

## API

The quorum module should expose functions for:

1. Creating quorum certificates
2. Adding signatures to certificates
3. Verifying certificate validity
4. Serializing and deserializing certificates

Expected function prototypes include:

```c
// Initialize a new quorum certificate
int bn_quorum_cert_init(bn_quorum_cert *cert,
                       const uint8_t *payload_hash,
                       uint64_t epoch);

// Add a signer to a quorum certificate
int bn_quorum_cert_add_signer(bn_quorum_cert *cert,
                             const bn_peer_id *signer,
                             double weight,
                             const uint8_t *signature);

// Verify a quorum certificate
bool bn_quorum_cert_verify(const bn_quorum_cert *cert,
                          const uint8_t *payload_hash);

// Check if a quorum certificate has sufficient weight
bool bn_quorum_cert_has_quorum(const bn_quorum_cert *cert,
                              double required_percentage);

// Serialize a quorum certificate to CBOR
int bn_quorum_cert_serialize(const bn_quorum_cert *cert,
                            uint8_t *buffer,
                            size_t buffer_size,
                            size_t *written);

// Deserialize a quorum certificate from CBOR
int bn_quorum_cert_deserialize(const uint8_t *buffer,
                              size_t buffer_size,
                              bn_quorum_cert *cert);

// Create a signature for a quorum certificate
int bn_quorum_cert_create_signature(const uint8_t *payload_hash,
                                   uint64_t epoch,
                                   const uint8_t *private_key,
                                   uint8_t *signature);

// Verify a signature in a quorum certificate
bool bn_quorum_cert_verify_signature(const uint8_t *payload_hash,
                                    uint64_t epoch,
                                    const bn_peer_id *signer,
                                    const uint8_t *signature);

// Compare two quorum certificates
int bn_quorum_cert_compare(const bn_quorum_cert *a,
                          const bn_quorum_cert *b);

// Free resources associated with a quorum certificate
void bn_quorum_cert_destroy(bn_quorum_cert *cert);
```

## Usage in Betanet

The quorum certificate functionality is used for:

1. Enabling the Emergency Advance mechanism for the alias ledger (§8.2)
2. Providing liveness when blockchain finality is unavailable
3. Ensuring secure governance-based consensus for emergency operations
4. Preventing unauthorized updates to the alias ledger

## Implementation Requirements

- **Certificate Format**:
  - Must implement the CBOR map format as specified
  - Must include payloadHash, epoch, signers, weights, and signatures

- **Signature Creation**:
  - Must sign over `("bn-aa1" ‖ payloadHash ‖ epoch)`
  - Must use Ed25519 signatures

- **Verification**:
  - Must validate weights according to §10.2–§10.3
  - Must reject duplicate signers
  - Must reject certificates with lower epochs than previously seen
  - Must verify all signatures
  - Must ensure total weight meets ≥ 67% threshold

- **Weight Validation**:
  - Must implement anti-concentration caps
  - Must enforce per-AS and per-Org limits
  - Must validate that effective weights are properly calculated