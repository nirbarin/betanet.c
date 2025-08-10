# Betanet.c Documentation

This documentation provides details about the implementation of the Betanet Version 1.1 specification. It serves as a reference for developers working on the codebase, explaining the purpose and functionality of each module and file.

## Project Overview

Betanet is a fully decentralized, censorship-resistant network intended to replace the public Internet. The implementation follows the official [Betanet Version 1.1 Specification](spec/README.md).

## Layer Model

| Layer  | Function                                                    | Module |
| ------ | ----------------------------------------------------------- | ------ |
| **L0** | Access media (any IP bearer: fibre, 5G, sat, LoRa, etc.)    | [net](modules/net/index.md) |
| **L1** | Path selection & routing (SCION + HTX-tunnelled transition) | [scion](modules/scion/index.md) |
| **L2** | Cover transport (HTX over TCP-443 / QUIC-443)               | [net/htx](modules/net/htx.md) |
| **L3** | Overlay mesh (libp2p-v2 object relay)                       | [overlay](modules/overlay/index.md) |
| **L4** | Optional privacy hop (Nym mixnet)                           | [privacy](modules/privacy/index.md) |
| **L5** | Naming & trust (self-certifying IDs + 3-chain alias ledger) | [naming](modules/naming/index.md) |
| **L6** | Payments (federated Cashu + Lightning)                      | [payment](modules/payment/index.md) |
| **L7** | Applications & Governance                                   | [governance](modules/governance/index.md) |

## Module Documentation

- [Cryptography](modules/crypto/index.md) - Core cryptographic primitives
- [Networking](modules/net/index.md) - TCP, QUIC, and HTX implementations
- [SCION](modules/scion/index.md) - Path selection and routing
- [Overlay](modules/overlay/index.md) - Peer-to-peer mesh networking
- [Privacy](modules/privacy/index.md) - Mixnet implementation
- [Naming](modules/naming/index.md) - Naming and trust system
- [Payment](modules/payment/index.md) - Payment infrastructure
- [Governance](modules/governance/index.md) - Governance mechanisms

## Building and Contributing

*Building instructions will be added as implementation progresses*