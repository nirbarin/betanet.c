## betanet.c

A C library by [nirbar](https://nirbar.in) that implements the [Betanet Version 1.1 spec](https://github.com/ravendevteam/betanet)

> [!WARNING]
> This repository contains only a skeleton structure, no functional code yet.
>
> The real implementation will grow incrementally from this point forward.

### Documentation

Documentation is available in the [docs](docs) directory:
- Main index: [docs/index.md](docs/index.md)
- Module documentation organized by layer
- Detailed specifications for each component and file
- API references and implementation requirements

The documentation follows the Betanet v1.1 specification and outlines the purpose, functionality, and requirements for each module.

### Project Structure

```
src/
├── crypto/           # Cryptographic primitives (§2)
│   ├── hash.c/h      # SHA-256 implementation
│   ├── ecdh.c/h      # X25519 Diffie-Hellman implementation
│   ├── kdf.c/h       # HKDF-SHA256 implementation
│   ├── sign.c/h      # Ed25519 signature implementation
│   └── pq/           # Post-quantum cryptography
│       ├── kyber.c/h # Kyber768 implementation
│       └── hybrid.c/h# X25519-Kyber768 hybrid implementation
├── net/              # Network layer components (§3 L0-L2)
│   ├── tcp.c/h       # TCP transport
│   ├── quic.c/h      # QUIC transport
│   └── htx/          # HTX protocol implementation (§5)
│       ├── htx.c/h           # Core HTX protocol
│       ├── frame.c/h         # Frame format handling
│       ├── noise.c/h         # Noise XK handshake
│       ├── ticket.c/h        # Access ticket implementation
│       └── origin_mirror.c/h # Origin mirroring for TLS
├── scion/            # SCION implementation (§4)
│   ├── header.h      # SCION packet header format
│   ├── transition.c/h# HTX-tunneled transition
│   └── path/         # Path selection and maintenance
│       ├── path.c/h         # Path representation
│       └── maintenance.c/h  # Path maintenance
├── overlay/          # Overlay mesh (§6)
│   ├── peer.c/h      # Peer identity
│   ├── discovery.c/h # Bootstrap discovery
│   ├── libp2p.c/h    # libp2p protocol
│   ├── bitswap.c/h   # Bitswap block exchange
│   └── pow.c/h       # Proof-of-work implementation
├── privacy/          # Privacy layer (§7)
│   ├── mixnet.c/h    # Mixnet implementation
│   ├── selection.c/h # Mixnode selection
│   └── trust.c/h     # Peer trust computation
├── naming/           # Naming & trust (§8)
│   ├── id.c/h        # Self-certifying IDs
│   ├── ledger.c/h    # Alias ledger
│   └── quorum.c/h    # Quorum certificates
├── payment/          # Payment system (§9)
│   ├── cashu.c/h     # Cashu implementation
│   ├── voucher.c/h   # Voucher format
│   └── lightning.c/h # Lightning settlement
├── governance/       # Governance & versioning (§10)
│   ├── uptime.c/h    # Node uptime scoring
│   ├── voting.c/h    # Voting power calculation
│   └── quorum.c/h    # Quorum and proposal handling
├── config.h          # Global configuration
└── main.c            # Main entry point
```

### Building

*Build instructions will be added as implementation progresses*