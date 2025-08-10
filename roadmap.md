# Betanet Implementation Roadmap

This roadmap outlines the step-by-step implementation plan for the Betanet v1.1 protocol. Tasks are organized by priority and dependency order.

## Phase 1: Core Infrastructure

### 1. Basic Build System
- [x] Set up CMake configuration
- [x] Create Makefile targets for build, test, and clean
- [x] Configure dependencies and external libraries
- [ ] Set up CI/CD pipeline

### 2. Cryptography Module
- [x] Implement SHA-256 hash functionality (hash.c/h)
- [x] Implement X25519 ECDH key exchange (ecdh.c/h)
- [x] Implement HKDF-SHA256 key derivation (kdf.c/h)
- [x] Implement Ed25519 signatures (sign.c/h)
- [x] Add unit tests for crypto primitives
- [x] Create crypto registry for algorithm agility

### 3. Network Basics
- [ ] Implement TCP transport (tcp.c/h)
- [ ] Implement QUIC transport (quic.c/h)
- [ ] Create network utility functions
- [ ] Add socket and connection management
- [ ] Set up TLS integration

## Phase 2: Cover Transport (HTX)

### 4. HTX Core
- [ ] Implement HTX protocol core (htx/htx.c/h)
- [ ] Implement inner frame format (htx/frame.c/h)
- [ ] Add stream multiplexing
- [ ] Implement connection management

### 5. HTX Security
- [ ] Implement Noise XK handshake (htx/noise.c/h)
- [ ] Add key rotation and nonce management
- [ ] Implement access tickets (htx/ticket.c/h)
- [ ] Add carrier selection and formatting

### 6. Origin Mirroring
- [ ] Implement TLS fingerprint mirroring (htx/origin_mirror.c/h)
- [ ] Add calibration pre-flight mechanism
- [ ] Implement HTTP/2 and HTTP/3 emulation
- [ ] Add anti-correlation fallback

## Phase 3: Routing Layer

### 7. SCION Basics
- [ ] Implement SCION header (scion/header.h)
- [ ] Add path representation (scion/path/path.c/h)
- [ ] Implement AS-hop validation

### 8. Path Management
- [ ] Implement path maintenance (scion/path/maintenance.c/h)
- [ ] Add path probing and failover
- [ ] Implement path selection algorithms

### 9. Transition Mechanism
- [ ] Implement HTX-tunneled transition (scion/transition.c/h)
- [ ] Add control stream negotiation
- [ ] Implement authentication and rate limiting

## Phase 4: Overlay Network

### 10. Peer Management
- [ ] Implement peer identity (overlay/peer.c/h)
- [ ] Add peer information storage and retrieval
- [ ] Implement peer authentication

### 11. Discovery
- [ ] Implement bootstrap discovery (overlay/discovery.c/h)
- [ ] Add rotating rendezvous DHT
- [ ] Implement multiple discovery methods
- [ ] Add BeaconSet calculation

### 12. Overlay Protocols
- [ ] Implement libp2p protocol (overlay/libp2p.c/h)
- [ ] Add protocol negotiation
- [ ] Implement Bitswap block exchange (overlay/bitswap.c/h)
- [ ] Add proof-of-work mechanisms (overlay/pow.c/h)

## Phase 5: Privacy Layer

### 13. Mixnet Implementation
- [ ] Implement core mixnet functionality (privacy/mixnet.c/h)
- [ ] Add privacy mode selection
- [ ] Implement packet format and encryption

### 14. Mix Selection
- [ ] Implement mixnode selection (privacy/selection.c/h)
- [ ] Add BeaconSet-based randomness
- [ ] Implement diversity requirements

### 15. Trust System
- [ ] Implement peer trust computation (privacy/trust.c/h)
- [ ] Add attestation handling
- [ ] Implement score calculation

## Phase 6: Naming System

### 16. Self-Certifying IDs
- [ ] Implement self-certifying identity (naming/id.c/h)
- [ ] Add verification mechanisms
- [ ] Implement string formatting and parsing

### 17. Alias Ledger
- [ ] Implement human-readable alias ledger (naming/ledger.c/h)
- [ ] Add multi-chain consensus
- [ ] Implement record validation

### 18. Emergency Advance
- [ ] Implement quorum certificates (naming/quorum.c/h)
- [ ] Add liveness mechanisms
- [ ] Implement certificate validation

## Phase 7: Payment System

### 19. Cashu Implementation
- [ ] Implement federated Cashu mints (payment/cashu.c/h)
- [ ] Add FROST-Ed25519 threshold signatures
- [ ] Implement blind signatures

### 20. Voucher System
- [ ] Implement voucher format (payment/voucher.c/h)
- [ ] Add validation and processing
- [ ] Implement double-spend prevention

### 21. Settlement
- [ ] Implement Lightning settlement (payment/lightning.c/h)
- [ ] Add invoice creation and payment
- [ ] Implement voucher redemption

## Phase 8: Governance

### 22. Uptime Scoring
- [ ] Implement node uptime scoring (governance/uptime.c/h)
- [ ] Add attestation mechanisms
- [ ] Implement score calculation

### 23. Voting System
- [ ] Implement voting power calculation (governance/voting.c/h)
- [ ] Add anti-concentration caps
- [ ] Implement stake consideration

### 24. Proposal Handling
- [ ] Implement quorum and proposal handling (governance/quorum.c/h)
- [ ] Add diversity and partition checks
- [ ] Implement activation rules

## Phase 9: Integration and Optimization

### 25. Core Integration
- [ ] Connect all modules in main.c
- [ ] Implement configuration system (config.h)
- [ ] Add initialization and shutdown sequences

### 26. Testing and Benchmarking
- [ ] Create integration tests
- [ ] Add benchmarking suite
- [ ] Perform security audits

### 27. Documentation and Deployment
- [ ] Complete implementation documentation
- [ ] Create user and developer guides
- [ ] Add deployment documentation

## Phase 10: Post-Quantum Readiness

### 28. Post-Quantum Implementation
- [ ] Implement Kyber768 (crypto/pq/kyber.c/h)
- [ ] Add hybrid X25519-Kyber768 scheme (crypto/pq/hybrid.c/h)
- [ ] Integrate with Noise protocol
- [ ] Test PQ resistance
