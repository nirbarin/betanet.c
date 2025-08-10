# Governance Module

The Governance module implements the Layer 7 (L7) functionality of the Betanet specification, providing mechanisms for network-wide decision making and protocol evolution.

## Overview

This module provides the following governance components:

| Component | Purpose | Files |
| --------- | ------- | ----- |
| Uptime | Node uptime scoring | [uptime.c/h](uptime.md) |
| Voting | Voting power calculation | [voting.c/h](voting.md) |
| Quorum | Quorum and proposal handling | [quorum.c/h](quorum.md) |

## Layer Model Coverage

The governance module represents:

- **L7**: Applications & Governance

## Key Features

1. **Uptime Scoring**: Measuring node reliability
2. **Voting Power**: Weighted voting system with anti-concentration
3. **Quorum Rules**: Requirements for proposal acceptance
4. **Upgrade Process**: Protocol for network upgrades

## Files

- [uptime.c/h](uptime.md) - Node uptime scoring implementation
- [voting.c/h](voting.md) - Voting power calculation implementation
- [quorum.c/h](quorum.md) - Quorum and proposal handling implementation

## Compliance Requirements

1. Implements node uptime scoring formula
2. Enforces anti-concentration caps for voting power
3. Verifies quorum, diversity, and partition safety for proposals
4. Implements upgrade delay and activation rules