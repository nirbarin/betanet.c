# SCION Path Maintenance

## Overview

The `maintenance.c/h` files implement the path maintenance functionality for SCION routing, providing mechanisms to discover, probe, and maintain valid paths through the network.

## File Information

- **Files**: `src/scion/path/maintenance.c`, `src/scion/path/maintenance.h`
- **Purpose**: Provide path discovery and maintenance algorithms
- **Specification Reference**: Section 4.3 (Path Maintenance)

## Path Maintenance Process

Path maintenance involves several key activities:

1. **Path Discovery**: Finding potential paths to destinations
2. **Path Validation**: Ensuring paths are valid and usable
3. **Path Monitoring**: Regularly probing paths to detect failures
4. **Path Failover**: Switching to alternative paths when failures occur
5. **Path Refresh**: Periodically refreshing path information

## API

The path maintenance module should expose functions for:

1. Initializing the path maintenance subsystem
2. Discovering paths to destinations
3. Monitoring and probing existing paths
4. Managing the set of paths for each destination
5. Handling path failures and failover

Expected function prototypes include:

```c
// Initialize the path maintenance subsystem
int bn_path_maintenance_init(bn_path_maintenance_ctx *ctx);

// Discover paths to a destination
int bn_path_discover(bn_path_maintenance_ctx *ctx, 
                    const bn_as_id *destination,
                    bn_path_set *paths);

// Add a newly discovered path
int bn_path_maintenance_add_path(bn_path_maintenance_ctx *ctx,
                               const bn_as_id *destination,
                               const bn_path *path);

// Probe a path to check its validity
int bn_path_probe(bn_path_maintenance_ctx *ctx,
                 const bn_as_id *destination,
                 const bn_path *path,
                 bool *valid);

// Handle a path failure event
int bn_path_handle_failure(bn_path_maintenance_ctx *ctx,
                          const bn_as_id *destination,
                          const bn_path *failed_path);

// Select the current best path to a destination
int bn_path_maintenance_get_best_path(bn_path_maintenance_ctx *ctx,
                                     const bn_as_id *destination,
                                     bn_path *path);

// Get all valid paths to a destination
int bn_path_maintenance_get_all_paths(bn_path_maintenance_ctx *ctx,
                                     const bn_as_id *destination,
                                     bn_path_set *paths);

// Run background path maintenance tasks
int bn_path_maintenance_process(bn_path_maintenance_ctx *ctx);

// Clean up the path maintenance subsystem
void bn_path_maintenance_cleanup(bn_path_maintenance_ctx *ctx);
```

## Usage in Betanet

The path maintenance functionality is used for:

1. Ensuring continuous connectivity despite network changes (§4.3)
2. Providing rapid failover when paths fail
3. Maintaining multiple disjoint paths for resilience
4. Optimizing path selection based on changing network conditions

## Implementation Requirements

As specified in §4.3:

- **Path Diversity**: Must maintain **up to 3** disjoint validated paths per peer
- **Failover Speed**: Must switch within **300 ms** when an alternative validated path exists
- **Probing Behavior**:
  - Must use exponential back-off (min 1s, max 60s)
  - Must not exceed 1 probe per destination per **10s** under persistent loss
- **Path Selection**: Should select paths based on performance metrics and diversity requirements
- **Background Maintenance**: Should perform background maintenance to ensure path validity before failures occur