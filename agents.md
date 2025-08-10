# AI Agent Guidelines for Betanet.c

This document provides essential information for AI agents to effectively assist developers working on the Betanet.c implementation. This is a high-standards project requiring meticulous attention to detail, security, and protocol conformance.

## Repository Overview

Betanet.c is a C implementation of the Betanet v1.1 protocol, a comprehensive network protocol stack designed for privacy, security, and resilience. The project follows a layered architecture similar to the OSI model, with components organized into distinct modules.

### Project Structure

```
betanet.c/
├── src/                    # Source code
│   ├── crypto/             # Cryptography primitives (L0)
│   │   ├── pq/             # Post-quantum cryptography
│   ├── net/                # Network transports (L1-L2)
│   │   ├── htx/            # HTX protocol components
│   ├── scion/              # SCION routing (L3)
│   │   ├── path/           # Path management
│   ├── overlay/            # Overlay mesh network (L4)
│   ├── privacy/            # Privacy layer (L5)
│   ├── naming/             # Naming system (L6)
│   ├── payment/            # Payment system (L6)
│   ├── governance/         # Governance system (L7)
│   ├── config.h            # Configuration constants
│   └── main.c              # Application entry point
├── docs/                   # Documentation
│   └── modules/            # Module-specific documentation
├── CMakeLists.txt          # CMake build configuration
├── Makefile                # Make build targets
├── roadmap.md              # Implementation roadmap
└── readme.md               # Project overview
```

## Development Guidelines

### Coding Standards

1. **C Standard**: 
   - Strictly adhere to C11 standard without compiler-specific extensions
   - Avoid undefined behavior as defined by the C specification
   - Maintain compatibility with standard C libraries

2. **Code Style**:
   - 4-space indentation, no tabs
   - Maximum line length of 100 characters
   - Use braces for all control structures, even single-line blocks
   - Place opening braces on the same line for functions and control structures
   - Add a space after keywords (if, while, for) but not after function names
   - Use consistent vertical spacing to group related code

3. **Naming Conventions**:
   - Functions: `snake_case` with module prefix for public API (e.g., `crypto_hash_compute()`)
   - Types/Structs: `PascalCase` with module prefix (e.g., `CryptoKeyPair`)
   - Constants: `UPPER_SNAKE_CASE` with module prefix (e.g., `CRYPTO_HASH_SIZE_SHA256`)
   - Global variables: `g_snake_case` with module prefix (e.g., `g_crypto_initialized`)
   - Macros: `UPPER_SNAKE_CASE` with underscore prefix (e.g., `_CRYPTO_INTERNAL_MACRO`)
   - Header guards: `BETANET_MODULE_FILENAME_H_`

4. **Documentation**: 
   - Every function must have a documentation comment explaining:
     ```c
     /**
      * @brief Brief description of function purpose
      *
      * Detailed description including algorithm, security considerations,
      * and any implementation notes relevant to callers.
      *
      * @param param1 Description of first parameter
      * @param param2 Description of second parameter
      *
      * @return Description of return value
      *         - SUCCESS (0): Operation completed successfully
      *         - ERROR_CODE (-1): Description of error condition
      *
      * @note Any special considerations or side effects
      *
      * @example
      * // Example usage of the function
      * int result = function_name(arg1, arg2);
      */
     ```

### Error Handling Patterns

1. **Return Value Consistency**:
   - Use consistent return value semantics across the codebase
   - Return 0 for success, negative values for errors
   - Define error codes in a central header with descriptive names
   - Always check return values from functions that can fail

2. **Error Propagation**:
   - Propagate errors upward with context enhancement
   - Use a pattern like:
     ```c
     int result = function_that_may_fail();
     if (result < 0) {
         // Either handle error or propagate with context
         return result; // Or more specific error code
     }
     ```

3. **Resource Cleanup**:
   - Use goto for error cleanup in C to avoid deeply nested if/else blocks:
     ```c
     int function() {
         void *resource1 = NULL;
         void *resource2 = NULL;
         int result = 0;
         
         resource1 = allocate_resource1();
         if (!resource1) {
             result = ERROR_ALLOCATION;
             goto cleanup;
         }
         
         resource2 = allocate_resource2();
         if (!resource2) {
             result = ERROR_ALLOCATION;
             goto cleanup;
         }
         
         // Main function logic
         result = SUCCESS;
         
     cleanup:
         if (resource2) free_resource2(resource2);
         if (resource1) free_resource1(resource1);
         return result;
     }
     ```

4. **Input Validation**:
   - Validate all function parameters at the beginning of functions
   - Return specific error codes for invalid parameters
   - Use assertions for internal logic checks, not for input validation

### Security Best Practices

1. **Cryptographic Implementation**:
   - Implement cryptographic operations in constant time to prevent timing attacks
   - Zero out sensitive memory after use with explicit_bzero or equivalent
   - Avoid branching on secret data
   - Use secure random number generation with proper entropy
   - Validate all cryptographic inputs and outputs
   - Follow reference implementations precisely for cryptographic algorithms

2. **Memory Management**:
   - Track all memory allocations and ensure proper deallocation
   - Use secure allocation for cryptographic materials when available
   - Implement strict bounds checking for all buffer operations
   - Avoid functions prone to buffer overflows (strcpy, sprintf, etc.)
   - Prefer fixed-size buffers with size checking for network data

3. **Input Sanitization**:
   - Treat all external data as untrusted
   - Implement strict validation for all network inputs
   - Use explicit length checks rather than null-termination
   - Sanitize all data crossing trust boundaries
   - Implement rate limiting for resource-intensive operations

4. **Side-Channel Resistance**:
   - Avoid variable-time operations for secret data
   - Implement blinding techniques where appropriate
   - Minimize data-dependent branching in cryptographic code
   - Consider cache timing vulnerabilities in critical sections

### Performance Optimization

1. **Algorithmic Efficiency**:
   - Optimize algorithms before micro-optimizing code
   - Use appropriate data structures for each task
   - Minimize memory allocations in critical paths
   - Consider time-space tradeoffs explicitly

2. **Resource Management**:
   - Implement connection pooling for network resources
   - Reuse buffers when processing large volumes of data
   - Consider zero-copy techniques for data processing pipelines
   - Implement appropriate batching for small operations

3. **Profiling and Benchmarking**:
   - Write benchmarks for performance-critical code paths
   - Establish baseline performance metrics before optimizing
   - Focus optimization efforts on measured bottlenecks
   - Document performance characteristics and guarantees

4. **Concurrency Considerations**:
   - Clearly document thread safety guarantees for each component
   - Use explicit synchronization mechanisms where needed
   - Minimize shared state between components
   - Consider lock-free algorithms for high-contention paths

## Implementation Approach

When implementing features, follow this rigorous process:

1. **Research and Planning**:
   - Study the specific Betanet v1.1 protocol section being implemented
   - Refer to the corresponding documentation in the `docs/` folder
   - Check `roadmap.md` to understand dependencies and priorities
   - Identify security considerations and edge cases
   - Plan for modularity and reusability

2. **Implementation Strategy**:
   - Start with interface definition and documentation
   - Implement core functionality first with proper error handling
   - Add comprehensive validation and security checks
   - Separate protocol logic from I/O operations
   - Implement test cases alongside the code

3. **Code Quality**:
   - Write self-documenting code with clear variable names
   - Keep functions focused and short (< 50 lines recommended)
   - Minimize cyclomatic complexity
   - Ensure complete error case coverage
   - Follow a consistent pattern for similar operations

4. **Integration**:
   - Define clear module boundaries and interfaces
   - Minimize inter-module dependencies
   - Use opaque pointers for implementation hiding
   - Document API contracts thoroughly
   - Create integration tests for cross-module interactions

## Module Integration Guidelines

Each module in Betanet.c must be designed with clear interfaces and minimal dependencies:

1. **Interface Design**:
   - Define clear public APIs in header files
   - Hide implementation details using opaque structs when possible
   - Document all assumptions and preconditions
   - Provide complete error handling documentation
   - Keep interfaces narrow and focused

2. **Dependency Management**:
   - Implement strict layering - higher layers may depend on lower layers, not vice versa
   - Document all dependencies explicitly in header files
   - Use dependency injection patterns where appropriate
   - Avoid circular dependencies between modules

3. **State Management**:
   - Clearly define ownership of resources
   - Document thread safety and concurrency guarantees
   - Implement proper initialization and cleanup sequences
   - Handle partial initialization and cleanup gracefully

4. **Cross-Module Communication**:
   - Use well-defined data structures for cross-module data exchange
   - Implement strict validation at module boundaries
   - Consider callback registration for event-based communication
   - Document all communication patterns

## Build and Test Instructions

### Building the Project

```bash
# Generate build files with CMake
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build the project
make -j$(nproc)

# Run tests
make test

# Build with release optimizations
cmake -B build -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Clean build artifacts
make clean
```

### Testing Requirements

When implementing tests, adhere to these guidelines:

1. **Unit Testing**:
   - Create unit tests for all public API functions
   - Test both success and failure paths
   - Mock dependencies to isolate the unit under test
   - Verify correct error propagation
   - Implement parameterized tests for edge cases

2. **Integration Testing**:
   - Test interactions between modules
   - Verify correct data flow through the system
   - Test realistic usage scenarios
   - Validate proper resource management

3. **Security Testing**:
   - Test resistance to malformed inputs
   - Verify cryptographic implementations against test vectors
   - Check for memory leaks and use-after-free conditions
   - Validate boundary conditions
   - Test concurrency correctness

4. **Performance Testing**:
   - Benchmark critical operations
   - Test scalability under load
   - Verify memory usage characteristics
   - Test latency and throughput metrics

## Protocol-Specific Guidance

### Cryptography (L0)

- All cryptographic primitives are in the `crypto/` directory
- Use constant-time implementations for all cryptographic operations
- Verify implementations against published test vectors
- Follow NIST guidance for secure implementations
- Include both pre-quantum and post-quantum algorithms
- Implement the following specific algorithms:
  - SHA-256 for hashing
  - X25519 for key exchange
  - Ed25519 for signatures
  - HKDF-SHA256 for key derivation
  - Kyber768 for post-quantum key exchange

**Security Requirements**:
- All cryptographic operations must be constant-time
- Implement secure key management with proper zeroization
- Add entropy collection and monitoring
- Use hardware acceleration where available

### Networking (L1-L2)

- The `net/` directory contains transport protocols (TCP, QUIC)
- The `htx/` subdirectory implements the HTX protocol for cover traffic
- Implement the following components:
  - TCP transport with TLS
  - QUIC transport with custom congestion control
  - HTX protocol with frame encapsulation
  - Noise XK handshake integration

**Requirements**:
- Handle network failures gracefully with proper error propagation
- Implement timeout and backoff mechanisms
- Add traffic shaping capabilities
- Support both IPv4 and IPv6
- Implement cover traffic generation

### SCION Routing (L3)

- Implement path-aware routing using SCION headers
- Handle path verification and selection efficiently
- Support transition from IP-based routing
- Implement the following components:
  - SCION header parsing and generation
  - Path storage and verification
  - Path maintenance and probing
  - Transition mechanisms

**Requirements**:
- Support multi-path routing
- Implement path verification cryptography
- Add path selection algorithms
- Support incremental deployment

### Overlay Network (L4)

- Implement peer discovery and management
- Support the libp2p protocol for interoperability
- Implement proof-of-work for resource allocation
- Include the following components:
  - Peer identity management
  - Bootstrap discovery
  - DHT-based peer discovery
  - Bitswap block exchange

**Requirements**:
- Implement NAT traversal techniques
- Add peer authentication
- Support resource limitation and fairness
- Implement reputation tracking

### Privacy Layer (L5)

- Implement mixnet capabilities
- Support onion routing principles
- Implement privacy settings and node selection
- Include the following components:
  - Mix node selection
  - Packet encryption layers
  - Timing obfuscation
  - Trust scoring

**Requirements**:
- Implement cover traffic mechanisms
  - Implement proper padding and timing
  - Support multiple privacy levels
  - Add verification of privacy guarantees

## Common AI Assistance Tasks

As an AI assistant for the Betanet.c project, you must adhere to these high standards:

1. **Implementing New Features**:
   - Always refer to the roadmap and documentation first
   - Understand dependencies between components
   - Implement proper error handling for all failure paths
   - Follow the project coding style precisely
   - Provide comprehensive tests for new code

2. **Code Reviews**:
   - Identify security vulnerabilities
   - Check for memory management issues
   - Verify error handling is complete
   - Ensure compliance with coding standards
   - Look for performance bottlenecks

3. **Debugging Assistance**:
   - Help identify root causes systematically
   - Suggest debugging approaches
   - Check for common pitfalls in C networking code
   - Verify cryptographic operations
   - Review thread safety issues

4. **Optimization**:
   - Profile before optimizing
   - Suggest algorithmic improvements
   - Identify memory bottlenecks
   - Consider constant-time requirements
   - Balance security and performance

5. **Documentation**:
   - Generate consistent API documentation
   - Explain complex algorithms clearly
   - Document security considerations
   - Include examples for non-trivial functions
   - Keep documentation synchronized with code

## Version Control Guidelines

When committing changes:

1. Use semantic commit messages with the format:
   ```
   feat(component): brief description
   
   - Detailed bullet points about the changes
   - Additional context or implementation notes
   - Security considerations if applicable
   - Related specification sections
   ```
   
2. Group related changes in a single commit
3. Make sure the code builds and passes tests before committing
4. Include test cases with new functionality
5. Reference relevant issues or documentation

## Getting Help

If you need additional information:

1. Refer to the detailed documentation in the `docs/` directory
2. Check the implementation roadmap in `roadmap.md`
3. Reference the Betanet v1.1 specification for protocol details
4. Study similar protocol implementations for reference