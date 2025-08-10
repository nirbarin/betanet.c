# Betanet.c Makefile
# This file provides convenient shortcuts to common build operations

# Detect number of CPU cores for parallel builds
NPROC := $(shell nproc 2>/dev/null || echo 4)

# Build directory
BUILD_DIR := build

# Default build type (Debug or Release)
BUILD_TYPE ?= Debug

.PHONY: all
all: build

.PHONY: build
build:
	@echo "Building betanet ($(BUILD_TYPE))"
	@mkdir -p $(BUILD_DIR)
	@cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)
	@cmake --build $(BUILD_DIR) -j $(NPROC)
	@echo "Build complete!"

.PHONY: release
release:
	@$(MAKE) BUILD_TYPE=Release build

.PHONY: debug
debug:
	@$(MAKE) BUILD_TYPE=Debug build

.PHONY: test
test: build
	@echo "Running tests"
	@cd $(BUILD_DIR) && ctest --output-on-failure -j $(NPROC)

.PHONY: clean
clean:
	@echo "Cleaning build directory"
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete!"

.PHONY: rebuild
rebuild: clean build

.PHONY: help
help:
	@echo "Betanet.c Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Same as build (default)"
	@echo "  build     - Build the project with default configuration (Debug)"
	@echo "  debug     - Build with debug configuration"
	@echo "  release   - Build with release configuration"
	@echo "  test      - Build and run tests"
	@echo "  clean     - Remove all build artifacts"
	@echo "  rebuild   - Clean and rebuild the project"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  BUILD_TYPE - Set build type (Debug or Release, default: Debug)"
	@echo "  NPROC      - Number of parallel build jobs (default: auto-detected)"