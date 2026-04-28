# Recrypt Rust Development Tasks
#
# Build system for Rust FFI bindings to OpenFHE and liboqs

# Show available tasks
default:
    @just --list

# --------------------
# Rust Development
# --------------------

# Build the workspace
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Run all tests (sequential: OpenFHE has global state that can't be shared across test threads)
# Note: OpenMP parallelism happens *within* each operation, not across test cases
test:
    cargo test -- --test-threads=1

# Run tests for recrypt-ffi specifically
test-ffi:
    cargo test -p recrypt-ffi -- --test-threads=1

# Run tests for recrypt-openfhe-sys (must be sequential due to OpenFHE global state)
test-openfhe:
    cargo test -p recrypt-openfhe-sys -- --test-threads=1

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Format code
format:
    cargo fmt

# Check formatting without applying
format-check:
    cargo fmt -- --check

# Build documentation
docs:
    cargo doc --no-deps

# Regenerate the OpenAPI snapshot consumed by recrypt-client and the
# generated sections of docs/http-api-reference.md. Run after touching
# any utoipa-annotated handler or schema in recrypt-server. CI should
# `just openapi-regen` and fail if the working tree is dirty afterwards.
openapi-regen:
    cargo run -q -p recrypt-server --bin dump_openapi
    cargo run -q -p recrypt-server --bin dump_endpoint_md -- \
        --spec crates/recrypt-client/openapi.json \
        --doc  docs/http-api-reference.md \
        --path /accounts \
        --method POST
    cargo run -q -p recrypt-server --bin dump_endpoint_md -- \
        --spec crates/recrypt-client/openapi.json \
        --doc  docs/http-api-reference.md \
        --path /capabilities/verify \
        --method POST
    cargo build -q -p recrypt-client

# Clean Rust build artifacts
clean-rust:
    cargo clean

# --------------------
# Submodules
# --------------------

# Initialize/update git submodules
submodules:
    git submodule update --init --recursive --depth 1

# --------------------
# OpenFHE (Static)
# --------------------

# Build OpenFHE as a static library (with OpenMP for thread safety)
build-openfhe:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    echo "Building OpenFHE C++ library (static + OpenMP)..."
    
    INSTALL_DIR="$(pwd)/vendor/openfhe-install"
    
    # Find OpenMP on macOS (Homebrew libomp)
    OMP_ROOT=""
    if [[ "$(uname)" == "Darwin" ]]; then
        if [[ -d "/opt/homebrew/opt/libomp" ]]; then
            OMP_ROOT="/opt/homebrew/opt/libomp"
        elif [[ -d "/usr/local/opt/libomp" ]]; then
            OMP_ROOT="/usr/local/opt/libomp"
        fi
    fi
    
    cd vendor/openfhe-development
    rm -rf build
    mkdir -p build
    cd build
    
    CMAKE_ARGS=(
        -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_STATIC=ON
        -DBUILD_UNITTESTS=OFF
        -DBUILD_EXAMPLES=OFF
        -DBUILD_BENCHMARKS=OFF
    )
    
    if [[ -n "${OMP_ROOT}" ]]; then
        echo "Using OpenMP from: ${OMP_ROOT}"
        CMAKE_ARGS+=(
            -DWITH_OPENMP=ON
            "-DOpenMP_C_FLAGS=-Xpreprocessor -fopenmp"
            "-DOpenMP_CXX_FLAGS=-Xpreprocessor -fopenmp"
            -DOpenMP_C_LIB_NAMES=omp
            -DOpenMP_CXX_LIB_NAMES=omp
            "-DOpenMP_omp_LIBRARY=${OMP_ROOT}/lib/libomp.dylib"
            "-DCMAKE_C_FLAGS=-I${OMP_ROOT}/include"
            "-DCMAKE_CXX_FLAGS=-I${OMP_ROOT}/include"
        )
    elif [[ "$(uname)" == "Darwin" ]]; then
        echo "⚠️  libomp not found. Install with: brew install libomp"
        echo "   Building without OpenMP (reduced parallelism)"
        CMAKE_ARGS+=(-DWITH_OPENMP=OFF)
    else
        # Linux: OpenMP usually just works with GCC
        echo "Using system OpenMP (GCC/libgomp)"
        CMAKE_ARGS+=(-DWITH_OPENMP=ON)
    fi
    
    cmake .. "${CMAKE_ARGS[@]}"
    
    # Cross-platform nproc
    NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    make -j${NPROC}
    make install
    
    echo ""
    echo "✅ OpenFHE static libraries installed to: ${INSTALL_DIR}"
    echo "   Libraries: ${INSTALL_DIR}/lib/"
    echo "   Headers:   ${INSTALL_DIR}/include/openfhe/"
    if [[ -n "${OMP_ROOT}" ]] || [[ "$(uname)" != "Darwin" ]]; then
        echo "   OpenMP:    ✅ Enabled (parallel ops)"
    else
        echo "   OpenMP:    ❌ Disabled"
    fi
    echo ""
    echo "Note: For recryption proxy, CryptoContext and keys should be"
    echo "      immutable after setup. Concurrent recrypt ops on different"
    echo "      ciphertexts are thread-safe."

# Check if OpenMP is available (macOS: brew install libomp)
check-omp:
    #!/usr/bin/env bash
    if [[ "$(uname)" == "Darwin" ]]; then
        if [[ -d "/opt/homebrew/opt/libomp" ]]; then
            echo "✅ libomp found at /opt/homebrew/opt/libomp"
            ls -la /opt/homebrew/opt/libomp/lib/
        elif [[ -d "/usr/local/opt/libomp" ]]; then
            echo "✅ libomp found at /usr/local/opt/libomp"
            ls -la /usr/local/opt/libomp/lib/
        else
            echo "❌ libomp not found. Install with: brew install libomp"
            exit 1
        fi
    else
        if command -v gcc &>/dev/null && gcc -fopenmp -E - < /dev/null &>/dev/null; then
            echo "✅ OpenMP available via GCC"
        else
            echo "❌ OpenMP not available. Install gcc or libgomp."
            exit 1
        fi
    fi

# Clean OpenFHE build artifacts
clean-openfhe:
    rm -rf vendor/openfhe-development/build vendor/openfhe-install


# --------------------
# Combined Targets
# --------------------

# Build all C/C++ dependencies (static)
build-deps: build-openfhe
    @echo ""
    @echo "✅ All dependencies built (static linking ready)"

# Clean all C/C++ dependency builds
clean-deps: clean-openfhe

# Clean everything (Rust + deps)
clean-all: clean-rust clean-deps

# Full rebuild from scratch
rebuild-all: clean-all submodules build-deps build

# --------------------
# Setup
# --------------------

# First-time setup: submodules + deps + build
setup: submodules build-deps build
    @echo ""
    @echo "🚀 Setup complete! Try: just test-ffi"
    @echo "💭 Optional: npx humanlayer thoughts init (for dev notes)"

# Show dependency install locations
show-deps:
    #!/usr/bin/env bash
    echo "Dependency install locations:"
    echo ""
    if [[ -d "vendor/openfhe-install" ]]; then
        echo "✅ OpenFHE: vendor/openfhe-install/"
        ls -la vendor/openfhe-install/lib/*.a 2>/dev/null || echo "   (no static libs found)"
    else
        echo "❌ OpenFHE: not built (run: just build-openfhe)"
    fi
    echo ""
    echo "ℹ️  liboqs: using oqs crate (no vendored build needed)"

# =============================================================================
# Storage Layer (Phase 4)
# =============================================================================

# Start Minio for development
minio-up:
    docker-compose -f docker/docker-compose.dev.yml up -d minio
    @echo "Minio console: http://localhost:9001 (minioadmin/minioadmin)"

# Stop Minio
minio-down:
    docker-compose -f docker/docker-compose.dev.yml down

# Run storage tests (in-memory + local only)
test-storage:
    cargo test -p recrypt-storage

# Run storage tests including S3/Minio integration
test-storage-s3: minio-up
    sleep 2  # Wait for Minio to be ready
    cargo test -p recrypt-storage --features s3-tests

# Check storage crate
check-storage:
    cargo check -p recrypt-storage
    cargo check -p recrypt-storage --features s3
    cargo clippy -p recrypt-storage -- -D warnings
    cargo clippy -p recrypt-storage --features s3 -- -D warnings

# =============================================================================
# Auth Service (Phase 4b)
# =============================================================================

# Run auth service tests (in-memory only)
test-auth:
    cargo test -p identikey-storage-auth -- --test-threads=1

# Run auth service tests with SQLite
test-auth-sqlite:
    cargo test -p identikey-storage-auth --features sqlite -- --test-threads=1

# Check auth service crate
check-auth:
    cargo check -p identikey-storage-auth
    cargo check -p identikey-storage-auth --features sqlite
    cargo clippy -p identikey-storage-auth -- -D warnings
    cargo clippy -p identikey-storage-auth --features sqlite -- -D warnings

# Generate auth service docs
docs-auth:
    cargo doc -p identikey-storage-auth --no-deps --open

# =============================================================================
# CLI Wallet Utilities (Phase 6b)
# =============================================================================

# Show wallet/config paths (macOS: ~/Library/Application Support/io.identikey.recrypt/)
cli-paths:
    @echo "Wallet file (macOS):  ~/Library/Application Support/io.identikey.recrypt/wallet.recrypt"
    @echo "Config file (macOS):  ~/Library/Application Support/io.identikey.recrypt/config.toml"
    @echo "Keychain entry:       service=recrypt, account=wallet-key"

# [macOS] Find cached wallet key in Keychain
keychain-find:
    security find-generic-password -s recrypt -a wallet-key

# [macOS] Delete cached wallet key from Keychain (will prompt for password on next CLI use)
keychain-delete:
    security delete-generic-password -s recrypt -a wallet-key

# [macOS] Delete wallet file (WARNING: loses all identities!)
wallet-delete:
    rm -i ~/Library/Application\ Support/io.identikey.recrypt/wallet.recrypt

# [macOS] Show wallet directory contents
wallet-dir:
    ls -la ~/Library/Application\ Support/io.identikey.recrypt/

# =============================================================================
# E2E Tests
# =============================================================================

# Run CLI unit test (no server, local encrypt/decrypt only)
test-cli: build-release
    ./test-cli.sh

# Run Rust e2e tests (mock backend, memory storage, ~30s)
test-e2e: build-release
    cargo test -p recrypt-e2e-tests -- --test-threads=1

# Run e2e tests with S3/Minio (~2min, requires Docker)
test-e2e-s3: build-release minio-up
    cargo test -p recrypt-e2e-tests --features s3-tests -- --test-threads=1

# Run e2e crypto-correctness tests against real OpenFHE BFV backend (slow)
test-e2e-lattice-rust: build-release
    cargo test -p recrypt-e2e-tests --features lattice-tests --test lattice_tests -- --test-threads=1

# Run comprehensive e2e (all backends + S3)
test-e2e-full: test-e2e test-e2e-s3 test-e2e-lattice-rust

# Run legacy bash e2e test with mock backend
test-e2e-legacy: build-release
    ./tests/e2e/recryption.sh mock

# Run legacy bash e2e with lattice backend (~3 minutes, post-quantum)
test-e2e-lattice: build-release
    ./tests/e2e/recryption.sh lattice

# =============================================================================
# Release Management
# =============================================================================

# Show current version from Cargo.toml
version:
    @grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2

# Create a new release (bumps version, commits, tags, pushes)
# Usage: just release 1.2.3
release version:
    #!/usr/bin/env bash
    set -Eeuo pipefail

    # Validate version format
    if ! [[ "{{version}}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Version must be in format X.Y.Z (e.g., 1.2.3)"
        exit 1
    fi

    # Check for clean working directory
    if ! git diff --quiet || ! git diff --staged --quiet; then
        echo "Error: Working directory not clean. Commit or stash changes first."
        exit 1
    fi

    # Check we're on main branch
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$BRANCH" != "main" ]]; then
        echo "Warning: Not on main branch (currently on $BRANCH)"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    echo "Releasing version {{version}}..."

    # Update version in root Cargo.toml
    sed -i.bak 's/^version = ".*"/version = "{{version}}"/' Cargo.toml
    rm Cargo.toml.bak

    # Update Cargo.lock
    cargo update --workspace

    # Commit and tag
    git add Cargo.toml Cargo.lock
    git commit -m "Release v{{version}}"
    git tag -a "v{{version}}" -m "Release v{{version}}"

    echo ""
    echo "Created commit and tag for v{{version}}"
    echo ""
    echo "To publish:"
    echo "  git push && git push --tags"
    echo ""
    echo "To undo:"
    echo "  git reset --hard HEAD~1 && git tag -d v{{version}}"

