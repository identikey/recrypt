#!/bin/bash
set -e

# E2E Test: Alice encrypts → uploads → shares with Bob → Bob downloads → decrypts
# Tests the full recryption proxy flow with ML-DSA-87 signatures
#
# Usage:
#   ./tests/e2e/recryption.sh         # Uses mock backend (fast, ~5s)
#   ./tests/e2e/recryption.sh lattice # Uses lattice backend (slow, ~3min)

BACKEND="${1:-mock}"

echo "═══════════════════════════════════════════════════════════════"
echo "  E2E RECRYPTION TEST - Backend: $BACKEND"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Setup temp dir and env
TEST_DIR=$(mktemp -d)
export RECRYPT_WALLET="$TEST_DIR/test-wallet.ikeyw"
export RECRYPT_BACKEND="$BACKEND"
export RECRYPT_WALLET_PASSWORD="testpass123"
export RECRYPT_SERVER="http://localhost:7222"
export RECRYPT_PRE_BACKEND="$BACKEND"  # Server config via env

CLI="./target/release/recrypt"
SERVER="./target/release/recrypt-server"
SERVER_PID=""

# Lattice backend takes ~2 min to initialize
if [ "$BACKEND" = "lattice" ]; then
    SERVER_STARTUP_WAIT=150  # 2.5 min
    echo "NOTE: Lattice backend will take ~2 min to initialize"
else
    SERVER_STARTUP_WAIT=2
fi

cleanup() {
    echo ""
    echo "=== CLEANUP ==="
    if [ -n "$SERVER_PID" ]; then
        echo "Stopping server (PID $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
    echo "✓ Cleaned up"
}
trap cleanup EXIT

echo "Test dir: $TEST_DIR"
echo "Backend:  $BACKEND"
echo ""

# Start server
echo "=== 1. Starting server ==="
RUST_LOG=recrypt_server=info $SERVER &
SERVER_PID=$!

if [ "$BACKEND" = "lattice" ]; then
    echo "Waiting for lattice backend to initialize (this takes ~2 min)..."
    # Poll health endpoint instead of fixed sleep
    STARTED=false
    for i in $(seq 1 $SERVER_STARTUP_WAIT); do
        if curl -s http://localhost:7222/health | grep -q '"status":"ok"'; then
            STARTED=true
            break
        fi
        sleep 1
        if [ $((i % 30)) -eq 0 ]; then
            echo "  Still waiting... ($i seconds)"
        fi
    done
    if [ "$STARTED" = "false" ]; then
        echo "✗ Server failed to start within ${SERVER_STARTUP_WAIT}s"
        exit 1
    fi
else
    sleep $SERVER_STARTUP_WAIT
    if ! curl -s http://localhost:7222/health | grep -q '"status":"ok"'; then
        echo "✗ Server failed to start"
        exit 1
    fi
fi
echo "✓ Server running on http://localhost:7222"
echo ""

# Create identities
echo "=== 2. Create identities (Alice & Bob) ==="
$CLI identity new --name alice
$CLI identity new --name bob
echo "✓ Created alice and bob"
echo ""

# Get fingerprints (using grep bc jq may not be available)
echo "=== 3. Get fingerprints ==="
ALICE_FP=$($CLI --json identity show --name alice | grep '"fingerprint"' | sed 's/.*: "\([^"]*\)".*/\1/')
BOB_FP=$($CLI --json identity show --name bob | grep '"fingerprint"' | sed 's/.*: "\([^"]*\)".*/\1/')
echo "Alice: $ALICE_FP"
echo "Bob:   $BOB_FP"
if [ -z "$ALICE_FP" ] || [ -z "$BOB_FP" ]; then
    echo "✗ Failed to get fingerprints"
    exit 1
fi
echo ""

# Register accounts on server
echo "=== 4. Register accounts on server ==="
$CLI identity use alice
$CLI account register
$CLI identity use bob
$CLI account register
echo "✓ Both accounts registered"
echo ""

# Create test file
echo "=== 5. Create test file ==="
SECRET_MSG="Top secret message for Bob! 🔐 $(date)"
echo "$SECRET_MSG" > "$TEST_DIR/secret.txt"
echo "Message: $SECRET_MSG"
echo ""

# Alice encrypts for herself
echo "=== 6. Alice encrypts file (for herself) ==="
$CLI identity use alice
$CLI encrypt "$TEST_DIR/secret.txt" --for alice --output "$TEST_DIR/encrypted.enc"
ls -la "$TEST_DIR/encrypted.enc"
echo "✓ Encrypted"
echo ""

# Alice uploads to server
echo "=== 7. Alice uploads to server ==="
FILE_HASH=$($CLI --json file upload "$TEST_DIR/encrypted.enc" | grep '"hash"' | sed 's/.*: "\([^"]*\)".*/\1/')
echo "File hash: $FILE_HASH"
if [ -z "$FILE_HASH" ]; then
    echo "✗ Failed to get file hash"
    exit 1
fi
echo "✓ Uploaded"
echo ""

# Alice shares with Bob (generates recrypt key, server stores it)
echo "=== 8. Alice creates share for Bob ==="
SHARE_ID=$($CLI --json share create "$FILE_HASH" --to "$BOB_FP" | grep '"share_id"' | sed 's/.*: "\([^"]*\)".*/\1/')
echo "Share ID: $SHARE_ID"
if [ -z "$SHARE_ID" ]; then
    echo "✗ Failed to get share ID"
    exit 1
fi
echo "✓ Share created (recrypt key stored on server)"
echo ""

# Bob lists his incoming shares
echo "=== 9. Bob lists incoming shares ==="
$CLI identity use bob
$CLI share list --to
echo ""

# Bob downloads the shared file (server applies recryption transform!)
echo "=== 10. Bob downloads shared file ==="
$CLI share download "$SHARE_ID" --output "$TEST_DIR/bob_received.enc"
ls -la "$TEST_DIR/bob_received.enc"
echo "✓ Downloaded (server recrypted wrapped_key for Bob)"
echo ""

# Bob decrypts
echo "=== 11. Bob decrypts ==="
$CLI decrypt "$TEST_DIR/bob_received.enc" --output "$TEST_DIR/bob_decrypted.txt"
BOB_MSG=$(cat "$TEST_DIR/bob_decrypted.txt")
echo "Decrypted: $BOB_MSG"
echo ""

# Verify roundtrip
echo "=== 12. Verify roundtrip ==="
echo "Original:  $SECRET_MSG"
echo "Decrypted: $BOB_MSG"
if [ "$SECRET_MSG" = "$BOB_MSG" ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ✓ E2E RECRYPTION TEST PASSED!"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Flow completed:"
    echo "    1. Alice encrypted with her PRE public key"
    echo "    2. Alice uploaded ciphertext to server"
    echo "    3. Alice generated recrypt key (Alice→Bob)"
    echo "    4. Alice registered share with server"
    echo "    5. Bob downloaded (server transformed wrapped_key)"
    echo "    6. Bob decrypted with his own secret key"
    echo ""
    if [ "$BACKEND" = "lattice" ]; then
        echo "  Crypto: XChaCha20 + Blake3/Bao + OpenFHE Lattice PRE (post-quantum)"
    else
        echo "  Crypto: XChaCha20 + Blake3/Bao + Mock PRE (testing only)"
    fi
    echo "  Auth:   Ed25519 + ML-DSA-87 dual signatures"
    echo ""
else
    echo ""
    echo "✗ E2E TEST FAILED - content mismatch!"
    echo ""
    diff "$TEST_DIR/secret.txt" "$TEST_DIR/bob_decrypted.txt" || true
    exit 1
fi
