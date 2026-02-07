#!/bin/bash
# Build script for RFQ Quote Commitment Circuit
#
# This script:
# 1. Compiles the Noir circuit to ACIR
# 2. Generates the verification key
# 3. Generates the Solidity verifier contract
# 4. Copies the verifier to src/verifiers/
#
# Prerequisites:
# - nargo (Noir compiler) must be installed
# - bb (Barretenberg backend) must be installed at ~/.bb/bb
#
# Usage:
#   cd circuits/rfq_quote
#   chmod +x build.sh
#   ./build.sh

set -e  # Exit on error

echo "========================================="
echo "  RFQ Quote Circuit Build Script"
echo "========================================="
echo ""

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Working directory: $SCRIPT_DIR"
echo ""

# Step 1: Compile Noir circuit
echo "[1/4] Compiling Noir circuit..."
nargo compile

if [ $? -eq 0 ]; then
    echo "✅ Circuit compiled successfully"
else
    echo "❌ Circuit compilation failed"
    exit 1
fi
echo ""

# Step 2: Generate verification key
echo "[2/4] Generating verification key..."
if [ -f "$HOME/.bb/bb" ]; then
    BB_PATH="$HOME/.bb/bb"
elif command -v bb &> /dev/null; then
    BB_PATH="bb"
else
    echo "❌ Barretenberg (bb) not found"
    echo "   Install from: https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg"
    echo "   Or run: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && noirup"
    exit 1
fi

$BB_PATH write_vk -b ./target/rfq_quote.json -o ./target/vk

if [ $? -eq 0 ]; then
    echo "✅ Verification key generated"
else
    echo "❌ Verification key generation failed"
    exit 1
fi
echo ""

# Step 3: Generate Solidity verifier
echo "[3/4] Generating Solidity verifier contract..."
$BB_PATH contract -k ./target/vk -c crs -b ./target/rfq_quote.json -o ./target/contract.sol

if [ $? -eq 0 ]; then
    echo "✅ Solidity verifier generated"
else
    echo "❌ Solidity verifier generation failed"
    exit 1
fi
echo ""

# Step 4: Copy verifier to src/verifiers/
echo "[4/4] Copying verifier to src/verifiers/..."
VERIFIER_DIR="../../src/verifiers"
mkdir -p "$VERIFIER_DIR"

cp ./target/contract.sol "$VERIFIER_DIR/NoirVerifier.sol"

if [ $? -eq 0 ]; then
    echo "✅ Verifier copied to $VERIFIER_DIR/NoirVerifier.sol"
else
    echo "❌ Failed to copy verifier"
    exit 1
fi
echo ""

echo "========================================="
echo "  ✅ Build Complete!"
echo "========================================="
echo ""
echo "Generated files:"
echo "  - target/rfq_quote.json (compiled circuit)"
echo "  - target/vk (verification key)"
echo "  - target/contract.sol (Solidity verifier)"
echo "  - ../../src/verifiers/NoirVerifier.sol (production verifier)"
echo ""
echo "Next steps:"
echo "  1. Run circuit tests: nargo test"
echo "  2. Compile Solidity: cd ../.. && forge build"
echo "  3. Run integration tests: forge test --match-contract NoirVerifier"
echo ""
