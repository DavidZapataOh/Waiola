#!/usr/bin/env bash
# =============================================================================
# Waiola RFQ - Full Demo Orchestration Script
# =============================================================================
# Deploys all contracts, initializes pool, and runs the full RFQ demo flow.
#
# Usage:
#   ./script/demo.sh [network]
#
# Networks:
#   sepolia         (default) Ethereum Sepolia
#   base-sepolia    Base Sepolia
#   arbitrum-sepolia Arbitrum Sepolia
#   local           Local Anvil fork
#
# Prerequisites:
#   - .env file configured (copy from .env.example)
#   - forge, cast installed
#   - nargo installed (for proof generation)
#   - node/npm installed (for TypeScript scripts)
#
# Author: Waiola Team
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load environment
if [ -f .env ]; then
    source .env
else
    echo -e "${RED}ERROR: .env file not found. Copy .env.example to .env and configure it.${NC}"
    exit 1
fi

# Parse network argument
NETWORK="${1:-sepolia}"

case "$NETWORK" in
    sepolia)
        RPC_URL="${SEPOLIA_RPC_URL}"
        POOL_MANAGER="${SEPOLIA_POOL_MANAGER}"
        CHAIN_ID=11155111
        EXPLORER="https://sepolia.etherscan.io"
        VERIFY_FLAGS="--etherscan-api-key ${ETHERSCAN_API_KEY:-}"
        ;;
    base-sepolia)
        RPC_URL="${BASE_SEPOLIA_RPC_URL}"
        POOL_MANAGER="${BASE_SEPOLIA_POOL_MANAGER}"
        CHAIN_ID=84532
        EXPLORER="https://sepolia.basescan.org"
        VERIFY_FLAGS="--etherscan-api-key ${BASESCAN_API_KEY:-}"
        ;;
    arbitrum-sepolia)
        RPC_URL="${ARBITRUM_SEPOLIA_RPC_URL}"
        POOL_MANAGER="${ARBITRUM_SEPOLIA_POOL_MANAGER}"
        CHAIN_ID=421614
        EXPLORER="https://sepolia.arbiscan.io"
        VERIFY_FLAGS="--etherscan-api-key ${ARBISCAN_API_KEY:-}"
        ;;
    local)
        RPC_URL="http://127.0.0.1:8545"
        POOL_MANAGER="${SEPOLIA_POOL_MANAGER}"
        CHAIN_ID=31337
        EXPLORER="local"
        VERIFY_FLAGS=""
        ;;
    *)
        echo -e "${RED}Unknown network: $NETWORK${NC}"
        echo "Usage: $0 [sepolia|base-sepolia|arbitrum-sepolia|local]"
        exit 1
        ;;
esac

echo -e "${BLUE}"
echo "========================================"
echo "  Waiola RFQ - Full Demo"
echo "========================================"
echo -e "  Network:      ${YELLOW}${NETWORK}${BLUE}"
echo -e "  Chain ID:     ${YELLOW}${CHAIN_ID}${BLUE}"
echo -e "  PoolManager:  ${YELLOW}${POOL_MANAGER}${BLUE}"
echo "========================================"
echo -e "${NC}"

# =============================================================================
# Step 1: Deploy all contracts
# =============================================================================
echo -e "\n${GREEN}[1/6] Deploying contracts...${NC}"

POOL_MANAGER="$POOL_MANAGER" forge script script/solidity/DeployAll.s.sol \
    --rpc-url "$RPC_URL" \
    --broadcast \
    $VERIFY_FLAGS \
    -vvv 2>&1 | tee /tmp/waiola-deploy.log

# Extract addresses from deployment JSON
DEPLOY_FILE="deployments/${CHAIN_ID}.json"
if [ -f "$DEPLOY_FILE" ]; then
    REGISTRY_ADDR=$(jq -r '.registry' "$DEPLOY_FILE")
    VERIFIER_ADDR=$(jq -r '.verifier' "$DEPLOY_FILE")
    HASHER_ADDR=$(jq -r '.hasher' "$DEPLOY_FILE")
    HOOK_ADDR=$(jq -r '.hook' "$DEPLOY_FILE")

    echo -e "${GREEN}  Registry:  ${REGISTRY_ADDR}${NC}"
    echo -e "${GREEN}  Verifier:  ${VERIFIER_ADDR}${NC}"
    echo -e "${GREEN}  Hasher:    ${HASHER_ADDR}${NC}"
    echo -e "${GREEN}  Hook:      ${HOOK_ADDR}${NC}"
else
    echo -e "${RED}ERROR: Deployment file not found at ${DEPLOY_FILE}${NC}"
    exit 1
fi

# =============================================================================
# Step 2: Initialize pool (if tokens are configured)
# =============================================================================
echo -e "\n${GREEN}[2/6] Initializing pool...${NC}"

if [ "${TOKEN0:-}" != "0x_TOKEN0_ADDRESS" ] && [ "${TOKEN1:-}" != "0x_TOKEN1_ADDRESS" ]; then
    HOOK_ADDRESS="$HOOK_ADDR" \
    TOKEN0="$TOKEN0" \
    TOKEN1="$TOKEN1" \
    POOL_MANAGER="$POOL_MANAGER" \
    forge script script/solidity/InitializePool.s.sol \
        --rpc-url "$RPC_URL" \
        --broadcast \
        -vvv
    echo -e "${GREEN}  Pool initialized!${NC}"
else
    echo -e "${YELLOW}  Skipping pool init (TOKEN0/TOKEN1 not configured)${NC}"
    echo -e "${YELLOW}  Set TOKEN0 and TOKEN1 in .env to initialize a pool${NC}"
fi

# =============================================================================
# Step 3: Setup maker ENS records
# =============================================================================
echo -e "\n${GREEN}[3/6] Setting up maker ENS records...${NC}"
echo -e "${YELLOW}  (Requires ENS name ownership on testnet)${NC}"
echo -e "${YELLOW}  Run manually: npm run maker:ens-setup${NC}"

# =============================================================================
# Step 4: Request quote from maker
# =============================================================================
echo -e "\n${GREEN}[4/6] Requesting quote from maker...${NC}"
echo -e "${YELLOW}  Run manually: npm run taker:request${NC}"

# =============================================================================
# Step 5: Generate ZK proof
# =============================================================================
echo -e "\n${GREEN}[5/6] Generating ZK proof...${NC}"
echo -e "${YELLOW}  Run manually: npm run taker:prove${NC}"

# =============================================================================
# Step 6: Execute swap
# =============================================================================
echo -e "\n${GREEN}[6/6] Executing swap...${NC}"
echo -e "${YELLOW}  Run manually: npm run taker:swap${NC}"

# =============================================================================
# Summary
# =============================================================================
echo -e "\n${BLUE}"
echo "========================================"
echo "  DEMO DEPLOYMENT COMPLETE"
echo "========================================"
echo -e "${NC}"
echo -e "  Network:    ${GREEN}${NETWORK}${NC}"
echo -e "  Registry:   ${GREEN}${REGISTRY_ADDR}${NC}"
echo -e "  Verifier:   ${GREEN}${VERIFIER_ADDR}${NC}"
echo -e "  Hasher:     ${GREEN}${HASHER_ADDR}${NC}"
echo -e "  Hook:       ${GREEN}${HOOK_ADDR}${NC}"
echo ""
echo -e "  Explorer links:"
if [ "$EXPLORER" != "local" ]; then
    echo -e "  Registry:   ${BLUE}${EXPLORER}/address/${REGISTRY_ADDR}${NC}"
    echo -e "  Hook:       ${BLUE}${EXPLORER}/address/${HOOK_ADDR}${NC}"
fi
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo "  1. Start maker server:  npm run maker:server"
echo "  2. Request quote:       npm run taker:request"
echo "  3. Generate proof:      npm run taker:prove"
echo "  4. Execute swap:        npm run taker:swap"
echo ""
echo -e "${BLUE}========================================${NC}"
