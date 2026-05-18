#!/usr/bin/env bash
# deploy-rescue.sh — Deploy FlashLoanRescue or FlashSwapRescue per chain.
#
# Usage:
#   ./deploy-rescue.sh <chain_id> [--flash-swap]
#
# Requirements:
#   - RESCUER_PRIVATE_KEY env var (deployer + owner)
#   - forge (Foundry) installed
#   - RPC URLs configured in .env (RPC_URL_<CHAIN_ID>)
#
# After deployment, add the contract address to RESCUE_FLASHLOAN_RECEIVER
# in .env: RESCUE_FLASHLOAN_RECEIVER=...,<chain_id>:<deployed_address>

set -euo pipefail

CHAIN_ID="${1:?Usage: deploy-rescue.sh <chain_id> [--flash-swap]}"
USE_FLASH_SWAP="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Load .env
if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

if [ -z "${RESCUER_PRIVATE_KEY:-}" ]; then
  echo "ERROR: RESCUER_PRIVATE_KEY not set in environment or .env"
  exit 1
fi

# Resolve RPC URL for this chain
RPC_VAR="RPC_URL_${CHAIN_ID}"
RPC_URL="${!RPC_VAR:-}"
if [ -z "$RPC_URL" ]; then
  echo "ERROR: $RPC_VAR not set. Add it to .env (e.g. RPC_URL_146=https://rpc.soniclabs.com)"
  exit 1
fi

# Aave V3 Pool addresses (for FlashLoanRescue)
declare -A AAVE_POOLS=(
  [1]="0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2"
  [10]="0x794a61358d6845594f94dc1db02a252b5b4814ad"
  [56]="0x6807dc923806fe8fd134338eabca509979a7e0cb"
  [100]="0xb50201558b00496a145fe76f7424749556e326d8"
  [137]="0x794a61358d6845594f94dc1db02a252b5b4814ad"
  [8453]="0xa238dd80c259a72e81d7e4664a9801593f98d1c5"
  [42161]="0x794a61358d6845594f94dc1db02a252b5b4814ad"
  [43114]="0x794a61358d6845594f94dc1db02a252b5b4814ad"
  [534352]="0x11fcfe756c05ad438e312a7fd934381537d3cffe"
)

# UniV2 Factory addresses (for FlashSwapRescue)
declare -A UNIV2_FACTORIES=(
  [1]="0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"
  [56]="0xca143ce32fe78f1f7019d7d551a6402fc5350c73"
  [137]="0x5757371414417b8c6caad45baef941abc7d3ab32"
  [146]="0x9BBE7C9Fa4ebd0bC3685e5dCd06f2BA7B8f099b7"
  [8453]="0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6"
  [42161]="0xc35dadb65012ec5796536bd9864ed8773abc74c4"
  [43114]="0x9ad6c38be94206ca50bb0d90783181834c915db8"
  [81457]="0x5C346464d33F90bABaf70dB6388507CC889C1070"
)

cd "$ROOT_DIR/contracts/rescue"

if [ "$USE_FLASH_SWAP" = "--flash-swap" ]; then
  FACTORY="${UNIV2_FACTORIES[$CHAIN_ID]:-}"
  if [ -z "$FACTORY" ]; then
    echo "ERROR: No UniV2 factory configured for chain $CHAIN_ID"
    echo "Add it to UNIV2_FACTORIES in this script"
    exit 1
  fi
  echo "Deploying FlashSwapRescue on chain $CHAIN_ID..."
  echo "  Factory: $FACTORY"
  echo "  RPC: $RPC_URL"
  echo ""

  forge create FlashSwapRescue \
    --rpc-url "$RPC_URL" \
    --private-key "$RESCUER_PRIVATE_KEY" \
    --constructor-args "$FACTORY" \
    --json | tee /tmp/deploy-result.json

  DEPLOYED=$(cat /tmp/deploy-result.json | python3 -c "import json,sys; print(json.load(sys.stdin)['deployedTo'])")
else
  POOL="${AAVE_POOLS[$CHAIN_ID]:-}"
  if [ -z "$POOL" ]; then
    echo "ERROR: No Aave V3 pool configured for chain $CHAIN_ID"
    echo "Use --flash-swap for chains without Aave, or add the pool to AAVE_POOLS"
    exit 1
  fi
  echo "Deploying FlashLoanRescue on chain $CHAIN_ID..."
  echo "  Aave Pool: $POOL"
  echo "  RPC: $RPC_URL"
  echo ""

  forge create FlashLoanRescue \
    --rpc-url "$RPC_URL" \
    --private-key "$RESCUER_PRIVATE_KEY" \
    --constructor-args "$POOL" \
    --json | tee /tmp/deploy-result.json

  DEPLOYED=$(cat /tmp/deploy-result.json | python3 -c "import json,sys; print(json.load(sys.stdin)['deployedTo'])")
fi

echo ""
echo "=========================================="
echo "  DEPLOYED: $DEPLOYED"
echo "=========================================="
echo ""
echo "Add to .env:"
echo "  RESCUE_FLASHLOAN_RECEIVER=...,$CHAIN_ID:$DEPLOYED"
echo ""
echo "Then restart the panel for changes to take effect."
