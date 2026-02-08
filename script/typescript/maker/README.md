# Maker ENS Setup Guide

This directory contains scripts for makers to publish their RFQ service discovery data on ENS.

## Prerequisites

1. **Own an ENS name** (e.g., `alice.eth` on Sepolia or mainnet)
2. **Have ETH** in the account that owns the ENS name (for gas)
3. **RPC endpoint** (Alchemy, Infura, or public RPC)

## Quick Start

### 1. Install Dependencies

```bash
cd ../../../  # Go to project root
npm install
```

### 2. Configure Environment

```bash
cd script/typescript/maker
cp .env.example .env
```

Edit `.env`:
```bash
MAKER_PRIVATE_KEY=0xYOUR_PRIVATE_KEY
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR-ALCHEMY-KEY
```

**⚠️ SECURITY**: Never commit `.env` to git! It's in `.gitignore`.

### 3. Configure Maker Settings

```bash
cd config
cp maker-config.example.json maker-config.json
cp policy.example.json policy.json
```

Edit `maker-config.json`:
```json
{
  "ensName": "yourname.eth",
  "endpoint": "https://your-rfq-api.example.com",
  "policyPath": "./policy.json",
  "pubkey": null,
  "rpcUrl": "${RPC_URL}",
  "resolverAddress": null
}
```

Edit `policy.json` with your trading pools and limits:
```json
{
  "version": "1.0.0",
  "spread": "0.1%",
  "maxQuoteValidity": 300,
  "pools": [
    {
      "tokenA": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      "tokenB": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "fee": 3000,
      "maxSlippage": "0.5%",
      "maxAmount": "10000000000000000000",
      "minAmount": "100000000000000000"
    }
  ]
}
```

### 4. Run ENS Setup

```bash
npm run maker:ens-setup
```

Expected output:
```
🔧 Setting up ENS for RFQ maker...

Configuration:
  ENS Name: yourname.eth
  Endpoint: https://your-rfq-api.example.com
  ...

1. Setting rfq-endpoint...
   TX: 0x1234...
   ✅ Confirmed

2. Setting rfq-policy-hash...
   TX: 0x5678...
   ✅ Confirmed

✅ ENS Setup Complete!
```

## What Gets Published on ENS

The script sets these ENS text records:

| Record | Value | Purpose |
|--------|-------|---------|
| `rfq-endpoint` | Your API URL | Where takers send quote requests |
| `rfq-policy-hash` | keccak256(policy.json) | Prevents you from changing policy after takers discover you |
| `rfq-pubkey` | Public key (optional) | For encrypted quote requests (future feature) |

## Verifying Your Setup

You can verify your ENS records are set correctly:

```bash
# Using cast (Foundry)
cast call --rpc-url $RPC_URL <RESOLVER_ADDRESS> \
  "text(bytes32,string)(string)" \
  $(cast namehash yourname.eth) \
  "rfq-endpoint"

# Or check on ENS app
# https://app.ens.domains/yourname.eth
```

## Updating Your Policy

If you need to update your policy:

1. Edit `policy.json` with new values
2. Run `npm run maker:ens-setup` again
3. **IMPORTANT**: This updates the `rfq-policy-hash` on ENS

**Warning**: Takers who cached your old policy will see a verification failure. This is intentional - it prevents you from changing terms after quotes are issued.

## Troubleshooting

### Error: No resolver found for yourname.eth

**Cause**: ENS name doesn't have a resolver set.

**Fix**:
1. Go to https://app.ens.domains
2. Find your name
3. Click "Set Resolver" → Use default Public Resolver

### Error: Insufficient funds

**Cause**: Not enough ETH for gas.

**Fix**: Send ETH to your maker address (the one that owns the ENS name).

### Error: Not authorized

**Cause**: The private key in `.env` doesn't match the ENS owner.

**Fix**: Verify you're using the correct private key for the account that owns the ENS name.

### TypeScript errors about setText

**Cause**: Using wrong ethers version or wrong ENS method.

**Fix**:
```bash
npm install ethers@^6.16.0
```

The script uses `ethers.Contract` to call `setText` directly on the resolver, not the read-only `EnsResolver` class.

## Gas Costs

Approximate costs (at 30 gwei, 1 ETH = $2800):

- Set 2 records (endpoint + policy-hash): ~60,000 gas (~$5)
- Set 3 records (+ pubkey): ~90,000 gas (~$7.50)

**This is a one-time cost** - you only pay again if you update your policy.

## Next Steps

After ENS setup:

1. **Deploy your RFQ API server** that serves `policy.json` at `/policy` endpoint
2. **Start your quote service** that responds to `/quote` requests
3. **Test with a taker script** to verify end-to-end flow

See `../taker/` directory for taker scripts.

## Security Notes

- ✅ Policy hash prevents post-discovery policy changes
- ✅ HTTPS required for endpoint (TLS security)
- ✅ Takers verify policy hash before trusting your policy
- ⚠️ ENS name transfer gives new owner control of records
- ⚠️ Onchain quotes are bound to your address, not ENS name

## Example Config Files

### Sepolia Testnet Example

`maker-config.json`:
```json
{
  "ensName": "testmaker.eth",
  "endpoint": "https://rfq-sepolia.example.com",
  "policyPath": "./policy.json",
  "pubkey": null,
  "rpcUrl": "https://eth-sepolia.g.alchemy.com/v2/YOUR-KEY"
}
```

`policy.json`:
```json
{
  "version": "1.0.0",
  "spread": "0.1%",
  "maxQuoteValidity": 300,
  "pools": [
    {
      "tokenA": "0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9",
      "tokenB": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
      "fee": 3000,
      "maxSlippage": "0.5%",
      "maxAmount": "10000000000000000000",
      "minAmount": "100000000000000000"
    }
  ]
}
```

## Support

For issues or questions:
- Check `specs/phase-5-completion.md` for detailed architecture
- Review `utils/ens-resolver.ts` for taker-side ENS resolution
- See CLAUDE.md for project overview

---

*Part of Waiola RFQ - Private RFQ on Uniswap v4*
