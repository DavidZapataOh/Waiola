# Taker Scripts - RFQ Quote Execution

This directory contains scripts for takers to discover makers, request quotes, generate proofs, and execute swaps.

## Prerequisites

1. **Node.js** (v18+)
2. **Deployed contracts** (Registry, Hook, PoolManager)
3. **Maker running** with ENS configured
4. **Noir installed** (for proof generation): https://noir-lang.org/docs/getting_started/installation/

## Quick Start

### 1. Install Dependencies

```bash
cd ../../../  # Go to project root
npm install
```

### 2. Configure Environment

```bash
cd script/typescript/taker
cp .env.example .env
```

Edit `.env`:
```bash
TAKER_PRIVATE_KEY=0xYOUR_PRIVATE_KEY
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR-KEY
CHAIN_ID=11155111

# Contract addresses (from deployment)
REGISTRY_ADDRESS=0x...
POOL_MANAGER_ADDRESS=0x...
HOOK_ADDRESS=0x...
```

### 3. Execute RFQ Flow

#### Step 1: Request Quote

```bash
npm run taker:request -- \
  alice.eth \
  0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 \
  0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  3000 \
  1000000000000000000 \
  0x742d35Cc6634C0532925a3b844Bc454e4438f44e
```

Arguments:
- `alice.eth` - Maker's ENS name
- `0xC02a...` - Token A address (WETH)
- `0xA0b8...` - Token B address (USDC)
- `3000` - Pool fee (0.3%)
- `1000000000000000000` - Amount in (1 ETH in wei)
- `0x742d...` - Taker address

Output: `quote.json` with signed quote

#### Step 2: Generate Proof

```bash
npm run taker:prove
```

This:
- Reads `quote.json`
- Writes `Prover.toml`
- Runs `nargo prove` to generate ZK proof
- Updates `quote.json` with proof

#### Step 3: Execute Swap

```bash
npm run taker:swap
```

This:
- Commits quote to registry
- Executes swap via PoolManager with hook validation
- Tests replay protection
- Saves TXIDs to `txids.json`

## Detailed Workflow

### 1. Quote Request (`request-quote.ts`)

**What it does:**
1. Resolves maker's ENS name
2. Fetches maker's policy from endpoint
3. Verifies policy hash against ENS
4. Checks pool compatibility
5. Validates amount against pool limits
6. Requests quote from maker
7. Verifies quote signature
8. Calculates slippage protection
9. Saves quote to `quote.json`

**Output (`quote.json`):**
```json
{
  "quote": {
    "poolKeyHash": "0x...",
    "taker": "0x...",
    "amountIn": "1000000000000000000",
    "quotedOut": "1995000000000000000",
    "expiry": "1738456789",
    "salt": "0x..."
  },
  "maker": "0x...",
  "signature": "0x...",
  "policyHash": "0x...",
  "poolKey": { ... },
  "minOut": "1985025000000000000",
  "slippageBps": 50
}
```

---

### 2. Proof Generation (`generate-proof.ts`)

**What it does:**
1. Loads quote from `quote.json`
2. Computes commitment hash
3. Writes `circuits/rfq-quote/Prover.toml`
4. Runs `nargo prove` to generate proof
5. Reads generated proof
6. Generates public inputs array
7. Updates `quote.json` with proof

**Prover.toml format:**
```toml
# Public inputs (visible onchain)
commitment = "0x..."
pool_key_hash = "0x..."
taker = "123456789012345678901234567890"
amount_in = "1000000000000000000"
min_out = "1985025000000000000"
expiry = "1738456789"

# Private inputs (only in ZK proof)
quoted_out = "1995000000000000000"
salt = "987654321098765432109876543210"
```

**Updated `quote.json`:**
```json
{
  // ... existing fields ...
  "commitment": "0x...",
  "proof": "0x...",
  "publicInputs": [
    "0x...", // commitment
    "0x...", // poolKeyHash
    "0x...", // taker (as bytes32)
    "0x...", // amountIn
    "0x...", // minOut
    "0x..."  // expiry
  ],
  "proofGeneratedAt": "2026-02-08T12:34:56.789Z"
}
```

---

### 3. Swap Execution (`execute-swap.ts`)

**What it does:**
1. Loads quote with proof
2. Commits quote to RFQRegistry
3. Encodes hookData
4. Executes swap via PoolManager
5. Verifies replay protection
6. Saves TXIDs

**hookData encoding:**
```solidity
abi.encode(
    Quote(poolKeyHash, taker, amountIn, quotedOut, expiry, salt),
    maker,
    signature,
    proof,
    publicInputs
)
```

**Output (`txids.json`):**
```json
{
  "commitTx": "0x...",
  "swapTx": "0x...",
  "timestamp": "2026-02-08T12:34:56.789Z"
}
```

---

## Error Handling

### Quote Request Errors

**Error: No resolver found for ENS name**
- **Cause**: ENS name not registered or no resolver set
- **Fix**: Check ENS name on https://app.ens.domains

**Error: No rfq-endpoint found**
- **Cause**: Maker hasn't set ENS text records
- **Fix**: Maker needs to run `npm run maker:ens-setup`

**Error: Policy hash mismatch**
- **Cause**: Maker changed policy without updating ENS
- **Fix**: Ask maker to update ENS or set `ALLOW_UNVERIFIED_POLICY=true`

**Error: Pool not supported**
- **Cause**: Maker doesn't support the requested pool
- **Fix**: Check maker's policy for supported pools

**Error: Amount below/above minimum/maximum**
- **Cause**: Requested amount outside maker's limits
- **Fix**: Adjust amount to be within pool limits

---

### Proof Generation Errors

**Error: nargo not found**
- **Cause**: Noir not installed
- **Fix**: Install Noir: https://noir-lang.org/docs/getting_started/installation/
- **Workaround**: Script generates mock proof for testing

**Error: Circuit not compiled**
- **Cause**: Noir circuit not compiled
- **Fix**: `cd circuits/rfq-quote && nargo compile`

**Error: Quote does not have required fields**
- **Cause**: Malformed quote.json
- **Fix**: Delete quote.json and re-run request-quote

---

### Swap Execution Errors

**Error: Quote already used (CommitmentAlreadyUsed)**
- **Cause**: Attempting to replay a quote
- **Fix**: Request a new quote

**Error: Quote expired (QuoteExpired)**
- **Cause**: Quote validity period expired
- **Fix**: Request a new quote

**Error: Invalid proof (InvalidProof)**
- **Cause**: Proof verification failed
- **Fix**: Re-generate proof or request new quote

**Error: Signature verification failed (InvalidSignature)**
- **Cause**: Quote signature doesn't match maker
- **Fix**: Request a new quote from the same maker

**Error: Insufficient funds**
- **Cause**: Taker doesn't have enough tokens
- **Fix**: Fund taker wallet with required tokens

---

## Testing Flow (Without Real Deployment)

For testing without deployed contracts:

1. **Mock Mode**: Set mock addresses in `.env`:
   ```bash
   REGISTRY_ADDRESS=0x0000000000000000000000000000000000000001
   POOL_MANAGER_ADDRESS=0x0000000000000000000000000000000000000002
   HOOK_ADDRESS=0x0000000000000000000000000000000000000003
   ```

2. **Run request-quote**: Will use mock proof generation

3. **Run generate-proof**: Will generate mock proof

4. **Deployment needed**: `execute-swap` requires real deployed contracts

---

## Advanced Usage

### Custom Slippage

```bash
npm run taker:request -- \
  alice.eth \
  0xC02a... \
  0xA0b8... \
  3000 \
  1000000000000000000 \
  0x742d... \
  100  # 1% slippage (100 basis points)
```

### Multiple Quotes

Request quotes from different makers:
```bash
# Quote from alice.eth
npm run taker:request -- alice.eth ... > alice-quote.json

# Quote from bob.eth
npm run taker:request -- bob.eth ... > bob-quote.json

# Compare and choose best quote
```

### Quote Expiry Tracking

```typescript
// In your app
import quote from './quote.json';

const expiryDate = new Date(Number(quote.quote.expiry) * 1000);
const timeRemaining = quote.quote.expiry - Math.floor(Date.now() / 1000);

console.log(`Quote expires at: ${expiryDate.toISOString()}`);
console.log(`Time remaining: ${timeRemaining}s`);
```

---

## File Structure

```
taker/
├── .env.example           # Environment template
├── .env                   # Your config (gitignored)
├── README.md              # This file
├── request-quote.ts       # Step 1: Request quote
├── generate-proof.ts      # Step 2: Generate proof
├── execute-swap.ts        # Step 3: Execute swap
├── quote.json            # Quote data (generated)
└── txids.json            # Transaction IDs (generated)
```

---

## Security Notes

- ✅ **Verify policy hash** before trusting maker's policy
- ✅ **Check quote expiry** before generating proof
- ✅ **Validate signature** from correct maker address
- ✅ **Use slippage protection** to prevent sandwich attacks
- ⚠️ **Never share private keys** - use .env (gitignored)
- ⚠️ **ENS resolution** - verify you're resolving the correct maker

---

## Gas Costs

Approximate gas costs (at 30 gwei):

| Operation | Gas | Cost (ETH) |
|-----------|-----|------------|
| Commit Quote | ~60,000 | ~0.0018 |
| Swap (w/ ZK proof) | ~450,000 | ~0.0135 |
| **Total** | **~510,000** | **~0.0153** |

*Costs at 1 ETH = $2800: ~$43*

---

## Troubleshooting

### Quote request hangs

**Check:**
1. Is maker's server running? `curl http://localhost:3000/status`
2. Is endpoint accessible? Check firewall/CORS
3. Is RPC responding? Test with `curl $RPC_URL`

### Proof generation fails

**Check:**
1. Noir installed? `nargo --version`
2. Circuit compiled? `ls circuits/rfq-quote/target/`
3. Prover.toml valid? Check for formatting errors

### Swap fails with no error message

**Check:**
1. Contract addresses correct in `.env`?
2. Taker has enough ETH for gas?
3. Tokens approved for PoolManager?
4. Pool initialized with correct hook?

---

## Support

For issues or questions:
- Check `../../../specs/phase-6-completion.md` for architecture
- Review `../../../test/integration/RFQSettlementHook.t.sol` for examples
- See CLAUDE.md for project overview

---

*Part of Waiola RFQ - Private RFQ on Uniswap v4*
