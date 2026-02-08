# Waiola - Private RFQ Settlement on Uniswap v4

> Private RFQ settlement with ENS-based maker discovery and mandatory Noir ZK enforcement for reduced pre-trade leakage and better execution.

<!-- TODO: Replace with actual demo video URL after recording -->
<!-- [![Demo Video](https://img.shields.io/badge/Demo-Watch%20on%20YouTube-red?logo=youtube)](https://youtu.be/YOUR_VIDEO_ID) -->

---

## Quickstart

```bash
# Clone and install
git clone https://github.com/DavidZapataOh/Waiola.git
cd Waiola
forge install && npm install

# Run full test suite (124 tests)
forge test -vvv

# Deploy to testnet (configure .env first)
cp .env.example .env
# Edit .env with your private key, RPC URL
npm run deploy:sepolia
```

---

## Problem

When traders request quotes through public RFQ systems, the process leaks information at every step:

- **Quote requests reveal intent** -- token pair, direction, and size are visible to all market participants
- **Makers can fade prices** -- seeing incoming flow allows adverse selection
- **Copy-traders front-run** -- large orders are detected and front-run before execution
- **Execution degrades** -- the result is systematically worse fills for everyone

Current solutions either sacrifice onchain verifiability (fully offchain OTC) or provide no privacy guarantees (public RFQ broadcasts).

## Solution

Waiola introduces a **Private RFQ workflow** on Uniswap v4 that reduces pre-trade information leakage while maintaining full onchain verifiability:

```
Taker                     ENS                    Maker                   Uniswap v4
  |                        |                       |                        |
  |-- 1. Resolve ENS ----->|                       |                        |
  |<-- endpoint + policy --|                       |                        |
  |                                                |                        |
  |-- 2. Request quote (private HTTP) ------------>|                        |
  |<-- Signed quote (EIP-712) + commitment --------|                        |
  |                                                                         |
  |-- 3. Generate Noir ZK proof locally                                     |
  |                                                                         |
  |-- 4. Commit quote onchain ------------------------------------------------>|
  |-- 5. Swap with proof in hookData ------------------------------------------>|
  |                                                                         |
  |                    Hook validates: signature + commitment +              |
  |                    expiry + ZK proof + replay protection                 |
  |                                                                         |
  |<-- 6. Swap executes (commitment consumed) -------------------------------|
```

**Three layers of protection:**

1. **ENS Discovery** -- Makers publish RFQ endpoints and policy hashes as ENS text records. Takers resolve them permissionlessly, like DNS for DeFi.

2. **Private Negotiation** -- Quote requests happen over direct HTTP between taker and maker. No public broadcast, no mempool visibility.

3. **ZK-Enforced Settlement** -- A Noir zero-knowledge proof is **mandatory** for every swap through the hook. The proof cryptographically binds the commitment to public inputs without revealing the quoted output price onchain.

---

## Architecture

```
+------------------+     +------------------+     +------------------+
|    ENS Registry   |     |   Maker Server   |     |  Noir Circuit    |
|                  |     |                  |     |                  |
| rfq-endpoint     |     | POST /quote      |     | Poseidon2 hash   |
| rfq-policy-hash  |     | GET  /policy     |     | quotedOut >= min  |
| rfq-pubkey       |     | EIP-712 signing  |     | commitment check |
+--------+---------+     +--------+---------+     +--------+---------+
         |                         |                        |
         v                         v                        v
+------------------------------------------------------------------------+
|                        Uniswap v4 PoolManager                          |
|                                                                        |
|  +------------------+  +------------------+  +------------------+      |
|  | RFQSettlement    |  |   RFQRegistry    |  |  HonkVerifier    |      |
|  | Hook             |  |                  |  |  (Noir/BB)       |      |
|  |                  |  | commitQuote()    |  |                  |      |
|  | beforeSwap:      |  | consumeQuote()   |  | verify(proof,    |      |
|  |  1. commitment   |  | isCommitted()    |  |   publicInputs)  |      |
|  |  2. signature    |  | isConsumed()     |  |                  |      |
|  |  3. expiry       |  |                  |  +------------------+      |
|  |  4. ZK proof     |  | Anti-replay:     |                           |
|  |  5. public inputs|  | used flag per    |  +------------------+      |
|  |  6. consume      |  | commitment       |  |   Poseidon2      |      |
|  +------------------+  +------------------+  |   Hasher         |      |
|                                              +------------------+      |
+------------------------------------------------------------------------+
```

### Onchain Contracts

| Contract | Purpose | Lines |
|----------|---------|-------|
| `RFQSettlementHook.sol` | Uniswap v4 hook -- validates quote + proof before swap | 469 |
| `RFQRegistry.sol` | Commitment storage with anti-replay protection | 167 |
| `QuoteCommitment.sol` | EIP-712 signing + Poseidon2 commitment library | 183 |
| `HonkVerifier.sol` | Noir ZK proof verifier (generated from Barretenberg) | Auto |
| `Poseidon2.sol` | ZK-friendly hash function for commitments | Lib |

### Offchain Components

| Component | Purpose |
|-----------|---------|
| Maker Server (`server.ts`) | Express.js RFQ server with `/quote`, `/policy`, `/status` |
| ENS Setup (`ens-setup.ts`) | Publishes maker discovery data to ENS text records |
| Taker Scripts | Quote request, proof generation, swap execution |
| Demo Script (`demo.sh`) | One-command deployment + demo orchestration |

### Noir Circuit

The RFQ quote commitment circuit enforces two constraints:

```noir
// Public inputs: commitment, pool_key_hash, taker, amount_in, min_out, expiry
// Private inputs: quoted_out, salt

// 1. Commitment integrity
assert(commitment == poseidon2([pool_key_hash, taker, amount_in, quoted_out, expiry, salt]));

// 2. Slippage protection
assert(quoted_out >= min_out);
```

The `quoted_out` (exact price the maker offered) stays hidden inside the proof. Only the `min_out` slippage bound is visible onchain.

---

## Testnet Deployments

<!-- TODO: Fill after deployment -->

| Network | Registry | Hook | Verifier | Hasher |
|---------|----------|------|----------|--------|
| **Sepolia** | `0x...` | `0x...` | `0x...` | `0x...` |
| **Base Sepolia** | `0x...` | `0x...` | `0x...` | `0x...` |
| **Arbitrum Sepolia** | `0x...` | `0x...` | `0x...` | `0x...` |

### Demo TXIDs

| Step | Network | TXID |
|------|---------|------|
| Deploy | Sepolia | `0x...` |
| Commit Quote | Sepolia | `0x...` |
| Swap (success) | Sepolia | `0x...` |
| Replay (reverts) | Sepolia | `0x...` |

---

## Gas Benchmarks

Measured via `forge test --gas-report`:

| Operation | Gas Cost | Notes |
|-----------|----------|-------|
| `commitQuote()` | ~47,000 | Register commitment onchain |
| `consumeQuote()` | ~26,000 | Mark commitment as used |
| `beforeSwap()` (full validation) | ~350,000+ | Signature + ZK proof + registry |
| ZK proof verification | ~250,000 | Honk verifier (Barretenberg) |
| EIP-712 signature recovery | ~5,000 | ECDSA.recover |
| Poseidon2 commitment | ~25,000 | 6-input hash |

> **Privacy overhead**: The ZK proof verification adds ~250k gas compared to a standard Uniswap v4 swap. This is the cost of mandatory cryptographic enforcement -- every swap through this hook is provably tied to a valid maker quote.

---

## ENS Integration

Waiola uses ENS as a **functional discovery layer** for RFQ makers:

### ENS Text Records

| Key | Value | Purpose |
|-----|-------|---------|
| `rfq-endpoint` | `https://rfq.maker.com/quote` | HTTP endpoint for quote requests |
| `rfq-policy-hash` | `0xabc...def` | Keccak256 of canonical policy JSON |
| `rfq-pubkey` | `0x04...` | Optional: maker's public key for encrypted quotes |

### How It Works

1. **Maker** registers an ENS name and sets text records with `npm run maker:ens-setup`
2. **Taker** resolves the ENS name to discover the maker's endpoint and policy
3. **Taker** fetches the policy from the endpoint and verifies its hash against the ENS record
4. If the hash matches, the taker trusts the policy and requests a quote

This prevents makers from silently changing their trading policies -- any change is detectable onchain via the policy hash mismatch.

### Setup

```bash
# Maker: Configure and publish ENS records
npm run maker:ens-setup

# Taker: Discover maker and request quote
npm run taker:request -- --maker alice.eth --amount 1000000000000000000
```

---

## Hook Enforcement Rules

The `RFQSettlementHook` implements **7 validation checks** in `beforeSwap`. The swap reverts unless ALL pass:

| # | Check | Revert Error |
|---|-------|-------------|
| 1 | Commitment exists in registry | `CommitmentNotFound` |
| 2 | Commitment not already used | `CommitmentAlreadyUsed` |
| 3 | Commitment bound to correct pool | `PoolMismatch` |
| 4 | Maker address matches commitment | `MakerMismatch` |
| 5 | EIP-712 signature valid for maker | `InvalidSignature` |
| 6 | Quote not expired | `QuoteExpired` |
| 7 | Noir ZK proof verifies | `InvalidProof` |

After all checks pass, the commitment is **atomically consumed** -- preventing any replay.

**Minimal permissions**: Only `beforeSwap` is enabled (from the [iceberg winning pattern](specs/winning-patterns-analysis.md)). No `afterSwap`, no liquidity hooks. This minimizes gas costs and attack surface.

---

## Testing

```bash
# Run all tests (124 passing)
forge test -vvv

# Run specific test suites
forge test --match-contract RFQRegistryTest -vvv      # 30+ tests
forge test --match-contract QuoteCommitmentTest -vvv   # 35+ tests
forge test --match-contract NoirVerifierTest -vvv      # Verifier tests
forge test --match-contract RFQSettlementHookTest -vvv  # Integration tests
forge test --match-contract ReplayProtectionTest -vvv   # Anti-replay edge cases
forge test --match-contract GasTest -vvv                # Gas benchmarks

# Coverage
forge coverage
```

### Test Categories

- **Unit tests**: RFQRegistry (commitment lifecycle, anti-replay, fuzz), QuoteCommitment (EIP-712 signing, hash determinism, tampering detection)
- **Integration tests**: Full swap flow through hook with real PoolManager
- **Replay protection**: Same commitment reuse, multi-pool attacks, expired commitment replay
- **Gas benchmarks**: Individual operation costs, full flow cost breakdown
- **Fuzz tests**: Random inputs for commitment hashing, signature verification

---

## Security Model

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for the complete security analysis.

### What We Protect Against

- **Pre-trade information leakage**: Quotes are negotiated privately over HTTP
- **Replay attacks**: Commitments are atomically consumed after first use
- **Signature forgery**: EIP-712 typed data with domain separator
- **Invalid proofs**: Mandatory Noir ZK verification in the hook
- **Stale quotes**: Expiry timestamp enforced both in circuit and onchain

### What We Do NOT Claim

- **Fully private onchain swaps**: AMM settlement effects are visible onchain
- **MEV protection post-commitment**: After commitment is posted, it's public
- **Encrypted balances**: We don't use FHE -- this is reduced leakage, not full privacy

This is an honest privacy model. See the [Threat Model](docs/THREAT_MODEL.md) for detailed analysis.

---

## Technical Details

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the complete technical deep dive.

### Key Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Hook permissions | `beforeSwap` only | Minimal permissions (iceberg pattern), lower gas |
| Hash function | Poseidon2 | ZK-friendly, matches Noir circuit |
| Commitment storage | Hybrid (hash onchain, details offchain) | Gas efficient, preserves privacy until swap |
| Proof system | Noir + Barretenberg (Honk) | Best hackathon tooling, growing ecosystem |
| Signature scheme | EIP-712 | Standard structured data signing, wallet support |
| Replay protection | Commitment registry with `used` flag | Atomic consume, impossible to replay |

---

## Project Structure

```
waiola/
├── src/                          # Solidity contracts
│   ├── RFQSettlementHook.sol     # Main Uniswap v4 hook
│   ├── RFQRegistry.sol           # Commitment registry
│   ├── libraries/
│   │   └── QuoteCommitment.sol   # EIP-712 + Poseidon2 library
│   ├── interfaces/               # Contract interfaces
│   └── verifiers/
│       └── NoirVerifier.sol      # Generated Honk verifier
│
├── circuits/rfq-quote/           # Noir ZK circuit
│   ├── src/main.nr               # Quote commitment circuit
│   └── Nargo.toml
│
├── test/                         # Foundry tests (124 tests)
│   ├── unit/                     # RFQRegistry, QuoteCommitment, Verifier
│   ├── integration/              # Hook + PoolManager, Replay, Gas
│   └── fixtures/                 # Shared test helpers
│
├── script/
│   ├── solidity/                 # Forge deployment scripts
│   │   ├── DeployAll.s.sol       # Full system deployment (CREATE2)
│   │   └── InitializePool.s.sol  # Pool initialization
│   ├── typescript/               # Offchain scripts
│   │   ├── maker/                # Server, ENS setup
│   │   ├── taker/                # Quote request, proof gen, swap
│   │   └── utils/                # EIP-712, ENS resolver, proof gen
│   └── demo.sh                   # One-command demo orchestration
│
├── docs/                         # Documentation
│   ├── ARCHITECTURE.md           # Technical deep dive
│   ├── THREAT_MODEL.md           # Security analysis
│   └── demo-video-script.md      # 3-min demo script
│
├── specs/                        # Implementation specs
├── deployments/                  # Deployment addresses per chain
├── foundry.toml                  # Foundry config (via-ir, optimizer)
└── package.json                  # npm scripts
```

---

## Deployment

### Deploy to Testnet

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env: DEPLOYER_PRIVATE_KEY, RPC_URL, POOL_MANAGER

# 2. Deploy all contracts
npm run deploy:sepolia          # Sepolia
npm run deploy:base-sepolia     # Base Sepolia
npm run deploy:arbitrum-sepolia # Arbitrum Sepolia

# 3. Initialize pool (after deploy)
HOOK_ADDRESS=0x... TOKEN0=0x... TOKEN1=0x... \
forge script script/solidity/InitializePool.s.sol \
  --rpc-url $RPC_URL --broadcast -vvv
```

### PoolManager Addresses (Testnets)

| Network | Chain ID | PoolManager |
|---------|----------|-------------|
| Sepolia | 11155111 | `0xE03A1074c86CFeDd5C142C4F04F1a1536e203543` |
| Base Sepolia | 84532 | `0x05E73354cFDd6745C338b50BcFDfA3Aa6fA03408` |
| Arbitrum Sepolia | 421614 | `0xFB3e0C6F74eB1a21CC1Da29aeC80D2Dfe6C9a317` |

---

## Demo Flow

The complete demo showcases all 6 steps of the Waiola RFQ flow:

1. **Resolve** maker via ENS text records
2. **Request** quote privately over HTTP
3. **Generate** Noir ZK proof (binds commitment to public inputs)
4. **Commit** quote onchain (register in RFQRegistry)
5. **Swap** via Uniswap v4 hook (validates signature + proof + replay)
6. **Replay** attempt fails with `CommitmentAlreadyUsed`

```bash
# One-command demo
./script/demo.sh sepolia
```

See [demo video script](docs/demo-video-script.md) for the 3-minute walkthrough.

---

## Built With

- [Uniswap v4](https://github.com/Uniswap/v4-core) -- Core AMM with hook system
- [Noir](https://noir-lang.org/) -- ZK circuit language (Aztec)
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) -- Honk proof system
- [ENS](https://ens.domains/) -- Ethereum Name Service for maker discovery
- [Foundry](https://book.getfoundry.sh/) -- Solidity development framework
- [Poseidon2](https://github.com/distributed-lab/poseidon2-evm) -- ZK-friendly hash function
- [OpenZeppelin](https://openzeppelin.com/contracts/) -- Ownable2Step, ECDSA, EIP-712

---

## Future Work

- **Solver networks**: Multiple makers compete via auction mechanism
- **Cross-chain RFQ**: Bridge quotes across L1 and L2s
- **FHE integration**: Fully encrypted onchain state (Fhenix/Zama)
- **Oracle-enhanced security**: Mandatory Pyth price deviation checks
- **Multi-asset quotes**: Complex swaps with baskets
- **Audit and mainnet**: Production deployment after security audit

---

## License

MIT
