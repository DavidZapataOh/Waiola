# Architecture: Waiola Private RFQ System

**Document Version**: 1.0
**Last Updated**: 2026-02-08

---

## System Overview

Waiola is a private RFQ (Request for Quote) settlement system built on Uniswap v4. It enables makers and takers to negotiate swap terms privately offchain, then enforce those terms onchain through a combination of EIP-712 signatures, Poseidon2 commitments, and Noir zero-knowledge proofs.

The system has three layers:

1. **Discovery Layer** (ENS) -- Permissionless maker discovery via ENS text records
2. **Negotiation Layer** (HTTP) -- Private quote requests between taker and maker
3. **Settlement Layer** (Uniswap v4 Hook) -- Onchain enforcement of quote terms with ZK proofs

---

## Component Architecture

### Onchain Components

#### 1. RFQSettlementHook (`src/RFQSettlementHook.sol`)

The core enforcement contract. Extends Uniswap v4's `BaseHook` and implements only the `beforeSwap` callback (minimal permissions pattern).

**Constructor Dependencies:**
```
IPoolManager  -- Uniswap v4 PoolManager
IRFQRegistry  -- Commitment registry
IVerifier     -- Noir ZK proof verifier (Honk)
Poseidon2     -- Hash function for commitments
```

**State:**
- `DOMAIN_SEPARATOR` (immutable) -- EIP-712 domain separator built at deployment
- References to registry, verifier, and hasher (all immutable)

**Validation Flow in `_beforeSwap()`:**

```
hookData
  |
  v
_decodeHookData() --> Quote, maker, signature, proof, publicInputs
  |
  v
computeCommitment(hasher, quote) --> commitment hash
  |
  v
registry.isCommitted(commitment)?  ---[NO]---> revert CommitmentNotFound
  |[YES]
  v
registry.isConsumed(commitment)?   ---[YES]--> revert CommitmentAlreadyUsed
  |[NO]
  v
registry.getCommitment() --> verify poolKeyHash matches
  |
  v
verify maker matches commitment data
  |
  v
QuoteCommitment.verifySignature(quote, signature, maker, DOMAIN_SEPARATOR)
  |                                               |
  |[VALID]                                        |[INVALID]--> revert InvalidSignature
  v
block.timestamp < quote.expiry?   ---[NO]---> revert QuoteExpired
  |[YES]
  v
verifier.verify(proof, publicInputs)?  ---[NO]--> revert InvalidProof
  |[YES]
  v
_verifyPublicInputs() --> match commitment, pool, taker, amount, expiry
  |
  v
registry.consumeQuote(commitment) --> mark as used (atomic)
  |
  v
emit QuoteValidated(commitment, maker, taker, poolKeyHash, amountIn)
  |
  v
return (selector, ZERO_DELTA, 0) --> swap proceeds normally
```

**Stack Depth Management:**

The hook splits validation into three internal functions to avoid Solidity's stack depth limit:
- `_decodeAndValidateCore()` -- Decode hookData, check commitment, verify signature
- `_validateProofAndInputs()` -- Check expiry, verify ZK proof, match public inputs
- `_finalizeValidation()` -- Consume commitment, emit event, return

A `ValidationData` struct passes data between these functions.

**hookData Encoding:**

```solidity
abi.encode(
    QuoteCommitment.Quote,  // (poolKeyHash, taker, amountIn, quotedOut, expiry, salt)
    address maker,
    bytes signature,         // EIP-712 signature from maker
    bytes proof,             // Noir ZK proof bytes
    bytes32[] publicInputs   // 6 public inputs for verifier
)
```

---

#### 2. RFQRegistry (`src/RFQRegistry.sol`)

Stores commitment metadata onchain and provides anti-replay protection. Inherits `Ownable2Step` from OpenZeppelin.

**Storage:**
```solidity
mapping(bytes32 => CommitmentData) public commitments;
address public hook;  // Authorized hook (only consumer)
```

**CommitmentData struct:**
```solidity
struct CommitmentData {
    uint256 expiry;       // Quote expiry timestamp
    address maker;        // Maker who signed the quote
    bytes32 poolKeyHash;  // Hash of PoolKey (pool binding)
    bool used;            // Anti-replay flag
}
```

**Access Control:**
- `commitQuote()` -- Permissionless (anyone can commit)
- `consumeQuote()` -- Restricted to authorized hook only
- `setHook()` -- Owner only (set once during deployment)

**Anti-Replay Mechanism:**

The `used` flag in `CommitmentData` is set to `true` atomically when the hook calls `consumeQuote()`. This happens inside the `beforeSwap` callback, which means:
- The commitment is consumed before the swap executes
- If the swap reverts for any other reason, the consumption also reverts (atomic)
- A second swap attempt with the same commitment will hit `CommitmentAlreadyUsed`

**Commitment Uniqueness:**

Commitments are computed as `Poseidon2(poolKeyHash, taker, amountIn, quotedOut, expiry, salt)`. The `salt` field (random 32 bytes) ensures that even identical quote terms produce different commitments. This prevents:
- Two quotes with the same terms from colliding
- Deterministic commitment prediction by third parties

---

#### 3. QuoteCommitment Library (`src/libraries/QuoteCommitment.sol`)

Stateless library providing EIP-712 hashing, Poseidon2 commitment computation, and signature verification.

**Quote Struct (EIP-712):**
```solidity
struct Quote {
    bytes32 poolKeyHash;  // Hash of PoolKey
    address taker;        // Taker address
    uint256 amountIn;     // Input amount
    uint256 quotedOut;    // Quoted output amount
    uint256 expiry;       // Quote expiry timestamp
    bytes32 salt;         // Unique salt
}
```

**EIP-712 Type Hash:**
```
Quote(bytes32 poolKeyHash,address taker,uint256 amountIn,uint256 quotedOut,uint256 expiry,bytes32 salt)
```

**Poseidon2 Commitment:**
```solidity
function computeCommitment(Poseidon2 hasher, Quote memory quote) internal pure returns (bytes32) {
    Field.Type[] memory inputs = new Field.Type[](6);
    inputs[0] = Field.toField(uint256(quote.poolKeyHash) % BN254_PRIME);
    inputs[1] = Field.toField(quote.taker);
    inputs[2] = Field.toField(quote.amountIn % BN254_PRIME);
    inputs[3] = Field.toField(quote.quotedOut % BN254_PRIME);
    inputs[4] = Field.toField(quote.expiry % BN254_PRIME);
    inputs[5] = Field.toField(uint256(quote.salt) % BN254_PRIME);
    return Field.toBytes32(hasher.hash(inputs));
}
```

All 256-bit values are reduced modulo the BN254 scalar field prime (`0x30644e...0001`) before being passed to Poseidon2. This ensures consistency with the Noir circuit which operates over the BN254 field.

**Signature Verification:**
```solidity
function verifySignature(Quote, bytes signature, address maker, bytes32 domainSeparator)
    -> bool
```
Uses OpenZeppelin's `ECDSA.recover` with EIP-712 structured data hashing.

---

#### 4. HonkVerifier (`src/verifiers/NoirVerifier.sol`)

Auto-generated Solidity contract from the Noir circuit via Barretenberg's `bb contract` command. Implements the `IVerifier` interface.

**Key Parameters:**
- Circuit size: N = 4096, LOG_N = 12
- Public inputs: 22 (6 logical inputs + 16 circuit overhead)
- Proof system: Honk (Barretenberg)

**Compilation Note:**

The verifier is compiled with `via_ir = false` via Foundry's `compilation_restrictions`:
```toml
compilation_restrictions = [
  { paths = "src/verifiers/**", via_ir = false }
]
```

This is because the auto-generated verifier uses assembly blocks that are incompatible with the Yul IR pipeline.

---

#### 5. Poseidon2 (`lib/poseidon2-evm/`)

External library providing the Poseidon2 hash function over the BN254 scalar field. Used for:
- Computing commitments in the QuoteCommitment library
- Matching the hash computation in the Noir circuit

---

### Noir Circuit

**Path:** `circuits/rfq-quote/src/main.nr`

**Purpose:** Prove knowledge of private quote details (quotedOut, salt) that are consistent with public inputs, without revealing them onchain.

**Public Inputs (6):**
| Index | Name | Type | Source |
|-------|------|------|--------|
| 0 | `commitment` | Field | Computed by hook |
| 1 | `pool_key_hash` | Field | From PoolKey |
| 2 | `taker` | Field | msg.sender |
| 3 | `amount_in` | Field | Swap params |
| 4 | `min_out` | Field | Taker's slippage bound |
| 5 | `expiry` | Field | Quote expiry |

**Private Inputs (2):**
| Name | Type | Purpose |
|------|------|---------|
| `quoted_out` | Field | Maker's actual quoted output (hidden) |
| `salt` | Field | Random nonce for commitment uniqueness |

**Constraints:**

1. **Commitment integrity**: `commitment == Poseidon2([pool_key_hash, taker, amount_in, quoted_out, expiry, salt])`
2. **Slippage protection**: `quoted_out >= min_out` (as u128 comparison)

The circuit uses Noir's built-in `std::hash::poseidon2::Poseidon2::hash()` function which operates over the same BN254 field as the Solidity Poseidon2 contract.

**Build Pipeline:**
```
main.nr --> nargo compile --> target/rfq_quote.json (ACIR)
         --> bb write_vk --> verification key
         --> bb contract --> NoirVerifier.sol
```

---

### Offchain Components

#### Maker Server (`script/typescript/maker/server.ts`)

Express.js HTTP server that makers run to serve quotes.

**Endpoints:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/status` | Health check, maker address, balance |
| GET | `/policy` | Serve maker's trading policy JSON |
| POST | `/quote` | Generate and sign a quote |
| POST | `/reload-policy` | Hot-reload policy (dev) |

**Quote Generation Flow:**
1. Validate request parameters (poolKeyHash, taker, amountIn)
2. Load policy and find matching pool configuration
3. Validate amount against pool limits (min/max)
4. Fetch current pool price
5. Calculate `quotedOut` with maker's spread (in basis points)
6. Generate random salt and compute expiry
7. Create Quote struct and sign with EIP-712
8. Return signed quote + policy hash

---

#### ENS Setup (`script/typescript/maker/ens-setup.ts`)

Script for makers to publish their RFQ discovery data as ENS text records.

**Records Set:**
| Key | Value |
|-----|-------|
| `rfq-endpoint` | Maker's HTTP endpoint URL |
| `rfq-policy-hash` | Keccak256 of canonical policy JSON |
| `rfq-pubkey` | Optional public key for encrypted quotes |

**Policy Hash Computation:**
```typescript
const canonicalJson = JSON.stringify(policy, Object.keys(policy).sort());
const policyHash = ethers.keccak256(ethers.toUtf8Bytes(canonicalJson));
```

Canonical JSON (sorted keys) ensures deterministic hashing regardless of key ordering.

---

#### Taker Scripts

**request-quote.ts**: Resolves maker ENS, verifies policy hash, requests quote over HTTP.

**generate-proof.ts**: Generates Noir ZK proof from quote data using `nargo prove`.

**execute-swap.ts**: Commits quote to registry, encodes hookData, executes swap through PoolManager.

---

### Deployment Architecture

**Script:** `script/solidity/DeployAll.s.sol`

**Deployment Order:**
1. `RFQRegistry` -- Commitment storage (constructor: deployer address)
2. `HonkVerifier` -- ZK proof verifier (no constructor args)
3. `Poseidon2` -- Hash function (no constructor args)
4. `RFQSettlementHook` -- Hook via CREATE2 with mined salt
5. `registry.setHook(hook)` -- Wire registry to hook

**CREATE2 Hook Address Mining:**

Uniswap v4 encodes hook permissions in the lowest 14 bits of the hook's address. For `BEFORE_SWAP_FLAG` (`1 << 7 = 0x80`), the hook address must have bit 7 set.

The script uses `HookMiner.find()` from `@uniswap/v4-periphery` to find a CREATE2 salt that produces a valid address:

```solidity
(address hookAddress, bytes32 salt) = HookMiner.find(
    CREATE2_DEPLOYER,    // 0x4e59...56C (standard across all EVM chains)
    flags,               // 0x80 (BEFORE_SWAP_FLAG)
    type(RFQSettlementHook).creationCode,
    constructorArgs
);
```

**Output:** Deployment addresses saved to `deployments/{chainId}.json`.

---

## Data Flow

### Complete RFQ Flow (6 Steps)

```
Step 1: DISCOVER
  Taker --> ENS Registry
  - Resolve maker.eth
  - Get rfq-endpoint, rfq-policy-hash
  - Verify policy hash

Step 2: NEGOTIATE
  Taker --> Maker Server (private HTTP)
  - POST /quote { poolKeyHash, taker, amountIn }
  - Maker computes quotedOut with spread
  - Maker signs Quote struct (EIP-712)
  - Returns: { quote, signature, policyHash }

Step 3: PROVE
  Taker (local)
  - Write Prover.toml with quote parameters
  - nargo prove --> ZK proof
  - Proof binds (commitment, pool, taker, amount, minOut, expiry)
  - quotedOut and salt remain hidden

Step 4: COMMIT
  Taker --> RFQRegistry
  - commitQuote(commitment, expiry, maker, poolKeyHash)
  - Registry stores metadata and sets used=false

Step 5: SWAP
  Taker --> PoolManager.swap(poolKey, params, hookData)
  - hookData contains: quote, maker, signature, proof, publicInputs
  - Hook validates all 7 checks
  - Hook consumes commitment (used=true)
  - Swap executes through AMM

Step 6: VERIFY REPLAY PROTECTION
  Attacker --> PoolManager.swap(same hookData)
  - Hook checks registry.isConsumed(commitment) --> true
  - Reverts with CommitmentAlreadyUsed
```

---

## Security Architecture

### Trust Model

| Component | Trust Level | Justification |
|-----------|-------------|---------------|
| Uniswap v4 PoolManager | Fully trusted | Audited protocol, controls hook invocation |
| RFQSettlementHook | Verified onchain | All validation logic is deterministic |
| RFQRegistry | Verified onchain | Simple state machine (commit/consume) |
| HonkVerifier | Verified onchain | Auto-generated from circuit, deterministic |
| Poseidon2 | Verified onchain | External audited library |
| Maker Server | Untrusted | Maker can refuse quotes, but can't forge signatures |
| ENS Records | Semi-trusted | Policy hash provides tamper detection |

### Invariants

1. **No swap without valid proof**: The hook reverts if `verifier.verify()` returns false
2. **No replay**: Each commitment can be consumed exactly once
3. **No signature forgery**: EIP-712 with ECDSA ensures only the maker can sign quotes
4. **No cross-pool attacks**: Commitment is bound to specific poolKeyHash
5. **No taker impersonation**: Public inputs include taker address, verified against msg.sender
6. **No stale quotes**: Expiry checked both in hook and in circuit public inputs

### EIP-712 Domain

```
name:              "WaiolaRFQ"
version:           "1"
chainId:           (deployment chain)
verifyingContract: (hook address)
```

This ensures signatures are bound to a specific hook deployment on a specific chain.

---

## Foundry Configuration

```toml
[profile.default]
solc_version = "0.8.27"
via_ir = true                    # Required for complex contracts
optimizer = true
optimizer_runs = 200
gas_reports = ["RFQSettlementHook", "RFQRegistry"]

# Verifier compiled without IR (assembly compatibility)
compilation_restrictions = [
  { paths = "src/verifiers/**", via_ir = false }
]

remappings = [
    "@poseidon/=lib/poseidon2-evm/",
    "@uniswap/v4-core/=lib/v4-core/",
    "@uniswap/v4-periphery/=lib/v4-periphery/",
    "@uniswap-hooks/=lib/uniswap-hooks/",
    "@openzeppelin/contracts/=lib/uniswap-hooks/lib/openzeppelin-contracts/contracts/"
]
```

---

## Design Decisions

### Why `beforeSwap` Only?

Following the iceberg winning pattern from ETHGlobal analysis. All validation happens before the swap:
- Lower gas (no post-swap callback overhead)
- Cleaner security model (fail fast -- revert before any state changes)
- Smaller attack surface (fewer hook entry points)

### Why Poseidon2 Over Keccak256?

Poseidon2 is a ZK-friendly hash function that produces ~100x fewer constraints in the Noir circuit compared to Keccak256. This means:
- Faster proof generation (~2-3 seconds vs potentially minutes)
- Smaller circuit size (4096 gates vs 100k+)
- Lower verification gas cost

### Why Hybrid Commitment Storage?

Only the commitment hash, expiry, maker, and poolKeyHash are stored onchain. The full quote details (quotedOut, salt) remain offchain until the swap, where they're included in hookData and validated via ZK proof. This:
- Reduces gas costs for `commitQuote()`
- Preserves privacy of quote terms until execution
- Still enables full onchain verification at swap time

### Why EIP-712 Over Raw Signatures?

EIP-712 structured data signing:
- Provides human-readable signing in wallets
- Includes chain ID and verifying contract in domain (prevents cross-chain replay)
- Is a well-understood standard with broad wallet support

### Why CREATE2 for Hook Deployment?

Uniswap v4 encodes hook permissions in the hook's address. The hook address must have specific bits set. CREATE2 with salt mining finds a deployment salt that produces a valid address.

---

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| v4-core | 1.0.2 | Uniswap v4 PoolManager, hooks, types |
| v4-periphery | 1.0.3 | BaseHook, HookMiner |
| uniswap-hooks | latest | Hook utilities |
| poseidon2-evm | latest | ZK-friendly hash function |
| openzeppelin-contracts | via uniswap-hooks | ECDSA, Ownable2Step, EIP-712 |
| Noir | latest | ZK circuit language |
| Barretenberg | latest | Honk proof system + verifier generation |
