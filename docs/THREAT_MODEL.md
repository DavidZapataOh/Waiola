# Threat Model: Waiola Private RFQ System

**Document Version**: 1.0
**Last Updated**: 2026-02-08

---

## Scope

This document analyzes the security properties, trust assumptions, and attack vectors of the Waiola Private RFQ system. It is deliberately honest about what the system does and does not protect against.

---

## What "Privacy" Means in Waiola

### We Provide: Reduced Pre-Trade Information Leakage

In a standard Uniswap v4 swap, the swap parameters (token pair, direction, amount) are visible in the mempool before execution. This enables:
- Front-running by MEV bots
- Copy-trading by adversarial participants
- Quote fading by makers who see incoming intent

Waiola reduces this leakage by moving quote negotiation offchain:
- **Quote request** happens over direct HTTP (not broadcast to mempool)
- **Quote terms** (exact output amount) are hidden inside a ZK proof
- **Settlement** happens through a Uniswap v4 hook that validates the proof

### We Do NOT Provide: Fully Private Onchain State

Waiola does NOT hide:
- **The swap itself** -- once the transaction is submitted, it's visible onchain
- **Token amounts** -- the AMM settlement (input/output) is visible in event logs
- **Participant addresses** -- taker and maker addresses are visible
- **The commitment** -- once posted to the registry, it's public

This is an important distinction. Waiola provides **pre-trade privacy** (quote negotiation is private), not **post-trade privacy** (the executed swap is visible). For fully encrypted onchain state, you would need FHE (Fully Homomorphic Encryption), which is a different architecture entirely.

---

## Threat Analysis

### T1: Replay Attacks

**Threat**: An attacker observes a valid swap transaction and resubmits the same `hookData` to execute the swap again.

**Protection**: The `RFQRegistry` maintains a `used` flag per commitment. After the first successful swap, `consumeQuote()` sets `used = true`. Any subsequent attempt reverts with `CommitmentAlreadyUsed`.

**Strength**: Strong. The consumption is atomic -- it happens inside `beforeSwap`, which means if the swap reverts, the consumption also reverts. There is no window where a commitment is consumed but the swap hasn't executed.

**Residual Risk**: None. The replay protection is airtight.

---

### T2: Signature Forgery

**Threat**: An attacker forges a maker's EIP-712 signature to create fake quotes.

**Protection**: The hook verifies the signature using `ECDSA.recover` and checks that the recovered address matches the `maker` stored in the commitment. The EIP-712 domain separator includes the chain ID and hook address, preventing cross-chain and cross-contract signature replay.

**Strength**: Strong. ECDSA signature forgery requires knowledge of the maker's private key. The EIP-712 domain binding prevents cross-context replay.

**Residual Risk**: If a maker's private key is compromised, an attacker could create valid signatures. This is a fundamental limitation of all signature-based systems, not specific to Waiola.

---

### T3: Invalid ZK Proofs

**Threat**: An attacker submits an invalid or fabricated ZK proof to bypass quote validation.

**Protection**: The `HonkVerifier` contract (auto-generated from the Noir circuit) performs full proof verification. The hook reverts with `InvalidProof` if verification fails. Additionally, the hook verifies that public inputs in the proof match the execution context (commitment, pool, taker, amount).

**Strength**: Strong. The soundness of the Honk proof system ensures that an invalid proof is rejected with overwhelming probability. The public input matching prevents proof reuse across different contexts.

**Residual Risk**: Theoretical soundness breaks in the proof system itself, which would require a fundamental cryptographic breakthrough. This is standard risk for all ZK systems.

---

### T4: Cross-Pool Attacks

**Threat**: An attacker takes a commitment made for Pool A and tries to use it in Pool B to extract value.

**Protection**: The commitment includes `poolKeyHash` as a public input. The hook computes `keccak256(abi.encode(key))` from the actual pool being swapped and verifies it matches the committed pool. Additionally, the registry stores `poolKeyHash` per commitment.

**Strength**: Strong. Pool binding is enforced at three levels: in the commitment hash (Poseidon2), in the registry data, and in the ZK proof's public inputs.

**Residual Risk**: None for cross-pool attacks.

---

### T5: Taker Impersonation

**Threat**: An attacker observes a committed quote for a specific taker and tries to execute the swap from a different address.

**Protection**: The taker address is included as a public input in the ZK proof. The hook verifies that `publicInputs[2]` (taker in proof) matches `sender` (the actual swap caller). The commitment hash also binds the taker.

**Strength**: Strong. The taker is bound at the circuit level and verified onchain.

**Residual Risk**: None for taker impersonation.

---

### T6: Stale Quote Execution

**Threat**: A taker holds a quote beyond its intended validity and executes it when market conditions have changed significantly against the maker.

**Protection**: Every quote has an `expiry` timestamp. The hook checks `block.timestamp < quote.expiry` and reverts with `QuoteExpired` if the quote is stale. The expiry is also included as a public input in the ZK proof.

**Strength**: Moderate. Expiry prevents indefinite quote holding, but within the validity window (typically 5 minutes), the quote is valid regardless of market movement. This is standard RFQ behavior -- the maker sets the validity window and prices accordingly.

**Residual Risk**: Within the validity window, market movements could make the quote unfavorable for the maker. Makers should set short validity windows and price in the risk.

---

### T7: Front-Running the Commitment Transaction

**Threat**: An attacker sees the `commitQuote()` transaction in the mempool and either:
1. Front-runs with a higher gas price to commit the same quote first
2. Uses the visible commitment to inform their own trading strategy

**Protection**:
- For (1): The commitment hash is computed from the quote details including the taker address. A different caller committing the same hash doesn't help them -- only the original taker can execute the swap.
- For (2): The commitment alone reveals very limited information -- it's a Poseidon2 hash that doesn't expose the quote terms.

**Strength**: Moderate. The commitment is privacy-preserving (Poseidon2 hash), but the fact that a commitment was posted is visible. An observer knows "someone is about to execute an RFQ swap on this pool" without knowing the exact terms.

**Residual Risk**: Metadata leakage at commitment time. An adversary who monitors the registry can detect that an RFQ swap is about to happen on a specific pool. This is inherent to any onchain commitment scheme.

---

### T8: MEV After Commitment

**Threat**: After the commitment is posted onchain but before the swap executes, MEV bots observe the commitment and sandwich the swap transaction.

**Protection**: Limited. The commitment hash doesn't reveal the exact swap terms, but the swap transaction itself (which includes hookData with the full quote) is visible in the mempool.

**Strength**: Weak for the swap transaction itself. The commitment provides some privacy (quote terms are hidden in the hash), but the actual swap transaction reveals the direction and amount.

**Residual Risk**: This is the primary privacy limitation. While quote negotiation is private, the final swap execution is visible in the mempool and susceptible to standard MEV extraction. Mitigations include:
- Using Flashbots Protect or private mempools for the swap transaction
- Block builders with MEV protection
- These are external to Waiola and up to the taker

---

### T9: Maker Collusion / Refusal

**Threat**: A maker refuses to provide quotes to certain takers, or colludes with other makers to provide unfavorable quotes.

**Protection**: None within the protocol. Maker behavior offchain is not enforced.

**Strength**: None. This is an inherent limitation of RFQ systems where maker participation is voluntary.

**Residual Risk**: Maker collusion is possible. Mitigations include:
- Multiple makers discoverable via ENS (competition)
- Policy hash on ENS provides transparency about maker terms
- Takers can compare quotes from multiple makers
- Future work: solver networks with mandatory quoting

---

### T10: ENS Record Manipulation

**Threat**: A maker changes their ENS records to point to a malicious endpoint or update the policy hash without updating the actual policy.

**Protection**:
- Policy hash is stored onchain (ENS text record). Takers fetch the policy from the endpoint and verify its hash matches the onchain record.
- If the hash doesn't match, the taker rejects the policy.
- ENS records require a transaction signed by the ENS name owner, so unauthorized changes aren't possible.

**Strength**: Moderate. Hash verification catches policy changes, but if the maker owns the ENS name, they can update both the policy and the hash simultaneously.

**Residual Risk**: A maker can change their policy at any time (they own the ENS name). But this is transparent -- takers see the new policy and hash. The risk is that a taker caches an old policy and doesn't re-verify.

---

### T11: Denial of Service

**Threat**: An attacker floods the registry with fake commitments, or the maker server with quote requests.

**Protection**:
- Registry: `commitQuote()` costs gas, so flooding requires spending ETH. There is no global state that can be blocked -- each commitment is independent.
- Maker server: Standard HTTP rate limiting (not implemented in MVP but straightforward to add).

**Strength**: Moderate. The economic cost of onchain spam is the primary protection.

**Residual Risk**: Maker server availability depends on traditional infrastructure protection.

---

## Trust Assumptions

| Assumption | Consequence if Violated |
|------------|------------------------|
| Maker's private key is secure | Forged signatures, unauthorized quotes |
| Uniswap v4 PoolManager is correct | Hook may not be called, incorrect swap execution |
| Noir/Barretenberg proof system is sound | Invalid proofs could pass verification |
| Poseidon2 is collision-resistant | Commitment collisions, potential replay |
| EVM/Solidity execution is deterministic | Non-deterministic verification results |
| ENS resolution is honest | Taker directed to wrong maker |
| HTTP channel is not eavesdropped | Quote terms leaked during negotiation |

---

## Privacy Guarantees Summary

| Phase | What's Private | What's Visible |
|-------|---------------|----------------|
| **ENS Discovery** | Nothing -- ENS records are public | Maker endpoint, policy hash |
| **Quote Request** | Quote terms (HTTP) | That a request was made (if network monitored) |
| **Quote Response** | quotedOut, salt | Nothing (direct HTTP) |
| **Proof Generation** | quotedOut, salt (inside proof) | Nothing (local computation) |
| **Commitment** | Quote terms (Poseidon2 hash) | Commitment hash, expiry, maker, pool |
| **Swap Execution** | quotedOut (in ZK proof) | amountIn, amountOut, taker, maker, pool |
| **Post-Swap** | Nothing new | All swap effects visible on-chain |

---

## Comparison with Alternatives

| Approach | Pre-Trade Privacy | Post-Trade Privacy | Onchain Verifiability | Complexity |
|----------|-------------------|--------------------|-----------------------|------------|
| **Public AMM** | None | None | Full | Low |
| **Public RFQ (UniswapX)** | Low | None | Full | Medium |
| **Waiola (Private RFQ + ZK)** | **High** | None | Full | Medium |
| **FHE-based (iceberg, etc.)** | High | **High** | Full | Very High |
| **Offchain OTC** | High | High | **None** | Low |

Waiola occupies a practical middle ground: strong pre-trade privacy with full onchain verifiability, without the complexity and chain requirements of FHE.

---

## Recommendations for Users

### For Makers
- Use short quote validity windows (5 minutes or less)
- Monitor for unusual quote patterns
- Price in the risk of market movement during validity window
- Use HTTPS for the quote endpoint
- Rotate private keys periodically

### For Takers
- Always verify the policy hash against ENS before trusting a quote
- Use private mempools (e.g., Flashbots Protect) for the swap transaction
- Compare quotes from multiple makers when possible
- Don't reuse quotes -- each quote has a unique salt and commitment

---

## Future Improvements

1. **Private mempool integration**: Submit swap transactions via Flashbots or similar to prevent T8 (MEV after commitment)
2. **Encrypted quote channel**: Use maker's public key (from ENS) to encrypt quote requests, preventing network-level eavesdropping
3. **FHE state**: Encrypt the commitment registry to hide even the commitment metadata
4. **Multi-party computation**: Enable multiple makers to provide quotes without seeing each other's terms
5. **Time-locked commitments**: Auto-expire commitments to reduce the metadata leakage window
6. **Solver networks**: Mandatory quoting to address maker collusion (T9)
