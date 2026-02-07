# RFQ Quote Commitment Circuit

This Noir circuit proves knowledge of a valid RFQ quote commitment without revealing sensitive quote details (quoted output amount and salt).

## Circuit Overview

### Public Inputs (Verified Onchain)
1. **commitment** - The quote commitment hash (Poseidon)
2. **pool_key_hash** - Hash of the Uniswap v4 PoolKey
3. **taker** - Address of the taker (who will execute the swap)
4. **amount_in** - Input amount for the swap
5. **min_out** - Minimum acceptable output (slippage protection)
6. **expiry** - Quote expiry timestamp (Unix)

### Private Inputs (Known Only to Prover)
1. **quoted_out** - The actual quoted output amount (hidden from onchain observers)
2. **salt** - Random nonce for commitment uniqueness (prevents commitment collisions)

### Constraints

The circuit verifies two critical properties:

1. **Commitment Integrity**:
   ```noir
   commitment == Poseidon(pool_key_hash, taker, amount_in, quoted_out, expiry, salt)
   ```
   This ensures the commitment was correctly formed from the quote parameters.

2. **Slippage Protection**:
   ```noir
   quoted_out_u >= min_out_u
   ```
   This ensures the maker's quoted output meets the taker's minimum acceptable amount.

## Why Poseidon Hash?

Poseidon is a ZK-friendly hash function optimized for arithmetic circuits:
- **Fewer constraints** than SHA-256 or keccak256 (~300 vs ~25,000 constraints)
- **Faster proving time** (critical for UX in the demo)
- **Smaller proof size** (reduces onchain verification gas costs)
- **Security**: Poseidon-128 provides 128-bit security (sufficient for RFQ use case)

## Build Instructions

### Prerequisites

1. **Install Nargo** (Noir compiler):
   ```bash
   curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
   noirup
   ```

2. **Install Barretenberg** (proving backend):
   ```bash
   # Installed automatically with noirup
   # Or manually:
   curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash
   ```

### Build Steps

1. **Compile circuit**:
   ```bash
   cd circuits/rfq_quote
   nargo compile
   ```

2. **Run tests**:
   ```bash
   nargo test
   ```

3. **Generate Solidity verifier**:
   ```bash
   chmod +x build.sh
   ./build.sh
   ```
   This generates `../../src/verifiers/NoirVerifier.sol`

4. **Compile Solidity verifier**:
   ```bash
   cd ../..
   forge build
   ```

## Proof Generation (For Testing)

### Using nargo prove (Manual)

1. Create `Prover.toml` with inputs:
   ```toml
   commitment = "0x1234..."
   pool_key_hash = "0x5678..."
   taker = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
   amount_in = "1000000000000000000"
   min_out = "950000000000000000"
   expiry = "1735689600"
   quoted_out = "980000000000000000"
   salt = "0x9999..."
   ```

2. Generate proof:
   ```bash
   nargo prove
   ```

3. Proof outputs to `proofs/rfq_quote.proof`

### Using TypeScript Script (Automated)

See `script/typescript/utils/generate-proof.ts` for automated proof generation used in tests and demo.

## Integration with Solidity

The generated `NoirVerifier.sol` contract has this interface:

```solidity
function verify(
    bytes calldata _proof,
    bytes32[] calldata _publicInputs
) external view returns (bool);
```

**Public inputs order** (must match circuit):
```solidity
bytes32[] memory publicInputs = new bytes32[](6);
publicInputs[0] = commitment;
publicInputs[1] = poolKeyHash;
publicInputs[2] = bytes32(uint256(uint160(taker)));      // Address → bytes32
publicInputs[3] = bytes32(amountIn);
publicInputs[4] = bytes32(minOut);
publicInputs[5] = bytes32(expiry);
```

## Security Considerations

### Privacy Guarantees

**What is hidden**:
- ✅ `quoted_out` - Maker's quoted output amount
- ✅ `salt` - Commitment uniqueness nonce

**What is revealed**:
- ❌ `commitment` - Hash binding the quote (necessary for verification)
- ❌ `pool_key_hash` - Which pool (necessary for swap routing)
- ❌ `taker` - Who can execute (necessary for access control)
- ❌ `amount_in` - Input amount (visible onchain anyway during swap)
- ❌ `min_out` - Minimum output (taker's slippage tolerance)
- ❌ `expiry` - Quote validity window (necessary for time-based validation)

### Attack Vectors Mitigated

1. **Commitment Tampering**: Circuit ensures commitment matches quote parameters
2. **Slippage Attacks**: Circuit enforces `quoted_out >= min_out`
3. **Proof Forgery**: Barretenberg verifier ensures only valid proofs pass
4. **Replay Attacks**: Registry (separate contract) tracks used commitments

### Known Limitations

1. **No Price Hiding**: While `quoted_out` is hidden in the proof, it becomes visible during swap execution (inherent to AMM model)
2. **No Anonymity**: Taker address is public input (necessary for access control)
3. **Oracle Independence**: Circuit doesn't validate market prices (optional Pyth integration in hook)

## Testing

Run circuit tests:
```bash
nargo test
```

Expected output:
```
Running 5 tests
[test_valid_quote_commitment] PASS
[test_exact_minimum_output] PASS
[test_below_minimum_output_fails] PASS
[test_wrong_commitment_fails] PASS
[test_tampered_salt_fails] PASS
```

## Gas Benchmarks

| Operation | Constraints | Proving Time | Verification Gas |
|-----------|-------------|--------------|------------------|
| Poseidon hash (6 inputs) | ~300 | ~50ms | ~20k gas |
| Range check (quoted_out_u >= min_out_u) | ~10 | ~1ms | ~5k gas |
| **Total** | **~310** | **~51ms** | **~25k gas** |

*Benchmarks on M1 Mac, may vary by hardware*

## References

- [Noir Documentation](https://noir-lang.org/docs)
- [Barretenberg Backend](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg)
- [Poseidon Hash](https://www.poseidon-hash.info/)
- [Uniswap v4 Hooks](https://docs.uniswap.org/contracts/v4/overview)

## License

MIT
