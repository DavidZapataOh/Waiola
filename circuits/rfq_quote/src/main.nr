/**
 * RFQ Quote Commitment Circuit
 *
 * Proves knowledge of a valid quote commitment without revealing:
 * - quotedOut (the output amount maker promised)
 * - salt (uniqueness nonce)
 *
 * Public Inputs:
 * - commitment: The commitment hash binding the quote
 * - pool_key_hash: Hash of the pool where swap will occur
 * - taker: Address of the taker (who will execute swap)
 * - amount_in: Input amount for the swap
 * - min_out: Minimum acceptable output (slippage protection)
 * - expiry: Quote expiry timestamp
 *
 * Private Inputs:
 * - quoted_out: The actual quoted output amount (hidden)
 * - salt: Random nonce for commitment uniqueness (hidden)
 *
 * Constraints:
 * 1. commitment == Poseidon(pool_key_hash, taker, amount_in, quoted_out, expiry, salt)
 * 2. quoted_out >= min_out (slippage protection)
 */

use poseidon::poseidon2::Poseidon2;

fn main(
    // Public inputs (verified onchain)
    commitment: pub Field,
    pool_key_hash: pub Field,
    taker: pub Field,
    amount_in: pub Field,
    min_out: pub Field,
    expiry: pub Field,

    // Private inputs (only known to prover)
    quoted_out: Field,
    salt: Field
) {
    // Constraint 1: Verify commitment is correctly formed
    // commitment = Poseidon(pool_key_hash, taker, amount_in, quoted_out, expiry, salt)
    let computed_commitment = Poseidon2::hash([
        pool_key_hash,
        taker,
        amount_in,
        quoted_out,
        expiry,
        salt
    ], 6);

    assert(
        computed_commitment == commitment,
        "Commitment verification failed: computed commitment does not match provided commitment"
    );

    // Constraint 2: Verify quoted output meets minimum requirement (slippage protection)
    // This ensures the maker's quote is at least as good as the minimum acceptable
    let quoted_out_u: u128 = quoted_out as u128;
    let min_out_u: u128 = min_out as u128;
    assert(
        quoted_out_u >= min_out_u,
        "Slippage check failed: quoted output is below minimum acceptable output"
    );
}

// Unit tests
#[test]
fn test_valid_quote_commitment() {
    // Test case: Valid quote with quoted_out above min_out
    let pool_key_hash = 0x1234567890abcdef;
    let taker = 0x742d35Cc6634C0532925a3b844Bc454e4438f44e;
    let amount_in = 1000000000000000000; // 1 ETH
    let min_out = 950000000000000000;   // 0.95 ETH (5% slippage tolerance)
    let expiry = 1735689600;             // Unix timestamp
    let quoted_out = 980000000000000000; // 0.98 ETH (better than min)
    let salt = 0x9999;

    // Compute expected commitment
    let commitment = Poseidon2::hash([
        pool_key_hash,
        taker,
        amount_in,
        quoted_out,
        expiry,
        salt
    ], 6);

    // Should pass all constraints
    main(
        commitment,
        pool_key_hash,
        taker,
        amount_in,
        min_out,
        expiry,
        quoted_out,
        salt
    );
}

#[test]
fn test_exact_minimum_output() {
    // Test case: quoted_out exactly equals min_out (edge case)
    let pool_key_hash = 0x1111;
    let taker = 0x2222;
    let amount_in = 1000000;
    let min_out = 950000;
    let expiry = 1735689600;
    let quoted_out = 950000; // Exactly at minimum
    let salt = 0x3333;

    let commitment = Poseidon2::hash([
        pool_key_hash,
        taker,
        amount_in,
        quoted_out,
        expiry,
        salt
    ], 6);

    // Should pass (quoted_out >= min_out is satisfied)
    main(
        commitment,
        pool_key_hash,
        taker,
        amount_in,
        min_out,
        expiry,
        quoted_out,
        salt
    );
}

#[test(should_fail_with = "Slippage check failed: quoted output is below minimum acceptable output")]
fn test_below_minimum_output_fails() {
    // Test case: quoted_out below min_out should fail
    let pool_key_hash = 0x1111;
    let taker = 0x2222;
    let amount_in = 1000000;
    let min_out = 950000;
    let expiry = 1735689600;
    let quoted_out = 940000; // Below minimum (should fail)
    let salt = 0x3333;

    let commitment = Poseidon2::hash([
        pool_key_hash,
        taker,
        amount_in,
        quoted_out,
        expiry,
        salt
    ], 6);

    // Should fail slippage check
    main(
        commitment,
        pool_key_hash,
        taker,
        amount_in,
        min_out,
        expiry,
        quoted_out,
        salt
    );
}

#[test(should_fail_with = "Commitment verification failed: computed commitment does not match provided commitment")]
fn test_wrong_commitment_fails() {
    // Test case: Providing wrong commitment should fail
    let pool_key_hash = 0x1111;
    let taker = 0x2222;
    let amount_in = 1000000;
    let min_out = 950000;
    let expiry = 1735689600;
    let quoted_out = 980000;
    let salt = 0x3333;

    // Use a fake commitment (not computed from inputs)
    let wrong_commitment = 0xdeadbeef;

    // Should fail commitment verification
    main(
        wrong_commitment,
        pool_key_hash,
        taker,
        amount_in,
        min_out,
        expiry,
        quoted_out,
        salt
    );
}

#[test(should_fail_with = "Commitment verification failed: computed commitment does not match provided commitment")]
fn test_tampered_salt_fails() {
    // Test case: Using different salt than what commitment was computed with
    let pool_key_hash = 0x1111;
    let taker = 0x2222;
    let amount_in = 1000000;
    let min_out = 950000;
    let expiry = 1735689600;
    let quoted_out = 980000;
    let original_salt = 0x3333;
    let tampered_salt = 0x4444; // Different salt

    // Commitment computed with original_salt
    let commitment = Poseidon2::hash([
        pool_key_hash,
        taker,
        amount_in,
        quoted_out,
        expiry,
        original_salt
    ], 6);

    // Try to prove with tampered_salt (should fail)
    main(
        commitment,
        pool_key_hash,
        taker,
        amount_in,
        min_out,
        expiry,
        quoted_out,
        tampered_salt
    );
}
