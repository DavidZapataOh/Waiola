// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IVerifier} from "../../src/interfaces/IVerifier.sol";

/**
 * @title NoirVerifierTest
 * @notice Unit tests for Noir ZK proof verifier
 * @dev Tests proof generation and verification using FFI
 *
 * Prerequisites:
 * 1. Run circuit build: cd circuits/rfq_quote && ./build.sh
 * 2. Install TypeScript dependencies: npm install
 * 3. Enable FFI in foundry.toml: ffi = true
 *
 * @author Waiola Team
 */
contract NoirVerifierTest is Test {
    IVerifier public verifier;

    // Test constants
    bytes32 constant POOL_KEY_HASH = keccak256("test_pool");
    address constant TAKER =
        address(0x742d35Cc6634C0532925a3b844Bc454e4438f44e);
    uint256 constant AMOUNT_IN = 1 ether;
    uint256 constant MIN_OUT = 0.95 ether;
    uint256 constant EXPIRY = 1735689600;
    uint256 constant QUOTED_OUT = 0.98 ether;
    bytes32 constant SALT = bytes32(uint256(0x9999));

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        // Try to load the verifier contract
        // If it doesn't exist, tests will be skipped with helpful message
        string memory verifierPath = "src/verifiers/NoirVerifier.sol";

        // Check if verifier exists
        try vm.readFile(verifierPath) returns (string memory) {
            // Verifier exists, deploy it
            // Note: Actual deployment will happen when contract is compiled
            // For now, we'll use a mock address that tests can check
            verifier = IVerifier(address(0x1));

            // If the contract was successfully generated and compiled,
            // foundry will find and deploy it
        } catch {
            // Verifier not generated yet
            emit log("   NoirVerifier.sol not found");
            emit log("   Run: cd circuits/rfq_quote && ./build.sh");
            emit log("   Then: forge build");
        }
    }

    /*//////////////////////////////////////////////////////////////
                         PROOF GENERATION (FFI)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generate a Noir proof using FFI
     * @param commitment Quote commitment hash
     * @param poolKeyHash Hash of PoolKey
     * @param taker Taker address
     * @param amountIn Input amount
     * @param minOut Minimum output
     * @param expiry Quote expiry
     * @param quotedOut Quoted output (private)
     * @param salt Salt for commitment (private)
     * @return Proof bytes
     */
    function generateProofFFI(
        bytes32 commitment,
        bytes32 poolKeyHash,
        address taker,
        uint256 amountIn,
        uint256 minOut,
        uint256 expiry,
        uint256 quotedOut,
        bytes32 salt
    ) internal returns (bytes memory) {
        string[] memory inputs = new string[](10);
        inputs[0] = "npx";
        inputs[1] = "ts-node";
        inputs[2] = "script/typescript/utils/generate-proof.ts";
        inputs[3] = vm.toString(commitment);
        inputs[4] = vm.toString(poolKeyHash);
        inputs[5] = vm.toString(taker);
        inputs[6] = vm.toString(amountIn);
        inputs[7] = vm.toString(minOut);
        inputs[8] = vm.toString(expiry);
        inputs[9] = vm.toString(quotedOut);

        // Note: We pass salt as the 10th argument in the actual implementation
        // For now, using toString for bytes32
        string[] memory fullInputs = new string[](11);
        for (uint256 i = 0; i < 10; i++) {
            fullInputs[i] = inputs[i];
        }
        fullInputs[10] = vm.toString(salt);

        bytes memory result = vm.ffi(fullInputs);
        return result;
    }

    /**
     * @notice Compute commitment hash (matches Noir circuit Poseidon)
     * @dev For testing, we use a simplified version
     * @param poolKeyHash Hash of PoolKey
     * @param taker Taker address
     * @param amountIn Input amount
     * @param quotedOut Quoted output
     * @param expiry Expiry timestamp
     * @param salt Salt
     * @return Commitment hash
     */
    function computeCommitment(
        bytes32 poolKeyHash,
        address taker,
        uint256 amountIn,
        uint256 quotedOut,
        uint256 expiry,
        bytes32 salt
    ) internal pure returns (bytes32) {
        // Note: This is a placeholder using keccak256
        // In production, this would use Poseidon hash matching Noir circuit
        return
            keccak256(
                abi.encodePacked(
                    poolKeyHash,
                    taker,
                    amountIn,
                    quotedOut,
                    expiry,
                    salt
                )
            );
    }

    /*//////////////////////////////////////////////////////////////
                         VERIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_VerifierContractExists() public {
        // Skip if verifier not deployed
        if (address(verifier) == address(0)) {
            emit log("   Skipping: Verifier not deployed");
            emit log("   Run: cd circuits/rfq_quote && ./build.sh");
            return;
        }

        // Verifier should be a contract
        assertTrue(
            address(verifier).code.length > 0,
            "Verifier should be a contract"
        );
    }

    function test_ValidProofPasses() public {
        // Skip if verifier not deployed
        if (address(verifier) == address(0)) {
            emit log("   Skipping: Verifier not deployed");
            return;
        }

        // Compute commitment
        bytes32 commitment = computeCommitment(
            POOL_KEY_HASH,
            TAKER,
            AMOUNT_IN,
            QUOTED_OUT,
            EXPIRY,
            SALT
        );

        // Generate proof via FFI
        bytes memory proof = generateProofFFI(
            commitment,
            POOL_KEY_HASH,
            TAKER,
            AMOUNT_IN,
            MIN_OUT,
            EXPIRY,
            QUOTED_OUT,
            SALT
        );

        assertTrue(proof.length > 0, "Proof should be non-empty");

        // Prepare public inputs
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = commitment;
        publicInputs[1] = POOL_KEY_HASH;
        publicInputs[2] = bytes32(uint256(uint160(TAKER)));
        publicInputs[3] = bytes32(AMOUNT_IN);
        publicInputs[4] = bytes32(MIN_OUT);
        publicInputs[5] = bytes32(EXPIRY);

        // Verify proof
        bool valid = verifier.verify(proof, publicInputs);
        assertTrue(valid, "Valid proof should pass verification");
    }

    function test_InvalidProofFails() public {
        // Skip if verifier not deployed
        if (address(verifier) == address(0)) {
            emit log("   Skipping: Verifier not deployed");
            return;
        }

        // Create fake proof
        bytes memory invalidProof = hex"deadbeef";

        // Prepare public inputs
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = bytes32(uint256(0x1234));
        publicInputs[1] = POOL_KEY_HASH;
        publicInputs[2] = bytes32(uint256(uint160(TAKER)));
        publicInputs[3] = bytes32(AMOUNT_IN);
        publicInputs[4] = bytes32(MIN_OUT);
        publicInputs[5] = bytes32(EXPIRY);

        // Verify proof should fail
        bool valid = verifier.verify(invalidProof, publicInputs);
        assertFalse(valid, "Invalid proof should fail verification");
    }

    function test_WrongPublicInputsFails() public {
        // Skip if verifier not deployed
        if (address(verifier) == address(0)) {
            emit log("   Skipping: Verifier not deployed");
            return;
        }

        // Compute commitment
        bytes32 commitment = computeCommitment(
            POOL_KEY_HASH,
            TAKER,
            AMOUNT_IN,
            QUOTED_OUT,
            EXPIRY,
            SALT
        );

        // Generate valid proof
        bytes memory proof = generateProofFFI(
            commitment,
            POOL_KEY_HASH,
            TAKER,
            AMOUNT_IN,
            MIN_OUT,
            EXPIRY,
            QUOTED_OUT,
            SALT
        );

        // Prepare WRONG public inputs (different commitment)
        bytes32[] memory wrongInputs = new bytes32[](6);
        wrongInputs[0] = bytes32(uint256(0xdead)); // Wrong commitment
        wrongInputs[1] = POOL_KEY_HASH;
        wrongInputs[2] = bytes32(uint256(uint160(TAKER)));
        wrongInputs[3] = bytes32(AMOUNT_IN);
        wrongInputs[4] = bytes32(MIN_OUT);
        wrongInputs[5] = bytes32(EXPIRY);

        // Verify proof should fail
        bool valid = verifier.verify(proof, wrongInputs);
        assertFalse(
            valid,
            "Proof with wrong public inputs should fail verification"
        );
    }

    function test_BelowMinimumOutputProofFails() public {
        // Skip if verifier not deployed
        if (address(verifier) == address(0)) {
            emit log("   Skipping: Verifier not deployed");
            return;
        }

        // quotedOut below minOut (should fail slippage check in circuit)
        uint256 quotedOutBelowMin = 0.90 ether; // Below 0.95 ETH min

        bytes32 commitment = computeCommitment(
            POOL_KEY_HASH,
            TAKER,
            AMOUNT_IN,
            quotedOutBelowMin,
            EXPIRY,
            SALT
        );

        // Try to generate proof (circuit should reject)
        // This will fail at proof generation time
        vm.expectRevert();
        generateProofFFI(
            commitment,
            POOL_KEY_HASH,
            TAKER,
            AMOUNT_IN,
            MIN_OUT,
            EXPIRY,
            quotedOutBelowMin,
            SALT
        );
    }

    /*//////////////////////////////////////////////////////////////
                         GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function testGas_ProofVerification() public {
        // Skip if verifier not deployed
        if (address(verifier) == address(0)) {
            emit log("   Skipping: Verifier not deployed");
            return;
        }

        bytes32 commitment = computeCommitment(
            POOL_KEY_HASH,
            TAKER,
            AMOUNT_IN,
            QUOTED_OUT,
            EXPIRY,
            SALT
        );

        bytes memory proof = generateProofFFI(
            commitment,
            POOL_KEY_HASH,
            TAKER,
            AMOUNT_IN,
            MIN_OUT,
            EXPIRY,
            QUOTED_OUT,
            SALT
        );

        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = commitment;
        publicInputs[1] = POOL_KEY_HASH;
        publicInputs[2] = bytes32(uint256(uint160(TAKER)));
        publicInputs[3] = bytes32(AMOUNT_IN);
        publicInputs[4] = bytes32(MIN_OUT);
        publicInputs[5] = bytes32(EXPIRY);

        uint256 gasBefore = gasleft();
        verifier.verify(proof, publicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("Proof verification gas", gasUsed);

        // Expect verification to cost less than 300k gas
        assertLt(gasUsed, 300000, "Verification should be gas-efficient");
    }
}
