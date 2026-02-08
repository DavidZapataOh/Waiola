// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";

import {RFQSettlementHook} from "../../src/RFQSettlementHook.sol";
import {RFQRegistry} from "../../src/RFQRegistry.sol";
import {IRFQRegistry} from "../../src/interfaces/IRFQRegistry.sol";
import {QuoteCommitment} from "../../src/libraries/QuoteCommitment.sol";
import {IVerifier} from "../../src/interfaces/IVerifier.sol";
import {HonkVerifier} from "../../src/verifiers/NoirVerifier.sol";
import {Poseidon2} from "@poseidon/src/Poseidon2.sol";
import {BaseHook} from "@uniswap/v4-periphery/src/utils/BaseHook.sol";

/// @dev Test wrapper that skips hook address validation
contract TestableRFQSettlementHook is RFQSettlementHook {
    constructor(
        IPoolManager pm,
        IRFQRegistry r,
        IVerifier v,
        Poseidon2 h
    ) RFQSettlementHook(pm, r, v, h) {}

    function validateHookAddress(BaseHook) internal pure override {}
}

/**
 * @title GasTest
 * @notice Gas benchmarking tests for RFQ Settlement system
 * @dev Measures gas costs for individual operations and provides a breakdown
 *      for the README. Use `forge test --match-contract GasTest -vvv` to see results.
 *
 *      Gas benchmark results are included in the README for transparency
 *      about the privacy overhead vs standard Uniswap v4 swaps.
 *
 * @author Waiola Team
 */
contract GasTest is Test {
    using PoolIdLibrary for PoolKey;

    /*//////////////////////////////////////////////////////////////
                               CONTRACTS
    //////////////////////////////////////////////////////////////*/

    IPoolManager poolManager;
    RFQRegistry registry;
    HonkVerifier verifier;
    RFQSettlementHook hook;
    Poseidon2 hasher;

    /*//////////////////////////////////////////////////////////////
                              TEST STATE
    //////////////////////////////////////////////////////////////*/

    PoolKey poolKey;
    address deployer = address(this);
    address maker;
    address taker;

    uint256 makerPrivateKey = 0x1111;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        maker = vm.addr(makerPrivateKey);
        taker = makeAddr("taker");

        poolManager = IPoolManager(address(new PoolManager(address(this))));
        registry = new RFQRegistry(deployer);
        verifier = new HonkVerifier();
        hasher = new Poseidon2();

        hook = new TestableRFQSettlementHook(
            poolManager,
            IRFQRegistry(address(registry)),
            IVerifier(address(verifier)),
            hasher
        );

        registry.setHook(address(hook));

        poolKey = PoolKey({
            currency0: Currency.wrap(address(0x1000)),
            currency1: Currency.wrap(address(0x2000)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _createQuote(
        bytes32 _salt
    ) internal view returns (QuoteCommitment.Quote memory) {
        return QuoteCommitment.Quote({
            poolKeyHash: keccak256(abi.encode(poolKey)),
            taker: taker,
            amountIn: 1 ether,
            quotedOut: 0.95 ether,
            expiry: block.timestamp + 1 hours,
            salt: _salt
        });
    }

    function _signQuote(
        QuoteCommitment.Quote memory quote
    ) internal view returns (bytes memory) {
        bytes32 domainSeparator = hook.getDomainSeparator();
        bytes32 structHash = QuoteCommitment.hashQuote(quote);
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                    INDIVIDUAL OPERATION BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Measure gas for Poseidon2 commitment computation
     */
    function testGas_Poseidon2_CommitmentComputation() public view {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt1"));

        uint256 gasBefore = gasleft();
        QuoteCommitment.computeCommitment(hasher, quote);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Poseidon2 commitment computation gas:", gasUsed);
    }

    /**
     * @notice Measure gas for EIP-712 quote hashing
     */
    function testGas_EIP712_QuoteHashing() public view {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt1"));

        uint256 gasBefore = gasleft();
        QuoteCommitment.hashQuote(quote);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("EIP-712 quote hashing gas:", gasUsed);
    }

    /**
     * @notice Measure gas for ECDSA signature verification
     */
    function testGas_ECDSA_SignatureVerification() public view {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt1"));
        bytes memory signature = _signQuote(quote);

        uint256 gasBefore = gasleft();
        QuoteCommitment.verifySignature(
            quote,
            signature,
            maker,
            hook.getDomainSeparator()
        );
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("ECDSA signature verification gas:", gasUsed);
    }

    /**
     * @notice Measure gas for registry commitQuote
     */
    function testGas_Registry_CommitQuote() public {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt1"));
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        uint256 gasBefore = gasleft();
        registry.commitQuote(
            commitment,
            block.timestamp + 1 hours,
            maker,
            poolKeyHash
        );
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Registry commitQuote gas:", gasUsed);
    }

    /**
     * @notice Measure gas for registry consumeQuote
     */
    function testGas_Registry_ConsumeQuote() public {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt1"));
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        registry.commitQuote(
            commitment,
            block.timestamp + 1 hours,
            maker,
            poolKeyHash
        );

        vm.prank(address(hook));
        uint256 gasBefore = gasleft();
        registry.consumeQuote(commitment);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Registry consumeQuote gas:", gasUsed);
    }

    /**
     * @notice Measure gas for registry isCommitted check
     */
    function testGas_Registry_IsCommitted() public {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt1"));
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        registry.commitQuote(
            commitment,
            block.timestamp + 1 hours,
            maker,
            poolKeyHash
        );

        uint256 gasBefore = gasleft();
        registry.isCommitted(commitment);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Registry isCommitted gas:", gasUsed);
    }

    /**
     * @notice Measure gas for registry isConsumed check
     */
    function testGas_Registry_IsConsumed() public {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt1"));
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        registry.commitQuote(
            commitment,
            block.timestamp + 1 hours,
            maker,
            poolKeyHash
        );

        uint256 gasBefore = gasleft();
        registry.isConsumed(commitment);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Registry isConsumed gas:", gasUsed);
    }

    /**
     * @notice Measure gas for registry getCommitment
     */
    function testGas_Registry_GetCommitment() public {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt1"));
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        registry.commitQuote(
            commitment,
            block.timestamp + 1 hours,
            maker,
            poolKeyHash
        );

        uint256 gasBefore = gasleft();
        registry.getCommitment(commitment);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Registry getCommitment gas:", gasUsed);
    }

    /**
     * @notice Measure gas for pool key hash computation
     */
    function testGas_PoolKeyHash_Computation() public view {
        uint256 gasBefore = gasleft();
        hook.computePoolKeyHash(poolKey);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Pool key hash computation gas:", gasUsed);
    }

    /*//////////////////////////////////////////////////////////////
                    COMPOSITE OPERATION BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Measure gas for full pre-swap validation (sans ZK proof)
     * @dev This measures: decode + commitment check + signature + registry reads
     */
    function testGas_FullPreSwapValidation_SansProof() public {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt_full"));
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes memory signature = _signQuote(quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        // Commit
        registry.commitQuote(
            commitment,
            block.timestamp + 1 hours,
            maker,
            poolKeyHash
        );

        // Measure the validation steps individually
        uint256 totalGas = 0;

        // 1. Commitment computation
        uint256 g1 = gasleft();
        QuoteCommitment.computeCommitment(hasher, quote);
        totalGas += (g1 - gasleft());

        // 2. Registry checks
        uint256 g2 = gasleft();
        registry.isCommitted(commitment);
        registry.isConsumed(commitment);
        registry.getCommitment(commitment);
        totalGas += (g2 - gasleft());

        // 3. Signature verification
        uint256 g3 = gasleft();
        QuoteCommitment.verifySignature(
            quote,
            signature,
            maker,
            hook.getDomainSeparator()
        );
        totalGas += (g3 - gasleft());

        console2.log("Full pre-swap validation (sans ZK proof) gas:", totalGas);
    }

    /**
     * @notice Measure gas for hookData encoding/decoding
     */
    function testGas_HookData_Encoding() public view {
        QuoteCommitment.Quote memory quote = _createQuote(keccak256("salt_enc"));
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes memory signature = _signQuote(quote);

        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = commitment;
        publicInputs[1] = keccak256(abi.encode(poolKey));
        publicInputs[2] = bytes32(uint256(uint160(taker)));
        publicInputs[3] = bytes32(uint256(1 ether));
        publicInputs[4] = bytes32(uint256(0.94 ether));
        publicInputs[5] = bytes32(block.timestamp + 1 hours);

        bytes memory proof = hex"";

        uint256 gasBefore = gasleft();
        abi.encode(quote, maker, signature, proof, publicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("HookData encoding gas:", gasUsed);
    }

    /*//////////////////////////////////////////////////////////////
                     MULTI-QUOTE BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Measure gas cost scaling for multiple commitments
     */
    function testGas_MultipleCommitments_5() public {
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));
        uint256 totalGas = 0;

        for (uint256 i = 0; i < 5; i++) {
            QuoteCommitment.Quote memory quote = _createQuote(bytes32(i));
            bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

            uint256 gasBefore = gasleft();
            registry.commitQuote(
                commitment,
                block.timestamp + 1 hours,
                maker,
                poolKeyHash
            );
            totalGas += (gasBefore - gasleft());
        }

        console2.log("5 commitments total gas:", totalGas);
        console2.log("Average per commitment:", totalGas / 5);
    }

    /**
     * @notice Measure gas cost scaling for multiple consumptions
     */
    function testGas_MultipleConsumptions_5() public {
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));
        bytes32[] memory commitments = new bytes32[](5);

        for (uint256 i = 0; i < 5; i++) {
            QuoteCommitment.Quote memory quote = _createQuote(bytes32(i));
            commitments[i] = QuoteCommitment.computeCommitment(hasher, quote);
            registry.commitQuote(
                commitments[i],
                block.timestamp + 1 hours,
                maker,
                poolKeyHash
            );
        }

        uint256 totalGas = 0;

        for (uint256 i = 0; i < 5; i++) {
            vm.prank(address(hook));
            uint256 gasBefore = gasleft();
            registry.consumeQuote(commitments[i]);
            totalGas += (gasBefore - gasleft());
        }

        console2.log("5 consumptions total gas:", totalGas);
        console2.log("Average per consumption:", totalGas / 5);
    }

    /*//////////////////////////////////////////////////////////////
                       SUMMARY REPORT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Print a full gas benchmark summary
     * @dev Run with `forge test --match-test testGas_Summary -vvv`
     */
    function testGas_Summary() public {
        console2.log("\n========================================");
        console2.log("  WAIOLA RFQ GAS BENCHMARK SUMMARY");
        console2.log("========================================\n");

        QuoteCommitment.Quote memory quote = _createQuote(keccak256("summary"));
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));
        bytes memory signature = _signQuote(quote);
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        // Individual operations
        uint256 g;

        g = gasleft();
        QuoteCommitment.hashQuote(quote);
        console2.log("EIP-712 hash:           ", g - gasleft(), "gas");

        g = gasleft();
        QuoteCommitment.computeCommitment(hasher, quote);
        console2.log("Poseidon2 commitment:   ", g - gasleft(), "gas");

        g = gasleft();
        QuoteCommitment.verifySignature(quote, signature, maker, hook.getDomainSeparator());
        console2.log("Signature verification: ", g - gasleft(), "gas");

        g = gasleft();
        registry.commitQuote(commitment, block.timestamp + 1 hours, maker, poolKeyHash);
        console2.log("Registry commit:        ", g - gasleft(), "gas");

        g = gasleft();
        registry.isCommitted(commitment);
        console2.log("Registry isCommitted:   ", g - gasleft(), "gas");

        g = gasleft();
        registry.isConsumed(commitment);
        console2.log("Registry isConsumed:    ", g - gasleft(), "gas");

        g = gasleft();
        registry.getCommitment(commitment);
        console2.log("Registry getCommitment: ", g - gasleft(), "gas");

        vm.prank(address(hook));
        g = gasleft();
        registry.consumeQuote(commitment);
        console2.log("Registry consume:       ", g - gasleft(), "gas");

        console2.log("\n========================================");
        console2.log("  NOTE: ZK proof verification gas will");
        console2.log("  be measured with real proofs via FFI");
        console2.log("========================================\n");
    }
}
