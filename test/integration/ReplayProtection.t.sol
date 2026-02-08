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
 * @title ReplayProtectionTest
 * @notice Dedicated integration tests for anti-replay protection
 * @dev Tests edge cases around commitment reuse, cross-pool replay,
 *      expiry manipulation, and multi-actor scenarios
 * @author Waiola Team
 */
contract ReplayProtectionTest is Test {
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

    PoolKey poolKey1;
    PoolKey poolKey2;

    address deployer = address(this);
    address maker;
    address taker;

    uint256 makerPrivateKey = 0x1111;
    uint256 takerPrivateKey = 0x2222;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        maker = vm.addr(makerPrivateKey);
        taker = vm.addr(takerPrivateKey);

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

        // Pool 1
        poolKey1 = PoolKey({
            currency0: Currency.wrap(address(0x1000)),
            currency1: Currency.wrap(address(0x2000)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        // Pool 2 (different tokens)
        poolKey2 = PoolKey({
            currency0: Currency.wrap(address(0x3000)),
            currency1: Currency.wrap(address(0x4000)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _createQuote(
        PoolKey memory _poolKey,
        address _taker,
        uint256 _amountIn,
        uint256 _quotedOut,
        uint256 _expiry,
        bytes32 _salt
    ) internal view returns (QuoteCommitment.Quote memory) {
        return
            QuoteCommitment.Quote({
                poolKeyHash: keccak256(abi.encode(_poolKey)),
                taker: _taker,
                amountIn: _amountIn,
                quotedOut: _quotedOut,
                expiry: _expiry,
                salt: _salt
            });
    }

    /*//////////////////////////////////////////////////////////////
                    SAME COMMITMENT DIFFERENT POOLS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Same quote parameters but for different pools should produce different commitments
     * @dev This ensures commitments are pool-bound via poolKeyHash
     */
    function test_SameQuoteDifferentPools_DifferentCommitments() public view {
        uint256 expiry = block.timestamp + 1 hours;

        QuoteCommitment.Quote memory quote1 = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt")
        );

        QuoteCommitment.Quote memory quote2 = _createQuote(
            poolKey2,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt")
        );

        bytes32 commitment1 = QuoteCommitment.computeCommitment(hasher, quote1);
        bytes32 commitment2 = QuoteCommitment.computeCommitment(hasher, quote2);

        // Different pools should produce different commitments
        assertTrue(commitment1 != commitment2);
    }

    /**
     * @notice Committing a quote for pool1 should not affect pool2
     */
    function test_CrossPoolIsolation() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash1 = keccak256(abi.encode(poolKey1));
        bytes32 poolKeyHash2 = keccak256(abi.encode(poolKey2));

        QuoteCommitment.Quote memory quote1 = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        QuoteCommitment.Quote memory quote2 = _createQuote(
            poolKey2,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt2")
        );

        bytes32 commitment1 = QuoteCommitment.computeCommitment(hasher, quote1);
        bytes32 commitment2 = QuoteCommitment.computeCommitment(hasher, quote2);

        // Commit both
        registry.commitQuote(commitment1, expiry, maker, poolKeyHash1);
        registry.commitQuote(commitment2, expiry, maker, poolKeyHash2);

        // Consume only commitment1
        vm.prank(address(hook));
        registry.consumeQuote(commitment1);

        // commitment1 is consumed, commitment2 is not
        assertTrue(registry.isConsumed(commitment1));
        assertFalse(registry.isConsumed(commitment2));

        // commitment2 can still be consumed
        vm.prank(address(hook));
        registry.consumeQuote(commitment2);
        assertTrue(registry.isConsumed(commitment2));
    }

    /*//////////////////////////////////////////////////////////////
                     COMMITMENT REUSE PREVENTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Double-commit the same commitment should fail
     */
    function test_CommitmentReuseFails() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey1));

        QuoteCommitment.Quote memory quote = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        // First commit succeeds
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        // Second commit with same commitment fails
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyExists.selector,
                commitment
            )
        );
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);
    }

    /**
     * @notice Consuming an already-consumed commitment must fail
     */
    function test_DoubleConsumeFails() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey1));

        QuoteCommitment.Quote memory quote = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        // First consume succeeds
        vm.prank(address(hook));
        registry.consumeQuote(commitment);

        // Second consume fails (replay attack)
        vm.prank(address(hook));
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyUsed.selector,
                commitment
            )
        );
        registry.consumeQuote(commitment);
    }

    /*//////////////////////////////////////////////////////////////
                    EXPIRED COMMITMENT REPLAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice An expired but consumed commitment cannot be replayed
     */
    function test_ExpiredCommitmentCannotReplay() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey1));

        QuoteCommitment.Quote memory quote = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        // Consume before expiry
        vm.prank(address(hook));
        registry.consumeQuote(commitment);

        // Warp past expiry
        vm.warp(expiry + 1);

        // Still cannot replay even after expiry
        vm.prank(address(hook));
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyUsed.selector,
                commitment
            )
        );
        registry.consumeQuote(commitment);
    }

    /**
     * @notice A commitment cannot be re-committed even after the original expires
     */
    function test_CannotRecommitAfterExpiry() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey1));

        QuoteCommitment.Quote memory quote = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        // Warp past expiry
        vm.warp(expiry + 1);

        // Cannot re-commit even though expired
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyExists.selector,
                commitment
            )
        );
        registry.commitQuote(commitment, expiry + 2 hours, maker, poolKeyHash);
    }

    /*//////////////////////////////////////////////////////////////
                      MULTI-ACTOR SCENARIOS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Different takers should produce different commitments for same quote terms
     */
    function test_DifferentTakers_DifferentCommitments() public {
        uint256 expiry = block.timestamp + 1 hours;
        address taker2 = makeAddr("taker2");

        QuoteCommitment.Quote memory quote1 = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt")
        );

        QuoteCommitment.Quote memory quote2 = _createQuote(
            poolKey1,
            taker2,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt")
        );

        bytes32 commitment1 = QuoteCommitment.computeCommitment(hasher, quote1);
        bytes32 commitment2 = QuoteCommitment.computeCommitment(hasher, quote2);

        assertTrue(commitment1 != commitment2);
    }

    /**
     * @notice Multiple takers can each have their own independent commitments
     */
    function test_MultipleTakers_IndependentLifecycles() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey1));
        address taker2 = makeAddr("taker2");
        address maker2 = makeAddr("maker2");

        QuoteCommitment.Quote memory quote1 = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt_taker1")
        );

        QuoteCommitment.Quote memory quote2 = _createQuote(
            poolKey1,
            taker2,
            2 ether,
            1.90 ether,
            expiry,
            keccak256("salt_taker2")
        );

        bytes32 commitment1 = QuoteCommitment.computeCommitment(hasher, quote1);
        bytes32 commitment2 = QuoteCommitment.computeCommitment(hasher, quote2);

        // Commit both
        registry.commitQuote(commitment1, expiry, maker, poolKeyHash);
        registry.commitQuote(commitment2, expiry, maker2, poolKeyHash);

        // Consume taker1's commitment
        vm.prank(address(hook));
        registry.consumeQuote(commitment1);

        // taker2's commitment should be unaffected
        assertTrue(registry.isConsumed(commitment1));
        assertFalse(registry.isConsumed(commitment2));

        // taker2 can still consume
        vm.prank(address(hook));
        registry.consumeQuote(commitment2);
        assertTrue(registry.isConsumed(commitment2));
    }

    /*//////////////////////////////////////////////////////////////
                       SALT UNIQUENESS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Same quote terms with different salts produce different commitments
     */
    function test_SaltUniqueness() public view {
        uint256 expiry = block.timestamp + 1 hours;

        QuoteCommitment.Quote memory quote1 = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        QuoteCommitment.Quote memory quote2 = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt2")
        );

        bytes32 commitment1 = QuoteCommitment.computeCommitment(hasher, quote1);
        bytes32 commitment2 = QuoteCommitment.computeCommitment(hasher, quote2);

        assertTrue(commitment1 != commitment2);
    }

    /**
     * @notice Same taker can get multiple quotes (with different salts)
     */
    function test_SameTakerMultipleQuotes() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey1));

        bytes32[] memory commitments = new bytes32[](5);

        for (uint256 i = 0; i < 5; i++) {
            QuoteCommitment.Quote memory quote = _createQuote(
                poolKey1,
                taker,
                1 ether,
                0.95 ether,
                expiry,
                bytes32(i)
            );

            commitments[i] = QuoteCommitment.computeCommitment(hasher, quote);
            registry.commitQuote(commitments[i], expiry, maker, poolKeyHash);
        }

        // All should be committed and unconsumed
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(registry.isCommitted(commitments[i]));
            assertFalse(registry.isConsumed(commitments[i]));
        }

        // Consume them in reverse order
        for (uint256 i = 5; i > 0; i--) {
            vm.prank(address(hook));
            registry.consumeQuote(commitments[i - 1]);
            assertTrue(registry.isConsumed(commitments[i - 1]));
        }
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ReplayAlwaysFails(
        uint256 amountIn,
        uint256 quotedOut,
        bytes32 _salt,
        uint256 expiry
    ) public {
        vm.assume(amountIn > 0 && amountIn < type(uint128).max);
        vm.assume(quotedOut > 0 && quotedOut < type(uint128).max);
        vm.assume(expiry > 0);

        bytes32 poolKeyHash = keccak256(abi.encode(poolKey1));

        QuoteCommitment.Quote memory quote = _createQuote(
            poolKey1,
            taker,
            amountIn,
            quotedOut,
            expiry,
            _salt
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        vm.prank(address(hook));
        registry.consumeQuote(commitment);

        // Replay must ALWAYS fail regardless of inputs
        vm.prank(address(hook));
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyUsed.selector,
                commitment
            )
        );
        registry.consumeQuote(commitment);
    }

    function testFuzz_DifferentSalts_DifferentCommitments(
        bytes32 salt1,
        bytes32 salt2
    ) public view {
        vm.assume(salt1 != salt2);

        uint256 expiry = block.timestamp + 1 hours;

        QuoteCommitment.Quote memory quote1 = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            salt1
        );

        QuoteCommitment.Quote memory quote2 = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            salt2
        );

        bytes32 commitment1 = QuoteCommitment.computeCommitment(hasher, quote1);
        bytes32 commitment2 = QuoteCommitment.computeCommitment(hasher, quote2);

        assertTrue(commitment1 != commitment2);
    }

    /*//////////////////////////////////////////////////////////////
                          GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function testGas_FullReplayProtectionFlow() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey1));

        QuoteCommitment.Quote memory quote = _createQuote(
            poolKey1,
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt_gas")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        // Commit
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        // Check + Consume
        registry.isCommitted(commitment);
        registry.isConsumed(commitment);

        vm.prank(address(hook));
        registry.consumeQuote(commitment);
    }
}
