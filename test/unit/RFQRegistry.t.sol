// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {RFQRegistry} from "../../src/RFQRegistry.sol";

contract RFQRegistryTest is Test {
    RFQRegistry public registry;

    address owner = makeAddr("owner");
    address hook = makeAddr("hook");
    address maker = makeAddr("maker");
    address unauthorizedUser = makeAddr("unauthorized");

    bytes32 constant COMMITMENT = keccak256("test_commitment");
    bytes32 constant POOL_KEY_HASH = keccak256("test_pool");
    uint256 constant EXPIRY = 1000000;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event QuoteCommitted(
        bytes32 indexed commitment,
        address indexed maker,
        bytes32 indexed poolKeyHash,
        uint256 expiry
    );

    event QuoteConsumed(bytes32 indexed commitment, address indexed consumer);

    event HookSet(address indexed hook);

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.prank(owner);
        registry = new RFQRegistry(owner);
    }

    /*//////////////////////////////////////////////////////////////
                           SET HOOK TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetHook() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit HookSet(hook);
        registry.setHook(hook);

        assertEq(registry.hook(), hook);
    }

    function test_SetHook_RevertsIfNotOwner() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert();
        registry.setHook(hook);
    }

    function test_SetHook_RevertsIfZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(RFQRegistry.RFQRegistry__ZeroAddress.selector);
        registry.setHook(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         COMMIT QUOTE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CommitQuote() public {
        vm.expectEmit(true, true, true, true);
        emit QuoteCommitted(COMMITMENT, maker, POOL_KEY_HASH, EXPIRY);

        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);

        // Verify commitment was stored correctly
        RFQRegistry.CommitmentData memory data = registry.getCommitment(
            COMMITMENT
        );
        assertEq(data.expiry, EXPIRY);
        assertEq(data.maker, maker);
        assertEq(data.poolKeyHash, POOL_KEY_HASH);
        assertFalse(data.used);

        // Verify view functions
        assertTrue(registry.isCommitted(COMMITMENT));
        assertFalse(registry.isConsumed(COMMITMENT));
    }

    function test_CommitQuote_RevertsIfAlreadyExists() public {
        // First commit succeeds
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);

        // Second commit with same commitment reverts
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyExists.selector,
                COMMITMENT
            )
        );
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);
    }

    function test_CommitQuote_DifferentCommitmentsAllowed() public {
        bytes32 commitment1 = keccak256("commitment1");
        bytes32 commitment2 = keccak256("commitment2");

        registry.commitQuote(commitment1, EXPIRY, maker, POOL_KEY_HASH);
        registry.commitQuote(commitment2, EXPIRY, maker, POOL_KEY_HASH);

        assertTrue(registry.isCommitted(commitment1));
        assertTrue(registry.isCommitted(commitment2));
    }

    function testFuzz_CommitQuote(
        bytes32 commitment,
        uint256 expiry,
        address _maker,
        bytes32 poolKeyHash
    ) public {
        vm.assume(commitment != bytes32(0));
        vm.assume(expiry > 0);
        vm.assume(_maker != address(0));

        registry.commitQuote(commitment, expiry, _maker, poolKeyHash);

        RFQRegistry.CommitmentData memory data = registry.getCommitment(
            commitment
        );
        assertEq(data.expiry, expiry);
        assertEq(data.maker, _maker);
        assertEq(data.poolKeyHash, poolKeyHash);
        assertFalse(data.used);
    }

    /*//////////////////////////////////////////////////////////////
                        CONSUME QUOTE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConsumeQuote() public {
        // Set hook first
        vm.prank(owner);
        registry.setHook(hook);

        // Commit quote
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);

        // Consume quote as hook
        vm.prank(hook);
        vm.expectEmit(true, true, false, false);
        emit QuoteConsumed(COMMITMENT, hook);
        registry.consumeQuote(COMMITMENT);

        // Verify quote is marked as used
        RFQRegistry.CommitmentData memory data = registry.getCommitment(
            COMMITMENT
        );
        assertTrue(data.used);
        assertTrue(registry.isConsumed(COMMITMENT));
    }

    function test_ConsumeQuote_RevertsIfNotHook() public {
        // Commit quote
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);

        // Try to consume as unauthorized user
        vm.prank(unauthorizedUser);
        vm.expectRevert(RFQRegistry.RFQRegistry__Unauthorized.selector);
        registry.consumeQuote(COMMITMENT);
    }

    function test_ConsumeQuote_RevertsIfCommitmentNotFound() public {
        // Set hook
        vm.prank(owner);
        registry.setHook(hook);

        bytes32 nonExistentCommitment = keccak256("nonexistent");

        // Try to consume non-existent commitment
        vm.prank(hook);
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentNotFound.selector,
                nonExistentCommitment
            )
        );
        registry.consumeQuote(nonExistentCommitment);
    }

    function test_ConsumeQuote_RevertsIfAlreadyUsed() public {
        // Set hook
        vm.prank(owner);
        registry.setHook(hook);

        // Commit and consume quote
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);
        vm.prank(hook);
        registry.consumeQuote(COMMITMENT);

        // Try to consume again (replay attack)
        vm.prank(hook);
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyUsed.selector,
                COMMITMENT
            )
        );
        registry.consumeQuote(COMMITMENT);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_IsCommitted_ReturnsFalseForNonExistent() public view {
        bytes32 nonExistentCommitment = keccak256("nonexistent");
        assertFalse(registry.isCommitted(nonExistentCommitment));
    }

    function test_IsCommitted_ReturnsTrueForExisting() public {
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);
        assertTrue(registry.isCommitted(COMMITMENT));
    }

    function test_IsConsumed_ReturnsFalseForUnused() public {
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);
        assertFalse(registry.isConsumed(COMMITMENT));
    }

    function test_IsConsumed_ReturnsTrueForUsed() public {
        vm.prank(owner);
        registry.setHook(hook);

        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);

        vm.prank(hook);
        registry.consumeQuote(COMMITMENT);

        assertTrue(registry.isConsumed(COMMITMENT));
    }

    function test_GetCommitment_ReturnsCorrectData() public {
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);

        RFQRegistry.CommitmentData memory data = registry.getCommitment(
            COMMITMENT
        );

        assertEq(data.expiry, EXPIRY);
        assertEq(data.maker, maker);
        assertEq(data.poolKeyHash, POOL_KEY_HASH);
        assertFalse(data.used);
    }

    function test_GetCommitment_ReturnsZeroForNonExistent() public view {
        bytes32 nonExistentCommitment = keccak256("nonexistent");

        RFQRegistry.CommitmentData memory data = registry.getCommitment(
            nonExistentCommitment
        );

        assertEq(data.expiry, 0);
        assertEq(data.maker, address(0));
        assertEq(data.poolKeyHash, bytes32(0));
        assertFalse(data.used);
    }

    /*//////////////////////////////////////////////////////////////
                        INTEGRATION SCENARIOS
    //////////////////////////////////////////////////////////////*/

    function test_FullLifecycle() public {
        // 1. Owner sets hook
        vm.prank(owner);
        registry.setHook(hook);

        // 2. User commits quote
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);
        assertTrue(registry.isCommitted(COMMITMENT));
        assertFalse(registry.isConsumed(COMMITMENT));

        // 3. Hook consumes quote
        vm.prank(hook);
        registry.consumeQuote(COMMITMENT);
        assertTrue(registry.isConsumed(COMMITMENT));

        // 4. Replay attack fails
        vm.prank(hook);
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyUsed.selector,
                COMMITMENT
            )
        );
        registry.consumeQuote(COMMITMENT);
    }

    function test_MultipleQuotesIndependent() public {
        vm.prank(owner);
        registry.setHook(hook);

        bytes32 commitment1 = keccak256("commitment1");
        bytes32 commitment2 = keccak256("commitment2");
        bytes32 commitment3 = keccak256("commitment3");

        // Commit multiple quotes
        registry.commitQuote(commitment1, EXPIRY, maker, POOL_KEY_HASH);
        registry.commitQuote(commitment2, EXPIRY + 100, maker, POOL_KEY_HASH);
        registry.commitQuote(commitment3, EXPIRY + 200, maker, POOL_KEY_HASH);

        // Consume only commitment2
        vm.prank(hook);
        registry.consumeQuote(commitment2);

        // Verify states
        assertTrue(registry.isCommitted(commitment1));
        assertFalse(registry.isConsumed(commitment1));

        assertTrue(registry.isCommitted(commitment2));
        assertTrue(registry.isConsumed(commitment2));

        assertTrue(registry.isCommitted(commitment3));
        assertFalse(registry.isConsumed(commitment3));
    }

    /*//////////////////////////////////////////////////////////////
                      ADDITIONAL FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ConsumeQuote(
        bytes32 commitment,
        uint256 expiry,
        address _maker,
        bytes32 poolKeyHash
    ) public {
        vm.assume(commitment != bytes32(0));
        vm.assume(expiry > 0);
        vm.assume(_maker != address(0));

        vm.prank(owner);
        registry.setHook(hook);

        registry.commitQuote(commitment, expiry, _maker, poolKeyHash);
        assertFalse(registry.isConsumed(commitment));

        vm.prank(hook);
        registry.consumeQuote(commitment);
        assertTrue(registry.isConsumed(commitment));

        // Replay must always fail
        vm.prank(hook);
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyUsed.selector,
                commitment
            )
        );
        registry.consumeQuote(commitment);
    }

    function testFuzz_CommitQuote_DifferentMakers(
        bytes32 commitment1,
        bytes32 commitment2,
        address maker1,
        address maker2
    ) public {
        vm.assume(commitment1 != commitment2);
        vm.assume(commitment1 != bytes32(0));
        vm.assume(commitment2 != bytes32(0));
        vm.assume(maker1 != address(0));
        vm.assume(maker2 != address(0));

        registry.commitQuote(commitment1, EXPIRY, maker1, POOL_KEY_HASH);
        registry.commitQuote(commitment2, EXPIRY, maker2, POOL_KEY_HASH);

        RFQRegistry.CommitmentData memory data1 = registry.getCommitment(commitment1);
        RFQRegistry.CommitmentData memory data2 = registry.getCommitment(commitment2);

        assertEq(data1.maker, maker1);
        assertEq(data2.maker, maker2);
    }

    function testFuzz_CommitQuote_DifferentPools(
        bytes32 pool1,
        bytes32 pool2
    ) public {
        vm.assume(pool1 != pool2);

        bytes32 commitment1 = keccak256(abi.encode("c1", pool1));
        bytes32 commitment2 = keccak256(abi.encode("c2", pool2));

        registry.commitQuote(commitment1, EXPIRY, maker, pool1);
        registry.commitQuote(commitment2, EXPIRY, maker, pool2);

        assertEq(registry.getCommitment(commitment1).poolKeyHash, pool1);
        assertEq(registry.getCommitment(commitment2).poolKeyHash, pool2);
    }

    /*//////////////////////////////////////////////////////////////
                       EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CommitQuote_ZeroExpiry() public {
        // expiry=0 is used as sentinel for "not committed"
        // Committing with expiry=0 stores it but isCommitted returns false
        bytes32 testCommitment = keccak256("zero_expiry");
        registry.commitQuote(testCommitment, 0, maker, POOL_KEY_HASH);

        // isCommitted returns false because expiry != 0 is the existence check
        assertFalse(registry.isCommitted(testCommitment));
    }

    function test_CommitQuote_MaxExpiry() public {
        bytes32 testCommitment = keccak256("max_expiry");
        uint256 maxExpiry = type(uint256).max;

        registry.commitQuote(testCommitment, maxExpiry, maker, POOL_KEY_HASH);

        RFQRegistry.CommitmentData memory data = registry.getCommitment(testCommitment);
        assertEq(data.expiry, maxExpiry);
        assertTrue(registry.isCommitted(testCommitment));
    }

    function test_CommitQuote_ZeroPoolKeyHash() public {
        bytes32 testCommitment = keccak256("zero_pool");

        registry.commitQuote(testCommitment, EXPIRY, maker, bytes32(0));

        RFQRegistry.CommitmentData memory data = registry.getCommitment(testCommitment);
        assertEq(data.poolKeyHash, bytes32(0));
    }

    function test_SetHook_CanUpdateHook() public {
        address newHook = makeAddr("new_hook");

        vm.prank(owner);
        registry.setHook(hook);
        assertEq(registry.hook(), hook);

        vm.prank(owner);
        registry.setHook(newHook);
        assertEq(registry.hook(), newHook);
    }

    function test_ConsumeQuote_OldHookCannotConsumeAfterUpdate() public {
        vm.prank(owner);
        registry.setHook(hook);

        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);

        // Update hook to new address
        address newHook = makeAddr("new_hook");
        vm.prank(owner);
        registry.setHook(newHook);

        // Old hook can no longer consume
        vm.prank(hook);
        vm.expectRevert(RFQRegistry.RFQRegistry__Unauthorized.selector);
        registry.consumeQuote(COMMITMENT);

        // New hook can consume
        vm.prank(newHook);
        registry.consumeQuote(COMMITMENT);
        assertTrue(registry.isConsumed(COMMITMENT));
    }

    function test_CommitQuote_AnybodyCanCommit() public {
        // Verify anyone can commit quotes (not just owner)
        address randomUser = makeAddr("random");
        bytes32 testCommitment = keccak256("random_commit");

        vm.prank(randomUser);
        registry.commitQuote(testCommitment, EXPIRY, maker, POOL_KEY_HASH);

        assertTrue(registry.isCommitted(testCommitment));
    }

    /*//////////////////////////////////////////////////////////////
                          GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function testGas_CommitQuote() public {
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);
    }

    function testGas_ConsumeQuote() public {
        vm.prank(owner);
        registry.setHook(hook);
        registry.commitQuote(COMMITMENT, EXPIRY, maker, POOL_KEY_HASH);

        vm.prank(hook);
        registry.consumeQuote(COMMITMENT);
    }

    function testGas_IsCommitted() public view {
        registry.isCommitted(COMMITMENT);
    }

    function testGas_IsConsumed() public view {
        registry.isConsumed(COMMITMENT);
    }

    function testGas_GetCommitment() public view {
        registry.getCommitment(COMMITMENT);
    }
}
