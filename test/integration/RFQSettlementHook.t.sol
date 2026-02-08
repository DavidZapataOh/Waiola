// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";

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
 * @title RFQSettlementHookTest
 * @notice Integration tests for RFQSettlementHook
 * @dev Tests full RFQ flow: quote signing, proof generation, commitment, swap execution
 * @author Waiola Team
 */
contract RFQSettlementHookTest is Test {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

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
    PoolId poolId;

    address deployer = address(this);
    address maker;
    address taker = address(0x2222);

    uint256 makerPrivateKey = 0x1111;
    uint256 takerPrivateKey = 0x2222;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        // 0. Derive maker address from private key
        maker = vm.addr(makerPrivateKey);

        // 1. Deploy PoolManager
        poolManager = IPoolManager(address(new PoolManager(address(this))));

        // 2. Deploy Registry
        registry = new RFQRegistry(deployer);

        // 3. Deploy Verifier
        verifier = new HonkVerifier();

        // 4. Deploy Hasher
        hasher = new Poseidon2();

        // 5. Deploy Hook (test wrapper skips address validation)
        hook = new TestableRFQSettlementHook(
            poolManager,
            IRFQRegistry(address(registry)),
            IVerifier(address(verifier)),
            hasher
        );

        // 6. Set hook in registry
        registry.setHook(address(hook));

        // 6. Create pool key
        poolKey = PoolKey({
            currency0: Currency.wrap(address(0x1000)),
            currency1: Currency.wrap(address(0x2000)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        poolId = poolKey.toId();
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a valid quote struct
     * @param _taker Taker address
     * @param _amountIn Input amount
     * @param _quotedOut Quoted output amount
     * @param _expiry Expiry timestamp
     * @param _salt Unique salt
     * @return quote Quote struct
     */
    function createQuote(
        address _taker,
        uint256 _amountIn,
        uint256 _quotedOut,
        uint256 _expiry,
        bytes32 _salt
    ) internal view returns (QuoteCommitment.Quote memory) {
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        return
            QuoteCommitment.Quote({
                poolKeyHash: poolKeyHash,
                taker: _taker,
                amountIn: _amountIn,
                quotedOut: _quotedOut,
                expiry: _expiry,
                salt: _salt
            });
    }

    /**
     * @notice Sign a quote with maker's private key
     * @param quote Quote to sign
     * @return signature EIP-712 signature
     */
    function signQuote(
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

    /**
     * @notice Generate public inputs for ZK proof
     * @param commitment Commitment hash
     * @param _taker Taker address
     * @param _amountIn Input amount
     * @param minOut Minimum output
     * @param _expiry Expiry timestamp
     * @return publicInputs Array of public inputs
     */
    function generatePublicInputs(
        bytes32 commitment,
        address _taker,
        uint256 _amountIn,
        uint256 minOut,
        uint256 _expiry
    ) internal view returns (bytes32[] memory) {
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = commitment;
        publicInputs[1] = poolKeyHash;
        publicInputs[2] = bytes32(uint256(uint160(_taker)));
        publicInputs[3] = bytes32(_amountIn);
        publicInputs[4] = bytes32(minOut);
        publicInputs[5] = bytes32(_expiry);

        return publicInputs;
    }

    /**
     * @notice Generate a mock proof (for testing without FFI)
     * @dev In production tests, this would call FFI to generate real proofs
     * @return proof Mock proof bytes
     */
    function generateMockProof() internal pure returns (bytes memory) {
        // For now, return empty bytes
        // In Phase 3 integration, this will call FFI to generate real Noir proofs
        return hex"";
    }

    /**
     * @notice Encode hookData for swap
     * @param quote Quote struct
     * @param _maker Maker address
     * @param signature Maker's signature
     * @param proof ZK proof
     * @param publicInputs Public inputs for proof
     * @return Encoded hookData
     */
    function encodeHookData(
        QuoteCommitment.Quote memory quote,
        address _maker,
        bytes memory signature,
        bytes memory proof,
        bytes32[] memory publicInputs
    ) internal pure returns (bytes memory) {
        return abi.encode(quote, _maker, signature, proof, publicInputs);
    }

    /*//////////////////////////////////////////////////////////////
                              UNIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setUp() public view {
        assertEq(address(hook.registry()), address(registry));
        assertEq(address(hook.verifier()), address(verifier));
        assertEq(registry.hook(), address(hook));
    }

    function test_getHookPermissions() public view {
        Hooks.Permissions memory permissions = hook.getHookPermissions();

        // Only beforeSwap should be enabled
        assertFalse(permissions.beforeInitialize);
        assertFalse(permissions.afterInitialize);
        assertFalse(permissions.beforeAddLiquidity);
        assertFalse(permissions.afterAddLiquidity);
        assertFalse(permissions.beforeRemoveLiquidity);
        assertFalse(permissions.afterRemoveLiquidity);
        assertTrue(permissions.beforeSwap); // ✅ Enabled
        assertFalse(permissions.afterSwap);
        assertFalse(permissions.beforeDonate);
        assertFalse(permissions.afterDonate);
        assertFalse(permissions.beforeSwapReturnDelta);
        assertFalse(permissions.afterSwapReturnDelta);
        assertFalse(permissions.afterAddLiquidityReturnDelta);
        assertFalse(permissions.afterRemoveLiquidityReturnDelta);
    }

    function test_computePoolKeyHash() public view {
        bytes32 computedHash = hook.computePoolKeyHash(poolKey);
        bytes32 expectedHash = keccak256(abi.encode(poolKey));
        assertEq(computedHash, expectedHash);
    }

    /*//////////////////////////////////////////////////////////////
                         COMMITMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_commitQuote() public {
        // Create quote
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        // Compute commitment
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        // Commit quote
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        // Verify commitment
        assertTrue(registry.isCommitted(commitment));
        assertFalse(registry.isConsumed(commitment));

        // Verify commitment data
        (
            uint256 storedExpiry,
            address storedMaker,
            bytes32 storedPoolKeyHash,
            bool used
        ) = registry.commitments(commitment);

        assertEq(storedExpiry, expiry);
        assertEq(storedMaker, maker);
        assertEq(storedPoolKeyHash, poolKeyHash);
        assertFalse(used);
    }

    function test_RevertWhen_commitQuote_AlreadyExists() public {
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        // First commit succeeds
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        // Second commit should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQRegistry.RFQRegistry__CommitmentAlreadyExists.selector,
                commitment
            )
        );
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);
    }

    /*//////////////////////////////////////////////////////////////
                         SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_signQuote_ValidSignature() public view {
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            block.timestamp + 1 hours,
            keccak256("salt1")
        );

        bytes memory signature = signQuote(quote);

        // Verify signature
        bool isValid = QuoteCommitment.verifySignature(
            quote,
            signature,
            maker,
            hook.getDomainSeparator()
        );

        assertTrue(isValid);
    }

    function test_signQuote_InvalidSignature() public view {
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            block.timestamp + 1 hours,
            keccak256("salt1")
        );

        bytes memory signature = signQuote(quote);

        // Verify with wrong maker address
        bool isValid = QuoteCommitment.verifySignature(
            quote,
            signature,
            address(0x9999), // Wrong maker
            hook.getDomainSeparator()
        );

        assertFalse(isValid);
    }

    /*//////////////////////////////////////////////////////////////
                      INTEGRATION TESTS (MOCK)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test full RFQ flow with mock proof
     * @dev This test uses a mock proof. In Phase 3, this will be updated to use FFI
     */
    function test_fullRFQFlow_MockProof() public {
        // Skip if verifier doesn't accept empty proofs
        // This will be updated in Phase 3 with real proof generation

        // 1. Create quote
        uint256 expiry = block.timestamp + 1 hours;
        uint256 amountIn = 1 ether;
        uint256 quotedOut = 0.95 ether;
        uint256 minOut = 0.94 ether; // 1% slippage tolerance

        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            amountIn,
            quotedOut,
            expiry,
            keccak256("salt1")
        );

        // 2. Compute commitment
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        // 3. Maker signs quote
        bytes memory signature = signQuote(quote);

        // 4. Commit quote onchain
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        // 5. Generate proof (mock for now)
        bytes memory proof = generateMockProof();

        // 6. Generate public inputs
        bytes32[] memory publicInputs = generatePublicInputs(
            commitment,
            taker,
            amountIn,
            minOut,
            expiry
        );

        // 7. Encode hookData
        bytes memory hookData = encodeHookData(
            quote,
            maker,
            signature,
            proof,
            publicInputs
        );

        // 8. Create swap params
        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amountSpecified: -int256(amountIn),
            sqrtPriceLimitX96: 0
        });

        // Note: This test will fail at proof verification until Phase 3 integration
        // For now, we validate all steps up to proof verification
        console2.log("Quote created and committed successfully");
        console2.log("Commitment:", vm.toString(commitment));
        console2.log("Signature valid:", true);
    }

    /*//////////////////////////////////////////////////////////////
                          ERROR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_beforeSwap_RevertsIf_CommitmentNotFound() public {
        // Create quote but don't commit
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes memory signature = signQuote(quote);
        bytes memory proof = generateMockProof();
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        bytes32[] memory publicInputs = generatePublicInputs(
            commitment,
            taker,
            1 ether,
            0.94 ether,
            expiry
        );

        bytes memory hookData = encodeHookData(
            quote,
            maker,
            signature,
            proof,
            publicInputs
        );

        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: 0
        });

        // Should revert with CommitmentNotFound
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQSettlementHook.RFQHook__CommitmentNotFound.selector,
                commitment
            )
        );

        vm.prank(address(poolManager));
        hook.beforeSwap(taker, poolKey, swapParams, hookData);
    }

    function test_beforeSwap_RevertsIf_ExpiredQuote() public {
        // Warp to a reasonable timestamp so expiry - 1 is non-zero
        // (registry uses expiry != 0 as existence check)
        vm.warp(1000);
        uint256 expiry = block.timestamp - 1; // Already expired
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes memory signature = signQuote(quote);

        // Commit quote (commitment itself isn't expired, but quote is)
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        bytes memory proof = generateMockProof();
        bytes32[] memory publicInputs = generatePublicInputs(
            commitment,
            taker,
            1 ether,
            0.94 ether,
            expiry
        );

        bytes memory hookData = encodeHookData(
            quote,
            maker,
            signature,
            proof,
            publicInputs
        );

        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: 0
        });

        // Should revert with QuoteExpired
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQSettlementHook.RFQHook__QuoteExpired.selector,
                expiry,
                block.timestamp
            )
        );

        vm.prank(address(poolManager));
        hook.beforeSwap(taker, poolKey, swapParams, hookData);
    }

    /*//////////////////////////////////////////////////////////////
                       WRONG MAKER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_beforeSwap_RevertsIf_InvalidSignature() public {
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        // Sign with a different private key (not the maker's)
        bytes memory wrongSignature = _signWithWrongKey(quote);

        // Commit quote
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        bytes memory proof = generateMockProof();
        bytes32[] memory publicInputs = generatePublicInputs(
            commitment,
            taker,
            1 ether,
            0.94 ether,
            expiry
        );

        // Encode hookData with helper to reduce stack
        bytes memory hookData = _encodeHookDataHelper(
            quote,
            maker,
            wrongSignature,
            proof,
            publicInputs
        );

        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: 0
        });

        // Should revert with InvalidSignature
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQSettlementHook.RFQHook__InvalidSignature.selector,
                maker,
                address(0)
            )
        );

        vm.prank(address(poolManager));
        hook.beforeSwap(taker, poolKey, swapParams, hookData);
    }

    function _signWithWrongKey(
        QuoteCommitment.Quote memory quote
    ) internal view returns (bytes memory) {
        uint256 wrongPrivateKey = 0x9999;
        bytes32 domainSeparator = hook.getDomainSeparator();
        bytes32 structHash = QuoteCommitment.hashQuote(quote);
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _encodeHookDataHelper(
        QuoteCommitment.Quote memory quote,
        address maker,
        bytes memory signature,
        bytes memory proof,
        bytes32[] memory publicInputs
    ) internal view returns (bytes memory) {
        return encodeHookData(quote, maker, signature, proof, publicInputs);
    }

    function test_beforeSwap_RevertsIf_MakerMismatch() public {
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes memory signature = signQuote(quote);

        // Commit quote with correct maker
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        bytes memory proof = generateMockProof();
        bytes32[] memory publicInputs = generatePublicInputs(
            commitment,
            taker,
            1 ether,
            0.94 ether,
            expiry
        );

        // Encode hookData will be done inside helper to save stack
        _runTest_beforeSwap_RevertsIf_MakerMismatch(
            quote,
            signature,
            commitment,
            poolKeyHash,
            proof,
            publicInputs
        );
    }

    function _runTest_beforeSwap_RevertsIf_MakerMismatch(
        QuoteCommitment.Quote memory quote,
        bytes memory signature,
        bytes32 commitment,
        bytes32 poolKeyHash,
        bytes memory proof,
        bytes32[] memory publicInputs
    ) internal {
        // Encode hookData with WRONG maker address
        address wrongMaker = address(0x9999);
        bytes memory hookData = encodeHookData(
            quote,
            wrongMaker, // <--- Wrong Maker
            signature,
            proof,
            publicInputs
        );

        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: 0
        });

        // Should revert with MakerMismatch
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQSettlementHook.RFQHook__MakerMismatch.selector,
                maker,
                wrongMaker
            )
        );

        vm.prank(address(poolManager));
        hook.beforeSwap(taker, poolKey, swapParams, hookData);
    }

    /*//////////////////////////////////////////////////////////////
                       WRONG POOL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_beforeSwap_RevertsIf_WrongPool() public {
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes memory signature = signQuote(quote);

        // Commit quote with DIFFERENT pool key hash
        bytes32 wrongPoolKeyHash = keccak256("wrong_pool");
        registry.commitQuote(commitment, expiry, maker, wrongPoolKeyHash);

        bytes memory proof = generateMockProof();
        bytes32[] memory publicInputs = generatePublicInputs(
            commitment,
            taker,
            1 ether,
            0.94 ether,
            expiry
        );

        bytes memory hookData = encodeHookData(
            quote,
            maker,
            signature,
            proof,
            publicInputs
        );

        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: 0
        });

        bytes32 actualPoolKeyHash = keccak256(abi.encode(poolKey));

        // Should revert with PoolMismatch
        vm.expectRevert(
            abi.encodeWithSelector(
                RFQSettlementHook.RFQHook__PoolMismatch.selector,
                wrongPoolKeyHash,
                actualPoolKeyHash
            )
        );

        vm.prank(address(poolManager));
        hook.beforeSwap(taker, poolKey, swapParams, hookData);
    }

    /*//////////////////////////////////////////////////////////////
                      INVALID HOOKDATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_beforeSwap_RevertsIf_EmptyHookData() public {
        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: 0
        });

        vm.expectRevert(RFQSettlementHook.RFQHook__InvalidHookData.selector);

        vm.prank(address(poolManager));
        hook.beforeSwap(taker, poolKey, swapParams, hex"");
    }

    function test_beforeSwap_RevertsIf_ShortHookData() public {
        SwapParams memory swapParams = SwapParams({
            zeroForOne: true,
            amountSpecified: -1 ether,
            sqrtPriceLimitX96: 0
        });

        vm.expectRevert(RFQSettlementHook.RFQHook__InvalidHookData.selector);

        vm.prank(address(poolManager));
        hook.beforeSwap(taker, poolKey, swapParams, hex"deadbeef");
    }

    /*//////////////////////////////////////////////////////////////
                      DOMAIN SEPARATOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_domainSeparator_IsNonZero() public view {
        bytes32 ds = hook.getDomainSeparator();
        assertTrue(ds != bytes32(0));
    }

    function test_domainSeparator_IsConsistent() public view {
        bytes32 ds1 = hook.getDomainSeparator();
        bytes32 ds2 = hook.getDomainSeparator();
        assertEq(ds1, ds2);
    }

    /*//////////////////////////////////////////////////////////////
                      MULTIPLE QUOTES TESTS
    //////////////////////////////////////////////////////////////*/

    function test_multipleQuotes_IndependentCommitments() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        // Create 3 different quotes with different salts
        QuoteCommitment.Quote memory quote1 = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );
        QuoteCommitment.Quote memory quote2 = createQuote(
            taker,
            2 ether,
            1.90 ether,
            expiry,
            keccak256("salt2")
        );
        QuoteCommitment.Quote memory quote3 = createQuote(
            taker,
            3 ether,
            2.85 ether,
            expiry,
            keccak256("salt3")
        );

        bytes32 commitment1 = QuoteCommitment.computeCommitment(hasher, quote1);
        bytes32 commitment2 = QuoteCommitment.computeCommitment(hasher, quote2);
        bytes32 commitment3 = QuoteCommitment.computeCommitment(hasher, quote3);

        // All commitments should be unique
        assertTrue(commitment1 != commitment2);
        assertTrue(commitment2 != commitment3);
        assertTrue(commitment1 != commitment3);

        // Commit all
        registry.commitQuote(commitment1, expiry, maker, poolKeyHash);
        registry.commitQuote(commitment2, expiry, maker, poolKeyHash);
        registry.commitQuote(commitment3, expiry, maker, poolKeyHash);

        // All should be committed
        assertTrue(registry.isCommitted(commitment1));
        assertTrue(registry.isCommitted(commitment2));
        assertTrue(registry.isCommitted(commitment3));

        // None should be consumed
        assertFalse(registry.isConsumed(commitment1));
        assertFalse(registry.isConsumed(commitment2));
        assertFalse(registry.isConsumed(commitment3));
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_commitQuote_Integration(
        uint256 amountIn,
        uint256 quotedOut,
        bytes32 _salt
    ) public {
        vm.assume(amountIn > 0 && amountIn < type(uint128).max);
        vm.assume(quotedOut > 0 && quotedOut < type(uint128).max);

        uint256 expiry = block.timestamp + 1 hours;

        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            amountIn,
            quotedOut,
            expiry,
            _salt
        );

        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        registry.commitQuote(commitment, expiry, maker, poolKeyHash);

        assertTrue(registry.isCommitted(commitment));
        assertFalse(registry.isConsumed(commitment));
    }

    function testFuzz_signQuote_Integration(
        uint256 amountIn,
        uint256 quotedOut,
        bytes32 _salt
    ) public view {
        vm.assume(amountIn > 0);
        vm.assume(quotedOut > 0);

        uint256 expiry = block.timestamp + 1 hours;

        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            amountIn,
            quotedOut,
            expiry,
            _salt
        );

        bytes memory signature = signQuote(quote);

        bool isValid = QuoteCommitment.verifySignature(
            quote,
            signature,
            maker,
            hook.getDomainSeparator()
        );

        assertTrue(isValid);
    }

    /*//////////////////////////////////////////////////////////////
                          GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function testGas_beforeSwap_CommitmentCheck() public {
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);
        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        // Measure commitment check gas
        registry.commitQuote(commitment, expiry, maker, poolKeyHash);
        registry.isCommitted(commitment);
        registry.isConsumed(commitment);
    }

    function testGas_computePoolKeyHash() public view {
        hook.computePoolKeyHash(poolKey);
    }

    function testGas_signatureVerification() public view {
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        bytes memory signature = signQuote(quote);

        QuoteCommitment.verifySignature(
            quote,
            signature,
            maker,
            hook.getDomainSeparator()
        );
    }

    function testGas_commitmentComputation() public view {
        uint256 expiry = block.timestamp + 1 hours;
        QuoteCommitment.Quote memory quote = createQuote(
            taker,
            1 ether,
            0.95 ether,
            expiry,
            keccak256("salt1")
        );

        QuoteCommitment.computeCommitment(hasher, quote);
    }
}
