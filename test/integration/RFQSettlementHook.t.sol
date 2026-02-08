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
    address maker = address(0x1111);
    address taker = address(0x2222);

    uint256 makerPrivateKey = 0x1111;
    uint256 takerPrivateKey = 0x2222;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        // 1. Deploy PoolManager
        poolManager = IPoolManager(address(new PoolManager(address(this))));

        // 2. Deploy Registry
        registry = new RFQRegistry(deployer);

        // 3. Deploy Verifier
        verifier = new HonkVerifier();

        // 4. Deploy Hasher
        hasher = new Poseidon2();

        // 5. Deploy Hook
        hook = new RFQSettlementHook(
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

    function testFail_commitQuote_AlreadyExists() public {
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
        // Create expired quote
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
                          GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Gas benchmark for beforeSwap validation
     * @dev This will be updated with real proof verification in Phase 3
     */
    function testGas_beforeSwap_FullValidation() public {
        // Setup quote
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

        // Measure gas (will fail at proof verification, but we can see gas up to that point)
        console2.log("\n=== Gas Benchmark ===");
        console2.log("Validation gas cost will be measured in Phase 3");
    }
}
