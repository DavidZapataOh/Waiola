// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {BaseHook} from "@uniswap/v4-periphery/src/utils/BaseHook.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";

import {QuoteCommitment} from "./libraries/QuoteCommitment.sol";
import {IRFQRegistry} from "./interfaces/IRFQRegistry.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {Poseidon2} from "@poseidon/src/Poseidon2.sol";

/**
 * @title RFQSettlementHook
 * @notice Uniswap v4 hook that enforces RFQ quote validation before swaps
 * @dev Validates: commitment exists, signature valid, not expired, proof valid, no replay
 * @author Waiola Team
 *
 * @custom:security-contact security@waiola.xyz
 * @custom:architecture Minimal permissions pattern - only beforeSwap enabled
 */
contract RFQSettlementHook is BaseHook {
    using PoolIdLibrary for PoolKey;

    /*//////////////////////////////////////////////////////////////
                               IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Registry contract for commitment storage
    IRFQRegistry public immutable registry;

    /// @notice ZK proof verifier contract
    IVerifier public immutable verifier;

    /// @notice Poseidon2 hasher for commitment generation
    Poseidon2 public immutable hasher;

    /// @notice EIP-712 domain separator for signature verification
    bytes32 private immutable DOMAIN_SEPARATOR;

    /// @notice Contract name for EIP-712
    string public constant NAME = "WaiolaRFQ";

    /// @notice Contract version for EIP-712
    string public constant VERSION = "1";

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error RFQHook__CommitmentNotFound(bytes32 commitment);
    error RFQHook__CommitmentAlreadyUsed(bytes32 commitment);
    error RFQHook__InvalidSignature(address expected, address actual);
    error RFQHook__QuoteExpired(uint256 expiry, uint256 currentTime);
    error RFQHook__InvalidProof();
    error RFQHook__PoolMismatch(bytes32 expected, bytes32 actual);
    error RFQHook__TakerMismatch(address expected, address actual);
    error RFQHook__AmountMismatch(uint256 expected, uint256 actual);
    error RFQHook__CommitmentMismatch();
    error RFQHook__InvalidHookData();
    error RFQHook__MakerMismatch(address expected, address actual);

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event QuoteValidated(
        bytes32 indexed commitment,
        address indexed maker,
        address indexed taker,
        bytes32 poolKeyHash,
        uint256 amountIn
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the RFQ Settlement Hook
     * @param _poolManager Uniswap v4 PoolManager address
     * @param _registry RFQRegistry address for commitment storage
     * @param _verifier Noir ZK proof verifier address
     * @param _hasher Poseidon2 hasher contract address
     */
    constructor(
        IPoolManager _poolManager,
        IRFQRegistry _registry,
        IVerifier _verifier,
        Poseidon2 _hasher
    ) BaseHook(_poolManager) {
        registry = _registry;
        verifier = _verifier;
        hasher = _hasher;

        // Build EIP-712 domain separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                          HOOK PERMISSIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Define hook permissions
     * @dev Following minimal permissions pattern from winning projects (iceberg)
     *      Only beforeSwap is enabled - all validation happens before swap execution
     * @return Hooks.Permissions struct with only beforeSwap = true
     */
    function getHookPermissions()
        public
        pure
        override
        returns (Hooks.Permissions memory)
    {
        return
            Hooks.Permissions({
                beforeInitialize: false,
                afterInitialize: false,
                beforeAddLiquidity: false,
                afterAddLiquidity: false,
                beforeRemoveLiquidity: false,
                afterRemoveLiquidity: false,
                beforeSwap: true, // ✅ ONLY THIS - Validate quote before swap
                afterSwap: false,
                beforeDonate: false,
                afterDonate: false,
                beforeSwapReturnDelta: false,
                afterSwapReturnDelta: false,
                afterAddLiquidityReturnDelta: false,
                afterRemoveLiquidityReturnDelta: false
            });
    }

    /*//////////////////////////////////////////////////////////////
                            HOOK CALLBACKS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate RFQ quote before swap execution
     * @dev Called by PoolManager before every swap on pools using this hook
     *
     * Validation flow:
     * 1. Decode hookData (quote + signature + proof + public inputs)
     * 2. Verify commitment exists in registry and not consumed
     * 3. Verify commitment bound to correct pool
     * 4. Verify maker signature (EIP-712)
     * 5. Verify quote not expired
     * 6. Verify ZK proof
     * 7. Verify public inputs match context (commitment, pool, taker, amount)
     * 8. Consume commitment (mark as used - prevents replay)
     *
     * @param sender Address executing the swap (taker)
     * @param key PoolKey for the pool being swapped
     * @param params Swap parameters (amount, direction, limit)
     * @param hookData Encoded quote data: (Quote, maker, signature, proof, publicInputs)
     * @return selector Function selector to indicate success
     * @return delta BeforeSwapDelta (ZERO_DELTA - no delta modifications)
     * @return lpFeeOverride LP fee override (0 - no override)
     */
    /**
     * @notice Validate RFQ quote before swap execution
     * @dev Main entry point - delegates to helper functions to avoid stack depth issues
     */
    function _beforeSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        bytes calldata hookData
    ) internal override returns (bytes4, BeforeSwapDelta, uint24) {
        bytes32 poolKeyHash = keccak256(abi.encode(key));

        // Step 1: Decode and validate commitment/signature
        ValidationData memory data = _decodeAndValidateCore(
            hookData,
            poolKeyHash
        );

        // Step 2: Validate proof and public inputs
        _validateProofAndInputs(data, poolKeyHash, sender, params);

        // Step 3: Finalize - consume and emit
        return _finalizeValidation(data, poolKeyHash, sender);
    }

    /**
     * @notice Validation data struct to reduce stack depth
     */
    struct ValidationData {
        bytes32 commitment;
        address maker;
        QuoteCommitment.Quote quote;
        bytes proof;
        bytes32[] publicInputs;
    }

    /**
     * @notice Decode hookData and validate commitment/signature
     * @return data Validation data including commitment, maker, quote, proof, and public inputs
     */
    function _decodeAndValidateCore(
        bytes calldata hookData,
        bytes32 poolKeyHash
    ) internal view returns (ValidationData memory data) {
        // Decode hookData
        (
            QuoteCommitment.Quote memory quote,
            address maker,
            bytes memory signature,
            bytes memory proof,
            bytes32[] memory publicInputs
        ) = _decodeHookData(hookData);

        // Compute commitment
        bytes32 commitment = QuoteCommitment.computeCommitment(hasher, quote);

        // Validate commitment exists and not consumed
        if (!registry.isCommitted(commitment)) {
            revert RFQHook__CommitmentNotFound(commitment);
        }
        if (registry.isConsumed(commitment)) {
            revert RFQHook__CommitmentAlreadyUsed(commitment);
        }

        // Validate commitment bound to correct pool
        IRFQRegistry.CommitmentData memory commitmentData = registry
            .getCommitment(commitment);
        if (commitmentData.poolKeyHash != poolKeyHash) {
            revert RFQHook__PoolMismatch(
                commitmentData.poolKeyHash,
                poolKeyHash
            );
        }

        // Validate maker matches
        if (commitmentData.maker != maker) {
            revert RFQHook__MakerMismatch(commitmentData.maker, maker);
        }

        // Validate signature
        bool signatureValid = QuoteCommitment.verifySignature(
            quote,
            signature,
            maker,
            DOMAIN_SEPARATOR
        );
        if (!signatureValid) {
            revert RFQHook__InvalidSignature(maker, address(0));
        }

        // Return validation data
        return
            ValidationData({
                commitment: commitment,
                maker: maker,
                quote: quote,
                proof: proof,
                publicInputs: publicInputs
            });
    }

    /**
     * @notice Validate ZK proof and public inputs
     */
    function _validateProofAndInputs(
        ValidationData memory data,
        bytes32 poolKeyHash,
        address sender,
        SwapParams calldata params
    ) internal view {
        // Verify quote not expired
        if (block.timestamp > data.quote.expiry) {
            revert RFQHook__QuoteExpired(data.quote.expiry, block.timestamp);
        }

        // Verify ZK proof
        if (!verifier.verify(data.proof, data.publicInputs)) {
            revert RFQHook__InvalidProof();
        }

        // Verify public inputs match context
        _verifyPublicInputs(
            data.publicInputs,
            data.commitment,
            poolKeyHash,
            sender,
            params,
            data.quote
        );
    }

    /**
     * @notice Finalize validation - consume commitment and emit event
     */
    function _finalizeValidation(
        ValidationData memory data,
        bytes32 poolKeyHash,
        address sender
    ) internal returns (bytes4, BeforeSwapDelta, uint24) {
        // Consume commitment (mark as used - prevents replay)
        registry.consumeQuote(data.commitment);

        // Emit validation event
        emit QuoteValidated(
            data.commitment,
            data.maker,
            sender,
            poolKeyHash,
            data.quote.amountIn
        );

        // Return success with no delta modifications
        return (
            BaseHook.beforeSwap.selector,
            BeforeSwapDeltaLibrary.ZERO_DELTA,
            0
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL VALIDATION
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        INTERNAL VALIDATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Decode hookData into structured components
     * @param hookData Encoded data from swap call
     * @return quote Quote struct
     * @return maker Maker address
     * @return signature Maker's EIP-712 signature
     * @return proof ZK proof bytes
     * @return publicInputs Array of public inputs for proof verification
     */
    function _decodeHookData(
        bytes calldata hookData
    )
        internal
        pure
        returns (
            QuoteCommitment.Quote memory quote,
            address maker,
            bytes memory signature,
            bytes memory proof,
            bytes32[] memory publicInputs
        )
    {
        // Expected encoding: (Quote, address, bytes, bytes, bytes32[])
        if (hookData.length < 32) {
            revert RFQHook__InvalidHookData();
        }

        (quote, maker, signature, proof, publicInputs) = abi.decode(
            hookData,
            (QuoteCommitment.Quote, address, bytes, bytes, bytes32[])
        );
    }

    /**
     * @notice Verify ZK proof public inputs match execution context
     * @dev Public inputs for RFQ Quote circuit (in order):
     *      [0] commitment    - Quote commitment hash
     *      [1] poolKeyHash   - Hash of PoolKey
     *      [2] taker         - Taker address (as bytes32)
     *      [3] amountIn      - Input amount
     *      [4] minOut        - Minimum output (slippage protection)
     *      [5] expiry        - Quote expiry timestamp
     *
     * @param publicInputs Public inputs from proof
     * @param commitment Computed commitment hash
     * @param poolKeyHash Computed pool key hash
     * @param sender Swap sender (taker)
     * @param params Swap parameters
     * @param quote Quote struct
     */
    function _verifyPublicInputs(
        bytes32[] memory publicInputs,
        bytes32 commitment,
        bytes32 poolKeyHash,
        address sender,
        SwapParams calldata params,
        QuoteCommitment.Quote memory quote
    ) internal pure {
        // Verify array length
        if (publicInputs.length != 6) {
            revert RFQHook__InvalidProof();
        }

        // [0] Verify commitment matches
        if (publicInputs[0] != commitment) {
            revert RFQHook__CommitmentMismatch();
        }

        // [1] Verify poolKeyHash matches
        if (publicInputs[1] != poolKeyHash) {
            revert RFQHook__PoolMismatch(publicInputs[1], poolKeyHash);
        }

        // [2] Verify taker matches
        address publicInputTaker = address(uint160(uint256(publicInputs[2])));
        if (publicInputTaker != sender) {
            revert RFQHook__TakerMismatch(sender, publicInputTaker);
        }

        // [3] Verify amountIn matches
        // Handle both exactInput (negative) and exactOutput (positive) swaps
        uint256 swapAmount = params.amountSpecified < 0
            ? uint256(-params.amountSpecified)
            : uint256(params.amountSpecified);

        if (uint256(publicInputs[3]) != swapAmount) {
            revert RFQHook__AmountMismatch(
                uint256(publicInputs[3]),
                swapAmount
            );
        }

        // [4] minOut is validated inside ZK circuit (quotedOut >= minOut)
        // No onchain verification needed here

        // [5] Verify expiry matches
        if (uint256(publicInputs[5]) != quote.expiry) {
            revert RFQHook__QuoteExpired(
                quote.expiry,
                uint256(publicInputs[5])
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the EIP-712 domain separator
     * @return Domain separator hash
     */
    function getDomainSeparator() external view returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }

    /**
     * @notice Compute pool key hash for a given pool
     * @param key PoolKey to hash
     * @return Pool key hash
     */
    function computePoolKeyHash(
        PoolKey calldata key
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }
}
