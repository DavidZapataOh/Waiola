// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {IRFQRegistry} from "./IRFQRegistry.sol";
import {IVerifier} from "./IVerifier.sol";

/**
 * @title IRFQSettlementHook
 * @notice Interface for RFQ Settlement Hook
 * @author Waiola Team
 */
interface IRFQSettlementHook {
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
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function beforeSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        bytes calldata hookData
    ) external returns (bytes4, BeforeSwapDelta, uint24);

    function getDomainSeparator() external view returns (bytes32);

    function computePoolKeyHash(
        PoolKey calldata key
    ) external pure returns (bytes32);

    function registry() external view returns (IRFQRegistry);

    function verifier() external view returns (IVerifier);

    function NAME() external view returns (string memory);

    function VERSION() external view returns (string memory);
}
