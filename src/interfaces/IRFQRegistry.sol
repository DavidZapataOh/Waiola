// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title IRFQRegistry
 * @notice Interface for RFQ Registry contract
 */
interface IRFQRegistry {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct CommitmentData {
        uint256 expiry;
        address maker;
        bytes32 poolKeyHash;
        bool used;
    }

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
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error RFQRegistry__CommitmentAlreadyExists(bytes32 commitment);
    error RFQRegistry__CommitmentNotFound(bytes32 commitment);
    error RFQRegistry__CommitmentAlreadyUsed(bytes32 commitment);
    error RFQRegistry__Unauthorized();
    error RFQRegistry__ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setHook(address _hook) external;

    function commitQuote(
        bytes32 commitment,
        uint256 expiry,
        address maker,
        bytes32 poolKeyHash
    ) external;

    function consumeQuote(bytes32 commitment) external;

    function isCommitted(bytes32 commitment) external view returns (bool);

    function isConsumed(bytes32 commitment) external view returns (bool);

    function getCommitment(bytes32 commitment) external view returns (CommitmentData memory);

    function hook() external view returns (address);
}
