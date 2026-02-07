// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title RFQRegistry
 * @notice Registry for RFQ quote commitments with anti-replay protection
 * @dev Stores commitment metadata onchain, tracks usage to prevent replay attacks
 * @author Waiola Team
 */
contract RFQRegistry is Ownable2Step {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Commitment data stored onchain
    struct CommitmentData {
        uint256 expiry;           // Quote expiry timestamp
        address maker;            // Maker who signed the quote
        bytes32 poolKeyHash;      // Hash of PoolKey
        bool used;                // Anti-replay flag
    }

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of commitment hash => commitment data
    mapping(bytes32 => CommitmentData) public commitments;

    /// @notice Authorized hook address (only hook can consume quotes)
    address public hook;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event QuoteCommitted(
        bytes32 indexed commitment,
        address indexed maker,
        bytes32 indexed poolKeyHash,
        uint256 expiry
    );

    event QuoteConsumed(
        bytes32 indexed commitment,
        address indexed consumer
    );

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
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address initialOwner) Ownable(initialOwner) {}

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set the authorized hook address
     * @param _hook Hook contract address
     */
    function setHook(address _hook) external onlyOwner {
        if (_hook == address(0)) revert RFQRegistry__ZeroAddress();
        hook = _hook;
        emit HookSet(_hook);
    }

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit a quote onchain
     * @param commitment Commitment hash (Poseidon hash of quote parameters)
     * @param expiry Quote expiry timestamp
     * @param maker Maker address who signed the quote
     * @param poolKeyHash Hash of PoolKey
     */
    function commitQuote(
        bytes32 commitment,
        uint256 expiry,
        address maker,
        bytes32 poolKeyHash
    ) external {
        if (commitments[commitment].expiry != 0) {
            revert RFQRegistry__CommitmentAlreadyExists(commitment);
        }

        commitments[commitment] = CommitmentData({
            expiry: expiry,
            maker: maker,
            poolKeyHash: poolKeyHash,
            used: false
        });

        emit QuoteCommitted(commitment, maker, poolKeyHash, expiry);
    }

    /**
     * @notice Consume a quote (mark as used)
     * @dev Only callable by authorized hook
     * @param commitment Commitment hash to consume
     */
    function consumeQuote(bytes32 commitment) external {
        if (msg.sender != hook) revert RFQRegistry__Unauthorized();

        CommitmentData storage data = commitments[commitment];

        if (data.expiry == 0) {
            revert RFQRegistry__CommitmentNotFound(commitment);
        }

        if (data.used) {
            revert RFQRegistry__CommitmentAlreadyUsed(commitment);
        }

        data.used = true;

        emit QuoteConsumed(commitment, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if a commitment is committed (exists onchain)
     * @param commitment Commitment hash
     * @return True if commitment exists
     */
    function isCommitted(bytes32 commitment) external view returns (bool) {
        return commitments[commitment].expiry != 0;
    }

    /**
     * @notice Check if a commitment has been consumed (used)
     * @param commitment Commitment hash
     * @return True if commitment has been used
     */
    function isConsumed(bytes32 commitment) external view returns (bool) {
        return commitments[commitment].used;
    }

    /**
     * @notice Get commitment data
     * @param commitment Commitment hash
     * @return data CommitmentData struct
     */
    function getCommitment(bytes32 commitment) external view returns (CommitmentData memory) {
        return commitments[commitment];
    }
}
