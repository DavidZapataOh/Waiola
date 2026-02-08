// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title QuoteCommitment
 * @notice Library for EIP-712 quote signing and verification
 * @dev Implements structured data hashing and signature verification for RFQ quotes
 * @author Waiola Team
 */
library QuoteCommitment {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Quote structure for EIP-712 signing
    struct Quote {
        bytes32 poolKeyHash; // Hash of PoolKey
        address taker; // Taker address
        uint256 amountIn; // Input amount
        uint256 quotedOut; // Quoted output amount
        uint256 expiry; // Quote expiry timestamp
        bytes32 salt; // Unique salt for commitment uniqueness
    }

    /*//////////////////////////////////////////////////////////////
                            TYPE HASHES
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 type hash for Quote struct
    /// @dev keccak256("Quote(bytes32 poolKeyHash,address taker,uint256 amountIn,uint256 quotedOut,uint256 expiry,bytes32 salt)")
    bytes32 internal constant QUOTE_TYPEHASH =
        keccak256(
            "Quote(bytes32 poolKeyHash,address taker,uint256 amountIn,uint256 quotedOut,uint256 expiry,bytes32 salt)"
        );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error QuoteCommitment__InvalidSignature();
    error QuoteCommitment__ExpiredQuote();
    error QuoteCommitment__InvalidTaker();
    error QuoteCommitment__InvalidPoolKey();

    /*//////////////////////////////////////////////////////////////
                           HASH FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Hash a quote according to EIP-712
     * @param quote Quote to hash
     * @return Hash of the quote struct
     */
    function hashQuote(Quote memory quote) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    QUOTE_TYPEHASH,
                    quote.poolKeyHash,
                    quote.taker,
                    quote.amountIn,
                    quote.quotedOut,
                    quote.expiry,
                    quote.salt
                )
            );
    }

    /**
     * @notice Compute commitment hash (Poseidon-like, but using keccak256 for MVP)
     * @dev In production, this would use Poseidon hash matching the Noir circuit
     * @param quote Quote to commit
     * @return Commitment hash
     */
    function computeCommitment(
        Quote memory quote
    ) internal pure returns (bytes32) {
        // For MVP, use keccak256. In Phase 3, this will match Poseidon in Noir circuit
        return
            keccak256(
                abi.encodePacked(
                    quote.poolKeyHash,
                    quote.taker,
                    quote.amountIn,
                    quote.quotedOut,
                    quote.expiry,
                    quote.salt
                )
            );
    }

    /*//////////////////////////////////////////////////////////////
                      SIGNATURE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify maker's EIP-712 signature on a quote
     * @param quote Quote that was signed
     * @param signature Maker's signature
     * @param maker Expected maker address
     * @param domainSeparator EIP-712 domain separator
     * @return True if signature is valid
     */
    function verifySignature(
        Quote memory quote,
        bytes memory signature,
        address maker,
        bytes32 domainSeparator
    ) internal pure returns (bool) {
        bytes32 structHash = hashQuote(quote);
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        address recoveredSigner = ECDSA.recover(digest, signature);
        return recoveredSigner == maker;
    }

    /**
     * @notice Verify maker's signature and revert if invalid
     * @param quote Quote that was signed
     * @param signature Maker's signature
     * @param maker Expected maker address
     * @param domainSeparator EIP-712 domain separator
     */
    function requireValidSignature(
        Quote memory quote,
        bytes memory signature,
        address maker,
        bytes32 domainSeparator
    ) internal pure {
        if (!verifySignature(quote, signature, maker, domainSeparator)) {
            revert QuoteCommitment__InvalidSignature();
        }
    }

    /*//////////////////////////////////////////////////////////////
                         VALIDATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate quote parameters against execution context
     * @param quote Quote to validate
     * @param expectedTaker Expected taker address
     * @param expectedPoolKeyHash Expected pool key hash
     */
    function validateQuote(
        Quote memory quote,
        address expectedTaker,
        bytes32 expectedPoolKeyHash
    ) internal view {
        if (quote.expiry < block.timestamp) {
            revert QuoteCommitment__ExpiredQuote();
        }

        if (quote.taker != expectedTaker) {
            revert QuoteCommitment__InvalidTaker();
        }

        if (quote.poolKeyHash != expectedPoolKeyHash) {
            revert QuoteCommitment__InvalidPoolKey();
        }
    }

    /**
     * @notice Check if quote is expired
     * @param quote Quote to check
     * @return True if expired
     */
    function isExpired(Quote memory quote) internal view returns (bool) {
        return quote.expiry < block.timestamp;
    }
}
