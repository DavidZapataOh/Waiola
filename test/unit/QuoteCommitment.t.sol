// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {QuoteCommitment} from "../../src/libraries/QuoteCommitment.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Poseidon2} from "@poseidon/src/Poseidon2.sol";

contract QuoteCommitmentHarness is EIP712 {
    constructor() EIP712("WaiolaRFQ", "1") {}

    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function hashQuote(
        QuoteCommitment.Quote memory quote
    ) external pure returns (bytes32) {
        return QuoteCommitment.hashQuote(quote);
    }

    function computeCommitment(
        Poseidon2 hasher,
        QuoteCommitment.Quote memory quote
    ) external pure returns (bytes32) {
        return QuoteCommitment.computeCommitment(hasher, quote);
    }

    function verifySignature(
        QuoteCommitment.Quote memory quote,
        bytes memory signature,
        address maker
    ) external view returns (bool) {
        return
            QuoteCommitment.verifySignature(
                quote,
                signature,
                maker,
                _domainSeparatorV4()
            );
    }

    function requireValidSignature(
        QuoteCommitment.Quote memory quote,
        bytes memory signature,
        address maker
    ) external view {
        QuoteCommitment.requireValidSignature(
            quote,
            signature,
            maker,
            _domainSeparatorV4()
        );
    }

    function validateQuote(
        QuoteCommitment.Quote memory quote,
        address expectedTaker,
        bytes32 expectedPoolKeyHash
    ) external view {
        QuoteCommitment.validateQuote(
            quote,
            expectedTaker,
            expectedPoolKeyHash
        );
    }

    function isExpired(
        QuoteCommitment.Quote memory quote
    ) external view returns (bool) {
        return QuoteCommitment.isExpired(quote);
    }
}

contract QuoteCommitmentTest is Test {
    QuoteCommitmentHarness public harness;
    Poseidon2 public hasher;

    address maker;
    uint256 makerPrivateKey;
    address taker = makeAddr("taker");
    bytes32 poolKeyHash = keccak256("test_pool");
    bytes32 salt = keccak256("test_salt");

    uint256 constant AMOUNT_IN = 1 ether;
    uint256 constant QUOTED_OUT = 2 ether;
    uint256 constant EXPIRY = 1000000;

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        harness = new QuoteCommitmentHarness();
        hasher = new Poseidon2();

        // Create maker with known private key for signing
        makerPrivateKey = 0x1234;
        maker = vm.addr(makerPrivateKey);
    }

    /*//////////////////////////////////////////////////////////////
                         HASH FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_HashQuote() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 hash = harness.hashQuote(quote);

        // Hash should be deterministic
        assertEq(hash, harness.hashQuote(quote));

        // Hash should be non-zero
        assertTrue(hash != bytes32(0));
    }

    function test_HashQuote_DifferentInputs() public view {
        QuoteCommitment.Quote memory quote1 = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        QuoteCommitment.Quote memory quote2 = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN + 1, // Different amountIn
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // Different quotes should have different hashes
        assertTrue(harness.hashQuote(quote1) != harness.hashQuote(quote2));
    }

    function test_ComputeCommitment() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 commitment = harness.computeCommitment(hasher, quote);

        // Commitment should be deterministic
        assertEq(commitment, harness.computeCommitment(hasher, quote));

        // Commitment should be non-zero
        assertTrue(commitment != bytes32(0));
    }

    function test_ComputeCommitment_DifferentSalts() public view {
        QuoteCommitment.Quote memory quote1 = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: keccak256("salt1")
        });

        QuoteCommitment.Quote memory quote2 = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: keccak256("salt2")
        });

        // Different salts should produce different commitments
        assertTrue(
            harness.computeCommitment(hasher, quote1) !=
                harness.computeCommitment(hasher, quote2)
        );
    }

    function testFuzz_ComputeCommitment(
        bytes32 _poolKeyHash,
        address _taker,
        uint256 _amountIn,
        uint256 _quotedOut,
        uint256 _expiry,
        bytes32 _salt
    ) public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: _poolKeyHash,
            taker: _taker,
            amountIn: _amountIn,
            quotedOut: _quotedOut,
            expiry: _expiry,
            salt: _salt
        });

        bytes32 commitment = harness.computeCommitment(hasher, quote);

        // Commitment should always be deterministic
        assertEq(commitment, harness.computeCommitment(hasher, quote));
    }

    /*//////////////////////////////////////////////////////////////
                    SIGNATURE VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_VerifySignature_ValidSignature() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // Sign the quote
        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature
        assertTrue(harness.verifySignature(quote, signature, maker));
    }

    function test_VerifySignature_InvalidSigner() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // Sign with wrong private key
        uint256 wrongPrivateKey = 0x5678;
        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature should fail
        assertFalse(harness.verifySignature(quote, signature, maker));
    }

    function test_VerifySignature_WrongQuoteData() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // Sign the original quote
        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Modify quote after signing
        quote.amountIn = AMOUNT_IN + 1;

        // Verification should fail
        assertFalse(harness.verifySignature(quote, signature, maker));
    }

    function test_RequireValidSignature_ValidSignature() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // Sign the quote
        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should not revert
        harness.requireValidSignature(quote, signature, maker);
    }

    function test_RequireValidSignature_RevertsOnInvalidSignature() public {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // Sign with wrong private key
        uint256 wrongPrivateKey = 0x5678;
        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should revert
        vm.expectRevert(
            QuoteCommitment.QuoteCommitment__InvalidSignature.selector
        );
        harness.requireValidSignature(quote, signature, maker);
    }

    /*//////////////////////////////////////////////////////////////
                      VALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ValidateQuote_Success() public {
        // Set timestamp to before expiry
        vm.warp(EXPIRY - 1);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // Should not revert
        harness.validateQuote(quote, taker, poolKeyHash);
    }

    function test_ValidateQuote_RevertsIfExpired() public {
        // Set timestamp to after expiry
        vm.warp(EXPIRY + 1);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // Should revert with ExpiredQuote
        vm.expectRevert(QuoteCommitment.QuoteCommitment__ExpiredQuote.selector);
        harness.validateQuote(quote, taker, poolKeyHash);
    }

    function test_ValidateQuote_RevertsIfInvalidTaker() public {
        vm.warp(EXPIRY - 1);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        address wrongTaker = makeAddr("wrong_taker");

        // Should revert with InvalidTaker
        vm.expectRevert(QuoteCommitment.QuoteCommitment__InvalidTaker.selector);
        harness.validateQuote(quote, wrongTaker, poolKeyHash);
    }

    function test_ValidateQuote_RevertsIfInvalidPoolKey() public {
        vm.warp(EXPIRY - 1);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 wrongPoolKeyHash = keccak256("wrong_pool");

        // Should revert with InvalidPoolKey
        vm.expectRevert(
            QuoteCommitment.QuoteCommitment__InvalidPoolKey.selector
        );
        harness.validateQuote(quote, taker, wrongPoolKeyHash);
    }

    /*//////////////////////////////////////////////////////////////
                       HELPER FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_IsExpired_ReturnsFalseIfNotExpired() public {
        vm.warp(EXPIRY - 1);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        assertFalse(harness.isExpired(quote));
    }

    function test_IsExpired_ReturnsTrueIfExpired() public {
        vm.warp(EXPIRY + 1);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        assertTrue(harness.isExpired(quote));
    }

    function test_IsExpired_ReturnsTrueIfExactlyExpired() public {
        vm.warp(EXPIRY);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // At exact expiry timestamp, quote should be considered expired
        assertTrue(harness.isExpired(quote));
    }

    /*//////////////////////////////////////////////////////////////
                       INTEGRATION SCENARIOS
    //////////////////////////////////////////////////////////////*/

    function test_FullQuoteFlow() public view {
        // 1. Create quote
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        // 2. Compute commitment
        bytes32 commitment = harness.computeCommitment(hasher, quote);
        assertTrue(commitment != bytes32(0));

        // 3. Maker signs quote
        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // 4. Verify signature
        assertTrue(harness.verifySignature(quote, signature, maker));
    }

    function test_DomainSeparator_IsConsistent() public view {
        bytes32 domain1 = harness.getDomainSeparator();
        bytes32 domain2 = harness.getDomainSeparator();

        // Domain separator should be consistent
        assertEq(domain1, domain2);
        assertTrue(domain1 != bytes32(0));
    }
}
