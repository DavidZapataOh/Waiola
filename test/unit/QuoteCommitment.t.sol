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

    /*//////////////////////////////////////////////////////////////
                      ADDITIONAL FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_HashQuote_Deterministic(
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

        // Hash should always be deterministic
        assertEq(harness.hashQuote(quote), harness.hashQuote(quote));
    }

    function testFuzz_HashQuote_UniquePerInput(
        uint256 _amountIn,
        uint256 _quotedOut
    ) public view {
        vm.assume(_amountIn != _quotedOut);

        QuoteCommitment.Quote memory quote1 = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: _amountIn,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        QuoteCommitment.Quote memory quote2 = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: _quotedOut,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        assertTrue(harness.hashQuote(quote1) != harness.hashQuote(quote2));
    }

    function testFuzz_VerifySignature(
        bytes32 _poolKeyHash,
        uint256 _amountIn,
        uint256 _expiry,
        bytes32 _salt
    ) public view {
        vm.assume(_amountIn > 0);
        vm.assume(_expiry > 0);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: _poolKeyHash,
            taker: taker,
            amountIn: _amountIn,
            quotedOut: QUOTED_OUT,
            expiry: _expiry,
            salt: _salt
        });

        // Sign with correct key
        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Should always verify with correct maker
        assertTrue(harness.verifySignature(quote, signature, maker));
    }

    function testFuzz_ValidateQuote_ExpiryBoundary(uint256 timestamp) public {
        vm.assume(timestamp > 0 && timestamp < type(uint256).max);

        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: timestamp,
            salt: salt
        });

        if (timestamp > 1) {
            vm.warp(timestamp - 1);
            // Should not revert (quote not expired yet)
            harness.validateQuote(quote, taker, poolKeyHash);
        }

        vm.warp(timestamp);
        // At exact expiry, should revert
        vm.expectRevert(QuoteCommitment.QuoteCommitment__ExpiredQuote.selector);
        harness.validateQuote(quote, taker, poolKeyHash);
    }

    function testFuzz_ComputeCommitment_UniquePerSalt(
        bytes32 salt1,
        bytes32 salt2
    ) public view {
        vm.assume(salt1 != salt2);

        QuoteCommitment.Quote memory quote1 = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt1
        });

        QuoteCommitment.Quote memory quote2 = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt2
        });

        // Different salts must produce different commitments
        assertTrue(
            harness.computeCommitment(hasher, quote1) !=
                harness.computeCommitment(hasher, quote2)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_HashQuote_ZeroValues() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: bytes32(0),
            taker: address(0),
            amountIn: 0,
            quotedOut: 0,
            expiry: 0,
            salt: bytes32(0)
        });

        bytes32 hash = harness.hashQuote(quote);
        // Even with all zeros, hash should be non-zero (due to type hash)
        assertTrue(hash != bytes32(0));
    }

    function test_ComputeCommitment_MaxValues() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: bytes32(type(uint256).max),
            taker: address(type(uint160).max),
            amountIn: type(uint256).max,
            quotedOut: type(uint256).max,
            expiry: type(uint256).max,
            salt: bytes32(type(uint256).max)
        });

        bytes32 commitment = harness.computeCommitment(hasher, quote);
        assertTrue(commitment != bytes32(0));
    }

    function test_VerifySignature_TamperedAmountIn() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Tamper with each field and verify rejection
        quote.amountIn = AMOUNT_IN + 1;
        assertFalse(harness.verifySignature(quote, signature, maker));
    }

    function test_VerifySignature_TamperedQuotedOut() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        quote.quotedOut = QUOTED_OUT - 1;
        assertFalse(harness.verifySignature(quote, signature, maker));
    }

    function test_VerifySignature_TamperedTaker() public {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        quote.taker = makeAddr("attacker");
        assertFalse(harness.verifySignature(quote, signature, maker));
    }

    function test_VerifySignature_TamperedExpiry() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        quote.expiry = EXPIRY + 3600;
        assertFalse(harness.verifySignature(quote, signature, maker));
    }

    function test_VerifySignature_TamperedSalt() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        quote.salt = keccak256("tampered_salt");
        assertFalse(harness.verifySignature(quote, signature, maker));
    }

    /*//////////////////////////////////////////////////////////////
                          GAS BENCHMARKS
    //////////////////////////////////////////////////////////////*/

    function testGas_HashQuote() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        harness.hashQuote(quote);
    }

    function testGas_ComputeCommitment() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        harness.computeCommitment(hasher, quote);
    }

    function testGas_VerifySignature() public view {
        QuoteCommitment.Quote memory quote = QuoteCommitment.Quote({
            poolKeyHash: poolKeyHash,
            taker: taker,
            amountIn: AMOUNT_IN,
            quotedOut: QUOTED_OUT,
            expiry: EXPIRY,
            salt: salt
        });

        bytes32 structHash = harness.hashQuote(quote);
        bytes32 domainSeparator = harness.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(makerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        harness.verifySignature(quote, signature, maker);
    }
}
