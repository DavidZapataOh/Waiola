/**
 * EIP-712 Quote Signing Utilities
 *
 * TypeScript utilities for signing and verifying RFQ quotes using EIP-712.
 * Matches the Solidity QuoteCommitment library implementation.
 *
 * @author Waiola Team
 */

import { ethers, Wallet, TypedDataDomain, TypedDataField } from 'ethers';

/*******************************************************************************
 *                                   TYPES                                     *
 *******************************************************************************/

/**
 * Quote structure matching Solidity QuoteCommitment.Quote
 */
export interface Quote {
  poolKeyHash: string;    // bytes32
  taker: string;          // address
  amountIn: bigint;       // uint256
  quotedOut: bigint;      // uint256
  expiry: bigint;         // uint256
  salt: string;           // bytes32
}

/**
 * Signed quote with maker's signature
 */
export interface SignedQuote {
  quote: Quote;
  signature: string;
  maker: string;
}

/*******************************************************************************
 *                              EIP-712 DOMAIN                                *
 *******************************************************************************/

/**
 * Get EIP-712 domain separator configuration
 *
 * @param chainId Chain ID for the domain
 * @param verifyingContract Address of the contract that will verify signatures
 * @returns EIP-712 domain configuration
 */
export function getEIP712Domain(
  chainId: number,
  verifyingContract: string
): TypedDataDomain {
  return {
    name: 'WaiolaRFQ',
    version: '1',
    chainId,
    verifyingContract,
  };
}

/**
 * EIP-712 type definition for Quote struct
 */
const QUOTE_TYPES: Record<string, TypedDataField[]> = {
  Quote: [
    { name: 'poolKeyHash', type: 'bytes32' },
    { name: 'taker', type: 'address' },
    { name: 'amountIn', type: 'uint256' },
    { name: 'quotedOut', type: 'uint256' },
    { name: 'expiry', type: 'uint256' },
    { name: 'salt', type: 'bytes32' },
  ],
};

/*******************************************************************************
 *                           SIGNING FUNCTIONS                                *
 *******************************************************************************/

/**
 * Sign a quote using EIP-712
 *
 * @param quote Quote to sign
 * @param makerWallet Maker's wallet (signer)
 * @param chainId Chain ID
 * @param verifyingContract Address of the contract that will verify this signature
 * @returns Signed quote object
 */
export async function signQuote(
  quote: Quote,
  makerWallet: Wallet,
  chainId: number,
  verifyingContract: string
): Promise<SignedQuote> {
  const domain = getEIP712Domain(chainId, verifyingContract);

  // Sign the structured data
  const signature = await makerWallet.signTypedData(domain, QUOTE_TYPES, quote);

  return {
    quote,
    signature,
    maker: makerWallet.address,
  };
}

/**
 * Verify a quote signature
 *
 * @param signedQuote Signed quote to verify
 * @param chainId Chain ID
 * @param verifyingContract Address of the contract that verifies signatures
 * @returns True if signature is valid, false otherwise
 */
export function verifyQuoteSignature(
  signedQuote: SignedQuote,
  chainId: number,
  verifyingContract: string
): boolean {
  try {
    const domain = getEIP712Domain(chainId, verifyingContract);

    // Recover the signer address from the signature
    const recoveredAddress = ethers.verifyTypedData(
      domain,
      QUOTE_TYPES,
      signedQuote.quote,
      signedQuote.signature
    );

    // Check if recovered address matches the expected maker
    return recoveredAddress.toLowerCase() === signedQuote.maker.toLowerCase();
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false;
  }
}

/*******************************************************************************
 *                           COMMITMENT HELPERS                               *
 *******************************************************************************/

/**
 * Compute quote commitment hash (matches Solidity computeCommitment)
 *
 * For MVP, uses keccak256. In Phase 3, this will be replaced with Poseidon
 * to match the Noir circuit.
 *
 * @param quote Quote to compute commitment for
 * @returns Commitment hash (bytes32)
 */
export function computeCommitment(quote: Quote): string {
  // Pack and hash quote parameters (matches Solidity abi.encodePacked)
  const packed = ethers.solidityPacked(
    ['bytes32', 'address', 'uint256', 'uint256', 'uint256', 'bytes32'],
    [
      quote.poolKeyHash,
      quote.taker,
      quote.amountIn,
      quote.quotedOut,
      quote.expiry,
      quote.salt,
    ]
  );

  return ethers.keccak256(packed);
}

/**
 * Generate a random salt for quote uniqueness
 *
 * @returns Random bytes32 salt
 */
export function generateSalt(): string {
  return ethers.hexlify(ethers.randomBytes(32));
}

/**
 * Create a quote expiry timestamp
 *
 * @param durationSeconds Validity duration in seconds
 * @returns Unix timestamp for expiry
 */
export function createExpiry(durationSeconds: number): bigint {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return BigInt(nowSeconds + durationSeconds);
}

/*******************************************************************************
 *                           VALIDATION HELPERS                               *
 *******************************************************************************/

/**
 * Check if a quote is expired
 *
 * @param quote Quote to check
 * @returns True if expired, false otherwise
 */
export function isQuoteExpired(quote: Quote): boolean {
  const nowSeconds = BigInt(Math.floor(Date.now() / 1000));
  return quote.expiry < nowSeconds;
}

/**
 * Validate quote parameters
 *
 * @param quote Quote to validate
 * @throws Error if quote is invalid
 */
export function validateQuote(quote: Quote): void {
  // Check taker address
  if (!ethers.isAddress(quote.taker)) {
    throw new Error(`Invalid taker address: ${quote.taker}`);
  }

  // Check amounts
  if (quote.amountIn <= 0n) {
    throw new Error('amountIn must be positive');
  }

  if (quote.quotedOut <= 0n) {
    throw new Error('quotedOut must be positive');
  }

  // Check expiry
  if (isQuoteExpired(quote)) {
    throw new Error('Quote is expired');
  }

  // Check hashes are valid bytes32
  if (!quote.poolKeyHash.match(/^0x[0-9a-fA-F]{64}$/)) {
    throw new Error('Invalid poolKeyHash format');
  }

  if (!quote.salt.match(/^0x[0-9a-fA-F]{64}$/)) {
    throw new Error('Invalid salt format');
  }
}

/*******************************************************************************
 *                              HELPER FUNCTIONS                              *
 *******************************************************************************/

/**
 * Create a quote object with type safety
 *
 * @param params Quote parameters
 * @returns Quote object
 */
export function createQuote(params: {
  poolKeyHash: string;
  taker: string;
  amountIn: bigint;
  quotedOut: bigint;
  expiry: bigint;
  salt?: string;
}): Quote {
  return {
    poolKeyHash: params.poolKeyHash,
    taker: params.taker,
    amountIn: params.amountIn,
    quotedOut: params.quotedOut,
    expiry: params.expiry,
    salt: params.salt || generateSalt(),
  };
}

/**
 * Parse a quote from JSON (handles bigint conversion)
 *
 * @param json JSON string or object
 * @returns Quote object
 */
export function parseQuote(json: string | any): Quote {
  const obj = typeof json === 'string' ? JSON.parse(json) : json;

  return {
    poolKeyHash: obj.poolKeyHash,
    taker: obj.taker,
    amountIn: BigInt(obj.amountIn),
    quotedOut: BigInt(obj.quotedOut),
    expiry: BigInt(obj.expiry),
    salt: obj.salt,
  };
}

/**
 * Stringify a quote to JSON (handles bigint serialization)
 *
 * @param quote Quote to stringify
 * @returns JSON string
 */
export function stringifyQuote(quote: Quote): string {
  return JSON.stringify(quote, (key, value) =>
    typeof value === 'bigint' ? value.toString() : value
  );
}

/*******************************************************************************
 *                               EXAMPLE USAGE                                *
 *******************************************************************************/

/**
 * Example: Complete quote signing and verification flow
 *
 * This demonstrates the end-to-end workflow for a maker signing a quote
 * and a taker verifying it.
 */
export async function exampleQuoteFlow() {
  // 1. Setup (maker creates wallet)
  const makerPrivateKey = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
  const makerWallet = new Wallet(makerPrivateKey);

  // 2. Create quote
  const quote = createQuote({
    poolKeyHash: ethers.keccak256(ethers.toUtf8Bytes('test_pool')),
    taker: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    amountIn: ethers.parseEther('1.0'),
    quotedOut: ethers.parseEther('2.0'),
    expiry: createExpiry(300), // 5 minutes
  });

  console.log('Quote created:', stringifyQuote(quote));

  // 3. Compute commitment
  const commitment = computeCommitment(quote);
  console.log('Commitment:', commitment);

  // 4. Sign quote
  const chainId = 1; // Mainnet (for demo)
  const verifyingContract = '0x1234567890123456789012345678901234567890';

  const signedQuote = await signQuote(quote, makerWallet, chainId, verifyingContract);
  console.log('Signature:', signedQuote.signature);

  // 5. Verify signature
  const isValid = verifyQuoteSignature(signedQuote, chainId, verifyingContract);
  console.log('Signature valid:', isValid);

  return { quote, commitment, signedQuote, isValid };
}

// Uncomment to run example:
// exampleQuoteFlow().catch(console.error);
