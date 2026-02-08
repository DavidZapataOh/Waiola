/**
 * @file request-quote.ts
 * @notice Taker script to discover makers via ENS and request quotes
 * @author Waiola Team
 *
 * This script:
 * 1. Resolves maker's ENS name to get endpoint and policy hash
 * 2. Fetches and verifies maker's policy
 * 3. Requests a quote from the maker
 * 4. Saves the quote for proof generation
 */

import { ethers } from 'ethers';
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import {
    discoverAndVerifyMaker,
    findCompatiblePool,
    validateQuoteAmount,
    calculateMinOutput,
    parseSlippageToBps
} from '../utils/ens-resolver.js';
import { verifyQuoteSignature, getDomain } from '../utils/eip712.js';

dotenv.config({ path: path.join(process.cwd(), 'script', 'typescript', 'taker', '.env') });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/*******************************************************************************
 *                              CONFIGURATION                                  *
 *******************************************************************************/

const RPC_URL = process.env.RPC_URL;
const HOOK_ADDRESS = process.env.HOOK_ADDRESS || '0x0000000000000000000000000000000000000000';
const CHAIN_ID = parseInt(process.env.CHAIN_ID || '11155111');

if (!RPC_URL) {
    console.error('Error: RPC_URL not set in .env');
    process.exit(1);
}

/*******************************************************************************
 *                          QUOTE REQUEST PARAMETERS                           *
 *******************************************************************************/

interface QuoteRequestParams {
    makerENS: string;
    tokenA: string;
    tokenB: string;
    fee: number;
    amountIn: string;
    taker: string;
    slippageBps?: number;
}

/*******************************************************************************
 *                          MAIN QUOTE REQUEST FLOW                            *
 *******************************************************************************/

async function requestQuote(params: QuoteRequestParams) {
    console.log(`\n🔍 Requesting quote from ${params.makerENS}...\n`);

    // 1. Connect to provider
    const provider = new ethers.JsonRpcProvider(RPC_URL);

    try {
        // 2. Discover and verify maker via ENS
        console.log('Step 1/5: Discovering maker via ENS...');
        const { discovery, policy, verified } = await discoverAndVerifyMaker(
            params.makerENS,
            provider
        );

        if (!verified && discovery.policyHash) {
            console.warn('\n⚠️  WARNING: Policy hash verification failed!');
            console.warn('   The maker may have updated their policy without updating ENS.');
            console.warn('   Proceed with caution.\n');

            // In production, you might want to abort here
            const shouldContinue = process.env.ALLOW_UNVERIFIED_POLICY === 'true';
            if (!shouldContinue) {
                throw new Error('Policy verification failed. Set ALLOW_UNVERIFIED_POLICY=true to override.');
            }
        }

        // 3. Find compatible pool
        console.log('\nStep 2/5: Checking pool compatibility...');
        const pool = findCompatiblePool(policy, params.tokenA, params.tokenB, params.fee);

        if (!pool) {
            throw new Error(`Maker does not support pool: ${params.tokenA}/${params.tokenB} @ ${params.fee / 10000}%`);
        }

        console.log(`   ✅ Compatible pool found`);
        console.log(`      Token A: ${pool.tokenA}`);
        console.log(`      Token B: ${pool.tokenB}`);
        console.log(`      Fee: ${pool.fee / 10000}%`);
        console.log(`      Max Slippage: ${pool.maxSlippage}`);

        // 4. Validate amount
        console.log('\nStep 3/5: Validating amount...');
        const amountInBigInt = BigInt(params.amountIn);
        const validation = validateQuoteAmount(pool, amountInBigInt);

        if (!validation.valid) {
            throw new Error(validation.reason);
        }

        console.log(`   ✅ Amount valid: ${ethers.formatEther(params.amountIn)} ETH`);
        console.log(`      Min: ${ethers.formatEther(pool.minAmount)} ETH`);
        console.log(`      Max: ${ethers.formatEther(pool.maxAmount)} ETH`);

        // 5. Compute poolKeyHash
        const poolKey = {
            currency0: params.tokenA < params.tokenB ? params.tokenA : params.tokenB,
            currency1: params.tokenA < params.tokenB ? params.tokenB : params.tokenA,
            fee: params.fee,
            tickSpacing: 60, // Standard tick spacing
            hooks: HOOK_ADDRESS
        };

        const poolKeyHash = ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
                ['address', 'address', 'uint24', 'int24', 'address'],
                [poolKey.currency0, poolKey.currency1, poolKey.fee, poolKey.tickSpacing, poolKey.hooks]
            )
        );

        console.log(`   Pool Key Hash: ${poolKeyHash}`);

        // 6. Request quote from maker's endpoint
        console.log('\nStep 4/5: Requesting quote from maker...');
        console.log(`   Endpoint: ${discovery.endpoint}`);

        const response = await fetch(discovery.endpoint!, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                poolKeyHash,
                taker: params.taker,
                amountIn: params.amountIn
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Quote request failed (${response.status}): ${errorText}`);
        }

        const quoteResponse = await response.json();

        console.log(`   ✅ Quote received from ${quoteResponse.maker}`);
        console.log(`      Quoted Out: ${ethers.formatEther(quoteResponse.quote.quotedOut)} ETH`);
        console.log(`      Expiry: ${new Date(Number(quoteResponse.quote.expiry) * 1000).toISOString()}`);

        // 7. Verify quote signature
        console.log('\nStep 5/5: Verifying quote signature...');

        const quote = {
            poolKeyHash: quoteResponse.quote.poolKeyHash,
            taker: quoteResponse.quote.taker,
            amountIn: BigInt(quoteResponse.quote.amountIn),
            quotedOut: BigInt(quoteResponse.quote.quotedOut),
            expiry: BigInt(quoteResponse.quote.expiry),
            salt: quoteResponse.quote.salt
        };

        const domain = getDomain(CHAIN_ID, HOOK_ADDRESS);
        const isValid = verifyQuoteSignature(
            {
                ...quote,
                maker: quoteResponse.maker,
                signature: quoteResponse.signature
            },
            CHAIN_ID,
            HOOK_ADDRESS
        );

        if (!isValid) {
            throw new Error('Quote signature verification failed!');
        }

        console.log(`   ✅ Signature valid`);

        // 8. Calculate minimum output with slippage
        const slippageBps = params.slippageBps || parseSlippageToBps(pool.maxSlippage);
        const minOut = calculateMinOutput(quote.quotedOut, slippageBps);

        console.log(`\n   Slippage Protection: ${slippageBps / 100}%`);
        console.log(`   Min Output: ${ethers.formatEther(minOut)} ETH`);

        // 9. Save quote to file
        const quoteData = {
            // Quote details
            quote: {
                poolKeyHash: quote.poolKeyHash,
                taker: quote.taker,
                amountIn: quote.amountIn.toString(),
                quotedOut: quote.quotedOut.toString(),
                expiry: quote.expiry.toString(),
                salt: quote.salt
            },
            // Signature and maker
            maker: quoteResponse.maker,
            signature: quoteResponse.signature,
            policyHash: quoteResponse.policyHash,
            // Pool details
            poolKey,
            // Slippage protection
            minOut: minOut.toString(),
            slippageBps,
            // Metadata
            requestedAt: new Date().toISOString(),
            makerENS: params.makerENS,
            endpoint: discovery.endpoint
        };

        const outputPath = path.join(__dirname, 'quote.json');
        await fs.writeFile(outputPath, JSON.stringify(quoteData, null, 2));

        console.log(`\n✅ Quote saved to: ${outputPath}`);
        console.log(`\nNext steps:`);
        console.log(`   1. Generate proof: npm run taker:prove`);
        console.log(`   2. Execute swap: npm run taker:swap`);

        return quoteData;

    } catch (error: any) {
        console.error(`\n❌ Error: ${error.message}`);
        if (error.stack) {
            console.error(error.stack);
        }
        process.exit(1);
    }
}

/*******************************************************************************
 *                              CLI INTERFACE                                  *
 *******************************************************************************/

// Parse command line arguments
const args = process.argv.slice(2);

if (args.length < 5) {
    console.log(`
Usage: npm run taker:request -- <makerENS> <tokenA> <tokenB> <fee> <amountIn> <taker> [slippageBps]

Arguments:
  makerENS     - Maker's ENS name (e.g., "alice.eth")
  tokenA       - Token A address
  tokenB       - Token B address
  fee          - Pool fee tier (e.g., 3000 for 0.3%)
  amountIn     - Input amount in wei
  taker        - Taker address
  slippageBps  - Optional: Slippage in basis points (default: from pool config)

Example:
  npm run taker:request -- \\
    alice.eth \\
    0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 \\
    0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \\
    3000 \\
    1000000000000000000 \\
    0x742d35Cc6634C0532925a3b844Bc454e4438f44e \\
    50
`);
    process.exit(1);
}

const [makerENS, tokenA, tokenB, feeStr, amountIn, taker, slippageBpsStr] = args;

const params: QuoteRequestParams = {
    makerENS,
    tokenA,
    tokenB,
    fee: parseInt(feeStr),
    amountIn,
    taker,
    slippageBps: slippageBpsStr ? parseInt(slippageBpsStr) : undefined
};

// Validate inputs
if (!ethers.isAddress(tokenA)) {
    console.error('Error: Invalid tokenA address');
    process.exit(1);
}

if (!ethers.isAddress(tokenB)) {
    console.error('Error: Invalid tokenB address');
    process.exit(1);
}

if (!ethers.isAddress(taker)) {
    console.error('Error: Invalid taker address');
    process.exit(1);
}

if (BigInt(amountIn) <= 0n) {
    console.error('Error: amountIn must be positive');
    process.exit(1);
}

// Run quote request
requestQuote(params).catch(console.error);
