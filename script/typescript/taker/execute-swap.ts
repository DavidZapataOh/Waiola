/**
 * @file execute-swap.ts
 * @notice Execute RFQ swap on Uniswap v4 with ZK proof
 * @author Waiola Team
 *
 * This script:
 * 1. Loads quote with proof from quote.json
 * 2. Commits the quote to the registry
 * 3. Executes the swap via PoolManager with hookData
 * 4. Verifies replay protection by attempting a second swap
 */

import { ethers } from 'ethers';
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config({ path: path.join(process.cwd(), 'script', 'typescript', 'taker', '.env') });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/*******************************************************************************
 *                              CONFIGURATION                                  *
 *******************************************************************************/

const RPC_URL = process.env.RPC_URL;
const TAKER_PRIVATE_KEY = process.env.TAKER_PRIVATE_KEY;
const REGISTRY_ADDRESS = process.env.REGISTRY_ADDRESS;
const POOL_MANAGER_ADDRESS = process.env.POOL_MANAGER_ADDRESS;
const HOOK_ADDRESS = process.env.HOOK_ADDRESS;

if (!RPC_URL || !TAKER_PRIVATE_KEY || !REGISTRY_ADDRESS || !POOL_MANAGER_ADDRESS || !HOOK_ADDRESS) {
    console.error('Error: Missing required environment variables');
    console.error('Required: RPC_URL, TAKER_PRIVATE_KEY, REGISTRY_ADDRESS, POOL_MANAGER_ADDRESS, HOOK_ADDRESS');
    process.exit(1);
}

/*******************************************************************************
 *                              CONTRACT ABIs                                  *
 *******************************************************************************/

const REGISTRY_ABI = [
    'function commitQuote(bytes32 commitment, uint256 expiry, address maker, bytes32 poolKeyHash) external',
    'function isCommitted(bytes32 commitment) external view returns (bool)',
    'function isConsumed(bytes32 commitment) external view returns (bool)',
    'function getCommitment(bytes32 commitment) external view returns (tuple(uint256 expiry, address maker, bytes32 poolKeyHash, bool used))'
];

const POOL_MANAGER_ABI = [
    'function swap(tuple(address currency0, address currency1, uint24 fee, int24 tickSpacing, address hooks) key, tuple(bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96) params, bytes hookData) external returns (int256)',
    'event Swap(bytes32 indexed poolId, address indexed sender, int128 amount0, int128 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick, uint24 fee)'
];

/*******************************************************************************
 *                          QUOTE LOADING                                      *
 *******************************************************************************/

interface QuoteData {
    quote: {
        poolKeyHash: string;
        taker: string;
        amountIn: string;
        quotedOut: string;
        expiry: string;
        salt: string;
    };
    maker: string;
    signature: string;
    policyHash: string;
    poolKey: {
        currency0: string;
        currency1: string;
        fee: number;
        tickSpacing: number;
        hooks: string;
    };
    commitment: string;
    proof: string;
    publicInputs: string[];
    minOut: string;
    [key: string]: any;
}

async function loadQuote(): Promise<QuoteData> {
    const quotePath = path.join(__dirname, 'quote.json');
    try {
        const quoteContent = await fs.readFile(quotePath, 'utf-8');
        const quote = JSON.parse(quoteContent);

        // Validate quote has proof
        if (!quote.proof) {
            throw new Error('Quote does not have a proof. Run: npm run taker:prove');
        }

        if (!quote.commitment) {
            throw new Error('Quote does not have a commitment. Run: npm run taker:prove');
        }

        return quote;
    } catch (error: any) {
        throw new Error(`Failed to load quote: ${error.message}`);
    }
}

/*******************************************************************************
 *                          SWAP EXECUTION                                     *
 *******************************************************************************/

async function executeSwap() {
    console.log(`\n🔄 Executing RFQ Swap...\n`);

    // 1. Setup provider and signer
    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const taker = new ethers.Wallet(TAKER_PRIVATE_KEY!, provider);

    console.log(`Taker Address: ${taker.address}`);

    // 2. Connect to contracts
    const registry = new ethers.Contract(REGISTRY_ADDRESS!, REGISTRY_ABI, taker);
    const poolManager = new ethers.Contract(POOL_MANAGER_ADDRESS!, POOL_MANAGER_ABI, taker);

    try {
        // 3. Load quote
        console.log('\nStep 1/5: Loading quote with proof...');
        const quoteData = await loadQuote();
        console.log(`   ✅ Quote loaded`);
        console.log(`      Commitment: ${quoteData.commitment}`);
        console.log(`      Maker: ${quoteData.maker}`);
        console.log(`      Amount In: ${ethers.formatEther(quoteData.quote.amountIn)} ETH`);
        console.log(`      Quoted Out: ${ethers.formatEther(quoteData.quote.quotedOut)} ETH`);

        // 4. Check if quote is already committed
        const isAlreadyCommitted = await registry.isCommitted(quoteData.commitment);

        if (!isAlreadyCommitted) {
            // 5. Commit quote to registry
            console.log('\nStep 2/5: Committing quote to registry...');
            const commitTx = await registry.commitQuote(
                quoteData.commitment,
                quoteData.quote.expiry,
                quoteData.maker,
                quoteData.quote.poolKeyHash
            );

            console.log(`   TX submitted: ${commitTx.hash}`);
            console.log(`   Waiting for confirmation...`);

            const commitReceipt = await commitTx.wait();
            console.log(`   ✅ Quote committed (block ${commitReceipt.blockNumber})`);
            console.log(`   Gas used: ${commitReceipt.gasUsed.toString()}`);
        } else {
            console.log('\nStep 2/5: Quote already committed (skipping)');
        }

        // 6. Verify commitment
        console.log('\nStep 3/5: Verifying commitment...');
        const commitmentData = await registry.getCommitment(quoteData.commitment);
        console.log(`   ✅ Commitment verified`);
        console.log(`      Maker: ${commitmentData.maker}`);
        console.log(`      Pool Key Hash: ${commitmentData.poolKeyHash}`);
        console.log(`      Expiry: ${new Date(Number(commitmentData.expiry) * 1000).toISOString()}`);
        console.log(`      Used: ${commitmentData.used}`);

        if (commitmentData.used) {
            console.warn(`\n⚠️  WARNING: Commitment already used!`);
            console.warn(`   This swap will fail due to replay protection.`);
        }

        // 7. Encode hookData
        console.log('\nStep 4/5: Preparing swap...');

        const hookData = ethers.AbiCoder.defaultAbiCoder().encode(
            [
                'tuple(bytes32 poolKeyHash, address taker, uint256 amountIn, uint256 quotedOut, uint256 expiry, bytes32 salt)',
                'address',
                'bytes',
                'bytes',
                'bytes32[]'
            ],
            [
                [
                    quoteData.quote.poolKeyHash,
                    quoteData.quote.taker,
                    quoteData.quote.amountIn,
                    quoteData.quote.quotedOut,
                    quoteData.quote.expiry,
                    quoteData.quote.salt
                ],
                quoteData.maker,
                quoteData.signature,
                quoteData.proof,
                quoteData.publicInputs
            ]
        );

        console.log(`   Hook data size: ${hookData.length / 2 - 1} bytes`);

        // 8. Prepare swap params
        const swapParams = {
            zeroForOne: quoteData.poolKey.currency0 < quoteData.poolKey.currency1,
            amountSpecified: -BigInt(quoteData.quote.amountIn), // Negative = exact input
            sqrtPriceLimitX96: 0 // No price limit
        };

        console.log(`   Direction: ${swapParams.zeroForOne ? 'currency0 → currency1' : 'currency1 → currency0'}`);
        console.log(`   Amount specified: ${ethers.formatEther(Math.abs(Number(swapParams.amountSpecified)))} ETH (exact input)`);

        // 9. Execute swap
        console.log('\nStep 5/5: Executing swap...');
        console.log(`   Pool: ${quoteData.poolKey.currency0}/${quoteData.poolKey.currency1}`);
        console.log(`   Fee: ${quoteData.poolKey.fee / 10000}%`);

        const swapTx = await poolManager.swap(
            quoteData.poolKey,
            swapParams,
            hookData
        );

        console.log(`   TX submitted: ${swapTx.hash}`);
        console.log(`   Waiting for confirmation...`);

        const swapReceipt = await swapTx.wait();
        console.log(`   ✅ Swap executed successfully! (block ${swapReceipt.blockNumber})`);
        console.log(`   Gas used: ${swapReceipt.gasUsed.toString()}`);

        // Parse swap event
        const swapEvent = swapReceipt.logs
            .map((log: any) => {
                try {
                    return poolManager.interface.parseLog(log);
                } catch {
                    return null;
                }
            })
            .find((event: any) => event && event.name === 'Swap');

        if (swapEvent) {
            console.log(`\n   Swap Details:`);
            console.log(`      Amount 0: ${swapEvent.args.amount0.toString()}`);
            console.log(`      Amount 1: ${swapEvent.args.amount1.toString()}`);
            console.log(`      Price: ${swapEvent.args.sqrtPriceX96.toString()}`);
        }

        // 10. Verify commitment is now consumed
        const isConsumed = await registry.isConsumed(quoteData.commitment);
        console.log(`\n   ✅ Commitment consumed: ${isConsumed}`);

        // 11. Test replay protection
        console.log(`\n\n🛡️  Testing Replay Protection...\n`);
        console.log(`Attempting to execute the same swap again...`);

        try {
            const replayTx = await poolManager.swap(
                quoteData.poolKey,
                swapParams,
                hookData
            );

            await replayTx.wait();

            console.log(`\n❌ CRITICAL: Replay attack succeeded! This is a BUG!`);
            process.exit(1);

        } catch (error: any) {
            if (error.message.includes('CommitmentAlreadyUsed') || error.message.includes('revert')) {
                console.log(`\n✅ Replay protection working correctly!`);
                console.log(`   Error: ${error.message.split('(')[0].trim()}`);
            } else {
                console.log(`\n⚠️  Unexpected error during replay test:`);
                console.log(`   ${error.message}`);
            }
        }

        // 12. Save TXIDs
        const txids = {
            commitTx: isAlreadyCommitted ? 'already committed' : commitTx?.hash,
            swapTx: swapTx.hash,
            timestamp: new Date().toISOString()
        };

        const txidsPath = path.join(__dirname, 'txids.json');
        await fs.writeFile(txidsPath, JSON.stringify(txids, null, 2));

        console.log(`\n\n✅ Swap Complete!`);
        console.log(`\nTransaction IDs:`);
        console.log(`   Commit: ${txids.commitTx}`);
        console.log(`   Swap: ${txids.swapTx}`);
        console.log(`   Saved to: ${txidsPath}`);

    } catch (error: any) {
        console.error(`\n❌ Error: ${error.message}`);

        if (error.data) {
            console.error(`   Error data: ${error.data}`);
        }

        if (error.stack) {
            console.error(error.stack);
        }

        process.exit(1);
    }
}

/*******************************************************************************
 *                              CLI INTERFACE                                  *
 *******************************************************************************/

// Check if quote file exists
const quotePath = path.join(__dirname, 'quote.json');
try {
    await fs.access(quotePath);
} catch {
    console.error(`\n❌ Error: quote.json not found at ${quotePath}`);
    console.error(`\nPlease run these steps first:`);
    console.error(`   1. Request quote: npm run taker:request -- <args>`);
    console.error(`   2. Generate proof: npm run taker:prove`);
    process.exit(1);
}

// Run swap execution
executeSwap().catch(console.error);
