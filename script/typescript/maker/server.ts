/**
 * @file server.ts
 * @notice Maker RFQ server - Provides quote generation and policy serving
 * @author Waiola Team
 *
 * This Express.js server enables makers to:
 * 1. Serve their RFQ policy at /policy endpoint
 * 2. Generate and sign quotes at /quote endpoint
 * 3. Provide health status at /status endpoint
 */

import express, { Request, Response } from 'express';
import { ethers } from 'ethers';
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { createQuote, signQuote, getDomain, generateSalt, createExpiry } from '../utils/eip712.js';
import { computePolicyHash } from '../utils/ens-resolver.js';

// Load environment variables
dotenv.config({ path: path.join(process.cwd(), 'script', 'typescript', 'maker', '.env') });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/*******************************************************************************
 *                              CONFIGURATION                                  *
 *******************************************************************************/

const PORT = process.env.PORT || 3000;
const MAKER_PRIVATE_KEY = process.env.MAKER_PRIVATE_KEY;
const RPC_URL = process.env.RPC_URL;
const HOOK_ADDRESS = process.env.HOOK_ADDRESS || '0x0000000000000000000000000000000000000000';
const CHAIN_ID = parseInt(process.env.CHAIN_ID || '11155111'); // Default: Sepolia

// Validate environment
if (!MAKER_PRIVATE_KEY) {
    console.error('Error: MAKER_PRIVATE_KEY not set in .env');
    process.exit(1);
}

if (!RPC_URL) {
    console.error('Error: RPC_URL not set in .env');
    process.exit(1);
}

/*******************************************************************************
 *                              INITIALIZATION                                 *
 *******************************************************************************/

const app = express();
app.use(express.json());

// Initialize maker wallet
const provider = new ethers.JsonRpcProvider(RPC_URL);
const makerWallet = new ethers.Wallet(MAKER_PRIVATE_KEY, provider);

console.log(`\n🚀 Maker RFQ Server`);
console.log(`Maker Address: ${makerWallet.address}`);
console.log(`Chain ID: ${CHAIN_ID}`);
console.log(`Hook Address: ${HOOK_ADDRESS}\n`);

/*******************************************************************************
 *                              POLICY LOADING                                 *
 *******************************************************************************/

interface MakerPolicy {
    version: string;
    spread: string;
    maxQuoteValidity: number;
    pools: PoolConfig[];
    oracleValidation?: OracleConfig;
}

interface PoolConfig {
    tokenA: string;
    tokenB: string;
    fee: number;
    maxSlippage: string;
    maxAmount: string;
    minAmount: string;
}

interface OracleConfig {
    enabled: boolean;
    maxPriceDeviation: string;
    oracleAddress?: string;
}

let cachedPolicy: MakerPolicy | null = null;
let policyHash: string | null = null;

/**
 * Load maker policy from config directory
 */
async function loadPolicy(): Promise<MakerPolicy> {
    if (cachedPolicy) {
        return cachedPolicy;
    }

    try {
        const policyPath = path.join(__dirname, 'config', 'policy.json');
        const policyContent = await fs.readFile(policyPath, 'utf-8');
        cachedPolicy = JSON.parse(policyContent);

        // Compute policy hash
        policyHash = computePolicyHash(cachedPolicy);

        console.log(`✅ Policy loaded: ${cachedPolicy.pools.length} pools configured`);
        console.log(`   Policy Hash: ${policyHash}`);

        return cachedPolicy;
    } catch (error) {
        console.error('Failed to load policy:', error);
        throw new Error('Policy configuration not found');
    }
}

/**
 * Reload policy (useful for hot-reloading during development)
 */
async function reloadPolicy(): Promise<void> {
    cachedPolicy = null;
    policyHash = null;
    await loadPolicy();
}

/*******************************************************************************
 *                          QUOTE PRICING LOGIC                                *
 *******************************************************************************/

/**
 * Parse spread percentage to basis points
 * @param spreadStr Spread string (e.g., "0.1%")
 * @returns Spread in basis points
 */
function parseSpreadToBps(spreadStr: string): number {
    const match = spreadStr.match(/^(\d+\.?\d*)%$/);
    if (!match) {
        throw new Error(`Invalid spread format: ${spreadStr}`);
    }
    const percentage = parseFloat(match[1]);
    return Math.floor(percentage * 100);
}

/**
 * Find pool configuration for given parameters
 */
function findPool(policy: MakerPolicy, poolKeyHash: string): PoolConfig | null {
    // In production, you would map poolKeyHash to pool config
    // For MVP, we return the first pool (simplified)
    return policy.pools.length > 0 ? policy.pools[0] : null;
}

/**
 * Fetch current pool price (simplified - should query actual pool)
 * @param poolKeyHash Hash of PoolKey
 * @returns Price as ratio (tokenOut per tokenIn)
 */
async function fetchPoolPrice(poolKeyHash: string): Promise<bigint> {
    // TODO: In production, query actual pool price from Uniswap v4
    // For MVP, return a mock price: 1 tokenIn = 2 tokenOut
    return 2n * 10n ** 18n / 10n ** 18n; // 2.0 ratio
}

/**
 * Calculate quoted output amount with maker's spread
 * @param amountIn Input amount
 * @param poolPrice Current pool price
 * @param spreadBps Maker's spread in basis points
 * @returns Quoted output amount
 */
function calculateQuotedOut(
    amountIn: bigint,
    poolPrice: bigint,
    spreadBps: number
): bigint {
    // Base output without spread
    const baseOut = (amountIn * poolPrice) / (10n ** 18n);

    // Apply spread (reduce output by spread percentage)
    const spreadMultiplier = 10000n - BigInt(spreadBps);
    const quotedOut = (baseOut * spreadMultiplier) / 10000n;

    return quotedOut;
}

/*******************************************************************************
 *                              API ENDPOINTS                                  *
 *******************************************************************************/

/**
 * GET /policy - Serve maker policy
 */
app.get('/policy', async (req: Request, res: Response) => {
    try {
        const policy = await loadPolicy();
        res.json(policy);
    } catch (error: any) {
        console.error('Error serving policy:', error);
        res.status(500).json({ error: 'Failed to load policy' });
    }
});

/**
 * GET /status - Health check
 */
app.get('/status', async (req: Request, res: Response) => {
    try {
        const policy = await loadPolicy();
        const balance = await provider.getBalance(makerWallet.address);

        res.json({
            status: 'ok',
            maker: makerWallet.address,
            chainId: CHAIN_ID,
            balance: balance.toString(),
            poolsConfigured: policy.pools.length,
            policyHash: policyHash,
            uptime: process.uptime()
        });
    } catch (error: any) {
        res.status(500).json({
            status: 'error',
            error: error.message
        });
    }
});

/**
 * POST /quote - Generate and sign a quote
 *
 * Request body:
 * {
 *   poolKeyHash: string,
 *   taker: string,
 *   amountIn: string,
 *   minOut?: string
 * }
 *
 * Response:
 * {
 *   quote: Quote,
 *   maker: string,
 *   signature: string,
 *   policyHash: string
 * }
 */
app.post('/quote', async (req: Request, res: Response) => {
    try {
        const { poolKeyHash, taker, amountIn, minOut } = req.body;

        // Validate request
        if (!poolKeyHash || !ethers.isHexString(poolKeyHash, 32)) {
            return res.status(400).json({ error: 'Invalid poolKeyHash' });
        }

        if (!taker || !ethers.isAddress(taker)) {
            return res.status(400).json({ error: 'Invalid taker address' });
        }

        if (!amountIn || BigInt(amountIn) <= 0n) {
            return res.status(400).json({ error: 'Invalid amountIn' });
        }

        // Load policy
        const policy = await loadPolicy();

        // Find pool configuration
        const pool = findPool(policy, poolKeyHash);
        if (!pool) {
            return res.status(404).json({ error: 'Pool not supported' });
        }

        // Validate amount against pool limits
        const amountInBigInt = BigInt(amountIn);
        const minAmount = BigInt(pool.minAmount);
        const maxAmount = BigInt(pool.maxAmount);

        if (amountInBigInt < minAmount) {
            return res.status(400).json({
                error: 'Amount below minimum',
                minAmount: minAmount.toString()
            });
        }

        if (amountInBigInt > maxAmount) {
            return res.status(400).json({
                error: 'Amount above maximum',
                maxAmount: maxAmount.toString()
            });
        }

        console.log(`\n📝 Quote Request:`);
        console.log(`   Pool: ${poolKeyHash}`);
        console.log(`   Taker: ${taker}`);
        console.log(`   Amount In: ${ethers.formatEther(amountIn)} ETH`);

        // Fetch current pool price
        const poolPrice = await fetchPoolPrice(poolKeyHash);

        // Calculate quoted output with spread
        const spreadBps = parseSpreadToBps(policy.spread);
        const quotedOut = calculateQuotedOut(amountInBigInt, poolPrice, spreadBps);

        console.log(`   Quoted Out: ${ethers.formatEther(quotedOut)} ETH`);
        console.log(`   Spread: ${policy.spread} (${spreadBps} bps)`);

        // Generate quote parameters
        const expiry = createExpiry(policy.maxQuoteValidity);
        const salt = generateSalt();

        // Create quote object
        const quote = createQuote({
            poolKeyHash,
            taker,
            amountIn: amountInBigInt,
            quotedOut,
            expiry,
            salt
        });

        // Sign quote
        const domain = getDomain(CHAIN_ID, HOOK_ADDRESS);
        const signature = await signQuote(quote, makerWallet, domain);

        console.log(`   ✅ Quote signed`);
        console.log(`   Expiry: ${new Date(Number(expiry) * 1000).toISOString()}`);

        // Return signed quote
        res.json({
            quote: {
                poolKeyHash: quote.poolKeyHash,
                taker: quote.taker,
                amountIn: quote.amountIn.toString(),
                quotedOut: quote.quotedOut.toString(),
                expiry: quote.expiry.toString(),
                salt: quote.salt
            },
            maker: makerWallet.address,
            signature,
            policyHash: policyHash!
        });

    } catch (error: any) {
        console.error('Error generating quote:', error);
        res.status(500).json({
            error: 'Failed to generate quote',
            message: error.message
        });
    }
});

/**
 * POST /reload-policy - Reload policy configuration (dev only)
 */
app.post('/reload-policy', async (req: Request, res: Response) => {
    try {
        await reloadPolicy();
        res.json({
            success: true,
            message: 'Policy reloaded',
            policyHash: policyHash
        });
    } catch (error: any) {
        res.status(500).json({
            error: 'Failed to reload policy',
            message: error.message
        });
    }
});

/*******************************************************************************
 *                              ERROR HANDLING                                 *
 *******************************************************************************/

// 404 handler
app.use((req: Request, res: Response) => {
    res.status(404).json({
        error: 'Not found',
        availableEndpoints: [
            'GET /status',
            'GET /policy',
            'POST /quote',
            'POST /reload-policy'
        ]
    });
});

// Error handler
app.use((err: any, req: Request, res: Response, next: any) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message
    });
});

/*******************************************************************************
 *                              SERVER START                                   *
 *******************************************************************************/

async function startServer() {
    try {
        // Load policy on startup
        await loadPolicy();

        // Start listening
        app.listen(PORT, () => {
            console.log(`\n✅ Maker RFQ server listening on port ${PORT}`);
            console.log(`\nEndpoints:`);
            console.log(`   GET  http://localhost:${PORT}/status`);
            console.log(`   GET  http://localhost:${PORT}/policy`);
            console.log(`   POST http://localhost:${PORT}/quote`);
            console.log(`\nReady to serve quotes! 🚀\n`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Start the server
startServer();

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n🛑 Shutting down server...');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n\n🛑 Shutting down server...');
    process.exit(0);
});
