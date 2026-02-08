/**
 * @file ens-resolver.ts
 * @notice ENS resolution utilities for RFQ maker discovery
 * @author Waiola Team
 *
 * This module provides utilities for takers to discover makers via ENS,
 * resolve their RFQ endpoints, and verify policy hashes.
 */

import { ethers } from 'ethers';

/**
 * Maker discovery data resolved from ENS
 */
export interface MakerDiscoveryData {
    ensName: string;
    endpoint: string | null;
    policyHash: string | null;
    pubkey: string | null;
    resolverAddress: string;
}

/**
 * Maker policy structure (fetched from endpoint)
 */
export interface MakerPolicy {
    version: string;
    spread: string;
    maxQuoteValidity: number;
    pools: PoolConfig[];
    oracleValidation?: OracleConfig;
}

export interface PoolConfig {
    tokenA: string;
    tokenB: string;
    fee: number;
    maxSlippage: string;
    maxAmount: string;
    minAmount: string;
}

export interface OracleConfig {
    enabled: boolean;
    maxPriceDeviation: string;
    oracleAddress?: string;
}

/**
 * Resolve RFQ endpoint from ENS text record
 * @param ensName ENS name (e.g., "alice.eth")
 * @param provider Ethereum provider
 * @returns RFQ endpoint URL or null if not set
 */
export async function resolveRFQEndpoint(
    ensName: string,
    provider: ethers.Provider
): Promise<string | null> {
    try {
        const resolver = await provider.getResolver(ensName);
        if (!resolver) {
            return null;
        }

        return await resolver.getText('rfq-endpoint');
    } catch (error) {
        console.error(`Error resolving rfq-endpoint for ${ensName}:`, error);
        return null;
    }
}

/**
 * Resolve RFQ policy hash from ENS text record
 * @param ensName ENS name
 * @param provider Ethereum provider
 * @returns Policy hash or null if not set
 */
export async function resolveRFQPolicyHash(
    ensName: string,
    provider: ethers.Provider
): Promise<string | null> {
    try {
        const resolver = await provider.getResolver(ensName);
        if (!resolver) {
            return null;
        }

        return await resolver.getText('rfq-policy-hash');
    } catch (error) {
        console.error(`Error resolving rfq-policy-hash for ${ensName}:`, error);
        return null;
    }
}

/**
 * Resolve RFQ public key from ENS text record (optional, for encrypted quotes)
 * @param ensName ENS name
 * @param provider Ethereum provider
 * @returns Public key or null if not set
 */
export async function resolveRFQPubkey(
    ensName: string,
    provider: ethers.Provider
): Promise<string | null> {
    try {
        const resolver = await provider.getResolver(ensName);
        if (!resolver) {
            return null;
        }

        return await resolver.getText('rfq-pubkey');
    } catch (error) {
        console.error(`Error resolving rfq-pubkey for ${ensName}:`, error);
        return null;
    }
}

/**
 * Resolve all RFQ-related ENS records for a maker
 * @param ensName ENS name
 * @param provider Ethereum provider
 * @returns Complete maker discovery data
 */
export async function resolveMakerDiscovery(
    ensName: string,
    provider: ethers.Provider
): Promise<MakerDiscoveryData> {
    const resolver = await provider.getResolver(ensName);

    if (!resolver) {
        throw new Error(`No resolver found for ${ensName}`);
    }

    const [endpoint, policyHash, pubkey] = await Promise.all([
        resolver.getText('rfq-endpoint').catch(() => null),
        resolver.getText('rfq-policy-hash').catch(() => null),
        resolver.getText('rfq-pubkey').catch(() => null)
    ]);

    return {
        ensName,
        endpoint,
        policyHash,
        pubkey,
        resolverAddress: await resolver.getAddress()
    };
}

/**
 * Fetch maker policy from endpoint
 * @param endpoint RFQ endpoint URL
 * @returns Maker policy object
 */
export async function fetchMakerPolicy(
    endpoint: string
): Promise<MakerPolicy> {
    try {
        // Normalize endpoint (add /policy if not present)
        const policyUrl = endpoint.endsWith('/policy')
            ? endpoint
            : `${endpoint}/policy`;

        const response = await fetch(policyUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}: ${response.statusText}`
            );
        }

        const policy = await response.json();

        // Basic validation
        if (!policy.version || !policy.pools) {
            throw new Error('Invalid policy structure');
        }

        return policy;
    } catch (error: any) {
        throw new Error(`Failed to fetch policy from ${endpoint}: ${error.message}`);
    }
}

/**
 * Compute policy hash (keccak256 of canonical JSON)
 * @param policy Maker policy object
 * @returns Policy hash
 */
export function computePolicyHash(policy: MakerPolicy): string {
    // Canonical JSON stringify (sorted keys, no whitespace)
    const canonicalJson = JSON.stringify(policy, Object.keys(policy).sort());
    return ethers.keccak256(ethers.toUtf8Bytes(canonicalJson));
}

/**
 * Verify that policy hash matches expected hash
 * @param policy Maker policy object
 * @param expectedHash Expected policy hash from ENS
 * @returns True if hashes match
 */
export function verifyPolicyHash(
    policy: MakerPolicy,
    expectedHash: string
): boolean {
    const computedHash = computePolicyHash(policy);
    return computedHash.toLowerCase() === expectedHash.toLowerCase();
}

/**
 * Complete maker discovery and verification workflow
 * @param ensName ENS name
 * @param provider Ethereum provider
 * @returns Verified maker data with policy
 */
export async function discoverAndVerifyMaker(
    ensName: string,
    provider: ethers.Provider
): Promise<{
    discovery: MakerDiscoveryData;
    policy: MakerPolicy;
    verified: boolean;
}> {
    console.log(`\n🔍 Discovering maker: ${ensName}`);

    // 1. Resolve ENS records
    console.log('1/3 Resolving ENS records...');
    const discovery = await resolveMakerDiscovery(ensName, provider);

    if (!discovery.endpoint) {
        throw new Error(`No rfq-endpoint found for ${ensName}`);
    }

    console.log(`   ✅ Endpoint: ${discovery.endpoint}`);
    console.log(`   ✅ Policy Hash: ${discovery.policyHash || 'not set'}`);

    // 2. Fetch policy from endpoint
    console.log('\n2/3 Fetching maker policy...');
    const policy = await fetchMakerPolicy(discovery.endpoint);

    console.log(`   ✅ Version: ${policy.version}`);
    console.log(`   ✅ Pools: ${policy.pools.length}`);
    console.log(`   ✅ Spread: ${policy.spread}`);

    // 3. Verify policy hash
    let verified = false;
    if (discovery.policyHash) {
        console.log('\n3/3 Verifying policy hash...');
        verified = verifyPolicyHash(policy, discovery.policyHash);

        if (verified) {
            console.log('   ✅ Policy hash verified!');
        } else {
            console.warn('   ⚠️  Policy hash mismatch!');
            console.warn('   The maker may have updated their policy without updating ENS.');
            console.warn('   Proceed with caution.');
        }
    } else {
        console.log('\n3/3 No policy hash set (skipping verification)');
        console.warn('   ⚠️  Policy cannot be verified. Proceed with caution.');
    }

    return { discovery, policy, verified };
}

/**
 * Find compatible pool in maker policy
 * @param policy Maker policy
 * @param tokenA Token A address
 * @param tokenB Token B address
 * @param fee Pool fee tier
 * @returns Pool config or null if not found
 */
export function findCompatiblePool(
    policy: MakerPolicy,
    tokenA: string,
    tokenB: string,
    fee: number
): PoolConfig | null {
    return policy.pools.find(pool =>
        (pool.tokenA.toLowerCase() === tokenA.toLowerCase() &&
         pool.tokenB.toLowerCase() === tokenB.toLowerCase() &&
         pool.fee === fee) ||
        (pool.tokenA.toLowerCase() === tokenB.toLowerCase() &&
         pool.tokenB.toLowerCase() === tokenA.toLowerCase() &&
         pool.fee === fee)
    ) || null;
}

/**
 * Validate quote amount against pool limits
 * @param pool Pool config
 * @param amount Amount in wei
 * @returns Validation result
 */
export function validateQuoteAmount(
    pool: PoolConfig,
    amount: bigint
): { valid: boolean; reason?: string } {
    const minAmount = BigInt(pool.minAmount);
    const maxAmount = BigInt(pool.maxAmount);

    if (amount < minAmount) {
        return {
            valid: false,
            reason: `Amount ${amount} below minimum ${minAmount}`
        };
    }

    if (amount > maxAmount) {
        return {
            valid: false,
            reason: `Amount ${amount} above maximum ${maxAmount}`
        };
    }

    return { valid: true };
}

/**
 * Parse slippage percentage string to basis points
 * @param slippageStr Slippage string (e.g., "0.5%")
 * @returns Slippage in basis points (e.g., 50 for 0.5%)
 */
export function parseSlippageToBps(slippageStr: string): number {
    const match = slippageStr.match(/^(\d+\.?\d*)%$/);
    if (!match) {
        throw new Error(`Invalid slippage format: ${slippageStr}`);
    }

    const percentage = parseFloat(match[1]);
    return Math.floor(percentage * 100);
}

/**
 * Calculate minimum output with slippage
 * @param quotedOut Quoted output amount
 * @param slippageBps Slippage in basis points
 * @returns Minimum output amount
 */
export function calculateMinOutput(
    quotedOut: bigint,
    slippageBps: number
): bigint {
    const slippageMultiplier = 10000n - BigInt(slippageBps);
    return (quotedOut * slippageMultiplier) / 10000n;
}
