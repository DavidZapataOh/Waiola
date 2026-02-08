/**
 * @file ens-setup.ts
 * @notice Maker ENS setup script - Configure ENS text records for RFQ discovery
 * @author Waiola Team
 *
 * This script allows makers to publish their RFQ endpoint and policy to ENS,
 * enabling permissionless maker discovery by takers.
 *
 * Usage:
 *   ts-node script/typescript/maker/ens-setup.ts
 *
 * Environment Variables:
 *   - RPC_URL: Ethereum RPC endpoint (e.g., Sepolia)
 *   - MAKER_PRIVATE_KEY: Maker's private key
 *   - MAKER_ENS_NAME: ENS name owned by maker (e.g., "alice.eth")
 */

import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
interface MakerConfig {
    ensName: string;
    endpoint: string;
    policyPath: string;
    pubkey?: string; // Optional: for encrypted quotes
}

interface MakerPolicy {
    version: string;
    pools: PoolConfig[];
    oracleValidation?: OracleConfig;
    spread: string;
    maxQuoteValidity: number; // seconds
}

interface PoolConfig {
    tokenA: string;
    tokenB: string;
    fee: number;
    maxSlippage: string; // e.g., "0.5%"
    maxAmount: string; // wei
    minAmount: string; // wei
}

interface OracleConfig {
    enabled: boolean;
    maxPriceDeviation: string; // e.g., "2%"
    oracleAddress?: string;
}

// Load .env file
const envPath = path.join(__dirname, '.env');

console.log(`Loading .env from: ${envPath}`);
if (fs.existsSync(envPath)) {
    const result = dotenv.config({ path: envPath });
    if (result.error) {
        console.error('Error loading .env:', result.error);
    } else {
        console.log('.env loaded successfully');
    }
} else {
    console.warn(`Warning: .env file not found at ${envPath}`);
}

/**
 * Load maker configuration from config file
 */
function loadConfig(): MakerConfig {
    const configPath = path.join(__dirname, 'maker-config.json');

    if (!fs.existsSync(configPath)) {
        console.error(`Config file not found: ${configPath}`);
        console.log('\nCreating template config file...');

        const templateConfig: MakerConfig = {
            ensName: 'alice.eth',
            endpoint: 'https://rfq.example.com/quote',
            policyPath: './maker-policy.json',
            pubkey: '0x...' // Optional
        };

        fs.writeFileSync(configPath, JSON.stringify(templateConfig, null, 2));
        console.log(`Template created at: ${configPath}`);
        console.log('Please edit the config and run again.');
        process.exit(0);
    }

    return JSON.parse(fs.readFileSync(configPath, 'utf-8'));
}

/**
 * Load maker policy from file
 */
function loadPolicy(policyPath: string): MakerPolicy {
    const fullPath = path.join(__dirname, policyPath);

    if (!fs.existsSync(fullPath)) {
        console.error(`Policy file not found: ${fullPath}`);
        console.log('\nCreating template policy file...');

        const templatePolicy: MakerPolicy = {
            version: '1.0',
            spread: '0.5%', // 0.5% spread
            maxQuoteValidity: 300, // 5 minutes
            pools: [
                {
                    tokenA: '0x0000000000000000000000000000000000000000', // ETH
                    tokenB: '0x1234567890123456789012345678901234567890', // USDC
                    fee: 3000, // 0.3%
                    maxSlippage: '0.5%',
                    maxAmount: ethers.parseEther('1000').toString(),
                    minAmount: ethers.parseEther('0.01').toString()
                }
            ],
            oracleValidation: {
                enabled: false, // Optional feature
                maxPriceDeviation: '2%'
            }
        };

        fs.writeFileSync(fullPath, JSON.stringify(templatePolicy, null, 2));
        console.log(`Template created at: ${fullPath}`);
        console.log('Please edit the policy and run again.');
        process.exit(0);
    }

    return JSON.parse(fs.readFileSync(fullPath, 'utf-8'));
}

/**
 * Compute policy hash (keccak256 of canonical JSON)
 */
function computePolicyHash(policy: MakerPolicy): string {
    // Canonical JSON stringify (sorted keys, no whitespace)
    const canonicalJson = JSON.stringify(policy, Object.keys(policy).sort());
    return ethers.keccak256(ethers.toUtf8Bytes(canonicalJson));
}

/**
 * Main ENS setup function
 */
async function setupENS() {
    console.log('=== Waiola Maker ENS Setup ===\n');

    // 1. Load configuration
    const config = loadConfig();
    const policy = loadPolicy(config.policyPath);

    console.log(`ENS Name: ${config.ensName}`);
    console.log(`Endpoint: ${config.endpoint}`);
    console.log(`Policy Version: ${policy.version}\n`);

    // 2. Initialize provider and signer
    const rpcUrl = process.env.RPC_URL;
    const privateKey = process.env.MAKER_PRIVATE_KEY;

    if (!rpcUrl || !privateKey) {
        console.error('Error: Missing environment variables');
        console.log('Required: RPC_URL, MAKER_PRIVATE_KEY');
        process.exit(1);
    }

    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const signer = new ethers.Wallet(privateKey, provider);

    console.log(`Maker Address: ${signer.address}`);
    console.log(`Network: ${(await provider.getNetwork()).name}\n`);

    // 3. Resolve ENS name to get resolver
    console.log(`Resolving ENS: ${config.ensName}...`);
    const resolver = await provider.getResolver(config.ensName);

    if (!resolver) {
        console.error(`Error: No resolver found for ${config.ensName}`);
        console.log('\nMake sure:');
        console.log('1. The ENS name is registered');
        console.log('2. A resolver is set for the name');
        console.log('3. You are connected to the correct network');
        process.exit(1);
    }

    console.log(`Resolver found: ${await resolver.getAddress()}\n`);

    // 4. Compute policy hash
    const policyHash = computePolicyHash(policy);
    console.log(`Policy Hash: ${policyHash}\n`);

    // 5. Set ENS text records
    console.log('Setting ENS text records...\n');

    // Get resolver contract for writing
    const resolverAddress = await resolver.getAddress();
    
    if (!resolverAddress) {
        console.error('Error: Could not get resolver address');
        process.exit(1);
    }
    
    const resolverAbi = [
        'function setText(bytes32 node, string calldata key, string calldata value) external'
    ];
    const resolverContract = new ethers.Contract(resolverAddress, resolverAbi, signer);
    const node = ethers.namehash(config.ensName);

    try {
        // 5a. Set rfq-endpoint
        console.log('1. Setting rfq-endpoint...');
        const tx1 = await resolverContract.setText(node, 'rfq-endpoint', config.endpoint);
        console.log(`   TX: ${tx1.hash}`);
        await tx1.wait();
        console.log('   ✅ Confirmed\n');

        // 5b. Set rfq-policy-hash
        console.log('2. Setting rfq-policy-hash...');
        const tx2 = await resolverContract.setText(node, 'rfq-policy-hash', policyHash);
        console.log(`   TX: ${tx2.hash}`);
        await tx2.wait();
        console.log('   ✅ Confirmed\n');

        // 5c. Set rfq-pubkey (optional)
        if (config.pubkey && config.pubkey !== '0x...') {
            console.log('3. Setting rfq-pubkey (optional)...');
            const tx3 = await resolverContract.setText(node, 'rfq-pubkey', config.pubkey);
            console.log(`   TX: ${tx3.hash}`);
            await tx3.wait();
            console.log('   ✅ Confirmed\n');
        } else {
            console.log('3. Skipping rfq-pubkey (not configured)\n');
        }

        // 6. Verify records
        console.log('Verifying ENS records...\n');

        const storedEndpoint = await resolver.getText('rfq-endpoint');
        const storedPolicyHash = await resolver.getText('rfq-policy-hash');
        const storedPubkey = await resolver.getText('rfq-pubkey');

        console.log(`✅ rfq-endpoint: ${storedEndpoint}`);
        console.log(`✅ rfq-policy-hash: ${storedPolicyHash}`);
        if (storedPubkey) {
            console.log(`✅ rfq-pubkey: ${storedPubkey}`);
        }

        // 7. Save summary
        const summary = {
            ensName: config.ensName,
            makerAddress: signer.address,
            endpoint: storedEndpoint,
            policyHash: storedPolicyHash,
            pubkey: storedPubkey || undefined,
            policy: policy,
            timestamp: new Date().toISOString()
        };

        const summaryPath = path.join(__dirname, 'ens-setup-summary.json');
        fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

        console.log(`\n✅ ENS setup complete!`);
        console.log(`\nSummary saved to: ${summaryPath}`);
        console.log('\nTakers can now discover you via ENS:');
        console.log(`  npm run taker:resolve -- ${config.ensName}`);

    } catch (error: any) {
        console.error('\n❌ Error setting ENS records:');
        console.error(error.message);

        if (error.code === 'INSUFFICIENT_FUNDS') {
            console.log('\nYou need ETH to pay for gas fees.');
        } else if (error.code === 'UNAUTHORIZED') {
            console.log('\nMake sure you own this ENS name and have permission to set text records.');
        }

        process.exit(1);
    }
}

/**
 * Validate policy before setup
 */
function validatePolicy(policy: MakerPolicy): boolean {
    // Check version
    if (!policy.version) {
        console.error('Error: Policy must have a version');
        return false;
    }

    // Check pools
    if (!policy.pools || policy.pools.length === 0) {
        console.error('Error: Policy must have at least one pool');
        return false;
    }

    // Check each pool
    for (const pool of policy.pools) {
        if (!ethers.isAddress(pool.tokenA)) {
            console.error(`Error: Invalid tokenA address: ${pool.tokenA}`);
            return false;
        }
        if (!ethers.isAddress(pool.tokenB)) {
            console.error(`Error: Invalid tokenB address: ${pool.tokenB}`);
            return false;
        }
        if (pool.fee < 0 || pool.fee > 1000000) {
            console.error(`Error: Invalid fee: ${pool.fee}`);
            return false;
        }
    }

    return true;
}

// Run setup
setupENS().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
});
