/**
 * @file generate-proof.ts
 * @notice Generate Noir ZK proof for RFQ quote
 * @author Waiola Team
 *
 * This script:
 * 1. Reads the quote from quote.json
 * 2. Writes Prover.toml with public and private inputs
 * 3. Runs nargo prove to generate the proof
 * 4. Reads the generated proof
 * 5. Updates quote.json with the proof
 *
 * NOTE: This requires the Noir circuit to be compiled first.
 *       Run: cd circuits/rfq-quote && nargo compile
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { computeCommitment } from '../utils/eip712.js';

const execAsync = promisify(exec);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/*******************************************************************************
 *                              CONFIGURATION                                  *
 *******************************************************************************/

const CIRCUIT_DIR = path.join(process.cwd(), 'circuits', 'rfq-quote');
const QUOTE_PATH = path.join(__dirname, 'quote.json');

/*******************************************************************************
 *                          PROOF GENERATION                                   *
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
    minOut: string;
    [key: string]: any;
}

/**
 * Load quote from JSON file
 */
async function loadQuote(): Promise<QuoteData> {
    try {
        const quoteContent = await fs.readFile(QUOTE_PATH, 'utf-8');
        return JSON.parse(quoteContent);
    } catch (error: any) {
        throw new Error(`Failed to load quote: ${error.message}`);
    }
}

/**
 * Compute commitment hash (matches Solidity QuoteCommitment.computeCommitment)
 * NOTE: In production, this should use Poseidon hash matching the Noir circuit
 */
function computeQuoteCommitment(quote: QuoteData['quote']): string {
    // For MVP, we use keccak256
    // TODO: Replace with Poseidon hash when Noir circuit is ready
    const packed = ethers.solidityPacked(
        ['bytes32', 'address', 'uint256', 'uint256', 'uint256', 'bytes32'],
        [
            quote.poolKeyHash,
            quote.taker,
            quote.amountIn,
            quote.quotedOut,
            quote.expiry,
            quote.salt
        ]
    );

    return ethers.keccak256(packed);
}

/**
 * Write Prover.toml for Noir circuit
 */
async function writeProverToml(quoteData: QuoteData, commitment: string): Promise<void> {
    const proverToml = `# Public inputs (visible onchain)
commitment = "${commitment}"
pool_key_hash = "${quoteData.quote.poolKeyHash}"
taker = "${BigInt(quoteData.quote.taker).toString()}"
amount_in = "${quoteData.quote.amountIn}"
min_out = "${quoteData.minOut}"
expiry = "${quoteData.quote.expiry}"

# Private inputs (only in ZK proof)
quoted_out = "${quoteData.quote.quotedOut}"
salt = "${BigInt(quoteData.quote.salt).toString()}"
`;

    const proverTomlPath = path.join(CIRCUIT_DIR, 'Prover.toml');
    await fs.writeFile(proverTomlPath, proverToml);
    console.log(`   ✅ Prover.toml written to ${proverTomlPath}`);
}

/**
 * Generate ZK proof using Noir
 */
async function generateNoirProof(): Promise<Buffer> {
    console.log(`\n   Generating proof (this may take 30-60 seconds)...`);

    try {
        // Run nargo prove
        const { stdout, stderr } = await execAsync(
            `cd "${CIRCUIT_DIR}" && nargo prove`,
            { maxBuffer: 10 * 1024 * 1024 } // 10MB buffer
        );

        if (stderr && !stderr.includes('Proving')) {
            console.warn(`   Warning: ${stderr}`);
        }

        console.log(`   ✅ Proof generated successfully`);

        // Read proof file
        const proofPath = path.join(CIRCUIT_DIR, 'proofs', 'rfq-quote.proof');
        const proof = await fs.readFile(proofPath);

        return proof;

    } catch (error: any) {
        // If nargo is not installed or circuit not compiled, generate mock proof
        if (error.message.includes('nargo') || error.message.includes('ENOENT')) {
            console.warn(`\n   ⚠️  Nargo not found or circuit not compiled`);
            console.warn(`   Generating MOCK proof for testing purposes`);
            console.warn(`   To generate real proofs:`);
            console.warn(`     1. Install Noir: https://noir-lang.org/docs/getting_started/installation/`);
            console.warn(`     2. Compile circuit: cd circuits/rfq-quote && nargo compile`);
            console.warn(`     3. Run this script again\n`);

            // Generate a deterministic mock proof (64 bytes)
            const mockProof = Buffer.alloc(64);
            mockProof.fill(0xab);
            return mockProof;
        }

        throw error;
    }
}

/**
 * Generate public inputs array for verifier
 */
function generatePublicInputs(quoteData: QuoteData, commitment: string): string[] {
    return [
        commitment,                                          // [0] commitment
        quoteData.quote.poolKeyHash,                        // [1] poolKeyHash
        ethers.zeroPadValue(quoteData.quote.taker, 32),     // [2] taker (as bytes32)
        ethers.zeroPadValue(ethers.toBeHex(quoteData.quote.amountIn), 32),  // [3] amountIn
        ethers.zeroPadValue(ethers.toBeHex(quoteData.minOut), 32),          // [4] minOut
        ethers.zeroPadValue(ethers.toBeHex(quoteData.quote.expiry), 32)     // [5] expiry
    ];
}

/**
 * Main proof generation flow
 */
async function generateProof() {
    console.log(`\n🔐 Generating ZK Proof for Quote...\n`);

    try {
        // 1. Load quote
        console.log('Step 1/5: Loading quote...');
        const quoteData = await loadQuote();
        console.log(`   ✅ Quote loaded`);
        console.log(`      Quoted Out: ${ethers.formatEther(quoteData.quote.quotedOut)} ETH`);
        console.log(`      Min Out: ${ethers.formatEther(quoteData.minOut)} ETH`);

        // 2. Compute commitment
        console.log('\nStep 2/5: Computing commitment...');
        const commitment = computeQuoteCommitment(quoteData.quote);
        console.log(`   ✅ Commitment: ${commitment}`);

        // 3. Write Prover.toml
        console.log('\nStep 3/5: Writing Prover.toml...');
        await writeProverToml(quoteData, commitment);

        // 4. Generate proof
        console.log('\nStep 4/5: Generating ZK proof...');
        const proofBuffer = await generateNoirProof();
        const proofHex = '0x' + proofBuffer.toString('hex');
        console.log(`   Proof size: ${proofBuffer.length} bytes`);

        // 5. Generate public inputs
        console.log('\nStep 5/5: Generating public inputs...');
        const publicInputs = generatePublicInputs(quoteData, commitment);
        console.log(`   ✅ ${publicInputs.length} public inputs generated`);

        // 6. Update quote.json with proof
        const updatedQuote = {
            ...quoteData,
            commitment,
            proof: proofHex,
            publicInputs,
            proofGeneratedAt: new Date().toISOString()
        };

        await fs.writeFile(QUOTE_PATH, JSON.stringify(updatedQuote, null, 2));

        console.log(`\n✅ Proof generated and saved to quote.json`);
        console.log(`\nNext step:`);
        console.log(`   Execute swap: npm run taker:swap`);

        return updatedQuote;

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

// Check if quote file exists
try {
    await fs.access(QUOTE_PATH);
} catch {
    console.error(`\n❌ Error: quote.json not found at ${QUOTE_PATH}`);
    console.error(`\nPlease run quote request first:`);
    console.error(`   npm run taker:request -- <args>`);
    process.exit(1);
}

// Run proof generation
generateProof().catch(console.error);
