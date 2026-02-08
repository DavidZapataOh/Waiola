/**
 * Noir Proof Generation Script
 *
 * Generates ZK proofs for RFQ quote commitments.
 * Called by Foundry tests via FFI for integration testing.
 *
 * Usage:
 *   ts-node generate-proof.ts <commitment> <poolKeyHash> <taker> <amountIn> <minOut> <expiry> <quotedOut> <salt>
 *
 * Example:
 *   ts-node generate-proof.ts \
 *     0x1234... \
 *     0x5678... \
 *     0x742d35Cc6634C0532925a3b844Bc454e4438f44e \
 *     1000000000000000000 \
 *     950000000000000000 \
 *     1735689600 \
 *     980000000000000000 \
 *     0x9999...
 *
 * @author Waiola Team
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';

const execAsync = promisify(exec);

// Parse command line arguments
const args = process.argv.slice(2);

if (args.length !== 8) {
  console.error('Error: Invalid number of arguments');
  console.error('Usage: ts-node generate-proof.ts <commitment> <poolKeyHash> <taker> <amountIn> <minOut> <expiry> <quotedOut> <salt>');
  process.exit(1);
}

const [commitment, poolKeyHash, taker, amountIn, minOut, expiry, quotedOut, salt] = args;

/**
 * Validate inputs
 */
function validateInputs(): void {
  // Validate hex strings (commitment, poolKeyHash, taker, salt)
  const hexFields = [
    { name: 'commitment', value: commitment },
    { name: 'poolKeyHash', value: poolKeyHash },
    { name: 'taker', value: taker },
    { name: 'salt', value: salt }
  ];

  for (const field of hexFields) {
    if (!field.value.startsWith('0x')) {
      throw new Error(`${field.name} must start with 0x`);
    }
    if (!/^0x[0-9a-fA-F]+$/.test(field.value)) {
      throw new Error(`${field.name} must be a valid hex string`);
    }
  }

  // Validate numeric fields
  const numericFields = [
    { name: 'amountIn', value: amountIn },
    { name: 'minOut', value: minOut },
    { name: 'expiry', value: expiry },
    { name: 'quotedOut', value: quotedOut }
  ];

  for (const field of numericFields) {
    if (!/^\d+$/.test(field.value)) {
      throw new Error(`${field.name} must be a valid number`);
    }
  }
}

/**
 * Convert values to Noir-compatible format
 */
function formatForNoir(value: string): string {
  // If it's a hex string, convert to decimal
  if (value.startsWith('0x')) {
    return BigInt(value).toString();
  }
  // If it's already a decimal string, return as-is
  return value;
}

/**
 * Generate Prover.toml file
 */
async function generateProverToml(): Promise<string> {
  const circuitPath = path.join(__dirname, '../../../circuits/rfq_quote');
  const proverTomlPath = path.join(circuitPath, 'Prover.toml');

  const proverToml = `# Auto-generated Prover.toml for RFQ Quote Circuit
# Generated at: ${new Date().toISOString()}

commitment = "${formatForNoir(commitment)}"
pool_key_hash = "${formatForNoir(poolKeyHash)}"
taker = "${formatForNoir(taker)}"
amount_in = "${formatForNoir(amountIn)}"
min_out = "${formatForNoir(minOut)}"
expiry = "${formatForNoir(expiry)}"
quoted_out = "${formatForNoir(quotedOut)}"
salt = "${formatForNoir(salt)}"
`;

  await fs.writeFile(proverTomlPath, proverToml, 'utf-8');
  return circuitPath;
}

/**
 * Run nargo prove
 */
async function runNargoProve(circuitPath: string): Promise<void> {
  try {
    const { stdout, stderr } = await execAsync('nargo prove', {
      cwd: circuitPath,
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer
    });

    if (stderr && !stderr.includes('warning')) {
      console.error('Nargo stderr:', stderr);
    }
  } catch (error: any) {
    console.error('Nargo prove failed:', error.message);
    if (error.stdout) console.error('stdout:', error.stdout);
    if (error.stderr) console.error('stderr:', error.stderr);
    throw error;
  }
}

/**
 * Read proof file and output as hex
 */
async function readProof(circuitPath: string): Promise<string> {
  const proofPath = path.join(circuitPath, 'proofs', 'rfq_quote.proof');

  try {
    const proof = await fs.readFile(proofPath);
    return '0x' + proof.toString('hex');
  } catch (error: any) {
    throw new Error(`Failed to read proof file: ${error.message}`);
  }
}

/**
 * Main function
 */
async function main(): Promise<void> {
  try {
    // Validate inputs
    validateInputs();

    // Generate Prover.toml
    const circuitPath = await generateProverToml();

    // Run nargo prove
    await runNargoProve(circuitPath);

    // Read and output proof
    const proofHex = await readProof(circuitPath);

    // Output proof to stdout (for FFI capture)
    console.log(proofHex);
  } catch (error: any) {
    console.error('Error generating proof:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main().catch((error) => {
    console.error('Unhandled error:', error);
    process.exit(1);
  });
}

export { main as generateProof, validateInputs, formatForNoir };
