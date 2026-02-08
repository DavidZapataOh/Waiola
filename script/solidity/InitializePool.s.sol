// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script, console2} from "forge-std/Script.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";

/**
 * @title InitializePool
 * @notice Initializes a Uniswap v4 pool with the Waiola RFQ hook attached
 * @dev Run after DeployAll.s.sol has been executed on the target network
 *
 * Usage:
 *   forge script script/solidity/InitializePool.s.sol \
 *     --rpc-url $RPC_URL \
 *     --broadcast \
 *     -vvv
 *
 * Required env vars:
 *   DEPLOYER_PRIVATE_KEY - Private key for deployer
 *   POOL_MANAGER         - PoolManager address on target chain
 *   HOOK_ADDRESS         - Deployed RFQSettlementHook address
 *   TOKEN0               - Currency0 address (lower address)
 *   TOKEN1               - Currency1 address (higher address)
 *
 * Optional env vars:
 *   POOL_FEE             - Fee tier in hundredths of bip (default: 3000 = 0.30%)
 *   TICK_SPACING         - Tick spacing (default: 60)
 *
 * @author Waiola Team
 */
contract InitializePool is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address poolManagerAddr = vm.envAddress("POOL_MANAGER");
        address hookAddr = vm.envAddress("HOOK_ADDRESS");
        address token0 = vm.envAddress("TOKEN0");
        address token1 = vm.envAddress("TOKEN1");

        // Optional params with defaults
        uint24 fee = uint24(vm.envOr("POOL_FEE", uint256(3000)));
        int24 tickSpacing = int24(int256(vm.envOr("TICK_SPACING", uint256(60))));

        // Ensure currency0 < currency1
        require(token0 < token1, "InitializePool: token0 must be < token1");

        IPoolManager poolManager = IPoolManager(poolManagerAddr);

        PoolKey memory poolKey = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: fee,
            tickSpacing: tickSpacing,
            hooks: IHooks(hookAddr)
        });

        // Start at 1:1 price (sqrtPriceX96 for tick 0)
        uint160 startingPrice = TickMath.getSqrtPriceAtTick(0);

        console2.log("========================================");
        console2.log("  Waiola RFQ - Pool Initialization");
        console2.log("========================================");
        console2.log("Chain ID:       ", block.chainid);
        console2.log("PoolManager:    ", poolManagerAddr);
        console2.log("Hook:           ", hookAddr);
        console2.log("Token0:         ", token0);
        console2.log("Token1:         ", token1);
        console2.log("Fee:            ", uint256(fee));
        console2.log("Tick Spacing:   ", uint256(int256(tickSpacing)));
        console2.log("Starting Price: ", uint256(startingPrice));
        console2.log("========================================\n");

        vm.startBroadcast(deployerPrivateKey);

        poolManager.initialize(poolKey, startingPrice);

        vm.stopBroadcast();

        bytes32 poolKeyHash = keccak256(abi.encode(poolKey));

        console2.log("[OK] Pool initialized!");
        console2.log("Pool Key Hash: ", vm.toString(poolKeyHash));
    }
}
