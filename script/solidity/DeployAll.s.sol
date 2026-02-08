// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Script, console2} from "forge-std/Script.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

import {RFQSettlementHook} from "../../src/RFQSettlementHook.sol";
import {RFQRegistry} from "../../src/RFQRegistry.sol";
import {IRFQRegistry} from "../../src/interfaces/IRFQRegistry.sol";
import {IVerifier} from "../../src/interfaces/IVerifier.sol";
import {HonkVerifier} from "../../src/verifiers/NoirVerifier.sol";
import {Poseidon2} from "@poseidon/src/Poseidon2.sol";

/**
 * @title DeployAll
 * @notice Deploys the complete Waiola RFQ system to a target network
 * @dev Deploys: Registry, Verifier, Hasher, Hook (with CREATE2 address mining)
 *
 * Usage:
 *   forge script script/solidity/DeployAll.s.sol \
 *     --rpc-url $RPC_URL \
 *     --broadcast \
 *     --verify \
 *     -vvv
 *
 * Required env vars:
 *   DEPLOYER_PRIVATE_KEY - Private key for deployer
 *   POOL_MANAGER         - PoolManager address on target chain
 *
 * @author Waiola Team
 */
contract DeployAll is Script {
    /// @dev Deterministic CREATE2 deployer proxy (standard across all EVM chains)
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address poolManagerAddr = vm.envAddress("POOL_MANAGER");
        address deployer = vm.addr(deployerPrivateKey);

        console2.log("========================================");
        console2.log("  Waiola RFQ - Full Deployment");
        console2.log("========================================");
        console2.log("Chain ID:      ", block.chainid);
        console2.log("Deployer:      ", deployer);
        console2.log("PoolManager:   ", poolManagerAddr);
        console2.log("========================================\n");

        vm.startBroadcast(deployerPrivateKey);

        // Step 1: Deploy RFQRegistry
        RFQRegistry registry = new RFQRegistry(deployer);
        console2.log("[1/5] Registry deployed:  ", address(registry));

        // Step 2: Deploy HonkVerifier (Noir ZK verifier)
        HonkVerifier verifier = new HonkVerifier();
        console2.log("[2/5] Verifier deployed:  ", address(verifier));

        // Step 3: Deploy Poseidon2 hasher
        Poseidon2 hasher = new Poseidon2();
        console2.log("[3/5] Hasher deployed:    ", address(hasher));

        // Step 4: Mine hook address and deploy with CREATE2
        // Extracted to separate function to avoid stack-too-deep
        address hookAddr = _deployHook(
            IPoolManager(poolManagerAddr),
            registry,
            IVerifier(address(verifier)),
            hasher
        );

        // Step 5: Wire registry to hook
        registry.setHook(hookAddr);
        console2.log("[5/5] Registry hook set:  ", hookAddr);

        vm.stopBroadcast();

        // Print summary + save JSON
        _logSummary(address(registry), address(verifier), address(hasher), hookAddr, poolManagerAddr);
        _saveDeployment(deployer, address(registry), address(verifier), address(hasher), hookAddr, poolManagerAddr);
    }

    /**
     * @dev Mine a CREATE2 salt and deploy the hook at a valid flag address.
     *      Isolated to its own function so temporary variables (flags, salt,
     *      constructorArgs) don't bloat run()'s stack frame.
     */
    function _deployHook(
        IPoolManager poolManager,
        RFQRegistry registry,
        IVerifier verifier,
        Poseidon2 hasher
    ) internal returns (address) {
        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG);

        bytes memory constructorArgs = abi.encode(
            poolManager,
            IRFQRegistry(address(registry)),
            verifier,
            hasher
        );

        console2.log("\n[4/5] Mining hook address (BEFORE_SWAP_FLAG)...");

        (address hookAddress, bytes32 salt) = HookMiner.find(
            CREATE2_DEPLOYER,
            flags,
            type(RFQSettlementHook).creationCode,
            constructorArgs
        );

        console2.log("       Target address:    ", hookAddress);

        RFQSettlementHook hook = new RFQSettlementHook{salt: salt}(
            poolManager,
            IRFQRegistry(address(registry)),
            verifier,
            hasher
        );

        require(address(hook) == hookAddress, "DeployAll: hook address mismatch");
        console2.log("       Hook deployed:     ", address(hook));

        return address(hook);
    }

    /**
     * @dev Print deployment summary to console
     */
    function _logSummary(
        address registry,
        address verifierAddr,
        address hasherAddr,
        address hookAddr,
        address poolManagerAddr
    ) internal pure {
        console2.log("\n========================================");
        console2.log("  DEPLOYMENT COMPLETE");
        console2.log("========================================");
        console2.log("Registry:      ", registry);
        console2.log("Verifier:      ", verifierAddr);
        console2.log("Hasher:        ", hasherAddr);
        console2.log("Hook:          ", hookAddr);
        console2.log("PoolManager:   ", poolManagerAddr);
        console2.log("========================================\n");
    }

    /**
     * @dev Save deployment addresses to deployments/{chainId}.json
     */
    function _saveDeployment(
        address deployer,
        address registry,
        address verifierAddr,
        address hasherAddr,
        address hookAddr,
        address poolManagerAddr
    ) internal {
        string memory obj = "deployment";
        vm.serializeUint(obj, "chainId", block.chainid);
        vm.serializeAddress(obj, "deployer", deployer);
        vm.serializeAddress(obj, "registry", registry);
        vm.serializeAddress(obj, "verifier", verifierAddr);
        vm.serializeAddress(obj, "hasher", hasherAddr);
        vm.serializeAddress(obj, "hook", hookAddr);
        string memory json = vm.serializeAddress(obj, "poolManager", poolManagerAddr);

        string memory path = string.concat(
            "deployments/",
            vm.toString(block.chainid),
            ".json"
        );
        vm.writeJson(json, path);
        console2.log("Addresses saved to:      ", path);
    }
}
