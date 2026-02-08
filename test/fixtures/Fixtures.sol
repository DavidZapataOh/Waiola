// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";

import {RFQSettlementHook} from "../../src/RFQSettlementHook.sol";
import {RFQRegistry} from "../../src/RFQRegistry.sol";
import {IRFQRegistry} from "../../src/interfaces/IRFQRegistry.sol";
import {HonkVerifier} from "../../src/verifiers/NoirVerifier.sol";
import {IVerifier} from "../../src/interfaces/IVerifier.sol";
import {Poseidon2} from "@poseidon/src/Poseidon2.sol";

/**
 * @title Fixtures
 * @notice Test fixtures and helper functions for RFQ Settlement Hook tests
 * @author Waiola Team
 */
contract Fixtures is Test {
    /*//////////////////////////////////////////////////////////////
                              DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deploy PoolManager
     * @return poolManager Deployed PoolManager instance
     */
    function deployPoolManager() internal returns (IPoolManager) {
        return IPoolManager(address(new PoolManager(address(this))));
    }

    /**
     * @notice Deploy RFQRegistry
     * @param owner Owner address
     * @return registry Deployed RFQRegistry instance
     */
    function deployRegistry(address owner) internal returns (RFQRegistry) {
        return new RFQRegistry(owner);
    }

    /**
     * @notice Deploy NoirVerifier
     * @return verifier Deployed NoirVerifier instance
     */
    function deployVerifier() internal returns (HonkVerifier) {
        return new HonkVerifier();
    }

    /**
     * @notice Deploy Poseidon2 hasher
     * @return hasher Deployed Poseidon2 instance
     */
    function deployHasher() internal returns (Poseidon2) {
        return new Poseidon2();
    }

    /**
     * @notice Deploy RFQSettlementHook
     * @param poolManager PoolManager address
     * @param registry RFQRegistry address
     * @param verifier Verifier address
     * @param hasher Poseidon2 hasher address
     * @return hook Deployed RFQSettlementHook instance
     */
    function deployHook(
        IPoolManager poolManager,
        RFQRegistry registry,
        IVerifier verifier,
        Poseidon2 hasher
    ) internal returns (RFQSettlementHook) {
        return
            new RFQSettlementHook(
                poolManager,
                IRFQRegistry(address(registry)),
                verifier,
                hasher
            );
    }

    /**
     * @notice Deploy all contracts and wire them together
     * @param owner Owner address for registry
     * @return poolManager Deployed PoolManager
     * @return registry Deployed RFQRegistry
     * @return verifier Deployed NoirVerifier
     * @return hook Deployed RFQSettlementHook
     */
    function deployAll(
        address owner
    )
        internal
        returns (
            IPoolManager poolManager,
            RFQRegistry registry,
            HonkVerifier verifier,
            RFQSettlementHook hook
        )
    {
        poolManager = deployPoolManager();
        registry = deployRegistry(owner);
        verifier = deployVerifier();
        Poseidon2 hasher = deployHasher();
        hook = deployHook(
            poolManager,
            registry,
            IVerifier(address(verifier)),
            hasher
        );

        // Wire registry to hook
        registry.setHook(address(hook));

        return (poolManager, registry, verifier, hook);
    }

    /*//////////////////////////////////////////////////////////////
                          POOL CREATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a standard test pool key
     * @param hook Hook address
     * @return poolKey PoolKey struct
     */
    function createPoolKey(
        address hook
    ) internal pure returns (PoolKey memory) {
        return
            PoolKey({
                currency0: Currency.wrap(address(0x1000)),
                currency1: Currency.wrap(address(0x2000)),
                fee: 3000,
                tickSpacing: 60,
                hooks: IHooks(hook)
            });
    }

    /**
     * @notice Create a custom pool key
     * @param currency0 Currency0 address
     * @param currency1 Currency1 address
     * @param fee Fee tier
     * @param tickSpacing Tick spacing
     * @param hook Hook address
     * @return poolKey PoolKey struct
     */
    function createPoolKey(
        address currency0,
        address currency1,
        uint24 fee,
        int24 tickSpacing,
        address hook
    ) internal pure returns (PoolKey memory) {
        return
            PoolKey({
                currency0: Currency.wrap(currency0),
                currency1: Currency.wrap(currency1),
                fee: fee,
                tickSpacing: tickSpacing,
                hooks: IHooks(hook)
            });
    }

    /*//////////////////////////////////////////////////////////////
                          TEST ACCOUNTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create test accounts with private keys
     * @return maker Maker address
     * @return taker Taker address
     * @return makerPrivateKey Maker's private key
     * @return takerPrivateKey Taker's private key
     */
    function createTestAccounts()
        internal
        pure
        returns (
            address maker,
            address taker,
            uint256 makerPrivateKey,
            uint256 takerPrivateKey
        )
    {
        makerPrivateKey = 0x1111;
        takerPrivateKey = 0x2222;
        maker = vm.addr(makerPrivateKey);
        taker = vm.addr(takerPrivateKey);

        return (maker, taker, makerPrivateKey, takerPrivateKey);
    }
}
