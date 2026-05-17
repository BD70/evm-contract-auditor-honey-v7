"""
Pre-bundled database of well-known EVM function and event selectors.

These are included for offline use — no API calls needed for common functions.
Covers ERC-20, ERC-721, ERC-1155, ERC-165, common OpenZeppelin, and DeFi patterns.
"""

from __future__ import annotations

# Function selector → text signature
# Format: hex selector (without 0x) → human-readable signature
KNOWN_FUNCTIONS: dict[str, str] = {
    # ── ERC-20 ────────────────────────────────────────────
    "18160ddd": "totalSupply()",
    "70a08231": "balanceOf(address)",
    "a9059cbb": "transfer(address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "dd62ed3e": "allowance(address,address)",
    "06fdde03": "name()",
    "95d89b41": "symbol()",
    "313ce567": "decimals()",

    # ── ERC-721 ───────────────────────────────────────────
    "6352211e": "ownerOf(uint256)",
    "b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
    "42842e0e": "safeTransferFrom(address,address,uint256)",
    "081812fc": "getApproved(uint256)",
    "a22cb465": "setApprovalForAll(address,bool)",
    "e985e9c5": "isApprovedForAll(address,address)",
    "c87b56dd": "tokenURI(uint256)",

    # ── ERC-1155 ──────────────────────────────────────────
    "00fdd58e": "balanceOf(address,uint256)",
    "4e1273f4": "balanceOfBatch(address[],uint256[])",
    "f242432a": "safeTransferFrom(address,address,uint256,uint256,bytes)",
    "2eb2c2d6": "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    "0e89341c": "uri(uint256)",

    # ── ERC-165 ───────────────────────────────────────────
    "01ffc9a7": "supportsInterface(bytes4)",

    # ── Ownable / Access Control ──────────────────────────
    "8da5cb5b": "owner()",
    "715018a6": "renounceOwnership()",
    "f2fde38b": "transferOwnership(address)",
    "79ba5097": "acceptOwnership()",

    # ── Pausable ──────────────────────────────────────────
    "8456cb59": "pause()",
    "3f4ba83a": "unpause()",
    "5c975abb": "paused()",

    # ── Proxy / Upgradeable ───────────────────────────────
    "3659cfe6": "upgradeTo(address)",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "5c60da1b": "implementation()",
    "f851a440": "admin()",
    "8f283970": "changeAdmin(address)",
    "3659cfe6": "upgradeTo(address)",

    # ── ERC-2612 Permit ───────────────────────────────────
    "d505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "3644e515": "DOMAIN_SEPARATOR()",
    "7ecebe00": "nonces(address)",
    "30adf81f": "PERMIT_TYPEHASH()",

    # ── Common DeFi ───────────────────────────────────────
    "d0e30db0": "deposit()",
    "2e1a7d4d": "withdraw(uint256)",
    "38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "8803dbee": "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
    "7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
    "18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    "e8e33700": "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    "f305d719": "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
    "baa2abde": "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
    "02751cec": "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
    "022c0d9f": "swap(uint256,uint256,address,bytes)",
    "0902f1ac": "getReserves()",
    "c45a0155": "factory()",
    "0dfe1681": "token0()",
    "d21220a7": "token1()",
    "5909c0d5": "price0CumulativeLast()",
    "5a3d5493": "price1CumulativeLast()",
    "7464fc3d": "kLast()",
    "ba9a7a56": "MINIMUM_LIQUIDITY()",
    "485cc955": "initialize(address,address)",
    "6a627842": "mint(address)",
    "89afcb44": "burn(address)",
    "bc25cf77": "skim(address)",
    "fff6cae9": "sync()",
    "ad5c4648": "WETH()",
    "1698ee82": "getPool(address,address,uint24)",
    "128acb08": "swap(address,bool,int256,uint160,bytes)",
    "a0712d68": "mint(uint256)",
    "40c10f19": "mint(address,uint256)",
    "42966c68": "burn(uint256)",
    "9dc29fac": "burn(address,uint256)",

    # ── Multicall ─────────────────────────────────────────
    "ac9650d8": "multicall(bytes[])",
    "5ae401dc": "multicall(uint256,bytes[])",

    # ── Misc Common ───────────────────────────────────────
    "8129fc1c": "initialize()",
    "c4d66de8": "initialize(address)",
    "fe4b84df": "initialize(uint256)",
    "150b7a02": "onERC721Received(address,address,uint256,bytes)",
    "f23a6e61": "onERC1155Received(address,address,uint256,uint256,bytes)",
    "bc197c81": "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)",

    # ── TetherToken / USDT specific ──────────────────────
    "0e136b19": "deprecated()",
    "26976e3f": "upgradedAddress()",
    "27e235e3": "balances(address)",
    "35390714": "maximumFee()",
    "3eaaf86b": "_totalSupply()",
    "5c658165": "allowed(address,address)",
    "dd644f72": "basisPointsRate()",
    "e47d6060": "isBlackListed(address)",
    "e5b5019a": "MAX_UINT()",

    # ── Blacklist ─────────────────────────────────────────
    "0ecb93c0": "addBlackList(address)",
    "e4997dc5": "removeBlackList(address)",
    "f3bdc228": "destroyBlackFunds(address)",
    "59bf1abe": "getBlackListStatus(address)",
    "893d20e8": "getOwner()",

    # ── Token Supply ─────────────────────────────────────
    "cc872b66": "issue(uint256)",
    "db006a75": "redeem(uint256)",
    "0753c30c": "deprecate(address)",
    "c0324c77": "setParams(uint256,uint256)",
}

# Event selectors (first 32 bytes of keccak256) → text signature
KNOWN_EVENTS: dict[str, str] = {
    # ERC-20
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": "Transfer(address,address,uint256)",
    "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": "Approval(address,address,uint256)",

    # ERC-721
    "17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31": "ApprovalForAll(address,address,bool)",

    # Ownable
    "8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0": "OwnershipTransferred(address,address)",

    # Proxy
    "bc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b": "Upgraded(address)",
    "7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f": "AdminChanged(address,address)",

    # Pausable
    "62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258": "Paused(address)",
    "5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa": "Unpaused(address)",
}


# ── ERC Standard Detection ─────────────────────────────────────

# Required selectors for each standard
ERC_STANDARDS: dict[str, dict] = {
    "ERC-20": {
        "required": ["18160ddd", "70a08231", "a9059cbb", "095ea7b3", "23b872dd", "dd62ed3e"],
        "optional": ["06fdde03", "95d89b41", "313ce567"],
        "description": "Fungible Token Standard",
    },
    "ERC-721": {
        # STRICT: requires NFT-specific selectors that ERC-20 does NOT share.
        # ownerOf(uint256) + safeTransferFrom + getApproved are unique to 721.
        # Shared selectors like balanceOf, approve, transferFrom do NOT count.
        "required": ["6352211e", "42842e0e", "b88d4fde", "081812fc", "a22cb465", "e985e9c5"],
        "optional": ["c87b56dd", "01ffc9a7"],
        "description": "Non-Fungible Token Standard",
        "strict_note": "Requires ownerOf + safeTransferFrom + getApproved (NFT-unique selectors)",
    },
    "ERC-1155": {
        "required": ["00fdd58e", "4e1273f4", "f242432a", "2eb2c2d6", "a22cb465", "e985e9c5"],
        "optional": ["0e89341c", "01ffc9a7"],
        "description": "Multi Token Standard",
    },
    "ERC-165": {
        "required": ["01ffc9a7"],
        "optional": [],
        "description": "Standard Interface Detection",
    },
}


def lookup_selector(selector_hex: str) -> list[str]:
    """
    Look up a function selector in the local database.

    Args:
        selector_hex: 4-byte selector, e.g. "a9059cbb" or "0xa9059cbb"

    Returns:
        List of matching text signatures (usually 1, but could be 0).
    """
    normalized = selector_hex.lower().replace("0x", "")
    if normalized in KNOWN_FUNCTIONS:
        return [KNOWN_FUNCTIONS[normalized]]
    return []


def lookup_event(topic_hex: str) -> list[str]:
    """Look up an event by its 32-byte topic hash."""
    normalized = topic_hex.lower().replace("0x", "")
    if normalized in KNOWN_EVENTS:
        return [KNOWN_EVENTS[normalized]]
    return []


def detect_standards(selector_set: set[str]) -> list[dict]:
    """
    Detect ERC standards from a set of function selectors.

    Args:
        selector_set: Set of hex selectors (without 0x prefix, lowercase)

    Returns:
        List of detected standards with confidence info.
    """
    results = []
    normalized = {s.lower().replace("0x", "") for s in selector_set}

    for standard, info in ERC_STANDARDS.items():
        required = set(info["required"])
        optional = set(info["optional"])

        matched_required = required & normalized
        matched_optional = optional & normalized

        if len(matched_required) == len(required):
            confidence = "full_match"
        elif len(matched_required) >= len(required) * 0.7:
            confidence = "likely"
        elif len(matched_required) >= len(required) * 0.5:
            confidence = "possible"
        else:
            continue

        results.append({
            "standard": standard,
            "description": info["description"],
            "confidence": confidence,
            "matched_required": len(matched_required),
            "total_required": len(required),
            "matched_optional": len(matched_optional),
            "missing": list(required - matched_required),
        })

    return results
