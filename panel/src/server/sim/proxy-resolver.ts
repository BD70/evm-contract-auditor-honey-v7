// Detects whether a contract is a proxy and looks up its implementation
// address by reading the well-known storage slots used by every mainstream
// proxy pattern. We only do simple eth_getStorageAt reads — no tracing — so
// this is cheap (one round trip per slot per address) and works on any chain.
//
// When a contract is a proxy we still simulate against the proxy address
// (msg.sender, storage, value all live there), but we use the impl's
// bytecode to enumerate candidate selectors with evm-decon. This is the
// dominant unlock for "no candidate exploitable selectors" inconclusive
// verdicts — the proxy itself has only a fallback in its runtime.

import { rpcRequest } from "./anvil-pool";

// Well-known proxy storage slots (all from the relevant EIPs).
//
// ERC-1967 impl slot (UUPS / transparent proxies):
//   bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
const ERC1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
// ERC-1967 admin slot:
//   bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)
const ERC1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
// ERC-1967 beacon slot:
//   bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)
const ERC1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
// OpenZeppelin legacy "unstructured storage" impl slot:
//   keccak256("org.zeppelinos.proxy.implementation")
const OZ_LEGACY_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";
// EIP-1822 (UUPS original) PROXIABLE slot:
//   keccak256("PROXIABLE")
const EIP1822_IMPL_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7";

const KNOWN_IMPL_SLOTS: { slot: string; family: string }[] = [
  { slot: ERC1967_IMPL_SLOT, family: "erc1967" },
  { slot: OZ_LEGACY_IMPL_SLOT, family: "oz-legacy" },
  { slot: EIP1822_IMPL_SLOT, family: "eip1822" },
];

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO32_HEX = "0x" + "0".repeat(64);

export interface ProxyInfo {
  isProxy: boolean;
  impl: string | null;
  admin: string | null;
  beacon: string | null;
  family: string | null; // e.g. "erc1967", "oz-legacy", "eip1822", "beacon"
}

/**
 * Heuristic: a runtime bytecode is "very likely a proxy" when it's small and
 * contains DELEGATECALL (0xf4). evm-decon also reports `globalTags`
 * including "delegatecall"; if you've already got a DeconResult, prefer the
 * `looksLikeProxy` helper below.
 */
export function bytecodeLooksLikeProxy(bytecodeHex: string): boolean {
  const clean = bytecodeHex.replace(/^0x/, "").toLowerCase();
  // Proxies are tiny: ~30-200 bytes. Anything bigger likely has real logic.
  if (clean.length > 2000) return false;
  // DELEGATECALL opcode = 0xf4. Without it the contract can't proxy.
  return clean.includes("f4");
}

export function looksLikeProxy(opts: { bytecodeHex: string; deconFamily?: string | null; globalTags?: string[] }): boolean {
  if (opts.deconFamily === "proxy" || opts.deconFamily === "minimal-proxy") return true;
  const tags = opts.globalTags ?? [];
  if (tags.includes("delegatecall") || tags.includes("proxy")) return true;
  return bytecodeLooksLikeProxy(opts.bytecodeHex);
}

function slotToAddress(slotHex: string | null | undefined): string | null {
  if (!slotHex || slotHex === "0x" || slotHex === ZERO32_HEX) return null;
  const clean = slotHex.replace(/^0x/, "").padStart(64, "0");
  if (clean === "0".repeat(64)) return null;
  const addr = "0x" + clean.slice(24).toLowerCase();
  if (addr === ZERO_ADDRESS) return null;
  return addr;
}

/**
 * Try every known proxy slot. Returns the first non-zero implementation
 * address found. Beacon proxies are resolved one extra hop: when the beacon
 * slot is set we call `implementation()` on the beacon to get the runtime
 * implementation.
 */
export async function resolveProxy(opts: {
  rpcUrl: string;
  address: string;
}): Promise<ProxyInfo> {
  const info: ProxyInfo = { isProxy: false, impl: null, admin: null, beacon: null, family: null };
  for (const { slot, family } of KNOWN_IMPL_SLOTS) {
    let raw: string | null = null;
    try {
      raw = await rpcRequest<string>(opts.rpcUrl, "eth_getStorageAt", [opts.address, slot, "latest"]);
    } catch {
      continue;
    }
    const impl = slotToAddress(raw);
    if (impl) {
      info.isProxy = true;
      info.impl = impl;
      info.family = family;
      break;
    }
  }
  // Beacon fallback (set the impl by calling the beacon).
  if (!info.impl) {
    try {
      const beaconRaw = await rpcRequest<string>(opts.rpcUrl, "eth_getStorageAt", [
        opts.address,
        ERC1967_BEACON_SLOT,
        "latest",
      ]);
      const beacon = slotToAddress(beaconRaw);
      if (beacon) {
        info.isProxy = true;
        info.beacon = beacon;
        info.family = "beacon";
        // beacon.implementation() selector = 0x5c60da1b
        try {
          const ret = await rpcRequest<string>(opts.rpcUrl, "eth_call", [
            { to: beacon, data: "0x5c60da1b" },
            "latest",
          ]);
          info.impl = slotToAddress(ret);
        } catch {
          // beacon may not expose implementation(); leave impl null.
        }
      }
    } catch {
      /* ignore */
    }
  }
  // Admin slot (informational).
  try {
    const adminRaw = await rpcRequest<string>(opts.rpcUrl, "eth_getStorageAt", [
      opts.address,
      ERC1967_ADMIN_SLOT,
      "latest",
    ]);
    info.admin = slotToAddress(adminRaw);
  } catch {
    /* ignore */
  }
  return info;
}

export const PROXY_SLOTS = {
  ERC1967_IMPL_SLOT,
  ERC1967_ADMIN_SLOT,
  ERC1967_BEACON_SLOT,
  OZ_LEGACY_IMPL_SLOT,
  EIP1822_IMPL_SLOT,
} as const;
