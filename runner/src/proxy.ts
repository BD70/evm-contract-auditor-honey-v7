import type { AuditTarget, ProxyResolution } from "./types.js";
import type { JsonRpcClient } from "./rpc.js";
import { normalizeHex, parseAddressFromStorage, stripHexPrefix } from "./utils.js";

const EIP1167_PREFIX = "363d3d373d3d3d363d73";
const EIP1167_SUFFIX = "5af43d82803e903d91602b57fd5bf3";
const EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
const IMPLEMENTATION_SELECTOR = "0x5c60da1b";

export function detectEip1167(bytecode: string): { implementationAddress?: string } | undefined {
  const raw = stripHexPrefix(bytecode);
  if (raw.length === 90 && raw.startsWith(EIP1167_PREFIX) && raw.endsWith(EIP1167_SUFFIX)) {
    return { implementationAddress: `0x${raw.slice(20, 60)}` };
  }
  const idx = raw.indexOf(EIP1167_PREFIX);
  if (idx >= 0) {
    const addressStart = idx + EIP1167_PREFIX.length;
    const suffixStart = addressStart + 40;
    if (raw.slice(suffixStart, suffixStart + EIP1167_SUFFIX.length) === EIP1167_SUFFIX) {
      return { implementationAddress: `0x${raw.slice(addressStart, addressStart + 40)}` };
    }
  }
  return undefined;
}

export async function resolveProxy(
  rpc: JsonRpcClient,
  address: string,
  runtimeBytecode: string,
  blockNumber: number,
): Promise<ProxyResolution> {
  const normalizedRuntime = normalizeHex(runtimeBytecode);
  const raw = stripHexPrefix(normalizedRuntime);
  const delegatecallOpcodePresent = raw.includes("f4");
  const eip1167 = detectEip1167(normalizedRuntime);
  if (eip1167?.implementationAddress) {
    return {
      detected: true,
      status: "resolved",
      proxyType: "eip1167",
      fixedCloneTarget: eip1167.implementationAddress,
      implementationAddress: eip1167.implementationAddress,
      implementationResolved: true,
      hints: {
        source: "runner-rpc",
        delegatecallOpcodePresent,
        eip1167Detected: true,
      },
    };
  }

  let implementationSlot: string;
  let adminSlot: string;
  let beaconSlot: string;
  try {
    [implementationSlot, adminSlot, beaconSlot] = await Promise.all([
      rpc.getStorageAt(address, EIP1967_IMPLEMENTATION_SLOT, blockNumber),
      rpc.getStorageAt(address, EIP1967_ADMIN_SLOT, blockNumber),
      rpc.getStorageAt(address, EIP1967_BEACON_SLOT, blockNumber),
    ]);
  } catch (error) {
    return {
      detected: false,
      status: "unresolved_rpc_error",
      implementationResolved: false,
      unresolvedReason: error instanceof Error ? error.message : "proxy_slot_lookup_failed",
      hints: {
        source: "runner-rpc",
        delegatecallOpcodePresent,
      },
    };
  }

  const implementationAddress = parseAddressFromStorage(implementationSlot);
  const adminAddress = parseAddressFromStorage(adminSlot);
  const beaconAddress = parseAddressFromStorage(beaconSlot);

  if (implementationAddress && beaconAddress) {
    return {
      detected: true,
      status: "ambiguous",
      proxyType: "beacon",
      implementationAddress,
      adminAddress,
      beaconAddress,
      implementationResolved: true,
      unresolvedReason: "both_implementation_and_beacon_slots_populated",
      hints: {
        source: "runner-rpc",
        delegatecallOpcodePresent,
      },
    };
  }

  if (beaconAddress) {
    try {
      const resolvedFromBeacon = await resolveBeaconImplementation(rpc, beaconAddress, blockNumber);
      return {
        detected: true,
        status: resolvedFromBeacon ? "resolved" : "unresolved_safe",
        proxyType: resolvedFromBeacon ? "beacon" : "erc1967",
        implementationAddress: resolvedFromBeacon,
        adminAddress,
        beaconAddress,
        implementationResolved: Boolean(resolvedFromBeacon),
        unresolvedReason: resolvedFromBeacon ? undefined : "beacon_implementation_unresolved",
        hints: {
          source: "runner-rpc",
          delegatecallOpcodePresent,
        },
      };
    } catch (error) {
      return {
        detected: true,
        status: "unresolved_rpc_error",
        proxyType: "beacon",
        adminAddress,
        beaconAddress,
        implementationResolved: false,
        unresolvedReason: error instanceof Error ? error.message : "beacon_call_failed",
        hints: {
          source: "runner-rpc",
          delegatecallOpcodePresent,
        },
      };
    }
  }

  if (implementationAddress) {
    return {
      detected: true,
      status: "resolved",
      proxyType: "erc1967",
      implementationAddress,
      adminAddress,
      implementationResolved: true,
      hints: {
        source: "runner-rpc",
        delegatecallOpcodePresent,
      },
    };
  }

  if (looksLikeGenericDelegatecallProxy(normalizedRuntime)) {
    return {
      detected: true,
      status: "unresolved_safe",
      proxyType: "delegatecall_generic",
      implementationResolved: false,
      unresolvedReason: "delegatecall_proxy_without_safe_resolution",
      hints: {
        source: "runner-rpc",
        delegatecallOpcodePresent,
      },
    };
  }

  // Bytecode-evidence fallback: if runtime bytecode contains EIP-1967 impl
  // slot constant or upgrade selectors, this is an implementation contract
  // (the logic behind a proxy). Storage slots are empty because the proxy
  // holds state, not the implementation. Without this fallback, every UUPS
  // implementation contract gets classified as "unresolved_safe" and never
  // audited for unprotected upgradeTo.
  const EIP1967_IMPL_HEX = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
  const UPGRADE_TO_SEL = "3659cfe6";
  const UPGRADE_TO_AND_CALL_SEL = "4f1ef286";
  const hasImplSlotInBytecode = raw.includes(EIP1967_IMPL_HEX);
  const hasUpgradeSelector = raw.includes(UPGRADE_TO_SEL) || raw.includes(UPGRADE_TO_AND_CALL_SEL);
  if (hasImplSlotInBytecode || hasUpgradeSelector) {
    return {
      detected: true,
      status: "unresolved_safe",
      proxyType: "erc1967_bytecode_evidence",
      implementationResolved: false,
      unresolvedReason: "implementation_contract_bytecode_evidence",
      hints: {
        source: "runner-rpc",
        delegatecallOpcodePresent,
        bytecodeEvidence: {
          hasEip1967ImplSlot: hasImplSlotInBytecode,
          hasUpgradeSelector,
        },
      },
    };
  }

  return {
    detected: false,
    status: "unresolved_safe",
    implementationResolved: false,
    hints: {
      source: "runner-rpc",
      delegatecallOpcodePresent,
    },
  };
}

export async function buildAdditionalAuditTargets(
  rpc: JsonRpcClient,
  baseTarget: AuditTarget,
): Promise<AuditTarget[]> {
  const targets: AuditTarget[] = [];
  const { proxy } = baseTarget;
  if (proxy.beaconAddress) {
    const beaconCode = normalizeHex(await rpc.getCode(proxy.beaconAddress, baseTarget.blockNumber));
    if (beaconCode !== "0x") {
      targets.push({
        ...baseTarget,
        targetKind: "beacon",
        targetAddress: proxy.beaconAddress,
        runtimeBytecode: beaconCode,
        runtimeBytecodeHash: "",
      });
    } else {
      proxy.status = "empty_code";
      proxy.unresolvedReason = proxy.unresolvedReason ?? "beacon_code_empty";
    }
  }
  if (proxy.implementationAddress) {
    const implementationCode = normalizeHex(await rpc.getCode(proxy.implementationAddress, baseTarget.blockNumber));
    if (implementationCode !== "0x") {
      targets.push({
        ...baseTarget,
        targetKind: "implementation",
        targetAddress: proxy.implementationAddress,
        runtimeBytecode: implementationCode,
        runtimeBytecodeHash: "",
      });
    } else {
      proxy.status = proxy.status === "ambiguous" ? "ambiguous" : "empty_code";
      proxy.unresolvedReason = proxy.unresolvedReason ?? "implementation_code_empty";
    }
  }
  return targets;
}

async function resolveBeaconImplementation(
  rpc: JsonRpcClient,
  beaconAddress: string,
  blockNumber: number,
): Promise<string | undefined> {
  const value = await rpc.ethCall(beaconAddress, IMPLEMENTATION_SELECTOR, blockNumber);
  return parseAddressFromStorage(value);
}

function looksLikeGenericDelegatecallProxy(bytecode: string): boolean {
  const raw = stripHexPrefix(bytecode);
  if (!raw.includes("f4")) {
    return false;
  }
  if (raw.length > 1600) {
    return false;
  }
  const hasFallbackCopyPattern = raw.includes("363d3d37") || raw.includes("366000600037");
  const hasReturnDataBubblePattern = raw.includes("3d82803e") || raw.includes("3e903d91");
  return hasFallbackCopyPattern && hasReturnDataBubblePattern;
}
