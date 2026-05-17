// Verbose inspection endpoint for the fork simulator. Use this to debug a
// suspected true-positive that the regular verifier is marking
// "not_exploitable". Returns a fully transparent dump of:
//
//   * Proxy resolution (which slot, what address, what family)
//   * Decompiler output (every function discovered, its selector, arg types)
//   * Every attempt that was made (selector, position, payload, value)
//   * The full call tree for each attempt
//   * Decoded revert reason for each attempt (via debug_traceCall + eth_call
//     fallback)
//
// Accepts EITHER `{findingId}` (look up contract+chain+rule from DB) OR
// raw `{chainId, contractAddress, ruleId}` so it can be used without first
// running an audit.

import { NextResponse } from "next/server";
import { bootOnce } from "@/src/server/boot";
import { anvilPool, ATTACKER_ADDRESS } from "@/src/server/sim/anvil-pool";
import { canVerifyRule, SUPPORTED_RULES } from "@/src/server/sim/exploits";
import { deconBytecode, rankExploitCandidates, type DeconFunction } from "@/src/server/sim/decon";
import { resolveProxy, looksLikeProxy } from "@/src/server/sim/proxy-resolver";
import {
  buildCalldataAddressAt,
  buildCalldataFromSignature,
  probePositionsFromSignature,
} from "@/src/server/sim/abi";
import { resolveSelectors } from "@/src/server/sim/selector-resolver";
import { getCode } from "@/src/server/sim/evm";
import {
  debugTraceCall,
  findProbeWitness,
  isAuthRevert,
  readContractOwner,
  impersonate,
  type CallNode,
} from "@/src/server/sim/trace";
import { rawDb } from "@/src/db/client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_CANDIDATES = Number(process.env.SIM_INSPECT_MAX_CANDIDATES ?? 32);
const MAX_POSITIONS = Number(process.env.SIM_INSPECT_MAX_POSITIONS ?? 6);
const MAX_TRACE_NODES = 256; // cap depth/breadth dumped back to client

const BYTES_PAYLOADS = [
  "0x",
  "0x00000000",
  "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
];
const VALUES = ["0x0", "0x1"];

interface InspectInput {
  chainId: number;
  contractAddress: string;
  ruleId: string;
}

export async function POST(req: Request) {
  bootOnce();
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid JSON" }, { status: 400 });
  }
  const input = await resolveInput(body);
  if ("error" in input) return NextResponse.json({ error: input.error }, { status: 400 });

  const supported = canVerifyRule(input.ruleId);
  const out: Record<string, any> = {
    input,
    supportedRule: supported,
    supportedRules: SUPPORTED_RULES,
    startedAt: Date.now(),
  };
  if (!supported) {
    out.note = "rule is not in the verifier registry; nothing to inspect";
    return NextResponse.json(out);
  }

  const anvil = await anvilPool.acquire(input.chainId).catch((e: any) => {
    out.anvilError = String(e?.message ?? e);
    return null;
  });
  if (!anvil) {
    out.note = "anvil acquisition failed";
    return NextResponse.json(out);
  }
  out.anvil = { url: anvil.url, probeAddress: anvil.probeAddress, forkBlock: anvil.forkBlock };

  let bytecode = "";
  try {
    bytecode = await getCode(anvil.url, input.contractAddress);
  } catch (err: any) {
    out.codeError = String(err?.message ?? err);
  }
  out.bytecode = {
    present: Boolean(bytecode && bytecode !== "0x"),
    byteLen: bytecode ? Math.max(0, (bytecode.length - 2) / 2) : 0,
    prefix: bytecode ? bytecode.slice(0, 50) + "…" : null,
  };
  if (!bytecode || bytecode === "0x") {
    out.note = "no bytecode at address on fork — verify chainId matches";
    return NextResponse.json(out);
  }

  const proxyInfo = await resolveProxy({ rpcUrl: anvil.url, address: input.contractAddress }).catch(
    () => null,
  );
  out.proxy = proxyInfo;

  let decon = await safeDecon(bytecode);
  out.decon = {
    contractFamily: decon.contractFamily,
    globalTags: decon.globalTags,
    functionCount: decon.functions.length,
    functions: decon.functions.map((f) => ({
      selector: f.selector,
      name: f.name,
      argCount: f.argCount,
      argTypes: f.argTypes,
      tags: (f as any).tags,
      mutability: (f as any).mutability,
    })),
  };

  let usedImpl: string | null = null;
  if (
    decon.functions.length === 0 &&
    proxyInfo?.impl &&
    looksLikeProxy({
      bytecodeHex: bytecode,
      deconFamily: decon.contractFamily,
      globalTags: decon.globalTags,
    })
  ) {
    out.proxyImplResolved = proxyInfo.impl;
    try {
      const implBytecode = await getCode(anvil.url, proxyInfo.impl);
      if (implBytecode && implBytecode !== "0x") {
        const implDecon = await safeDecon(implBytecode);
        if (implDecon.functions.length > 0) {
          decon = implDecon;
          usedImpl = proxyInfo.impl;
          out.deconImpl = {
            contractFamily: implDecon.contractFamily,
            functionCount: implDecon.functions.length,
            functions: implDecon.functions.map((f) => ({
              selector: f.selector,
              name: f.name,
              argCount: f.argCount,
              argTypes: f.argTypes,
            })),
          };
        }
      }
    } catch (err: any) {
      out.deconImplError = String(err?.message ?? err);
    }
  }

  const candidates = rankExploitCandidates(decon.functions).slice(0, MAX_CANDIDATES);
  const resolvedSignatures = await resolveSelectors(candidates.map((c) => c.selector!));
  out.candidates = candidates.map((f) => {
    const sigs = resolvedSignatures.get(f.selector!) ?? [];
    return {
      selector: f.selector,
      name: f.name,
      argCount: f.argCount,
      argTypes: f.argTypes,
      resolvedSignatures: sigs.map((s) => ({ name: s.name, argTypes: s.argTypes, source: s.source })),
    };
  });
  if (candidates.length === 0) {
    out.note = "no candidate exploitable selectors after ranking — verifier had nothing to try";
    return NextResponse.json(out);
  }

  const victimLower = input.contractAddress.toLowerCase();
  const attempts: any[] = [];

  for (const fn of candidates) {
    const resolved = (resolvedSignatures.get(fn.selector!) ?? [])[0] ?? null;
    const positions = resolved
      ? probePositionsFromSignature(resolved.argTypes).slice(0, MAX_POSITIONS)
      : candidatePositions(fn);
    for (const pos of positions) {
      for (const bytesPayload of BYTES_PAYLOADS) {
        const data = resolved
          ? buildCalldataFromSignature(
              fn.selector!,
              resolved.argTypes,
              pos,
              anvil.probeAddress,
              { dataBytes: bytesPayload },
            )
          : buildCalldataAddressAt(
              fn.selector!,
              fn.argTypes,
              fn.argCount,
              pos,
              anvil.probeAddress,
              { dataBytes: bytesPayload },
            );
        for (const value of VALUES) {
          const trace = await debugTraceCall(anvil.url, {
            from: ATTACKER_ADDRESS,
            to: input.contractAddress,
            data,
            value,
          });
          const witness = trace.root
            ? findProbeWitness(trace.root, anvil.probeAddress, victimLower)
            : { hit: false };
          attempts.push({
            selector: fn.selector,
            name: resolved?.name ?? fn.name,
            position: pos,
            argCount: resolved?.argTypes.length ?? fn.argCount,
            argTypes: resolved?.argTypes ?? fn.argTypes,
            resolved: Boolean(resolved),
            bytesPayload,
            value,
            calldataPreview: data.slice(0, 100) + (data.length > 100 ? "…" : ""),
            traceError: trace.error,
            revertReason: trace.revertReason,
            authRevert: isAuthRevert(trace.revertReason),
            hit: witness.hit,
            witness,
            callTree: slimTree(trace.root, MAX_TRACE_NODES),
          });
          if (witness.hit) break;
        }
      }
    }
  }

  out.attemptCount = attempts.length;
  out.attempts = attempts;
  const hits = attempts.filter((a) => a.hit);
  const authReverts = attempts.filter((a) => a.authRevert);
  out.summary = {
    hits: hits.length,
    authReverts: authReverts.length,
    otherReverts: attempts.length - hits.length - authReverts.length,
    suggestion:
      hits.length > 0
        ? "EXPLOITABLE: regular verifier would mark this VERIFIED."
        : authReverts.length === attempts.length
          ? "Every attempt was rejected by an access-control check. Try `Re-verify` (owner impersonation will fire) or supply the owner key manually."
          : "Every attempt reverted for non-auth reasons. Review `revertReason` per attempt — the function may need specific state or arg shapes we don't try.",
  };

  // Optionally probe owner impersonation
  if (hits.length === 0 && authReverts.length > 0) {
    const owner = await readContractOwner(anvil.url, input.contractAddress).catch(() => null);
    out.owner = owner;
    if (owner) {
      await impersonate(anvil.url, owner);
      const ownerAttempts: any[] = [];
      for (const fn of candidates.slice(0, 6)) {
        const positions = candidatePositions(fn);
        for (const pos of positions) {
          const calldata = buildCalldataAddressAt(
            fn.selector!,
            fn.argTypes,
            fn.argCount,
            pos,
            anvil.probeAddress,
            { dataBytes: "0x" },
          );
          const trace = await debugTraceCall(anvil.url, {
            from: owner,
            to: input.contractAddress,
            data: calldata,
            value: "0x0",
          });
          const witness = trace.root
            ? findProbeWitness(trace.root, anvil.probeAddress, victimLower)
            : { hit: false };
          ownerAttempts.push({
            selector: fn.selector,
            position: pos,
            hit: witness.hit,
            witnessKind: witness.kind,
            revertReason: trace.revertReason,
          });
          if (witness.hit) break;
        }
      }
      out.ownerImpersonationAttempts = ownerAttempts;
      out.ownerImpersonationHits = ownerAttempts.filter((a) => a.hit);
    }
  }

  out.durationMs = Date.now() - out.startedAt;
  return NextResponse.json(out);
}

async function resolveInput(
  body: any,
): Promise<InspectInput | { error: string }> {
  const findingId = body?.findingId;
  if (findingId) {
    const row = rawDb
      .prepare(
        `SELECT rule_id as ruleId, contract_address as contractAddress, chain_id as chainId
         FROM findings WHERE id = ?`,
      )
      .get(String(findingId)) as
      | { ruleId: string; contractAddress: string | null; chainId: number | null }
      | undefined;
    if (!row) return { error: "finding not found" };
    if (!row.contractAddress || row.chainId == null) return { error: "finding missing contract/chain" };
    return { chainId: row.chainId, contractAddress: row.contractAddress, ruleId: row.ruleId };
  }
  const chainId = Number(body?.chainId);
  const contractAddress = String(body?.contractAddress ?? "");
  const ruleId = String(body?.ruleId ?? "");
  if (!Number.isFinite(chainId) || chainId <= 0) return { error: "chainId required" };
  if (!/^0x[a-fA-F0-9]{40}$/.test(contractAddress)) return { error: "valid contractAddress required" };
  if (!ruleId) return { error: "ruleId required" };
  return { chainId, contractAddress, ruleId };
}

async function safeDecon(bytecodeHex: string) {
  try {
    return await deconBytecode(bytecodeHex);
  } catch {
    return {
      bytecodeHash: "",
      functions: [] as DeconFunction[],
      contractFamily: null as string | null,
      globalTags: [] as string[],
    };
  }
}

function candidatePositions(fn: DeconFunction): number[] {
  const ps: number[] = [];
  const n = Math.min(fn.argCount, 8);
  for (let i = 0; i < n; i++) if (fn.argTypes[i] === "address") ps.push(i);
  for (let i = 0; i < Math.min(n, MAX_POSITIONS); i++) if (!ps.includes(i)) ps.push(i);
  return ps.slice(0, MAX_POSITIONS + 1);
}

/** Slim a call tree down to something serializable + bounded. */
function slimTree(node: CallNode | null, budget: number): any {
  if (!node) return null;
  let remaining = budget;
  function visit(n: CallNode | undefined): any {
    if (!n || remaining <= 0) return null;
    remaining--;
    const out: Record<string, any> = {
      type: n.type,
      from: n.from,
      to: n.to,
      input: n.input ? n.input.slice(0, 80) + (n.input.length > 80 ? "…" : "") : null,
      output: n.output ? n.output.slice(0, 80) + (n.output.length > 80 ? "…" : "") : null,
      value: n.value,
      error: n.error,
      revertReason: n.revertReason,
    };
    if (Array.isArray(n.calls) && n.calls.length > 0 && remaining > 0) {
      out.calls = n.calls.map(visit).filter((x) => x !== null);
    }
    return out;
  }
  return visit(node);
}
