// Safe (Gnosis) multisig integration for the rescue pipeline.
//
// When a contract is owned by a Safe, we can't just sign a rescue tx from
// the owner's EOA — the Safe requires the configured threshold of
// co-signers, and the actual call goes via `execTransaction(...)` on the
// Safe contract itself.
//
// Two-tier approach:
//   1. DETECT: if the verifier evidence carries `ownerClassification.kind
//      === "safe"`, AND the PoE has at least one owner-executor drain
//      step, the PoE is tagged with verdict `requires_safe_signing` (or
//      via the executorOwner being recorded as a Safe — broadcaster
//      checks both).
//   2. PROPOSE: when the operator chooses "live" mode, instead of
//      broadcasting raw txs, the broadcaster constructs a Safe Transaction
//      Service payload (one MultiSig tx per drain step) and POSTs each
//      to the chain-appropriate tx-service endpoint. The operator then
//      uses the Safe app to collect the remaining signatures.
//
// In v4 we only ship the DETECTION layer + a deeplink generator for the
// Safe app's Transaction Builder. Direct tx-service POSTing requires a
// proposer key + EIP-712 signing of SafeTx — that's a separate v5 lift
// the operator can wire later. The deeplink is enough for a human to:
//   - click into the Safe app
//   - paste the rescue calldata into Transaction Builder
//   - propose to co-signers
//
// Safe Transaction Service per-chain endpoints (Safe Global):
//   mainnet:  https://safe-transaction-mainnet.safe.global
//   polygon:  https://safe-transaction-polygon.safe.global
//   bsc:      https://safe-transaction-bsc.safe.global
//   arbitrum: https://safe-transaction-arbitrum.safe.global
//   optimism: https://safe-transaction-optimism.safe.global
//   base:     https://safe-transaction-base.safe.global
//   avalanche: https://safe-transaction-avalanche.safe.global
//
// Safe app deeplink format (Transaction Builder):
//   https://app.safe.global/{shortName}:{safeAddress}/apps?appUrl=...

export interface SafeChainMeta {
  /** Short EIP-3770 name used in the Safe app URL */
  shortName: string;
  /** Safe Transaction Service base URL (no trailing slash) */
  txServiceUrl: string;
}

export const SAFE_CHAINS: Record<number, SafeChainMeta> = {
  1: { shortName: "eth", txServiceUrl: "https://safe-transaction-mainnet.safe.global" },
  10: { shortName: "oeth", txServiceUrl: "https://safe-transaction-optimism.safe.global" },
  56: { shortName: "bnb", txServiceUrl: "https://safe-transaction-bsc.safe.global" },
  100: { shortName: "gno", txServiceUrl: "https://safe-transaction-gnosis-chain.safe.global" },
  137: { shortName: "matic", txServiceUrl: "https://safe-transaction-polygon.safe.global" },
  8453: { shortName: "base", txServiceUrl: "https://safe-transaction-base.safe.global" },
  42161: { shortName: "arb1", txServiceUrl: "https://safe-transaction-arbitrum.safe.global" },
  43114: { shortName: "avax", txServiceUrl: "https://safe-transaction-avalanche.safe.global" },
};

/** Generate a Safe app deeplink that lands the operator in the
 *  Transaction Builder for a specific Safe, on the right chain. The
 *  operator pastes our rescue calldata into the builder and proposes. */
export function safeAppDeeplink(chainId: number, safeAddress: string): string | null {
  const meta = SAFE_CHAINS[chainId];
  if (!meta) return null;
  const safe = safeAddress.toLowerCase();
  // Direct link to the Transaction Builder app on the Safe.
  return `https://app.safe.global/${meta.shortName}:${safe}/apps?appUrl=https%3A%2F%2Fapps-portal.safe.global%2Ftx-builder`;
}

/** Generate a Safe tx-service "create proposal" endpoint URL for a given
 *  Safe address. The operator (or a v5 background proposer) can POST a
 *  SafeMultisigTransactionData blob to this URL with their proposer
 *  signature. */
export function safeTxServiceEndpoint(chainId: number, safeAddress: string): string | null {
  const meta = SAFE_CHAINS[chainId];
  if (!meta) return null;
  const override = (process.env.RESCUE_SAFE_TX_SERVICE_URL ?? "").trim();
  const base = override || meta.txServiceUrl;
  return `${base.replace(/\/$/, "")}/api/v1/safes/${safeAddress}/multisig-transactions/`;
}

/** Build the human-readable instructions that we emit alongside the
 *  refusal when the broadcaster sees owner=safe. */
export function safeInstructionsFor(
  chainId: number,
  safeAddress: string,
  drainPlan: Array<{ to: string; data: string; value: string; asset: string }>,
): string {
  const deeplink = safeAppDeeplink(chainId, safeAddress);
  const txService = safeTxServiceEndpoint(chainId, safeAddress);
  const lines: string[] = [
    `OWNER IS A SAFE — live broadcast refused.`,
    `Safe address: ${safeAddress}`,
    `Drain plan has ${drainPlan.length} step(s); each needs to be proposed as a separate Safe tx (or batched via the Transaction Builder).`,
  ];
  if (deeplink) {
    lines.push(`Open Transaction Builder: ${deeplink}`);
  }
  if (txService) {
    lines.push(`Or POST proposals to: ${txService}`);
  }
  lines.push(`For each drain step, paste {to, data, value} from the PoE drainPlan into the builder.`);
  return lines.join("\n");
}

/** Quick check: does this PoE need Safe handling? Returns the safe address
 *  when yes, null otherwise. Reads from ownerClassification in evidence
 *  if available, falls back to executorOwner. */
export function needsSafeProposal(args: {
  evidence: Record<string, unknown> | undefined;
  executorOwner: string | null | undefined;
}): string | null {
  const ev = (args.evidence ?? {}) as any;
  const cls = ev.ownerClassification;
  if (cls && cls.kind === "safe" && typeof cls.address === "string") return cls.address.toLowerCase();
  // Heuristic fallback: when executorOwner is set, check the verifier's
  // classification heuristic flag if available.
  if (args.executorOwner && cls && cls.kind === "safe") {
    return args.executorOwner.toLowerCase();
  }
  return null;
}
