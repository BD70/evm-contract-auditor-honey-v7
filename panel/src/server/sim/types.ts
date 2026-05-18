// Shared types for the simulation verifier pipeline. Each verifier
// (arbitrary-call, selfdestruct, initialize-takeover, …) consumes a
// VerifyInput and returns a VerifyResult. The worker treats the verdict as
// authoritative for the (bytecode_hash, rule_id, engine, engine_version)
// quad — same combination = same answer.

export type VerdictStatus =
  | "verified"
  | "not_exploitable"
  | "inconclusive"
  | "skipped"
  | "error";

export interface VerifyInput {
  chainId: number;
  contractAddress: string;
  ruleId: string;
  /** Optional precomputed runtime bytecode for the target. When omitted, the
   * driver fetches it via eth_getCode against the fork. */
  bytecodeHex?: string;
  /** Raw Go analyzer finding JSON; passed to extractWitnessSelector for
   * identifying the vulnerable function selector. */
  evidence?: unknown;
}

export interface VerifyResult {
  status: VerdictStatus;
  /** Short human-readable explanation; rendered in the UI verdict badge. */
  verdict?: string;
  engine: string;
  engineVersion: string;
  /** Free-form structured evidence. Verifiers should namespace their fields
   * (e.g. `attempts`, `selfdestruct`, `initialize`) so the UI can render the
   * shape it recognises. */
  evidence: Record<string, unknown>;
  durationMs: number;
}

export interface Verifier {
  /** Stable identifier used by the cache (`engine`). Must not change unless
   * the verification semantics change. */
  id: string;
  version: string;
  /** Rule IDs this verifier knows how to verify. */
  rules: string[];
  verify(input: VerifyInput): Promise<VerifyResult>;
}
