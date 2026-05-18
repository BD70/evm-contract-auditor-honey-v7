// Per-rule "value-at-risk" surface.
//
// Different vulnerability families drain different things. Treating ALL
// findings as "has exposure if native OR tokens > 0" is misleading:
//   * An unguarded selfdestruct CAN'T touch ERC-20 balances — they stay
//     glued to the address regardless. Only native ETH is at risk.
//   * An arbitrary external CALL can drain ERC-20s (the attacker can
//     impersonate this contract toward any pre-approved spender) AND
//     native (CALL with value). Both surfaces matter.
//   * A controlled DELEGATECALL is a total takeover: same as both.
//   * An uninitialized initializer means the new owner inherits all
//     privileges — practically equivalent to "both".
//
// The worker uses this to decide whether a finding's exposure justifies
// running a (relatively expensive) fork simulation. The UI uses it to
// show ONLY the at-risk surface (or visually de-emphasise the rest) so
// the user isn't misled into thinking a token balance is "covered" by a
// native-only vulnerability.

export type ExposureSurface = "native" | "token" | "both" | "none";

// Rule -> surface mapping. Keep keys lowercased to match the rule_id
// canonicalisation in the findings DB.
const RULE_SURFACE: Record<string, ExposureSurface> = {
  // --- arbitrary external call: drains anything (native via CALL{value:},
  // tokens via transferFrom on pre-approved spenders / direct transfer)
  "call.arbitrary_external_call_unvalidated_target": "both",
  "call.unvalidated_calldataload_target_injection": "both",
  "call.user_controlled_external_target": "both",

  // --- delegatecall: total takeover. Same as both.
  "delegatecall.storage_controlled_target": "both",
  "delegatecall.user_controlled_target": "both",
  "delegatecall.unvalidated_target": "both",

  // --- selfdestruct: native only. ERC-20s held by the address are NOT
  // refunded to anyone; they stay at the address. Post-EIP-6780 this only
  // matters on contracts deployed in the same tx, but the rule still
  // flags pre-6780 contracts where the issue is live.
  "selfdestruct.unguarded": "native",
  "control.unguarded_selfdestruct": "native",
  "control.selfdestruct_user_controlled_recipient": "native",

  // --- init / takeover: new owner can do anything, so both surfaces are
  // at risk through the eventual owner-only operations.
  "init.public_initializer_takeover": "both",
  "init.uninitialized_proxy": "both",
  "control.unguarded_initialize": "both",
  "access.public_initialize": "both",

  // --- reentrancy: reenters into a function that can drain both native and
  // token balances depending on what the contract does. Default to both.
  "reentrancy.classic_mutex_absent": "both",
  "reentrancy.cross_function": "both",
  "reentrancy.read_only_exposure": "both",

  // --- access-control / ownership escalation: total takeover, both surfaces.
  "access.ownership_transfer_unguarded": "both",
  "access.admin_role_grant_unguarded": "both",

  // --- price-oracle manipulation: depends on what's swapped; typically tokens.
  "oracle.spot_price_manipulation": "token",
  "oracle.unchecked_chainlink_answer": "both",

  // --- permissionless economic action: function with no auth triggers an
  // AMM swap, vulnerable to flash-loan price manipulation. The drained
  // asset can be either the contract's tokens (forced sell at bad rate),
  // its native (forced wrap-and-swap) or both, so we conservatively flag
  // both surfaces as at-risk.
  "economic.unguarded_amm_action": "both",
  "access.public_economic_action_unguarded": "both",
};

/**
 * Look up the at-risk surface for a rule. Unknown rules default to "both"
 * (conservative: don't accidentally skip exposure checking for a rule we
 * haven't classified yet).
 */
export function exposureSurfaceForRule(ruleId: string): ExposureSurface {
  return RULE_SURFACE[ruleId] ?? "both";
}

/**
 * Pretty label for the surface, for use in verdicts and UI tooltips.
 */
export function surfaceLabel(s: ExposureSurface): string {
  switch (s) {
    case "native":
      return "native only";
    case "token":
      return "ERC-20 tokens only";
    case "both":
      return "native + ERC-20 tokens";
    case "none":
      return "none";
  }
}
