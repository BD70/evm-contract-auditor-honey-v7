// Package witness ports evm_check.witness: native deterministic witness backends.
package witness

import (
	"fmt"
	"math/big"

	chk "github.com/evm-auditor/evm-auditor/internal/check"
)

// Collect mirrors evm_check.witness.collect_witness. Returns nil when no
// witness is produced.
func Collect(audit, rule map[string]any, context map[string]any) map[string]any {
	if context == nil {
		context = map[string]any{}
	}
	proof := chk.AsMap(rule["proof"])
	preferred := chk.AsString(proof["preferred_witness"])
	if preferred == "" {
		preferred = "none"
	}
	switch preferred {
	case "none":
		return nil
	case "deterministic_accounting_witness":
		return deterministicAccountingWitness(context)
	case "deterministic_arithmetic_witness":
		return deterministicRoundingWitness(audit, context)
	case "transaction_sequence":
		return transactionSequenceWitness(rule, context)
	case "reachable_path", "invariant_argument":
		return map[string]any{
			"kind":    preferred,
			"source":  "native_checker",
			"summary": "Matched detector predicates with bound state joins and effect constraints.",
		}
	}
	wg := chk.AsMap(proof["witness_generation"])
	adapters, _ := wg["optional_adapters"].([]any)
	if len(adapters) > 0 {
		return map[string]any{
			"kind":     preferred,
			"source":   "adapter_placeholder",
			"summary":  "Optional witness adapters are declared but not required for base detection.",
			"adapters": adapters,
		}
	}
	return nil
}

func deterministicRoundingWitness(audit, context map[string]any) map[string]any {
	fn := chk.AsMap(context["function"])
	for _, factAny := range chk.AsList(fn["arithmetic"]) {
		fact := chk.AsMap(factAny)
		op := chk.AsString(fact["operation"])
		if op != "fixed_point_mul_div" && op != "fixed_point_candidate" {
			continue
		}
		scale := chk.AsInt(fact["scaling_factor"], 1_000_000_000_000_000_000)
		denom := chk.AsInt(fact["denominator"], 1_000_000_000_000_000_000)
		if denom == 0 {
			continue
		}
		// EVM arithmetic is 256-bit; Python uses arbitrary-precision ints.
		// int64 products overflow (256 * 1e18) and produced bogus negative
		// witnesses — must use math/big to stay byte-identical to Python.
		bScale := big.NewInt(int64(scale))
		bDenom := big.NewInt(int64(denom))
		const maxAmount = 256
		for amount := 1; amount <= maxAmount; amount++ {
			bAmount := big.NewInt(int64(amount))
			product := new(big.Int).Mul(bAmount, bScale)
			bRounded := new(big.Int).Quo(product, bDenom)
			bRemainder := new(big.Int).Rem(product, bDenom)
			rounded := bRounded.Int64()
			remainder := bRemainder.Int64()
			if bRemainder.Sign() != 0 && bRounded.Cmp(bAmount) <= 0 {
				paths := chk.AsList(fn["paths"])
				var pathID any
				if len(paths) > 0 {
					pathID = chk.AsMap(paths[0])["id"]
				}
				return map[string]any{
					"kind":                 "deterministic_arithmetic_witness",
					"source":               "native_checker",
					"witness_id":           fact["id"],
					"path_id":              pathID,
					"amount":               amount,
					"scaling_factor":       scale,
					"denominator":          denom,
					"rounded":              rounded,
					"discarded_remainder":  remainder,
					"evidence_refs": map[string]any{
						"arithmetic_fact": fact["id"],
						"offset":          fact["offset"],
						"block":           fact["block"],
					},
				}
			}
		}
	}
	_ = audit
	return nil
}

func transactionSequenceWitness(rule, context map[string]any) map[string]any {
	sequencesAny := chk.AsList(context["sequences"])
	if len(sequencesAny) == 0 {
		return nil
	}
	first := chk.AsMap(sequencesAny[0])
	pathIDs := []any{}
	evidenceRefs := []any{}
	steps := chk.AsList(first["steps"])
	for _, sa := range steps {
		step := chk.AsMap(sa)
		writer := chk.AsMap(step["writer"])
		reader := chk.AsMap(step["reader"])
		call := chk.AsMap(step["call"])
		var path any
		if v := writer["path"]; v != nil {
			path = v
		} else if v := reader["path"]; v != nil {
			path = v
		} else if v := call["path"]; v != nil {
			path = v
		} else if v := step["path"]; v != nil {
			path = v
		}
		if path != nil && !inList(pathIDs, path) {
			pathIDs = append(pathIDs, path)
		}
		for _, row := range []map[string]any{writer, reader, call} {
			if ref := row["action_id"]; ref != nil && !inList(evidenceRefs, ref) {
				evidenceRefs = append(evidenceRefs, ref)
			}
		}
		if slot := step["slot"]; slot != nil && !inList(evidenceRefs, slot) {
			evidenceRefs = append(evidenceRefs, slot)
		}
	}
	ruleMeta := chk.AsMap(rule["rule"])
	ruleID := chk.AsString(ruleMeta["id"])
	stepCount := len(steps)
	return map[string]any{
		"kind":          "transaction_sequence",
		"source":        "native_checker",
		"witness_id":    fmt.Sprintf("%s:%d_step_sequence", ruleID, stepCount),
		"path_ids":      pathIDs,
		"steps":         steps,
		"bindings":      first["bindings"],
		"evidence_refs": evidenceRefs,
		"summary":       fmt.Sprintf("Matched %d-step exploit sequence for %s.", stepCount, ruleID),
	}
}

func deterministicAccountingWitness(context map[string]any) map[string]any {
	fn := chk.AsMap(context["function"])
	for _, factAny := range chk.AsList(fn["accounting"]) {
		fact := chk.AsMap(factAny)
		effects := chk.SetFromList(fact["economic_effects"])
		if _, ok := effects["balance_inflation_without_supply_change"]; !ok {
			continue
		}
		evidenceRefs := chk.AsMap(fact["evidence_refs"])
		return map[string]any{
			"kind":                 "deterministic_accounting_witness",
			"source":               "native_checker",
			"witness_id":           fact["id"],
			"path_id":              fact["path_id"],
			"gross_amount":         fact["gross_amount"],
			"fee_amount":           fact["fee_amount"],
			"net_amount":           fact["net_amount"],
			"proved_relation":      fact["proved_relation"],
			"sender_debit":         fact["sender_debit"],
			"recipient_credit":     fact["recipient_credit"],
			"fee_credit":           fact["fee_credit"],
			"side_credits":         coalesceList(fact["side_credits"]),
			"total_credited":       fact["sum_of_credits"],
			"total_supply_delta":   fact["supply_delta"],
			"balance_sum_delta":    fact["balance_sum_delta"],
			"invariant":            fact["invariant"],
			"post_invariant_delta": fact["post_invariant_delta"],
			"mismatch_amount":      fact["net_mismatch"],
			"mismatch_relation":    fact["mismatch_relation"],
			"evidence_refs": map[string]any{
				"sender_debit_action":          evidenceRefs["sender_debit_action"],
				"recipient_credit_action":      evidenceRefs["recipient_credit_action"],
				"fee_credit_action":            evidenceRefs["fee_credit_action"],
				"total_supply_nonwrite_proof":  evidenceRefs["total_supply_nonwrite_proof"],
			},
		}
	}
	return nil
}

func coalesceList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{}
}

func inList(list []any, v any) bool {
	for _, item := range list {
		if fmt.Sprint(item) == fmt.Sprint(v) {
			return true
		}
	}
	return false
}
